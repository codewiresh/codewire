//! Migration 35's authority-stamp triggers on the claim-time bind
//! transaction. The recorder's fence holds the environment row, then
//! `write_binding` locks the backend and the Pod's binding, releases the
//! previous binding, inserts the new one, moves the backend pointer and
//! notifies; the release, insert and pointer move each bump the environment's
//! generation. These tests run that exact transaction against concurrent
//! writers and measure what the triggers add to it.

use std::time::Instant;

use anyhow::Context;

use super::*;

const ITERATIONS: usize = 100;
const OTHER_USER: &str = "workspace-binding-stamp-other";
const OTHER_CREDENTIAL: &str = "workspace-binding-stamp-credential";
const OTHER_PROFILE: &str = "workspace-binding-stamp-profile";

/// One fenced bind of a fresh Pod, as the recorder runs it, and how long the
/// transaction took from BEGIN to COMMIT.
async fn bind(pool: &PgPool, environment: &str) -> Result<Duration> {
    let pod = uuid::Uuid::new_v4().to_string();
    let authority = ActivityAuthority::capture(pool, environment, GENERATION).await?;
    let started = Instant::now();
    let mut guard = authority.begin_external_mutation(&RUNNING).await?;
    let outcome = write_binding(guard.transaction(), &record(environment, &pod)).await?;
    guard.commit().await?;
    let elapsed = started.elapsed();
    ensure!(outcome == WriteOutcome::Recorded);
    Ok(elapsed)
}

async fn generation(pool: &PgPool, kind: &str, id: &str) -> Result<i64> {
    let generations: Vec<i64> = sqlx::query_scalar(
        "SELECT generations FROM public.codewire_platform_authority_stamp(ARRAY[$1], ARRAY[$2])",
    )
    .bind(kind)
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(generations[0])
}

/// A credential and a profile that belong to another user: writes on scopes
/// the bind transaction never touches.
async fn seed_other_scope(db: &TestDatabase) -> Result<()> {
    db.user(OTHER_USER).await?;
    sqlx::raw_sql(&format!(
        "INSERT INTO platform_credentials(id,user_id,provider,authentication_kind,display_name, \
         status,revocation_generation,material_generation) \
         VALUES ('{OTHER_CREDENTIAL}','{OTHER_USER}','openai','api_key','Other','active',1,1); \
         INSERT INTO platform_access_profiles(id,user_id,name,current_revision) \
         VALUES ('{OTHER_PROFILE}','{OTHER_USER}','Other',1); \
         INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ('{OTHER_PROFILE}',1); \
         INSERT INTO platform_access_profile_entries(profile_id,revision,capability_slot,credential_id) \
         VALUES ('{OTHER_PROFILE}',1,'codex','{OTHER_CREDENTIAL}');"
    ))
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// The concurrent writers. Each is one committed transaction.
#[derive(Clone, Copy, Debug)]
enum Writer {
    /// Bump and restore the environment's operation generation.
    Generation,
    /// A lifecycle-style state write on the environment, then its backend,
    /// in the program-wide order.
    StateThenBackend,
    /// A backend write that does not lock the environment row first.
    BackendOnly,
    /// Billing's tracking update, which the stamp ignores.
    Billing,
    /// A credential rename and a new profile revision of another user.
    OtherScope,
}

fn writer_sql(writer: Writer, iteration: usize) -> String {
    match writer {
        Writer::Generation => format!(
            "UPDATE environments SET environment_operation_generation=environment_operation_generation+1 \
             WHERE id='{ENV_A}'; \
             UPDATE environments SET environment_operation_generation=environment_operation_generation-1 \
             WHERE id='{ENV_A}';"
        ),
        Writer::StateThenBackend => format!(
            "UPDATE environments SET state='running', state_changed_at=clock_timestamp() WHERE id='{ENV_A}'; \
             UPDATE sandbox_environment_backend SET pod_ip='10.0.{}.{}' WHERE environment_id='{ENV_A}';",
            iteration / 250,
            iteration % 250
        ),
        Writer::BackendOnly => format!(
            "UPDATE sandbox_environment_backend SET pod_ip='10.1.{}.{}' WHERE environment_id='{ENV_A}'",
            iteration / 250,
            iteration % 250
        ),
        Writer::Billing => format!(
            "UPDATE environments SET last_billing_event_at=now(), \
             total_running_seconds=total_running_seconds+1 WHERE id='{ENV_A}'"
        ),
        Writer::OtherScope => format!(
            "UPDATE platform_credentials SET display_name='Other {iteration}' WHERE id='{OTHER_CREDENTIAL}'; \
             INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ('{OTHER_PROFILE}',{revision}); \
             INSERT INTO platform_access_profile_entries(profile_id,revision,capability_slot,credential_id) \
             VALUES ('{OTHER_PROFILE}',{revision},'codex','{OTHER_CREDENTIAL}'); \
             UPDATE platform_access_profiles SET current_revision={revision} WHERE id='{OTHER_PROFILE}';",
            revision = iteration + 2
        ),
    }
}

async fn write(pool: &PgPool, writer: Writer, iteration: usize) -> Result<()> {
    // A multi-statement simple query is one implicit transaction.
    sqlx::raw_sql(&writer_sql(writer, iteration))
        .execute(pool)
        .await?;
    Ok(())
}

/// Whether any session of this test database waits for a lock another holds.
/// A row-lock wait is on the holder's transaction ID, which `pg_locks` does
/// not attribute to a database, so ask for each session's blockers instead.
async fn lock_waiter(pool: &PgPool) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() \
         AND cardinality(pg_blocking_pids(pid)) > 0)",
    )
    .fetch_one(pool)
    .await?)
}

/// Wait until `task` is blocked on a lock or has finished. Returns whether it
/// was blocked.
async fn blocked_or_done<T>(pool: &PgPool, task: &tokio::task::JoinHandle<T>) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if task.is_finished() {
            return Ok(false);
        }
        if lock_waiter(pool).await? {
            return Ok(true);
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    anyhow::bail!("neither blocked nor finished")
}

/// Both lock orders, forced: the bind transaction holds every lock it takes
/// while the writer runs, then the writer holds its locks while a bind runs.
/// Each side must finish once the other commits. Returns how many of the two
/// orders actually waited on a lock.
async fn forced_orders(pool: &PgPool, writer: Writer, iteration: usize) -> Result<usize> {
    let mut waited = 0;
    // The bind first.
    let pod = uuid::Uuid::new_v4().to_string();
    let authority = ActivityAuthority::capture(pool, ENV_A, GENERATION).await?;
    let mut guard = authority.begin_external_mutation(&RUNNING).await?;
    ensure!(
        write_binding(guard.transaction(), &record(ENV_A, &pod)).await? == WriteOutcome::Recorded
    );
    let writing = tokio::spawn({
        let pool = pool.clone();
        async move { write(&pool, writer, iteration).await }
    });
    waited += usize::from(blocked_or_done(pool, &writing).await?);
    guard.commit().await?;
    tokio::time::timeout(Duration::from_secs(10), writing)
        .await
        .context("writer did not finish after the bind committed")???;

    // The writer first.
    let mut writing = pool.begin().await?;
    sqlx::raw_sql(&writer_sql(writer, iteration + ITERATIONS))
        .execute(&mut *writing)
        .await?;
    let binding = tokio::spawn({
        let pool = pool.clone();
        async move { bind(&pool, ENV_A).await }
    });
    waited += usize::from(blocked_or_done(pool, &binding).await?);
    writing.commit().await?;
    tokio::time::timeout(Duration::from_secs(10), binding)
        .await
        .context("bind did not finish after the writer committed")???;
    Ok(waited)
}

fn deadlocked(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .and_then(|error| error.as_database_error())
            .and_then(|error| error.code())
            .as_deref()
            == Some("40P01")
    })
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_stamp_triggers_never_deadlock_the_bind_transaction() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        seed_other_scope(&db).await?;
        bind(&db.pool, ENV_A).await?;
        for writer in [
            Writer::Generation,
            Writer::StateThenBackend,
            Writer::BackendOnly,
            Writer::Billing,
            Writer::OtherScope,
        ] {
            let env_before = generation(&db.pool, "env", ENV_A).await?;
            let creds_before = generation(&db.pool, "creds", &format!("user:{OTHER_USER}")).await?;
            let mut waited = 0;
            for iteration in 0..5 {
                waited += forced_orders(&db.pool, writer, 2 * ITERATIONS + iteration).await?;
            }
            let mut failures = Vec::new();
            for iteration in 0..ITERATIONS {
                // Vary which transaction reaches the environment row first.
                let stagger = Duration::from_micros((iteration % 7) as u64 * 150);
                let (bound, written) = tokio::time::timeout(Duration::from_secs(30), async {
                    tokio::join!(bind(&db.pool, ENV_A), async {
                        tokio::time::sleep(stagger).await;
                        write(&db.pool, writer, iteration).await
                    })
                })
                .await
                .with_context(|| format!("{writer:?} iteration {iteration} stalled"))?;
                for outcome in [bound.map(|_| ()), written] {
                    if let Err(error) = outcome {
                        failures.push(format!(
                            "{writer:?} {iteration}: deadlock={} {error:#}",
                            deadlocked(&error)
                        ));
                    }
                }
            }
            ensure!(failures.is_empty(), "{}", failures.join("\n"));
            // Every bind bumped the environment; only the other-scope writer
            // bumped the other user's credentials.
            ensure!(generation(&db.pool, "env", ENV_A).await? > env_before);
            let creds_after = generation(&db.pool, "creds", &format!("user:{OTHER_USER}")).await?;
            ensure!(
                matches!(writer, Writer::OtherScope) == (creds_after > creds_before),
                "{writer:?} changed another scope"
            );
            eprintln!(
                "authority stamp: {writer:?}: both forced lock orders 5 times each ({waited} of 10 waited \
                 on a lock) and {ITERATIONS} staggered concurrent bind transactions, no deadlock"
            );
        }
        // Each bind left exactly one live binding behind.
        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sandbox_workspace_bindings WHERE environment_id=$1 AND released_at IS NULL",
        )
        .bind(ENV_A)
        .fetch_one(&db.pool)
        .await?;
        ensure!(live == 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}

fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * fraction).round() as usize]
}

/// The bind transaction's latency with the stamp triggers on the binding and
/// backend tables enabled and disabled, measured in interleaved blocks. Each
/// block pair's median difference is the cost of the three generation bumps
/// per bind under that moment's load; the median over the pairs is reported
/// and bounded, so load drift between blocks does not count as cost.
///
/// The bound is 1 ms locally, the design target. Hosted CI runners are
/// shared and several times slower (the same three bumps measured 0.27 ms
/// idle and up to 0.62 ms under load here), so there the bound is 3 ms. The
/// database runner already selects its hosted PostgreSQL by `GITHUB_ACTIONS`
/// (`scripts/ci/verify/integration-postgres.sh`); this uses the same signal.
/// 3 ms still fails a fan-out regression: one bump costs about 0.06 ms, so
/// a trigger that touched dozens of rows per write would exceed it.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_stamp_triggers_add_under_a_millisecond_to_the_bind_transaction() -> Result<()> {
    const BLOCKS: usize = 10;
    const PER_BLOCK: usize = 30;
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        // Warm the connections, plans and the trigger function.
        for _ in 0..PER_BLOCK {
            bind(&db.pool, ENV_A).await?;
        }
        let mut enabled = Vec::new();
        let mut disabled = Vec::new();
        let mut added = Vec::new();
        let toggle = |state: &str| {
            format!(
                "ALTER TABLE sandbox_workspace_bindings {state} TRIGGER codewire_stamp_authority_row; \
                 ALTER TABLE sandbox_workspace_bindings {state} TRIGGER codewire_stamp_authority_update; \
                 ALTER TABLE sandbox_environment_backend {state} TRIGGER codewire_stamp_authority_update;"
            )
        };
        for _ in 0..BLOCKS {
            let mut on = Vec::with_capacity(PER_BLOCK);
            for _ in 0..PER_BLOCK {
                on.push(bind(&db.pool, ENV_A).await?);
            }
            sqlx::raw_sql(&toggle("DISABLE")).execute(&db.pool).await?;
            let mut off = Vec::with_capacity(PER_BLOCK);
            let measured = async {
                for _ in 0..PER_BLOCK {
                    off.push(bind(&db.pool, ENV_A).await?);
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            sqlx::raw_sql(&toggle("ENABLE")).execute(&db.pool).await?;
            measured?;
            on.sort();
            off.sort();
            added.push(percentile(&on, 0.5).as_secs_f64() - percentile(&off, 0.5).as_secs_f64());
            enabled.extend(on);
            disabled.extend(off);
        }
        enabled.sort();
        disabled.sort();
        added.sort_by(f64::total_cmp);
        let (on, off) = (percentile(&enabled, 0.5), percentile(&disabled, 0.5));
        let added = added[added.len() / 2];
        eprintln!(
            "authority stamp bind transaction over {} binds each: with triggers p50 {:.3} ms p95 {:.3} ms; \
             without p50 {:.3} ms p95 {:.3} ms; added {:.3} ms (median of paired block medians)",
            enabled.len(),
            on.as_secs_f64() * 1e3,
            percentile(&enabled, 0.95).as_secs_f64() * 1e3,
            off.as_secs_f64() * 1e3,
            percentile(&disabled, 0.95).as_secs_f64() * 1e3,
            added * 1e3,
        );
        let hosted = std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true");
        let bound = if hosted { 0.003 } else { 0.001 };
        ensure!(
            added < bound,
            "the stamp triggers add {:.3} ms to the bind transaction (bound {:.0} ms)",
            added * 1e3,
            bound * 1e3
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
