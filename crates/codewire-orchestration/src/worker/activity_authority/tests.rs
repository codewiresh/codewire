use super::*;
use crate::worker::setup_lease::{
    PhaseAcquire, PhasePreparation, SetupActivityIdentity, SetupPhaseAuthority,
};

#[tokio::test]
async fn external_mutation_wait_is_bounded() {
    let result = await_external_mutation_with_timeout(
        Duration::from_millis(5),
        std::future::pending::<anyhow::Result<()>>(),
    )
    .await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("external mutation exceeded")
    );
}

/// One running Sandbox, for a claim test.
async fn seed_environment(pool: &PgPool) -> String {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let user_id = format!("usr_continued_{suffix}");
    let org_id = format!("org_continued_{suffix}");
    let preset_id = format!("pre_continued_{suffix}");
    let environment_id = format!("env_continued_{suffix}");
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(format!("{suffix}@continued.invalid"))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)")
        .bind(&org_id)
        .bind("Continued test")
        .bind(format!("continued-{suffix}"))
        .bind(&user_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
         VALUES ($1, $2, $3, $4, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(&preset_id)
    .bind(&org_id)
    .bind("Continued test")
    .bind(format!("continued-{suffix}"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO environments
                (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
         VALUES ($1, $2, $3, 'sandbox', 'running', 'started', $4,
                 '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(&environment_id)
    .bind(&org_id)
    .bind(&user_id)
    .bind(&preset_id)
    .execute(pool)
    .await
    .unwrap();
    environment_id
}

async fn generation(pool: &PgPool, environment_id: &str) -> i64 {
    sqlx::query_scalar("SELECT environment_operation_generation FROM environments WHERE id = $1")
        .bind(environment_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// #5950: a run that continued as new from the current holder keeps its
/// generation, once, so a credentialed Sandbox's binding (captured at that
/// generation) stays current; every other claim is fenced as before.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_continued_run_takes_over_its_predecessors_generation_once() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let environment_id = seed_environment(&pool).await;
    let claim = |run: &'static str, scheduled: i64, closed_holder: Option<&'static str>| {
        let pool = pool.clone();
        let environment_id = environment_id.clone();
        async move {
            ActivityAuthority::claim_taking_over(
                &pool,
                &environment_id,
                run,
                scheduled,
                closed_holder,
            )
            .await
        }
    };

    assert_eq!(claim("run-a", 10, None).await.unwrap(), 1);
    // A Sandbox bound now captures generation 1.
    let bound_generation = generation(&pool, &environment_id).await;

    // The continued run keeps it, and the environment's generation, which
    // the binding is compared with, does not move.
    assert_eq!(claim("run-b", 20, Some("run-a")).await.unwrap(), 1);
    assert_eq!(generation(&pool, &environment_id).await, bound_generation);
    // Its retry is idempotent; the predecessor's own retry is fenced.
    assert_eq!(claim("run-b", 20, Some("run-a")).await.unwrap(), 1);
    assert!(is_authority_lost(
        &claim("run-a", 10, None).await.unwrap_err()
    ));

    // Once only: a second successor of the same predecessor finds the
    // claim held by run-b and claims as a new run.
    assert_eq!(claim("run-c", 30, Some("run-a")).await.unwrap(), 2);
    // A predecessor that does not hold the current claim hands nothing on.
    assert_eq!(claim("run-d", 40, Some("run-b")).await.unwrap(), 3);
    // Nor does one scheduled later than its successor.
    assert!(is_authority_lost(
        &claim("run-e", 35, Some("run-d")).await.unwrap_err()
    ));
    // A run naming itself is no continuation.
    assert_eq!(claim("run-f", 50, Some("run-f")).await.unwrap(), 4);
    // Without a predecessor, a new run claims the next generation.
    assert_eq!(claim("run-g", 60, None).await.unwrap(), 5);
}

/// The run named by the claim row of `generation`, if any.
async fn holder_of(pool: &PgPool, environment_id: &str, generation: i64) -> Option<String> {
    sqlx::query_scalar(
        "SELECT workflow_run_id FROM environment_operation_generation_claims
          WHERE environment_id = $1 AND generation = $2",
    )
    .bind(environment_id)
    .bind(generation)
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// A claim by `run` whose read of the holder answers `status`, checking
/// that the holder it asks about is `holder`.
async fn claim_reading(
    pool: &PgPool,
    environment_id: &str,
    run: &str,
    scheduled: i64,
    holder: &str,
    status: anyhow::Result<Option<WorkflowExecutionStatus>>,
) -> anyhow::Result<i64> {
    let expected = holder.to_owned();
    ActivityAuthority::claim_after_holder(
        pool,
        environment_id,
        run,
        scheduled,
        |asked| async move {
            assert_eq!(asked, expected, "the claim asks about the current holder");
            status
        },
    )
    .await
}

/// A Sandbox backend row, for the setup lease.
async fn seed_backend(pool: &PgPool, environment_id: &str) {
    sqlx::query(
        "INSERT INTO sandbox_environment_backend (environment_id, namespace)
         VALUES ($1, 'takeover-test')",
    )
    .bind(environment_id)
    .execute(pool)
    .await
    .unwrap();
}

/// Whether the backend row records a setup owner.
async fn setup_owned(pool: &PgPool, environment_id: &str) -> bool {
    sqlx::query_scalar(
        "SELECT setup_owner_generation IS NOT NULL FROM sandbox_environment_backend
          WHERE environment_id = $1",
    )
    .bind(environment_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn setup_identity(generation: i64) -> SetupActivityIdentity {
    // Activity ids are a per-run sequence, so two runs' setups can share one.
    SetupActivityIdentity::new(generation, "7".into(), 1).unwrap()
}

/// #6103: a holder hands its generation on only when Temporal describes it
/// as closed, with any close status.
#[test]
fn only_an_explicitly_closed_holder_hands_its_generation_on() {
    for status in [
        WorkflowExecutionStatus::ContinuedAsNew,
        WorkflowExecutionStatus::Completed,
        WorkflowExecutionStatus::Failed,
        WorkflowExecutionStatus::Terminated,
        WorkflowExecutionStatus::TimedOut,
        WorkflowExecutionStatus::Canceled,
    ] {
        assert!(is_closed(Some(status)), "{status:?}");
    }
    for status in [
        WorkflowExecutionStatus::Running,
        WorkflowExecutionStatus::Unspecified,
    ] {
        assert!(!is_closed(Some(status)), "{status:?}");
    }
    assert!(!is_closed(None), "a run Temporal has no record of");
}

/// #6103: a fresh run, started after the run holding the generation failed,
/// takes the generation over and keeps it, so a credentialed Sandbox bound
/// at it is not restarted. Its retry reads nothing and keeps it; the failed
/// run's own retried claim is fenced.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_fresh_run_takes_over_the_generation_of_a_run_that_failed() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let environment_id = seed_environment(&pool).await;
    assert_eq!(
        ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
            .await
            .unwrap(),
        1
    );

    let failed = Ok(Some(WorkflowExecutionStatus::Failed));
    assert_eq!(
        claim_reading(&pool, &environment_id, "run-b", 20, "run-a", failed)
            .await
            .unwrap(),
        1
    );
    assert_eq!(generation(&pool, &environment_id).await, 1);
    assert_eq!(
        holder_of(&pool, &environment_id, 1).await.as_deref(),
        Some("run-b")
    );

    let retry =
        ActivityAuthority::claim_after_holder(&pool, &environment_id, "run-b", 20, |_| async {
            anyhow::bail!("a run holding the generation reads no holder")
        })
        .await;
    assert_eq!(retry.unwrap(), 1);
    assert!(is_authority_lost(
        &ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
            .await
            .unwrap_err()
    ));
}

/// #6103: a holder Temporal describes as running, with no status it knows,
/// or has no record of, is not taken over: the new run claims the next
/// generation, which fences it, as a replacement run always has.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_holder_still_running_or_unknown_to_temporal_is_not_taken_over() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let environment_id = seed_environment(&pool).await;
    assert_eq!(
        ActivityAuthority::claim(&pool, &environment_id, "run-0", 10)
            .await
            .unwrap(),
        1
    );
    let statuses = [
        Some(WorkflowExecutionStatus::Running),
        Some(WorkflowExecutionStatus::Unspecified),
        None,
    ];
    for (step, status) in (1_i64..).zip(statuses) {
        let holder = format!("run-{}", step - 1);
        let run = format!("run-{step}");
        assert_eq!(
            claim_reading(
                &pool,
                &environment_id,
                &run,
                10 + step * 10,
                &holder,
                Ok(status)
            )
            .await
            .unwrap(),
            step + 1,
            "{status:?}"
        );
        assert_eq!(
            holder_of(&pool, &environment_id, step).await.as_deref(),
            Some(holder.as_str()),
            "{status:?}: the holder's row stays its own"
        );
        assert!(
            is_authority_lost(
                &ActivityAuthority::claim(&pool, &environment_id, &holder, step * 10)
                    .await
                    .unwrap_err()
            ),
            "{status:?}: the holder is fenced"
        );
    }
}

/// #6103: a holder read that fails claims nothing, on every attempt: the
/// generation and the claim rows stay as they were, and the claim activity
/// retries. A read that then succeeds takes over as usual.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_failed_holder_read_never_claims_a_new_generation() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let environment_id = seed_environment(&pool).await;
    assert_eq!(
        ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
            .await
            .unwrap(),
        1
    );
    for attempt in 1..=3 {
        let error = claim_reading(
            &pool,
            &environment_id,
            "run-b",
            20,
            "run-a",
            Err(anyhow::anyhow!("temporal unavailable")),
        )
        .await
        .unwrap_err();
        assert!(!is_authority_lost(&error), "attempt {attempt}: {error:#}");
        assert_eq!(
            generation(&pool, &environment_id).await,
            1,
            "attempt {attempt}"
        );
        assert_eq!(
            holder_of(&pool, &environment_id, 1).await.as_deref(),
            Some("run-a"),
            "attempt {attempt}"
        );
        assert_eq!(
            holder_of(&pool, &environment_id, 2).await,
            None,
            "attempt {attempt}"
        );
    }
    assert_eq!(
        claim_reading(
            &pool,
            &environment_id,
            "run-b",
            20,
            "run-a",
            Ok(Some(WorkflowExecutionStatus::Failed))
        )
        .await
        .unwrap(),
        1
    );
}

/// #6103: two runs that both read the same closed holder race to take it
/// over; the row locks and the conditional UPDATE on the exact row let
/// exactly one of them keep the generation. The other claims as a new run
/// would against the winner: the next generation if it was scheduled later,
/// `AuthorityLost` if earlier.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_runs_racing_for_one_closed_holder_take_it_over_once() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    for _ in 0..5 {
        let environment_id = seed_environment(&pool).await;
        assert_eq!(
            ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
                .await
                .unwrap(),
            1
        );
        // Both runs have read the holder before either claims.
        let both_read = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let racer = |run: &'static str, scheduled: i64| {
            let pool = pool.clone();
            let environment_id = environment_id.clone();
            let both_read = both_read.clone();
            async move {
                ActivityAuthority::claim_after_holder(
                    &pool,
                    &environment_id,
                    run,
                    scheduled,
                    |holder| async move {
                        assert_eq!(holder, "run-a");
                        both_read.wait().await;
                        Ok(Some(WorkflowExecutionStatus::Terminated))
                    },
                )
                .await
            }
        };
        let (b, c) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(
                tokio::spawn(racer("run-b", 20)),
                tokio::spawn(racer("run-c", 30))
            )
        })
        .await
        .expect("both claims finish");
        let (b, c) = (b.unwrap(), c.unwrap());
        let winner = match (&b, &c) {
            (Ok(1), Ok(2)) => "run-b",
            (Err(error), Ok(1)) if is_authority_lost(error) => "run-c",
            other => panic!("expected exactly one takeover, got {other:?}"),
        };
        assert_eq!(
            holder_of(&pool, &environment_id, 1).await.as_deref(),
            Some(winner)
        );
        let run_a_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM environment_operation_generation_claims
              WHERE environment_id = $1 AND workflow_run_id = 'run-a'",
        )
        .bind(&environment_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(run_a_rows, 0);
    }
}

/// #6103: after a run takes over a terminated run's generation, an activity
/// still executing for the terminated run holds the same generation number,
/// and is refused at its next check by the claim row's run id; the new
/// run's activity writes. A capture outside any run pins the holder too.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_activity_of_a_run_whose_generation_was_taken_over_is_refused() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let environment_id = seed_environment(&pool).await;
    assert_eq!(
        ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
            .await
            .unwrap(),
        1
    );
    let stale = ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-a")
        .await
        .unwrap();
    let pinned = ActivityAuthority::capture(&pool, &environment_id, 1)
        .await
        .unwrap();
    assert_eq!(pinned.claim_run(), Some("run-a"));
    assert!(is_authority_lost(
        &ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-b")
            .await
            .unwrap_err()
    ));

    let terminated = Ok(Some(WorkflowExecutionStatus::Terminated));
    assert_eq!(
        claim_reading(&pool, &environment_id, "run-b", 20, "run-a", terminated)
            .await
            .unwrap(),
        1
    );
    assert_eq!(stale.operation_generation(), 1);

    let write = |authority: ActivityAuthority, reason: &'static str| {
        let environment_id = environment_id.clone();
        async move {
            authority
                .execute_for_states(
                    &["running"],
                    sqlx::query("UPDATE environments SET error_reason = $1 WHERE id = $2")
                        .bind(reason)
                        .bind(&environment_id),
                )
                .await
        }
    };
    for authority in [stale.clone(), pinned] {
        assert!(is_authority_lost(&authority.ensure().await.unwrap_err()));
        assert!(is_authority_lost(
            &authority.ensure_for_states(&["running"]).await.unwrap_err()
        ));
        assert!(is_authority_lost(
            &write(authority.clone(), "stale").await.unwrap_err()
        ));
        assert!(is_authority_lost(
            &authority
                .begin_external_mutation(&["running"])
                .await
                .err()
                .unwrap()
        ));
    }
    assert!(is_authority_lost(
        &ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-a")
            .await
            .unwrap_err()
    ));

    let current = ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-b")
        .await
        .unwrap();
    assert_eq!(write(current, "current").await.unwrap().rows_affected(), 1);
    let reason: Option<String> =
        sqlx::query_scalar("SELECT error_reason FROM environments WHERE id = $1")
            .bind(&environment_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(reason.as_deref(), Some("current"));
    assert_eq!(
        ActivityAuthority::capture(&pool, &environment_id, 1)
            .await
            .unwrap()
            .claim_run(),
        Some("run-b")
    );
}

/// #6103: a takeover clears the setup owner held at the generation, so the
/// old run's next setup step is refused, even with the same activity id and
/// attempt, and the new run's setup acquires the lease as a fresh owner.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn after_a_takeover_the_old_runs_setup_is_refused_and_the_new_runs_acquires() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let environment_id = seed_environment(&pool).await;
    seed_backend(&pool, &environment_id).await;
    assert_eq!(
        ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
            .await
            .unwrap(),
        1
    );
    let old_setup = SetupPhaseAuthority::new(
        ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-a")
            .await
            .unwrap(),
        setup_identity(1),
    )
    .unwrap();
    assert_eq!(
        old_setup.prepare_phase(0).await.unwrap(),
        PhasePreparation::Ready(PhaseAcquire::Acquired)
    );
    assert!(setup_owned(&pool, &environment_id).await);

    let failed = Ok(Some(WorkflowExecutionStatus::Failed));
    assert_eq!(
        claim_reading(&pool, &environment_id, "run-b", 20, "run-a", failed)
            .await
            .unwrap(),
        1
    );
    assert!(!setup_owned(&pool, &environment_id).await);
    assert!(is_authority_lost(
        &old_setup.prepare_phase(0).await.unwrap_err()
    ));

    let new_setup = SetupPhaseAuthority::new(
        ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-b")
            .await
            .unwrap(),
        setup_identity(1),
    )
    .unwrap();
    assert_eq!(
        new_setup.prepare_phase(0).await.unwrap(),
        PhasePreparation::Ready(PhaseAcquire::Acquired)
    );
    new_setup.ensure_active(0).await.unwrap();
    // The lease's identity is the old setup's too; the claim row's run id
    // is what refuses it.
    assert!(is_authority_lost(
        &old_setup.ensure_active(0).await.unwrap_err()
    ));
    assert!(is_authority_lost(
        &old_setup
            .emit_log(0, "health_check", "started", "", None)
            .await
            .unwrap_err()
    ));
}

/// #6103: a takeover and the old run's setup step race. The locks are taken
/// in one order (claim row, environment row, backend row), so neither
/// deadlocks, and the outcome is one of two consistent ones: the setup step
/// acquired first and the takeover cleared its owner, or the takeover came
/// first and the setup step was refused. Either way no owner is left and the
/// old setup is fenced.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_takeover_and_a_setup_step_race_to_one_consistent_outcome() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    for _ in 0..10 {
        let environment_id = seed_environment(&pool).await;
        seed_backend(&pool, &environment_id).await;
        assert_eq!(
            ActivityAuthority::claim(&pool, &environment_id, "run-a", 10)
                .await
                .unwrap(),
            1
        );
        let old_setup = SetupPhaseAuthority::new(
            ActivityAuthority::capture_for_run(&pool, &environment_id, 1, "run-a")
                .await
                .unwrap(),
            setup_identity(1),
        )
        .unwrap();
        let setup = {
            let old_setup = old_setup.clone();
            tokio::spawn(async move { old_setup.prepare_phase(0).await })
        };
        let takeover = {
            let pool = pool.clone();
            let environment_id = environment_id.clone();
            tokio::spawn(async move {
                claim_reading(
                    &pool,
                    &environment_id,
                    "run-b",
                    20,
                    "run-a",
                    Ok(Some(WorkflowExecutionStatus::Failed)),
                )
                .await
            })
        };
        let (setup, takeover) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(setup, takeover)
        })
        .await
        .expect("neither the takeover nor the setup step deadlocks");
        assert_eq!(takeover.unwrap().unwrap(), 1);
        match setup.unwrap() {
            Ok(preparation) => {
                assert_eq!(preparation, PhasePreparation::Ready(PhaseAcquire::Acquired))
            }
            Err(error) => assert!(is_authority_lost(&error), "{error:#}"),
        }
        assert!(!setup_owned(&pool, &environment_id).await);
        assert_eq!(
            holder_of(&pool, &environment_id, 1).await.as_deref(),
            Some("run-b")
        );
        assert!(is_authority_lost(
            &old_setup.ensure_active(0).await.unwrap_err()
        ));
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn generation_claim_and_external_mutation_locking_are_fenced() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPool::connect(&database_url).await.unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let user_id = format!("usr_authority_{suffix}");
    let org_id = format!("org_authority_{suffix}");
    let preset_id = format!("pre_authority_{suffix}");
    let environment_id = format!("env_authority_{suffix}");

    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(format!("{suffix}@authority.invalid"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $2, $3, $4)")
        .bind(&org_id)
        .bind("Authority test")
        .bind(format!("authority-{suffix}"))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
         VALUES ($1, $2, $3, $4, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(&preset_id)
    .bind(&org_id)
    .bind("Authority test")
    .bind(format!("authority-{suffix}"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO environments
                (id, org_id, created_by, type, state, desired_state, preset_id, project_spec)
         VALUES ($1, $2, $3, 'sandbox', 'running', 'started', $4,
                 '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(&environment_id)
    .bind(&org_id)
    .bind(&user_id)
    .bind(&preset_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO sandbox_environment_backend (environment_id, namespace)
         VALUES ($1, 'authority-test')",
    )
    .bind(&environment_id)
    .execute(&pool)
    .await
    .unwrap();

    let old = ActivityAuthority::claim(&pool, &environment_id, "run-old", 10)
        .await
        .unwrap();
    assert_eq!(old, 1);
    let old_authority = ActivityAuthority::capture(&pool, &environment_id, old)
        .await
        .unwrap();
    assert_eq!(
        ActivityAuthority::claim(&pool, &environment_id, "run-old", 10)
            .await
            .unwrap(),
        old,
        "an activity retry must reuse its workflow execution generation"
    );
    let mismatched_retry = ActivityAuthority::claim(&pool, &environment_id, "run-old", 11)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&mismatched_retry));

    let replacement = ActivityAuthority::claim(&pool, &environment_id, "run-new", 20)
        .await
        .unwrap();
    assert_eq!(replacement, 2);
    let old_retry = ActivityAuthority::claim(&pool, &environment_id, "run-old", 10)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&old_retry));
    let delayed_old = ActivityAuthority::claim(&pool, &environment_id, "run-delayed", 15)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&delayed_old));

    let stale_backend = old_authority
        .execute_for_states(
            &["running"],
            sqlx::query(
                "UPDATE sandbox_environment_backend SET namespace = 'stale'
                  WHERE environment_id = $1",
            )
            .bind(&environment_id),
        )
        .await
        .unwrap_err();
    assert!(is_authority_lost(&stale_backend));
    let stale_state = old_authority
        .execute_for_states(
            &["running"],
            sqlx::query("UPDATE environments SET error_reason = 'stale' WHERE id = $1")
                .bind(&environment_id),
        )
        .await
        .unwrap_err();
    assert!(is_authority_lost(&stale_state));
    let stale_log = super::super::env_log::emit_authoritative_environment_log_for_states(
        &old_authority,
        &["running"],
        "stale",
        "failed",
        "stale",
        None,
    )
    .await
    .unwrap_err();
    assert!(is_authority_lost(&stale_log));
    let stale_log_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM environment_logs
          WHERE environment_id = $1 AND phase = 'stale'",
    )
    .bind(&environment_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale_log_count, 0);

    let current_authority = ActivityAuthority::capture(&pool, &environment_id, replacement)
        .await
        .expect("current generation retains authority");

    let guard = current_authority
        .begin_external_mutation(&["running"])
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query(
            "INSERT INTO confidential_storage_keys
                    (environment_id, kbs_uri, openbao_path, version, state)
             VALUES ($1, $2, $3, 1, 'provisioning')",
        )
        .bind(&environment_id)
        .bind(format!(
            "kbs:///default/codewire-workspace-luks/{environment_id}"
        ))
        .bind(format!("confidential-storage/{environment_id}"))
        .execute(&pool),
    )
    .await
    .expect("child foreign-key insert blocked behind its own authority guard")
    .unwrap();

    let mut competing = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '100ms'")
        .execute(&mut *competing)
        .await
        .unwrap();
    let error = sqlx::query("UPDATE environments SET desired_state = 'stopped' WHERE id = $1")
        .bind(&environment_id)
        .execute(&mut *competing)
        .await
        .unwrap_err();
    match error {
        sqlx::Error::Database(database) => {
            assert_eq!(database.code().as_deref(), Some("55P03"));
        }
        other => panic!("expected PostgreSQL lock timeout, got {other}"),
    }
    competing.rollback().await.unwrap();
    guard.commit().await.unwrap();

    let stale = ActivityAuthority::capture(&pool, &environment_id, old)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&stale));

    let missing_generation = ActivityAuthority::capture(&pool, &environment_id, 0)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&missing_generation));

    let empty_run = ActivityAuthority::claim(&pool, &environment_id, "", 30)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&empty_run));

    sqlx::query("DELETE FROM environments WHERE id = $1")
        .bind(&environment_id)
        .execute(&pool)
        .await
        .unwrap();
    let missing = ActivityAuthority::capture(&pool, &environment_id, replacement)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&missing));
    let missing_claim = ActivityAuthority::claim(&pool, &environment_id, "run-missing", 30)
        .await
        .unwrap_err();
    assert!(is_authority_lost(&missing_claim));
    sqlx::query("DELETE FROM environment_presets WHERE id = $1")
        .bind(&preset_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(&org_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
}
