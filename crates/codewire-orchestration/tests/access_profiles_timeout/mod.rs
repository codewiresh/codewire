//! Request timeout is distinct from server query/transaction ownership.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use codewire_access::builtin_provider_catalog;
use codewire_platform_credentials::PlatformAccessProfileStore;
use reqwest::StatusCode;
use serde_json::json;
use sqlx::{PgConnection, PgPool, postgres::PgPoolOptions};

use super::support::*;

async fn timeouts(connection: &mut PgConnection) -> Result<(i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT \
         (SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='statement_timeout'), \
         (SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='lock_timeout'), \
         (SELECT setting::bigint FROM pg_catalog.pg_settings WHERE name='idle_in_transaction_session_timeout')",
    ).fetch_one(connection).await?)
}

async fn set_session_timeouts(
    connection: &mut PgConnection,
    values: (i64, i64, i64),
) -> Result<()> {
    // Explicitly synthetic session configuration: the production initializer
    // must preserve, not replace, these already-shorter values.
    sqlx::query(
        "SELECT pg_catalog.set_config('statement_timeout',$1,false), \
         pg_catalog.set_config('lock_timeout',$2,false), \
         pg_catalog.set_config('idle_in_transaction_session_timeout',$3,false)",
    )
    .bind(values.0.to_string())
    .bind(values.1.to_string())
    .bind(values.2.to_string())
    .execute(connection)
    .await?;
    Ok(())
}

async fn released_backend(h: &Harness, request_pool: &PgPool, pid: i32) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // Observe the exact request backend, not an unrelated spare pool
            // connection. An idle backend or a terminated backend is safe;
            // active/aborted transactions and pending pool cleanup are not.
            let released: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity \
                 WHERE pid=$1 AND (state<>'idle' OR xact_start IS NOT NULL))",
            )
            .bind(pid)
            .fetch_one(&h.db)
            .await?;
            if released && request_pool.num_idle() == request_pool.size() as usize {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("profile request backend or pooled connection survived its server deadline")?
}

async fn assert_local_settings_do_not_leak(h: &Harness) -> Result<()> {
    // Authenticate as the SAME actual restricted role in a one-connection
    // synthetic pool. This makes same-session GUC nonleak deterministic without
    // changing the real service pool or relying on admin + SET ROLE.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*h.service_pool.connect_options()).clone())
        .await?;
    let test = async {
        let store = PlatformAccessProfileStore::new(pool.clone(), builtin_provider_catalog());
        let mut connection = pool.acquire().await?;
        let identity: (String, String, i32) =
            sqlx::query_as("SELECT current_user::text,session_user::text,pg_backend_pid()")
                .fetch_one(&mut *connection)
                .await?;
        ensure!(identity.0 == h.role && identity.1 == h.role);
        let baseline = timeouts(&mut connection).await?;
        drop(connection);
        for configured in [baseline, (750, 500, 1000)] {
            let mut connection = pool.acquire().await?;
            set_session_timeouts(&mut connection, configured).await?;
            drop(connection);
            for commit in [false, true] {
                let mut tx = store.begin_transaction().await?;
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *tx)
                    .await?;
                ensure!(pid == identity.2, "fixture switched sessions");
                let expected = (clamp(configured.0), configured.1, clamp(configured.2));
                ensure!(timeouts(&mut tx).await? == expected);
                if commit {
                    tx.commit().await?;
                } else {
                    tx.rollback().await?;
                }
                let mut connection = pool.acquire().await?;
                ensure!(timeouts(&mut connection).await? == configured);
            }
        }
        let mut connection = pool.acquire().await?;
        set_session_timeouts(&mut connection, baseline).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    pool.close().await;
    test
}

fn clamp(value: i64) -> i64 {
    if value == 0 { 5_000 } else { value.min(5_000) }
}

async fn assert_released_locks(db: &PgPool, binding: bool) -> Result<()> {
    let mut probe = db.begin().await?;
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(ALICE)
        .fetch_one(&mut *probe)
        .await?;
    if binding {
        sqlx::query("SELECT id FROM environments WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(ENV)
            .fetch_one(&mut *probe)
            .await?;
    }
    probe.rollback().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn public_profile_timeouts_release_waiting_backends_and_preserve_session_settings()
-> Result<()> {
    let h = Harness::create().await?;
    let result = async {
        let profile = h.rpc.create("timeout-binding", CREDENTIAL).await?;
        let selection = source_binding(&profile);
        assert_local_settings_do_not_leak(&h).await?;
        sqlx::query("UPDATE environments SET state='stopped',desired_state='stopped' WHERE id=$1")
            .bind(ENV).execute(&h.db).await?;
        let source_pool = PgPoolOptions::new().max_connections(1)
            .connect_with((*h.db.connect_options()).clone()).await?;
        let source_role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&source_pool).await?;

        // Cover both transaction ownership paths: profile store create and
        // direct source-admission authorization (not a retired HTTP route).
        // Both operations take
        // owner locks before encountering their deliberately held row barrier.
        for binding_path in [false, true] {
            let mut blocker = h.db.begin().await?;
            let holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker)
                .await?;
            if binding_path {
                sqlx::query("SELECT id FROM org_members WHERE user_id=$1 AND org_id=$2 FOR UPDATE")
                    .bind(ALICE).bind(ORG).fetch_one(&mut *blocker).await?;
            } else {
                sqlx::query("SELECT id FROM platform_credentials WHERE id=$1 FOR UPDATE")
                    .bind(CREDENTIAL).fetch_one(&mut *blocker).await?;
            }
            let rpc = h.rpc.clone();
            let pool = source_pool.clone();
            let selected = selection.clone();
            let pending = spawn(async move {
                if binding_path {
                    let request = source_replacement(Default::default(), selected);
                    let error = admit_sources(&pool, &source_actor(ALICE), ENV, &request).await.unwrap_err();
                    ensure!(matches!(error, codewire_server_core::AppError::ServiceUnavailable(_)));
                    ensure!(!error.to_string().contains("synthetic"));
                } else {
                    let response = rpc.call("CreateAccessProfile", Auth::Alice,
                        json!({"name":"must-not-publish","entries":entries(CREDENTIAL)})).await?;
                    ensure!(response.0 == StatusCode::SERVICE_UNAVAILABLE);
                    ensure!(response.1["code"] == "unavailable");
                    ensure!(!response.1.to_string().contains("synthetic"));
                }
                Ok(())
            });
            let role = if binding_path { &source_role } else { &h.role };
            let pids = blocked_service(&h.db, role, holder, 1).await?;
            let waiter = *pids.first().context("missing blocked request backend")?;
            joined(pending).await?;

            // Do not release the barrier to make cleanup succeed. Old code's
            // Rust-only timeout returns the same HTTP error but leaves this
            // exact backend, pool connection and earlier owner locks waiting.
            let request_pool = if binding_path { &source_pool } else { &h.service_pool };
            released_backend(&h, request_pool, waiter).await?;
            assert_released_locks(&h.db, binding_path).await?;
            let still_holder: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *blocker).await?;
            ensure!(still_holder == holder);
            let absent: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM platform_access_profiles WHERE name='must-not-publish') \
                 AND NOT EXISTS(SELECT 1 FROM platform_environment_access_bindings WHERE environment_id=$1)",
            ).bind(ENV).fetch_one(&h.db).await?;
            ensure!(absent, "timed-out request published metadata");
            h.rpc.ok("ListAccessProfiles", Auth::Alice, json!({})).await?;
            blocker.rollback().await?;
        }
        source_pool.close().await;
        Ok(())
    }.await;
    h.finish(result).await
}
