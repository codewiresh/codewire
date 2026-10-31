//! Disposable-PostgreSQL proof of what a user is told when a running sandbox's
//! Pod fails and it comes back (#3772), and of when that notice ends.

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;

use crate::api::environments::OrgQuota;
use crate::lifecycle::{
    PgLifecycleStore, SANDBOX_RESTARTED_ERROR_CODE, SANDBOX_STOPPED_ERROR_CODE,
    SANDBOX_STOPPED_MESSAGE, Service, StartQuota,
};
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "stopped-creator";
const ORGANIZATION: &str = "stopped-organization";
const PRESET: &str = "stopped-preset";
const ENVIRONMENT: &str = "6d2e8b14-3f7a-4c95-a1d0-7e9c4b2f8a10";

async fn seed(db: &TestDatabase, state: &str) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Stopped','stopped',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,$5,'started',$6)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(state)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// (state, code, reason)
async fn row(pool: &PgPool) -> Result<(String, Option<String>, Option<String>)> {
    Ok(
        sqlx::query_as("SELECT state, error_code, error_reason FROM environments WHERE id = $1")
            .bind(ENVIRONMENT)
            .fetch_one(pool)
            .await?,
    )
}

async fn set_state(pool: &PgPool, state: &str) -> Result<()> {
    sqlx::query("UPDATE environments SET state = $2 WHERE id = $1")
        .bind(ENVIRONMENT)
        .bind(state)
        .execute(pool)
        .await?;
    Ok(())
}

/// Stopped unexpectedly, then back to running, as liveness and a start do it.
async fn stopped_and_restarted(svc: &Service<PgLifecycleStore>, pool: &PgPool) -> Result<()> {
    ensure!(svc.mark_sandbox_stopped(ENVIRONMENT).await?);
    set_state(pool, "running").await?;
    svc.mark_started(ENVIRONMENT).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stopped_sandbox_says_so_then_becomes_a_notice() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        ensure!(svc.mark_sandbox_stopped(ENVIRONMENT).await?);
        let (state, code, reason) = row(pool).await?;
        ensure!(state == "error", "{state}");
        ensure!(
            code.as_deref() == Some(SANDBOX_STOPPED_ERROR_CODE),
            "{code:?}"
        );
        ensure!(
            reason.as_deref() == Some(SANDBOX_STOPPED_MESSAGE),
            "{reason:?}"
        );
        // Already not running: nothing to say twice.
        ensure!(!svc.mark_sandbox_stopped(ENVIRONMENT).await?);

        // Back to running: it says what happened, and not that it is failing.
        set_state(pool, "running").await?;
        svc.mark_started(ENVIRONMENT).await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(
            code.as_deref() == Some(SANDBOX_RESTARTED_ERROR_CODE),
            "{code:?}"
        );
        let reason = reason.unwrap_or_default();
        ensure!(
            reason.starts_with("Restarted at ")
                && reason
                    .ends_with(" UTC after stopping unexpectedly. Running processes were lost."),
            "{reason}"
        );

        // Recording the start again keeps the notice.
        svc.mark_started(ENVIRONMENT).await?;
        let (_, code, again) = row(pool).await?;
        ensure!(
            code.as_deref() == Some(SANDBOX_RESTARTED_ERROR_CODE),
            "{code:?}"
        );
        ensure!(again.as_deref() == Some(reason.as_str()), "{again:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_sandbox_not_running_is_never_marked_stopped() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "creating").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());
        ensure!(!svc.mark_sandbox_stopped(ENVIRONMENT).await?);
        let (state, code, reason) = row(pool).await?;
        ensure!(state == "creating" && code.is_none() && reason.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_notice_ends_at_the_next_stop_or_start() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        // A stop.
        stopped_and_restarted(&svc, pool).await?;
        set_state(pool, "stopped").await?;
        svc.mark_stopped(ENVIRONMENT).await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none() && reason.is_none(), "{code:?} {reason:?}");

        // A start.
        set_state(pool, "running").await?;
        stopped_and_restarted(&svc, pool).await?;
        set_state(pool, "stopped").await?;
        let quota = StartQuota {
            quota: OrgQuota {
                max_concurrent_environments: -1,
                max_concurrent_sandbox: -1,
                max_cpu_millicores: -1,
                max_memory_mb: -1,
            },
            env_type: "sandbox",
            cpu_millicores: 1000,
            memory_mb: 1024,
            credit_enforcement: Default::default(),
        };
        svc.admit_start(ENVIRONMENT, ORGANIZATION, "standard", quota)
            .await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none() && reason.is_none(), "{code:?} {reason:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_running_again_clears_any_old_reason_and_another_failure_replaces_the_notice()
-> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db, "running").await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        // Another failure on a restarted sandbox has its own reason and no notice.
        stopped_and_restarted(&svc, pool).await?;
        svc.mark_error_for_states(ENVIRONMENT, "sandbox pod missing", &["running"])
            .await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none(), "{code:?}");
        ensure!(
            reason.as_deref() == Some("sandbox pod missing"),
            "{reason:?}"
        );

        // A reason from an earlier failure doesn't outlive the return to running.
        set_state(pool, "running").await?;
        svc.mark_started(ENVIRONMENT).await?;
        let (_, code, reason) = row(pool).await?;
        ensure!(code.is_none() && reason.is_none(), "{code:?} {reason:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
