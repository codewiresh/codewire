//! Disposable-PostgreSQL proof that a stop records why it happened and a start
//! clears it (#3384), and that its lifecycle log wakes log followers at commit
//! (#4762).

use std::time::Duration;

use anyhow::{Result, ensure};
use serde_json::to_value;
use sqlx::PgPool;
use sqlx::postgres::PgListener;

use crate::api::environments::OrgQuota;
use crate::api::log_notifications::ENVIRONMENT_LOGS_CHANNEL;
use crate::lifecycle::{PgLifecycleStore, Service, StartQuota, StopReason};
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "stop-reason-creator";
const ORGANIZATION: &str = "stop-reason-organization";
const PRESET: &str = "stop-reason-preset";
const ENVIRONMENT: &str = "3b8f5c2e-9d14-4a67-b0e3-5f1c7a9d2e48";

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Stop reason','stop-reason',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'running','started',$5)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// (desired state, stop reason)
async fn row(pool: &PgPool) -> Result<(String, Option<String>)> {
    Ok(
        sqlx::query_as("SELECT desired_state, stop_reason FROM environments WHERE id = $1")
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

fn unlimited() -> StartQuota<'static> {
    StartQuota {
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
    }
}

async fn stop(svc: &Service<PgLifecycleStore>, pool: &PgPool, reason: StopReason) -> Result<()> {
    svc.request_stop(ENVIRONMENT, reason).await?;
    let (desired, recorded) = row(pool).await?;
    ensure!(desired == "stopped", "{desired}");
    ensure!(recorded.as_deref() == Some(reason.as_str()), "{recorded:?}");
    set_state(pool, "stopped").await?;
    svc.mark_stopped(ENVIRONMENT).await?;
    // Finishing the stop keeps the reason.
    let (_, kept) = row(pool).await?;
    ensure!(kept.as_deref() == Some(reason.as_str()), "{kept:?}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stop_records_its_reason_and_a_start_clears_it() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        for reason in [StopReason::User, StopReason::Credit] {
            stop(&svc, pool, reason).await?;
            svc.admit_start(ENVIRONMENT, ORGANIZATION, "standard", unlimited())
                .await?;
            let (desired, cleared) = row(pool).await?;
            ensure!(desired == "started", "{desired}");
            ensure!(cleared.is_none(), "{cleared:?}");
            set_state(pool, "running").await?;
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_retrying_a_failed_confidential_start_clears_the_reason() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let svc = Service::for_pool(pool.clone());

        stop(&svc, pool, StopReason::User).await?;
        set_state(pool, "error").await?;
        svc.retry_confidential_start(ENVIRONMENT, ORGANIZATION)
            .await?;
        let (desired, cleared) = row(pool).await?;
        ensure!(desired == "started", "{desired}");
        ensure!(cleared.is_none(), "{cleared:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_stop_wakes_log_followers_at_commit() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let pool = &db.pool;
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen(ENVIRONMENT_LOGS_CHANNEL).await?;
        let svc = Service::for_pool(pool.clone());
        svc.request_stop(ENVIRONMENT, StopReason::User).await?;
        let notification = tokio::time::timeout(Duration::from_secs(10), listener.recv()).await??;
        ensure!(
            notification.payload() == ENVIRONMENT,
            "{}",
            notification.payload()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
