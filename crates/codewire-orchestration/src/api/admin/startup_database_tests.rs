//! Disposable-PostgreSQL proof for the admin startup summary and timings.
//! Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;

use crate::test_database_support::TestDatabase;

const CREATOR: &str = "startup-summary-creator";
const ORGANIZATION: &str = "startup-summary-organization";
const PRESET: &str = "startup-summary-preset";

async fn seed_environment(
    pool: &PgPool,
    id: &str,
    state: &str,
    desired_state: &str,
    age_minutes: i32,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
         project_spec,created_at) \
         VALUES ($1,$2,$3,'sandbox',$4,$5,$6, \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb, \
         NOW() - make_interval(mins => $7::int))",
    )
    .bind(id)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(state)
    .bind(desired_state)
    .bind(age_minutes)
    .execute(pool)
    .await?;
    Ok(())
}

/// A lifecycle-service state transition journal row, `seconds_ago` old.
async fn transition(pool: &PgPool, env: &str, to_state: &str, seconds_ago: i32) -> Result<()> {
    sqlx::query(
        "INSERT INTO environment_lifecycle_journal \
         (id,environment_id,kind,actor,phase,status,to_state,created_at) \
         VALUES (gen_random_uuid()::text,$1,'transition','lifecycle_service', \
         'lifecycle_transition','completed',$2,NOW() - make_interval(secs => $3::int))",
    )
    .bind(env)
    .bind(to_state)
    .bind(seconds_ago)
    .execute(pool)
    .await?;
    Ok(())
}

async fn log(
    pool: &PgPool,
    env: &str,
    phase: &str,
    status: &str,
    duration_ms: Option<i64>,
    seconds_ago: i32,
) -> Result<()> {
    let metadata = duration_ms.map(|duration_ms| serde_json::json!({ "duration_ms": duration_ms }));
    sqlx::query(
        "INSERT INTO environment_logs (id,environment_id,phase,status,message,metadata,created_at) \
         VALUES (gen_random_uuid()::text,$1,$2,$3,'',$4,NOW() - make_interval(secs => $5::int))",
    )
    .bind(env)
    .bind(phase)
    .bind(status)
    .bind(metadata)
    .bind(seconds_ago)
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_organization(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Startup summary','startup-summary', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .execute(&db.pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_startup_summary_binds_backlog_states_and_counts_the_current_incarnation() -> Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        seed_organization(&db).await?;
        let pool = &db.pool;

        // Starting backlog: only desired=started environments in a starting
        // state count, bucketed by age.
        seed_environment(pool, "backlog-old", "creating", "started", 11).await?;
        seed_environment(pool, "backlog-mid", "pending", "started", 6).await?;
        seed_environment(pool, "backlog-new", "starting", "started", 0).await?;
        seed_environment(pool, "backlog-stopping", "creating", "stopped", 30).await?;

        // Created, gateway ready during create: not counted.
        seed_environment(pool, "running-created", "running", "started", 3).await?;
        transition(pool, "running-created", "creating", 120).await?;
        log(
            pool,
            "running-created",
            "access_ready",
            "completed",
            Some(20_000),
            100,
        )
        .await?;

        // Ready at create, restarted since, no readiness for the restart.
        seed_environment(pool, "running-restarted", "running", "started", 60).await?;
        transition(pool, "running-restarted", "creating", 3_000).await?;
        log(
            pool,
            "running-restarted",
            "access_ready",
            "completed",
            Some(20_000),
            2_980,
        )
        .await?;
        transition(pool, "running-restarted", "starting", 60).await?;

        // Restart readiness failed while the environment kept running.
        seed_environment(pool, "running-restart-failed", "running", "started", 60).await?;
        transition(pool, "running-restart-failed", "starting", 60).await?;
        log(
            pool,
            "running-restart-failed",
            "access_ready",
            "failed",
            Some(90_000),
            10,
        )
        .await?;

        // No recorded incarnation transition: any completed readiness counts.
        seed_environment(pool, "running-legacy", "running", "started", 600).await?;
        log(
            pool,
            "running-legacy",
            "access_ready",
            "completed",
            Some(15_000),
            30_000,
        )
        .await?;
        seed_environment(pool, "running-never", "running", "started", 600).await?;

        let summary = startup_summary(pool, 240)
            .await
            .map_err(|error| anyhow::anyhow!("startup summary: {error:?}"))?;
        ensure!(summary.window_minutes == 240);
        ensure!(
            summary.starting_backlog_count == 3,
            "{}",
            summary.starting_backlog_count
        );
        ensure!(summary.starting_backlog_over_5m_count == 2);
        ensure!(summary.starting_backlog_over_10m_count == 1);
        ensure!(
            summary.running_without_access_ready_count == 3,
            "running without gateway ready: {}",
            summary.running_without_access_ready_count
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_startup_phase_summary_and_timings_include_pod_stages_only() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_organization(&db).await?;
        let pool = &db.pool;
        seed_environment(pool, "timed", "running", "started", 5).await?;
        seed_environment(pool, "other", "running", "started", 5).await?;

        log(pool, "timed", "create_claim", "completed", Some(1_000), 200).await?;
        log(pool, "timed", "workspace_bind", "completed", Some(150), 190).await?;
        log(
            pool,
            "timed",
            "access_ready",
            "completed",
            Some(20_000),
            180,
        )
        .await?;
        log(
            pool,
            "timed",
            "pod_scheduled",
            "completed",
            Some(3_000),
            170,
        )
        .await?;
        log(
            pool,
            "timed",
            "pod_initialized",
            "completed",
            Some(33_000),
            170,
        )
        .await?;
        log(
            pool,
            "timed",
            "pod_volume_provisioned",
            "completed",
            Some(2_000),
            170,
        )
        .await?;
        log(pool, "timed", "pod_running", "completed", Some(2_000), 170).await?;
        log(
            pool,
            "timed",
            "pod_containers_ready",
            "completed",
            Some(2_000),
            170,
        )
        .await?;
        log(
            pool,
            "other",
            "pod_scheduled",
            "completed",
            Some(5_000),
            160,
        )
        .await?;
        // Not startup phases, not completed, or outside the window.
        log(pool, "timed", "health_check", "completed", Some(200), 150).await?;
        log(pool, "other", "pod_running", "failed", Some(600_000), 150).await?;
        log(
            pool,
            "other",
            "pod_initialized",
            "completed",
            Some(1),
            5 * 60 * 60,
        )
        .await?;

        let summary = startup_summary(pool, 240)
            .await
            .map_err(|error| anyhow::anyhow!("startup summary: {error:?}"))?;
        let phases: Vec<_> = summary
            .phase_durations
            .iter()
            .map(|phase| {
                (
                    phase.phase.as_str(),
                    phase.sample_count,
                    phase.p50_ms,
                    phase.p95_ms,
                )
            })
            .collect();
        ensure!(
            phases
                == [
                    ("create_claim", 1, Some(1_000), Some(1_000)),
                    ("wait_for_ready", 0, None, None),
                    ("workspace_bind", 1, Some(150), Some(150)),
                    ("access_ready", 1, Some(20_000), Some(20_000)),
                    ("pod_created", 0, None, None),
                    ("pod_volume_provisioned", 1, Some(2_000), Some(2_000)),
                    ("pod_volume_bound", 0, None, None),
                    ("pod_scheduled", 2, Some(4_000), Some(4_900)),
                    ("pod_sandbox_ready", 0, None, None),
                    ("pod_initialized", 1, Some(33_000), Some(33_000)),
                    ("pod_workspace_started", 0, None, None),
                    ("pod_dind_started", 0, None, None),
                    ("pod_running", 1, Some(2_000), Some(2_000)),
                    ("pod_containers_ready", 1, Some(2_000), Some(2_000)),
                    ("file_ready", 0, None, None),
                ],
            "{phases:?}"
        );

        let timings = startup_timings(pool, "timed")
            .await
            .map_err(|error| anyhow::anyhow!("startup timings: {error:?}"))?;
        let timed: Vec<_> = timings
            .timings
            .iter()
            .map(|timing| (timing.phase.as_str(), timing.duration_ms))
            .collect();
        ensure!(
            timed
                == [
                    ("create_claim", Some(1_000)),
                    ("workspace_bind", Some(150)),
                    ("access_ready", Some(20_000)),
                    ("pod_volume_provisioned", Some(2_000)),
                    ("pod_scheduled", Some(3_000)),
                    ("pod_initialized", Some(33_000)),
                    ("pod_running", Some(2_000)),
                    ("pod_containers_ready", Some(2_000)),
                ],
            "{timed:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
