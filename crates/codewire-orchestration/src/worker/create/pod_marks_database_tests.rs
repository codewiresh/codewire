//! Disposable-PostgreSQL proof that a warm member's start marks, written after
//! "ready", keep their order and can never hurt the environment (#3684).

use anyhow::{Result, ensure};
use serde_json::to_value;

use super::*;

use crate::sandbox::client::PodStartTimeline;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "pod-marks-creator";
const ENVIRONMENT: &str = "3f1c7a52-8e64-4d0b-9c21-5a7e6b8f0d14";
const GENERATION: i64 = 7;
const ORGANIZATION: &str = "pod-marks-organization";
const POD: &str = "b71d2c44-0a9e-4f36-8d15-2e6c9a7f3b10";
const OTHER_POD: &str = "c82e3d55-1baf-4047-9e26-3f7dab804c21";
const PRESET: &str = "pod-marks-preset";

async fn seed_running(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Pod marks','pod-marks',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
         environment_operation_generation,project_spec) \
         VALUES ($1,$2,$3,'sandbox',$4,'running','started',$5,$6)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(GENERATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    Ok(())
}

fn timeline() -> PodStartTimeline {
    let at = |second: u8| format!("2026-10-30T10:00:{second:02}Z").parse().ok();
    PodStartTimeline {
        created_at: at(0),
        scheduled_at: at(1),
        ready_to_start_containers_at: at(2),
        initialized_at: at(3),
        workspace_started_at: at(4),
        dind_started_at: at(5),
        running_at: at(6),
        containers_ready_at: at(7),
        ..Default::default()
    }
}

fn marks(pod_uid: &str) -> DeferredPodMarks {
    DeferredPodMarks {
        namespace: None,
        probe: ProbeResult {
            pod_uid: pod_uid.to_owned(),
            pod_timeline: timeline(),
            ..Default::default()
        },
        path: StartPath::Warm,
        profile: StartProfile::Commodity,
    }
}

/// The environment's log phases, in the order readers serve them.
async fn phases(db: &TestDatabase) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT phase FROM environment_logs WHERE environment_id = $1 \
          ORDER BY created_at ASC, id ASC",
    )
    .bind(ENVIRONMENT)
    .fetch_all(&db.pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_marks_written_after_ready_keep_their_order_once_per_pod() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_running(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;
        emit_running_log(&authority, "complete", "completed", "", None).await?;

        marks(POD).record(&db.pool, None, &authority).await;
        let mut expected = vec!["complete".to_owned()];
        expected.extend(
            pod_stage_timings(&timeline(), StartPath::Warm)
                .iter()
                .map(|timing| timing.stage.as_str().to_owned()),
        );
        ensure!(expected.len() > 1, "the fixture has stages");
        ensure!(phases(&db).await? == expected, "{:?}", phases(&db).await?);

        // An attempt that reaches them again for the same Pod adds nothing.
        marks(POD).record(&db.pool, None, &authority).await;
        ensure!(phases(&db).await? == expected, "{:?}", phases(&db).await?);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_marks_a_lost_authority_refuses_change_nothing_and_fail_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed_running(&db).await?;
        let authority = ActivityAuthority::capture(&db.pool, ENVIRONMENT, GENERATION).await?;
        emit_running_log(&authority, "complete", "completed", "", None).await?;
        // The user moved on right after "ready".
        sqlx::query(
            "UPDATE environments SET environment_operation_generation = $2, \
             desired_state = 'stopped' WHERE id = $1",
        )
        .bind(ENVIRONMENT)
        .bind(GENERATION + 1)
        .execute(&db.pool)
        .await?;

        // Returns no error to fail the activity with, and writes no row.
        marks(OTHER_POD).record(&db.pool, None, &authority).await;
        ensure!(
            phases(&db).await? == ["complete"],
            "{:?}",
            phases(&db).await?
        );
        let (state, generation): (String, i64) = sqlx::query_as(
            "SELECT state, environment_operation_generation FROM environments WHERE id = $1",
        )
        .bind(ENVIRONMENT)
        .fetch_one(&db.pool)
        .await?;
        ensure!(state == "running" && generation == GENERATION + 1);
        Ok(())
    }
    .await;
    db.finish(result).await
}
