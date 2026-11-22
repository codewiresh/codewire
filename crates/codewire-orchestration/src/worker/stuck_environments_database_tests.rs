//! Disposable-PostgreSQL proof of which environments the stuck-state sweep
//! reconciles (#3384): every one not in its desired state and quiet for the
//! window, a running Sandbox whose desired state is `started` included, since
//! the sweep is what recovers its stale bootstrap. Its trigger says so (#5913).

use anyhow::{Result, ensure};
use serde_json::to_value;

use crate::test_database_support::TestDatabase;
use crate::worker::loops::stuck_environment_ids;

const CREATOR: &str = "stuck-creator";
const ORGANIZATION: &str = "stuck-organization";
const PRESET: &str = "stuck-preset";

/// (id, state, desired state, the reason the sweep takes it with, if it does)
const CASES: [(&str, &str, &str, Option<&str>); 6] = [
    (
        "1b7e0c52-6a1d-4f0e-9d3a-000000000001",
        "running",
        "started",
        Some("running bootstrap check"),
    ),
    (
        "1b7e0c52-6a1d-4f0e-9d3a-000000000002",
        "stopped",
        "stopped",
        None,
    ),
    (
        "1b7e0c52-6a1d-4f0e-9d3a-000000000003",
        "running",
        "stopped",
        Some("stuck-state recovery"),
    ),
    (
        "1b7e0c52-6a1d-4f0e-9d3a-000000000004",
        "stopped",
        "started",
        Some("stuck-state recovery"),
    ),
    (
        "1b7e0c52-6a1d-4f0e-9d3a-000000000005",
        "error",
        "started",
        Some("stuck-state recovery"),
    ),
    (
        "1b7e0c52-6a1d-4f0e-9d3a-000000000006",
        "creating",
        "started",
        Some("stuck-state recovery"),
    ),
];

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    let project = to_value(codewire_project::ProjectSpec::default())?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Stuck','stuck',$3)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .bind(&project)
    .execute(&db.pool)
    .await?;
    for (id, state, desired_state, _) in CASES {
        // Quiet for ten minutes, past the five-minute recovery window.
        sqlx::query(
            "INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,\
             project_spec,state_changed_at) \
             VALUES ($1,$2,$3,'sandbox',$4,$5,$6,$7,NOW() - interval '10 minutes')",
        )
        .bind(id)
        .bind(ORGANIZATION)
        .bind(CREATOR)
        .bind(PRESET)
        .bind(state)
        .bind(desired_state)
        .bind(&project)
        .execute(&db.pool)
        .await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_every_quiet_mismatch_is_swept_a_running_sandbox_included() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let swept = stuck_environment_ids(&db.pool).await?;
        for (id, state, desired_state, expected) in CASES {
            let reason = swept
                .iter()
                .find(|(swept, _)| swept == id)
                .map(|(_, reason)| *reason);
            ensure!(
                reason == expected,
                "{state} with desired {desired_state}: swept with {reason:?}, expected {expected:?}"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_recent_change_is_not_swept() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        sqlx::query("UPDATE environments SET state_changed_at = NOW()")
            .execute(&db.pool)
            .await?;
        let swept = stuck_environment_ids(&db.pool).await?;
        ensure!(swept.is_empty(), "swept within the window: {swept:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
