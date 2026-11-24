//! Disposable-PostgreSQL proof of Admin → Organizations' Sandbox counts
//! (#6086). Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::sandbox_counts::{SandboxCounts, list_organization_sandbox_counts_core};
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "counts-creator";
/// Has a Sandbox in every kind of state.
const BUSY: &str = "counts-busy";
/// Has only a deleted Sandbox.
const QUIET: &str = "counts-quiet";
/// Has never created one.
const EMPTY: &str = "counts-empty";

async fn sandbox(pool: &PgPool, organization: &str, state: &str, created_at: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO environments (id, org_id, created_by, type, preset_id, state, \
         desired_state, project_spec, created_at) \
         VALUES ($1 || '-' || $3 || '-' || gen_random_uuid(), $1, $2, 'sandbox', $1, $3, \
         'started', '{}'::jsonb, $4::timestamp)",
    )
    .bind(organization)
    .bind(CREATOR)
    .bind(state)
    .bind(created_at)
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_each_organization_s_sandboxes_are_counted_by_state_with_totals() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(CREATOR).await?;
        for organization in [BUSY, QUIET, EMPTY] {
            db.organization(organization).await?;
            sqlx::query(
                "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
                 VALUES ($1, $1, 'Preset', 'ready', '{}'::jsonb)",
            )
            .bind(organization)
            .execute(&db.pool)
            .await?;
        }
        let pool = &db.pool;
        ensure!(
            list_organization_sandbox_counts_core(pool).await?.totals == SandboxCounts::default(),
            "nothing is counted before a Sandbox exists"
        );

        // One Sandbox in every state the table allows, each counted once.
        for state in [
            "pending",
            "pending_build",
            "building",
            "pulling_snapshot",
            "creating",
            "starting",
            "running",
            "restoring",
            "resizing",
            "stopping",
            "stopped",
            "archiving",
            "archived",
            "error",
            "build_failed",
            "unknown",
            "destroying",
        ] {
            sandbox(pool, BUSY, state, "2026-11-01 10:00:00").await?;
        }
        sandbox(pool, BUSY, "destroyed", "2026-11-20 09:30:00").await?;
        sandbox(pool, QUIET, "destroyed", "2026-10-05 08:00:00").await?;

        let counts = list_organization_sandbox_counts_core(pool).await?;
        let ids: Vec<_> = counts
            .organizations
            .iter()
            .map(|row| row.organization_id.as_str())
            .collect();
        ensure!(
            ids == [BUSY, QUIET],
            "an organization with none is left out: {ids:?}"
        );

        let busy = &counts.organizations[0];
        ensure!(
            busy.counts
                == SandboxCounts {
                    created: 18,
                    running: 9,
                    stopped: 4,
                    failed: 3,
                    deleted: 2,
                },
            "{busy:?}"
        );
        ensure!(
            busy.last_created_at.map(|at| at.to_string()).as_deref() == Some("2026-11-20 09:30:00"),
            "the newest Sandbox, deleted or not: {busy:?}"
        );

        let quiet = &counts.organizations[1];
        ensure!(
            quiet.counts
                == SandboxCounts {
                    created: 1,
                    deleted: 1,
                    ..SandboxCounts::default()
                },
            "{quiet:?}"
        );

        ensure!(
            counts.totals
                == SandboxCounts {
                    created: 19,
                    running: 9,
                    stopped: 4,
                    failed: 3,
                    deleted: 3,
                },
            "{:?}",
            counts.totals
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
