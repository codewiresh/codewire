//! Disposable-PostgreSQL proof for the audited organization dedicated-CPU write
//! and what the worker reads from it (#3635). Only synthetic rows in an isolated
//! test database are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;

use crate::test_database_support::TestDatabase;

const ADMIN: &str = "dedicated-admin";
const ORGANIZATION: &str = "dedicated-organization";

async fn dedicated(pool: &PgPool) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT dedicated_cpu FROM organizations WHERE id = $1")
            .bind(ORGANIZATION)
            .fetch_one(pool)
            .await?,
    )
}

/// The audit entries, oldest first, as (user, metadata).
async fn audit_entries(pool: &PgPool) -> Result<Vec<(String, serde_json::Value)>> {
    Ok(sqlx::query_as(
        "SELECT user_id, metadata FROM audit_logs \
         WHERE action = 'admin.organization.dedicated_cpu_set' AND severity = 'warn' \
         ORDER BY timestamp, id",
    )
    .fetch_all(pool)
    .await?)
}

fn app_error(error: AppError) -> anyhow::Error {
    anyhow::anyhow!("{error:?}")
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_dedicated_cpu_set_audits_only_a_change() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        ensure!(!dedicated(pool).await?, "an organization starts sharing");

        // Setting the value it already has changes and records nothing.
        let previous = set_organization_dedicated_cpu_core(pool, ADMIN, ORGANIZATION, false)
            .await
            .map_err(app_error)?;
        ensure!(!previous);
        ensure!(audit_entries(pool).await?.is_empty());

        let previous = set_organization_dedicated_cpu_core(pool, ADMIN, ORGANIZATION, true)
            .await
            .map_err(app_error)?;
        ensure!(!previous);
        ensure!(dedicated(pool).await?);
        let entries = audit_entries(pool).await?;
        ensure!(entries.len() == 1, "{entries:?}");
        ensure!(entries[0].0 == ADMIN);
        ensure!(entries[0].1["organization_id"] == ORGANIZATION);
        ensure!(entries[0].1["previous"] == false, "{}", entries[0].1);
        ensure!(entries[0].1["dedicated_cpu"] == true, "{}", entries[0].1);

        // The overview shows it.
        let overview = get_organization_overview_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(overview.dedicated_cpu);

        let previous = set_organization_dedicated_cpu_core(pool, ADMIN, ORGANIZATION, false)
            .await
            .map_err(app_error)?;
        ensure!(previous);
        ensure!(!dedicated(pool).await?);
        ensure!(audit_entries(pool).await?.len() == 2);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The query every Sandbox is rendered from reads the setting as it is now, so
/// a change reaches the next rendering of an environment that already exists.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_worker_reads_dedicated_cpu_from_the_organization() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
             VALUES ('dedicated-preset', $1, 'Dedicated', 'dedicated', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(ORGANIZATION)
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO environments \
             (id, org_id, created_by, preset_id, type, state, desired_state, project_spec) \
             VALUES ('dedicated-environment', $1, $2, 'dedicated-preset', 'sandbox', 'running', \
             'started', '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .bind(ORGANIZATION)
        .bind(ADMIN)
        .execute(pool)
        .await?;
        let load = crate::worker::env_data::load_environment;

        ensure!(!load(pool, "dedicated-environment").await?.dedicated_cpu);
        set_organization_dedicated_cpu_core(pool, ADMIN, ORGANIZATION, true)
            .await
            .map_err(app_error)?;
        ensure!(load(pool, "dedicated-environment").await?.dedicated_cpu);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_dedicated_cpu_set_refuses_an_unknown_organization_and_records_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        let pool = &db.pool;
        let error = set_organization_dedicated_cpu_core(pool, ADMIN, "no-such-organization", true)
            .await
            .expect_err("an unknown organization");
        ensure!(matches!(error, AppError::NotFound(_)), "{error:?}");
        ensure!(audit_entries(pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}
