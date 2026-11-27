//! Disposable-PostgreSQL proof for the audited organization agent-chat write
//! and what organization reads return. Only synthetic rows in an isolated test
//! database are used.

use anyhow::{Result, ensure};
use sqlx::PgPool;

use super::*;

use crate::test_database_support::TestDatabase;

const ADMIN: &str = "agent-chat-admin";
const ORGANIZATION: &str = "agent-chat-organization";

async fn agent_chat(pool: &PgPool) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT agent_chat FROM organizations WHERE id = $1")
            .bind(ORGANIZATION)
            .fetch_one(pool)
            .await?,
    )
}

/// The audit entries, oldest first, as (user, metadata).
async fn audit_entries(pool: &PgPool) -> Result<Vec<(String, serde_json::Value)>> {
    Ok(sqlx::query_as(
        "SELECT user_id, metadata FROM audit_logs \
         WHERE action = 'admin.organization.agent_chat_set' AND severity = 'warn' \
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
async fn db_agent_chat_set_audits_only_a_change() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        db.organization(ORGANIZATION).await?;
        let pool = &db.pool;
        ensure!(
            !agent_chat(pool).await?,
            "an organization starts with agent chat off"
        );

        // Setting the value it already has changes and records nothing.
        let previous = set_organization_agent_chat_core(pool, ADMIN, ORGANIZATION, false)
            .await
            .map_err(app_error)?;
        ensure!(!previous);
        ensure!(audit_entries(pool).await?.is_empty());

        let previous = set_organization_agent_chat_core(pool, ADMIN, ORGANIZATION, true)
            .await
            .map_err(app_error)?;
        ensure!(!previous);
        ensure!(agent_chat(pool).await?);
        let entries = audit_entries(pool).await?;
        ensure!(entries.len() == 1, "{entries:?}");
        ensure!(entries[0].0 == ADMIN);
        ensure!(entries[0].1["organization_id"] == ORGANIZATION);
        ensure!(entries[0].1["previous"] == false, "{}", entries[0].1);
        ensure!(entries[0].1["agent_chat"] == true, "{}", entries[0].1);

        // The admin overview shows it.
        let overview = get_organization_overview_core(pool, ORGANIZATION)
            .await
            .map_err(app_error)?;
        ensure!(overview.agent_chat);

        let previous = set_organization_agent_chat_core(pool, ADMIN, ORGANIZATION, false)
            .await
            .map_err(app_error)?;
        ensure!(previous);
        ensure!(!agent_chat(pool).await?);
        ensure!(audit_entries(pool).await?.len() == 2);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_agent_chat_set_refuses_an_unknown_organization_and_records_nothing() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        db.user(ADMIN).await?;
        let pool = &db.pool;
        let error = set_organization_agent_chat_core(pool, ADMIN, "no-such-organization", true)
            .await
            .expect_err("an unknown organization");
        ensure!(matches!(error, AppError::NotFound(_)), "{error:?}");
        ensure!(audit_entries(pool).await?.is_empty());
        Ok(())
    }
    .await;
    db.finish(result).await
}
