//! Disposable-PostgreSQL proof that the mint log keeps 30 days and no more.
//! Only synthetic rows in an isolated test database are used.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

async fn mint(db: &TestDatabase, jti: &str, minted_at: DateTime<Utc>) -> Result<()> {
    sqlx::query(
        "INSERT INTO identity_mints \
         (jti, environment_id, org_id, audience, kid, groups_version, audience_version, minted_at) \
         VALUES ($1, 'environment', 'organization', 'https://verifier.example', \
                 'sandbox-identity-1', 0, 1, $2)",
    )
    .bind(jti)
    .bind(minted_at)
    .execute(&db.pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_mint_rows_older_than_30_days_are_deleted_and_younger_ones_kept() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let now = Utc::now();
        mint(&db, "past", now - RETENTION - chrono::Duration::minutes(1)).await?;
        mint(&db, "long-past", now - chrono::Duration::days(90)).await?;
        mint(
            &db,
            "inside",
            now - RETENTION + chrono::Duration::minutes(1),
        )
        .await?;
        mint(&db, "today", now).await?;

        ensure!(delete_minted_before(&db.pool, now - RETENTION).await? == 2);
        let kept: Vec<String> =
            sqlx::query_scalar("SELECT jti FROM identity_mints ORDER BY minted_at")
                .fetch_all(&db.pool)
                .await?;
        ensure!(kept == ["inside", "today"], "{kept:?}");
        ensure!(delete_minted_before(&db.pool, now - RETENTION).await? == 0);
        Ok(())
    }
    .await;
    db.finish(result).await
}
