//! Confidential environments opt-in (0005, #2497): an upgrade from 0004 leaves
//! every existing organization out, and a new organization starts out too.
//! Its rollback (drop the column) restores the 0004 schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

async fn opted_in(pool: &PgPool) -> anyhow::Result<Vec<(String, bool)>> {
    Ok(sqlx::query_as(
        "SELECT id, confidential_environments_enabled FROM organizations ORDER BY id",
    )
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn organization_confidential_upgrade_leaves_every_organization_out() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0005: the baseline and 0002 to 0004, with
        // organizations.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(4).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        let organizations: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            organizations > 0,
            "the upgrade needs existing organizations"
        );

        // Through 0005 only, so its rollback restores the 0004 shape; later
        // migrations prove their own upgrade and rollback.
        let through_0005 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(5).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0005.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let existing = opted_in(&pool).await?;
        anyhow::ensure!(
            existing.len() as i64 == organizations && existing.iter().all(|(_, enabled)| !enabled),
            "an existing organization is opted in: {existing:?}"
        );
        // A new organization starts out, and the column is never null.
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('confidential-new-org','New','confidential-new-org','credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let enabled: bool = sqlx::query_scalar(
            "SELECT confidential_environments_enabled FROM organizations \
             WHERE id='confidential-new-org'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!enabled);
        let null = sqlx::query(
            "UPDATE organizations SET confidential_environments_enabled=NULL \
             WHERE id='confidential-new-org'",
        )
        .execute(&pool)
        .await
        .expect_err("the opt-in is never null");
        anyhow::ensure!(
            null.as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23502")
        );

        // Rollback: dropping the column restores the 0004 schema.
        sqlx::raw_sql(
            "DELETE FROM organizations WHERE id='confidential-new-org'; \
             ALTER TABLE organizations DROP COLUMN confidential_environments_enabled;",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
