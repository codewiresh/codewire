//! Dedicated CPU (0008, #3635): an upgrade from 0007 leaves every existing
//! organization sharing, and a new organization starts sharing. Its rollback
//! (drop the column) restores the 0007 schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn organization_dedicated_cpu_upgrade_leaves_every_organization_sharing() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0008: the baseline and 0002 to 0007, with
        // organizations.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(7).cloned().collect()),
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

        // Through 0008 only, so its rollback restores the 0007 shape; later
        // migrations prove their own upgrade and rollback.
        let through_0008 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(8).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0008.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let dedicated: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organizations WHERE dedicated_cpu")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(dedicated == 0, "{dedicated} organizations became dedicated");
        // A new organization shares, and the column is never null.
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('dedicated-new-org','New','dedicated-new-org','credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let new: bool = sqlx::query_scalar(
            "SELECT dedicated_cpu FROM organizations WHERE id='dedicated-new-org'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!new);
        let null =
            sqlx::query("UPDATE organizations SET dedicated_cpu=NULL WHERE id='dedicated-new-org'")
                .execute(&pool)
                .await
                .expect_err("dedicated_cpu is never null");
        anyhow::ensure!(
            null.as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23502")
        );

        // Rollback: dropping the column restores the 0007 schema.
        sqlx::raw_sql(
            "DELETE FROM organizations WHERE id='dedicated-new-org'; \
             ALTER TABLE organizations DROP COLUMN dedicated_cpu;",
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
