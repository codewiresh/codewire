//! Environment quota defaults (0004, #3583): an upgrade from 0003 seeds the
//! one row with the constants the plan fallback used before it, refuses a
//! second row and any limit that is neither -1 nor positive, and its rollback
//! (drop the table) restores the 0003 schema.

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
async fn environment_quota_defaults_upgrade_seeds_todays_constants_in_one_row() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0004: the baseline, 0002 and 0003.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(3).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        // Through 0004 only, so its rollback restores the 0003 shape; later
        // migrations prove their own upgrade and rollback.
        let through_0004 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(4).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0004.run(&pool).await?;
        let seeded: Vec<(i32, i32, i32, i32)> = sqlx::query_as(
            "SELECT max_concurrent_environments, max_concurrent_sandbox, \
             max_cpu_millicores, max_memory_mb FROM environment_quota_defaults",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(seeded == [(10, 50, 32_000, 65_536)], "{seeded:?}");

        // Each refusal in its own transaction.
        for (sql, code) in [
            // A second row.
            (
                "INSERT INTO environment_quota_defaults \
                 (singleton, max_concurrent_environments, max_concurrent_sandbox, \
                  max_cpu_millicores, max_memory_mb) VALUES (true, 1, 1, 1, 1)",
                "23505",
            ),
            (
                "INSERT INTO environment_quota_defaults \
                 (singleton, max_concurrent_environments, max_concurrent_sandbox, \
                  max_cpu_millicores, max_memory_mb) VALUES (false, 1, 1, 1, 1)",
                "23514",
            ),
            // Zero would mean "no default"; other negatives mean nothing.
            (
                "UPDATE environment_quota_defaults SET max_concurrent_sandbox = 0",
                "23514",
            ),
            (
                "UPDATE environment_quota_defaults SET max_memory_mb = -2",
                "23514",
            ),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .expect_err("invalid default accepted");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "{sql}: {error}"
            );
            tx.rollback().await?;
        }
        // Unlimited is a valid default.
        sqlx::query("UPDATE environment_quota_defaults SET max_concurrent_environments = -1")
            .execute(&pool)
            .await?;

        // Rollback: dropping what 0004 added restores the 0003 schema.
        sqlx::raw_sql("DROP TABLE environment_quota_defaults;")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
