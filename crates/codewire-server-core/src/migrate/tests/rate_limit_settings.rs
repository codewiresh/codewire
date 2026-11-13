//! Rate limit settings (0022, #3297): an admin's global count per named limit
//! and per-user counts, each a non-negative count under a lower-case name. An
//! override goes with its user. The upgrade adds two empty tables; the
//! rollback drops them and restores the previous shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

/// The refusing constraint's name, or `None` when the statement succeeded.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.constraint().unwrap_or("?").to_owned()),
        Err(error) => Some(error.to_string()),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn rate_limit_settings_upgrade_stores_valid_counts_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(21).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;
        through(22).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        sqlx::query("INSERT INTO users (id, email) VALUES ('limited', 'limited@example.test')")
            .execute(&pool)
            .await?;
        anyhow::ensure!(
            refused(
                &pool,
                "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
                 VALUES ('sandbox_create', 20, 'admin')"
            )
            .await
            .is_none()
        );
        anyhow::ensure!(
            refused(
                &pool,
                "INSERT INTO rate_limit_overrides (user_id, name, max_requests, updated_by) \
                 VALUES ('limited', 'sandbox_create', 0, 'admin')"
            )
            .await
            .is_none()
        );
        // Counts are non-negative and names are lower-case limit names.
        for (sql, constraint) in [
            (
                "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
                 VALUES ('sandbox_start', -1, 'admin')",
                "rate_limit_settings_max_requests_check",
            ),
            (
                "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
                 VALUES ('Sandbox Start', 1, 'admin')",
                "rate_limit_settings_name_check",
            ),
            (
                "INSERT INTO rate_limit_overrides (user_id, name, max_requests, updated_by) \
                 VALUES ('limited', 'sandbox_start', -5, 'admin')",
                "rate_limit_overrides_max_requests_check",
            ),
            (
                "INSERT INTO rate_limit_overrides (user_id, name, max_requests, updated_by) \
                 VALUES ('nobody', 'sandbox_start', 1, 'admin')",
                "rate_limit_overrides_user_id_fkey",
            ),
        ] {
            let refusal = refused(&pool, sql).await;
            anyhow::ensure!(refusal.as_deref() == Some(constraint), "{sql}: {refusal:?}");
        }
        // An override goes with its user.
        sqlx::query("DELETE FROM users WHERE id = 'limited'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM rate_limit_overrides")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 0, "the override outlived its user");

        // Rollback: drop both tables to restore the previous shape.
        sqlx::query("DROP TABLE rate_limit_overrides, rate_limit_settings")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
