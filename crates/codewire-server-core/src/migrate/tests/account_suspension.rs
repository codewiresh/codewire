//! Account suspension (0027, #3297): an upgrade from the shape before it adds
//! nullable columns to users and to organizations and suspends nothing;
//! a suspender is only recorded with a suspension time, and a suspended
//! account is never enabled; the rollback (drop
//! the five columns) restores the earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// 0027 from the shape before it after later migrations land.
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

async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.constraint().unwrap_or("?").to_owned()),
        Err(error) => Some(error.to_string()),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_suspension_upgrade_suspends_nothing_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(26).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query("INSERT INTO users (id, email) VALUES ('existing', 'existing@example.test')")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('existing-org', 'Existing', 'existing-org', 'existing')",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(27).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "0027 changes the schema"
        );
        let (user, organization): (
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT (SELECT suspended_at FROM users WHERE id = 'existing'), \
                        (SELECT suspended_at FROM organizations WHERE id = 'existing-org')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            user.is_none() && organization.is_none(),
            "the upgrade suspends nothing"
        );

        // A suspender is recorded only together with the time.
        for (sql, constraint) in [
            (
                "UPDATE users SET suspended_by = 'admin' WHERE id = 'existing'",
                "users_suspended_by_check",
            ),
            (
                "UPDATE organizations SET suspended_by = 'admin' WHERE id = 'existing-org'",
                "organizations_suspended_by_check",
            ),
            (
                "UPDATE organizations SET suspended_at = now() WHERE id = 'existing-org'",
                "organizations_suspended_for_check",
            ),
        ] {
            let refusal = refused(&pool, sql).await;
            anyhow::ensure!(refusal.as_deref() == Some(constraint), "{sql}: {refusal:?}");
        }
        // A suspended account is never enabled.
        let refusal = refused(
            &pool,
            "UPDATE users SET enabled = true, suspended_at = now(), suspended_by = 'admin' \
             WHERE id = 'existing'",
        )
        .await;
        anyhow::ensure!(
            refusal.as_deref() == Some("users_suspended_disabled_check"),
            "{refusal:?}"
        );
        anyhow::ensure!(
            refused(
                &pool,
                "UPDATE users SET enabled = false, suspended_at = now(), suspended_by = 'admin' \
                 WHERE id = 'existing'"
            )
            .await
            .is_none()
        );

        // Rollback: drop the five columns to restore the previous shape.
        sqlx::query("ALTER TABLE users DROP COLUMN suspended_at, DROP COLUMN suspended_by")
            .execute(&pool)
            .await?;
        sqlx::query(
            "ALTER TABLE organizations DROP COLUMN suspended_at, DROP COLUMN suspended_by, \
             DROP COLUMN suspended_for",
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
