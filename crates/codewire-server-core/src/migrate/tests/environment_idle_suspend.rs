//! Idle suspend (0059, #5529): the upgrade leaves every environment with idle
//! suspend off and not suspended, and every snapshot without a timeout; the
//! checks hold; the rollback restores the 0056 shape.

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

/// Whether `statement` is refused by the check `constraint`.
async fn refused_by(pool: &PgPool, statement: &str, constraint: &str) -> anyhow::Result<bool> {
    Ok(match sqlx::query(statement).execute(pool).await {
        Err(sqlx::Error::Database(error)) => error.constraint() == Some(constraint),
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    })
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn idle_suspend_upgrade_defaults_off_is_checked_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(58).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('suspend-org','Org','suspend-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('suspend-preset','suspend-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec) \
             VALUES ('suspend-env','suspend-org','credential-user-a','suspend-preset', \
             'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO hosted_snapshots(id,org_id,created_by,source_environment_id,name) \
             VALUES ('suspend-snap','suspend-org','credential-user-a','suspend-env','snap');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(59).run(&pool).await?;
        let row: (i32, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "SELECT idle_suspend_seconds, suspended_at FROM environments \
             WHERE id = 'suspend-env'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(row == (0, None), "an existing environment: {row:?}");
        let snapshot: Option<i32> = sqlx::query_scalar(
            "SELECT idle_suspend_seconds FROM hosted_snapshots WHERE id = 'suspend-snap'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(snapshot.is_none(), "an existing snapshot: {snapshot:?}");

        // A suspended sandbox stays 'running'; the mark is a time.
        sqlx::query("UPDATE environments SET suspended_at = now() WHERE id = 'suspend-env'")
            .execute(&pool)
            .await?;
        // Off, or five minutes to seven days.
        for seconds in [0, 300, 900, 604_800] {
            sqlx::query(
                "UPDATE environments SET idle_suspend_seconds = $1 WHERE id = 'suspend-env'",
            )
            .bind(seconds)
            .execute(&pool)
            .await?;
            sqlx::query(
                "UPDATE hosted_snapshots SET idle_suspend_seconds = $1 WHERE id = 'suspend-snap'",
            )
            .bind(seconds)
            .execute(&pool)
            .await?;
        }
        for seconds in [-1, 1, 299, 604_801] {
            anyhow::ensure!(
                refused_by(
                    &pool,
                    &format!(
                        "UPDATE environments SET idle_suspend_seconds = {seconds} \
                         WHERE id = 'suspend-env'"
                    ),
                    "environments_idle_suspend_seconds_check",
                )
                .await?
                    && refused_by(
                        &pool,
                        &format!(
                            "UPDATE hosted_snapshots SET idle_suspend_seconds = {seconds} \
                             WHERE id = 'suspend-snap'"
                        ),
                        "hosted_snapshots_idle_suspend_seconds_check",
                    )
                    .await?,
                "{seconds} seconds is refused"
            );
        }

        // Rollback: drop the columns, with their checks.
        sqlx::raw_sql(
            "ALTER TABLE environments DROP COLUMN idle_suspend_seconds, \
             DROP COLUMN suspended_at; \
             ALTER TABLE hosted_snapshots DROP COLUMN idle_suspend_seconds;",
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
