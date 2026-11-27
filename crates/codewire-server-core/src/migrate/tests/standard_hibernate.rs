//! Standard Sandbox hibernate columns and `hibernated` billing session rate
//! kind (0062, #6647): the upgrade defaults `idle_hibernate_seconds` to 0,
//! leaves hibernate marks NULL, allows `rate_kind = 'hibernated'`, enforces
//! every check constraint, and rolls back cleanly to the exact prior schema.

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

async fn refused_by(pool: &PgPool, statement: &str, constraint: &str) -> anyhow::Result<bool> {
    Ok(match sqlx::query(statement).execute(pool).await {
        Err(sqlx::Error::Database(error)) => error.constraint() == Some(constraint),
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    })
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn standard_hibernate_upgrade_defaults_off_is_checked_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(61).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('hib-org','Org','hib-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('hib-preset','hib-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             idle_suspend_seconds,project_spec) \
             VALUES ('hib-env','hib-org','credential-user-a','hib-preset', \
             'sandbox','stopped','stopped',900, \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO hosted_snapshots(id,org_id,created_by,source_environment_id,name) \
             VALUES ('hib-snap','hib-org','credential-user-a','hib-env','snap'); \
             INSERT INTO sandbox_running_sessions(id,environment_id,organization_id, \
             runtime_type,runtime_uid,runtime_name,runtime_namespace,cpu_millicores, \
             memory_mib,disk_gib,runtime_class,started_at,last_observed_at) \
             VALUES ('hib-session','hib-env','hib-org','sandbox','uid-1','sbx', \
             'ns',1000,1024,10,'standard',now(),now());",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        type EnvHibernateRow = (
            i32,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            Option<serde_json::Value>,
            Option<String>,
        );
        through(62).run(&pool).await?;
        let env_row: EnvHibernateRow = sqlx::query_as(
                "SELECT idle_hibernate_seconds, hibernated_at, hibernate_reason, \
                        hibernate_record, hibernate_fallback_reason \
                 FROM environments WHERE id = 'hib-env'",
            )
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(env_row == (0, None, None, None, None), "existing env: {env_row:?}");

        let snap_row: Option<i32> = sqlx::query_scalar(
            "SELECT idle_hibernate_seconds FROM hosted_snapshots WHERE id = 'hib-snap'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(snap_row.is_none(), "existing snap: {snap_row:?}");

        // Valid updates pass: idle_hibernate > idle_suspend (900), valid mark ('idle' and 'user'), rate_kind = 'hibernated'.
        sqlx::query(
            "UPDATE environments SET idle_hibernate_seconds = 21600, hibernated_at = now(), \
             hibernate_reason = 'idle', hibernate_record = '{\"restore_generation\":2}'::jsonb, \
             hibernate_fallback_reason = NULL WHERE id = 'hib-env'",
        )
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE environments SET hibernate_reason = 'user' WHERE id = 'hib-env'")
            .execute(&pool)
            .await?;
        sqlx::query("UPDATE hosted_snapshots SET idle_hibernate_seconds = 21600 WHERE id = 'hib-snap'")
            .execute(&pool)
            .await?;
        sqlx::query(
            "UPDATE sandbox_running_sessions SET rate_kind = 'hibernated' WHERE id = 'hib-session'",
        )
        .execute(&pool)
        .await?;

        // Invalid values are refused by their check constraints.
        for (statement, constraint) in [
            (
                "UPDATE environments SET idle_suspend_seconds = 0, idle_hibernate_seconds = 299 WHERE id = 'hib-env'",
                "environments_idle_hibernate_seconds_check",
            ),
            (
                "UPDATE environments SET idle_suspend_seconds = 0, idle_hibernate_seconds = 604801 WHERE id = 'hib-env'",
                "environments_idle_hibernate_seconds_check",
            ),
            (
                "UPDATE environments SET idle_hibernate_seconds = 900 WHERE id = 'hib-env'",
                "environments_idle_hibernate_after_suspend_check",
            ),
            (
                "UPDATE environments SET idle_hibernate_seconds = 600 WHERE id = 'hib-env'",
                "environments_idle_hibernate_after_suspend_check",
            ),
            (
                "UPDATE environments SET hibernate_reason = 'manual' WHERE id = 'hib-env'",
                "environments_hibernate_reason_check",
            ),
            (
                "UPDATE environments SET hibernate_reason = 'other' WHERE id = 'hib-env'",
                "environments_hibernate_reason_check",
            ),
            (
                "UPDATE environments SET hibernate_record = NULL WHERE id = 'hib-env'",
                "environments_hibernate_mark_check",
            ),
            (
                "UPDATE environments SET hibernate_reason = NULL WHERE id = 'hib-env'",
                "environments_hibernate_mark_check",
            ),
            (
                "UPDATE environments SET hibernated_at = NULL, hibernate_record = NULL WHERE id = 'hib-env'",
                "environments_hibernate_mark_check",
            ),
            (
                "UPDATE hosted_snapshots SET idle_hibernate_seconds = 299 WHERE id = 'hib-snap'",
                "hosted_snapshots_idle_hibernate_seconds_check",
            ),
            (
                "UPDATE sandbox_running_sessions SET rate_kind = 'sleeping' WHERE id = 'hib-session'",
                "sandbox_running_sessions_rate_kind_check",
            ),
        ] {
            anyhow::ensure!(
                refused_by(&pool, statement, constraint).await?,
                "{statement} must be refused by {constraint}"
            );
        }

        // Rollback restores the exact schema fingerprint from 0061.
        sqlx::raw_sql(
            "UPDATE sandbox_running_sessions SET rate_kind = 'paused' WHERE rate_kind = 'hibernated'; \
             ALTER TABLE sandbox_running_sessions \
                 DROP CONSTRAINT sandbox_running_sessions_rate_kind_check, \
                 ADD CONSTRAINT sandbox_running_sessions_rate_kind_check \
                     CHECK (rate_kind IN ('running', 'paused')); \
             ALTER TABLE environments \
                 DROP COLUMN idle_hibernate_seconds, \
                 DROP COLUMN hibernated_at, \
                 DROP COLUMN hibernate_reason, \
                 DROP COLUMN hibernate_record, \
                 DROP COLUMN hibernate_fallback_reason; \
             ALTER TABLE hosted_snapshots DROP COLUMN idle_hibernate_seconds;",
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
