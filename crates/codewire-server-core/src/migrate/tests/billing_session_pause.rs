//! A billing session's pause columns (0061, #5529): the upgrade leaves every
//! session running with no pause mark and no review; the checks hold; the
//! rollback restores the shape before it.

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
async fn billing_session_pause_upgrade_reads_every_session_as_running_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(60).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('pause-org','Org','pause-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('pause-preset','pause-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec) \
             VALUES ('pause-env','pause-org','credential-user-a','pause-preset', \
             'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO sandbox_running_sessions(id,environment_id,organization_id, \
             runtime_type,runtime_uid,runtime_name,runtime_namespace,cpu_millicores, \
             memory_mib,disk_gib,runtime_class,started_at,last_observed_at) \
             VALUES ('pause-session','pause-env','pause-org','sandbox','uid-1','sbx', \
             'ns',1000,1024,10,'kata',now(),now());",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(61).run(&pool).await?;
        let row: (String, Option<i64>, Option<i64>, Option<String>) = sqlx::query_as(
            "SELECT rate_kind, pause_generation, pause_sequence, review_reason \
             FROM sandbox_running_sessions WHERE id = 'pause-session'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            row == ("running".to_owned(), None, None, None),
            "an existing session: {row:?}"
        );

        sqlx::query(
            "UPDATE sandbox_running_sessions SET rate_kind = 'paused', pause_generation = 7, \
             pause_sequence = 0, paused_seen_at = now(), review_reason = 'pause_records_gap' \
             WHERE id = 'pause-session'",
        )
        .execute(&pool)
        .await?;
        for (statement, constraint) in [
            (
                "UPDATE sandbox_running_sessions SET rate_kind = 'suspended'",
                "sandbox_running_sessions_rate_kind_check",
            ),
            (
                "UPDATE sandbox_running_sessions SET pause_sequence = NULL",
                "sandbox_running_sessions_pause_mark_check",
            ),
            (
                "UPDATE sandbox_running_sessions SET pause_generation = -1",
                "sandbox_running_sessions_pause_mark_check",
            ),
            (
                "UPDATE sandbox_running_sessions SET review_reason = 'other'",
                "sandbox_running_sessions_review_reason_check",
            ),
        ] {
            anyhow::ensure!(
                refused_by(&pool, statement, constraint).await?,
                "{statement} is refused by {constraint}"
            );
        }

        // Rollback: drop the columns, with their checks.
        sqlx::raw_sql(
            "ALTER TABLE sandbox_running_sessions DROP COLUMN rate_kind, \
             DROP COLUMN pause_generation, DROP COLUMN pause_sequence, \
             DROP COLUMN paused_seen_at, DROP COLUMN review_reason;",
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
