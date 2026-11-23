//! A systemd workspace's recorded profile (0047, #5638): an upgrade leaves
//! every existing environment without one, a profile is accepted only on a
//! systemd workspace and only as `commodity` or `standard`, and the systemd
//! record is written once, at insert. Its rollback (drop the trigger, its
//! function and the column) restores the earlier schema.

use super::*;

const VERSION: i64 = 47;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to, or through, this migration, chosen by version so the
/// test does not depend on how many migrations come before it.
fn history(through: bool) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .take_while(|migration| {
                    migration.version < VERSION || (through && migration.version == VERSION)
                })
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

/// The SQLSTATE a statement failed with.
async fn refused(pool: &PgPool, statement: &str) -> anyhow::Result<String> {
    let error = sqlx::raw_sql(statement)
        .execute(pool)
        .await
        .expect_err(statement);
    Ok(error
        .as_database_error()
        .and_then(|error| error.code())
        .map(|code| code.into_owned())
        .unwrap_or_default())
}

const ENVIRONMENT_COLUMNS: &str = "INSERT INTO environments(id,org_id,created_by,preset_id,type,\
     state,desired_state,project_spec,systemd_workspace";
const ENVIRONMENT_VALUES: &str = "'systemd-org','credential-user-a','systemd-preset','sandbox',\
     'stopped','stopped','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn systemd_runtime_profile_is_recorded_once_and_only_on_a_systemd_workspace()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        anyhow::ensure!(
            MIGRATOR
                .iter()
                .any(|migration| migration.version == VERSION),
            "migration {VERSION} is not embedded"
        );
        // The shape before 0047, with a systemd workspace and a plain one.
        let mut connection = PgConnection::connect(&db.url).await?;
        history(false).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(&format!(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('systemd-org','Org','systemd-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('systemd-preset','systemd-org','P','p', \
             '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
             {ENVIRONMENT_COLUMNS}) VALUES ('old-systemd',{ENVIRONMENT_VALUES},true); \
             {ENVIRONMENT_COLUMNS}) VALUES ('old-plain',{ENVIRONMENT_VALUES},false);"
        ))
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        // Through 0047 only, so its rollback restores the earlier shape.
        history(true).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let recorded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM environments WHERE systemd_runtime_profile IS NOT NULL",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            recorded == 0,
            "{recorded} environments were given a profile"
        );

        // An insert records it, on a systemd workspace only, as one of two.
        sqlx::raw_sql(&format!(
            "{ENVIRONMENT_COLUMNS},systemd_runtime_profile) \
             VALUES ('new-standard',{ENVIRONMENT_VALUES},true,'standard'); \
             {ENVIRONMENT_COLUMNS},systemd_runtime_profile) \
             VALUES ('new-commodity',{ENVIRONMENT_VALUES},true,'commodity');"
        ))
        .execute(&pool)
        .await?;
        for statement in [
            format!(
                "{ENVIRONMENT_COLUMNS},systemd_runtime_profile) \
                 VALUES ('plain-standard',{ENVIRONMENT_VALUES},false,'standard')"
            ),
            format!(
                "{ENVIRONMENT_COLUMNS},systemd_runtime_profile) \
                 VALUES ('systemd-runc',{ENVIRONMENT_VALUES},true,'runc')"
            ),
        ] {
            anyhow::ensure!(refused(&pool, &statement).await? == "23514", "{statement}");
        }

        // Written once: no update changes either half of the record, from
        // NULL, between profiles, or back to NULL.
        for statement in [
            "UPDATE environments SET systemd_runtime_profile='standard' WHERE id='old-systemd'",
            "UPDATE environments SET systemd_runtime_profile='commodity' WHERE id='new-standard'",
            "UPDATE environments SET systemd_runtime_profile=NULL WHERE id='new-commodity'",
            "UPDATE environments SET systemd_workspace=false WHERE id='old-systemd'",
            "UPDATE environments SET systemd_workspace=true WHERE id='old-plain'",
        ] {
            anyhow::ensure!(refused(&pool, statement).await? == "23514", "{statement}");
        }
        // An update that leaves the record as it is still works.
        sqlx::raw_sql(
            "UPDATE environments SET systemd_runtime_profile='standard', state='running' \
             WHERE id='new-standard'; \
             UPDATE environments SET state='running' WHERE id='old-systemd';",
        )
        .execute(&pool)
        .await?;

        // Rollback: dropping what 0047 added restores the earlier schema.
        sqlx::raw_sql(
            "DELETE FROM environments WHERE id IN ('new-standard','new-commodity'); \
             DROP TRIGGER environment_systemd_record_immutable ON environments; \
             DROP FUNCTION codewire_environment_systemd_record_immutable(); \
             ALTER TABLE environments DROP COLUMN systemd_runtime_profile;",
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
