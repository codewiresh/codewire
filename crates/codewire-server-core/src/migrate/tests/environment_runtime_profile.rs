//! An environment's recorded runtime profile and an organization's move onto
//! `standard` (0056, #5602). The backfill gives every existing environment a
//! profile: `confidential` on the confidential tier, a systemd workspace the
//! profile 0047 recorded (`commodity` where none was), every other
//! environment `commodity`. The record is written once; the confidential tier
//! is always `confidential`; a systemd workspace is never `confidential`; and
//! an older Pod's insert, which names only 0047's column, records the same
//! profile. 0047's column stays for that rollout. Its rollback restores 0047's
//! trigger and drops what 0056 added.

use super::*;

const VERSION: i64 = 56;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history before, or through, this migration, chosen by version so the
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

async fn profiles(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    Ok(
        sqlx::query_as("SELECT id, runtime_profile FROM environments ORDER BY id")
            .fetch_all(pool)
            .await?,
    )
}

const COLUMNS: &str = "INSERT INTO environments(id,org_id,created_by,preset_id,type,state,\
     desired_state,project_spec,isolation_tier,systemd_workspace";
const VALUES: &str = "'profile-org','credential-user-a','profile-preset','sandbox','stopped',\
     'stopped','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb";

/// A database with the shape before 0056 (a plain, a confidential and three
/// systemd workspaces: recorded `standard`, recorded `commodity`, unrecorded),
/// then upgraded through it. Returns the pool and the fingerprint before.
async fn upgraded(db: &TestDatabase) -> anyhow::Result<(PgPool, String)> {
    anyhow::ensure!(
        MIGRATOR
            .iter()
            .any(|migration| migration.version == VERSION),
        "migration {VERSION} is not embedded"
    );
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
         VALUES ('profile-org','Org','profile-org','credential-user-a'); \
         INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ('profile-preset','profile-org','P','p', \
         '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         {COLUMNS}) VALUES ('old-plain',{VALUES},'standard',false); \
         {COLUMNS}) VALUES ('old-confidential',{VALUES},'confidential',false); \
         {COLUMNS},systemd_runtime_profile) \
         VALUES ('old-systemd-standard',{VALUES},'standard',true,'standard'); \
         {COLUMNS},systemd_runtime_profile) \
         VALUES ('old-systemd-commodity',{VALUES},'standard',true,'commodity'); \
         {COLUMNS}) VALUES ('old-systemd-unrecorded',{VALUES},'standard',true);"
    ))
    .execute(&pool)
    .await?;
    let previous = fingerprint(&pool).await?;
    history(true).run(&pool).await?;
    anyhow::ensure!(fingerprint(&pool).await? != previous);
    Ok((pool, previous))
}

/// Inserts after 0056: explicit profiles, the default, an empty profile, the
/// confidential tier's default and an older Pod's insert naming only 0047's
/// column.
async fn insert_new(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(&format!(
        "{COLUMNS},runtime_profile) VALUES ('new-standard',{VALUES},'standard',false,'standard'); \
         {COLUMNS},runtime_profile) VALUES ('new-systemd',{VALUES},'standard',true,'standard'); \
         {COLUMNS}) VALUES ('new-default',{VALUES},'standard',false); \
         {COLUMNS},runtime_profile) VALUES ('new-unprofiled',{VALUES},'standard',false,''); \
         {COLUMNS}) VALUES ('new-confidential',{VALUES},'confidential',false); \
         {COLUMNS},systemd_runtime_profile) \
         VALUES ('new-older-pod',{VALUES},'standard',true,'standard');"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

fn pairs<const N: usize>(rows: [(&str, &str); N]) -> [(String, String); N] {
    rows.map(|(id, profile)| (id.to_owned(), profile.to_owned()))
}

/// 0056's rollback: restore 0047's trigger and drop what 0056 added. 0047's
/// column was never dropped, so its values are as they were.
const ROLLBACK: &str = "DELETE FROM environments WHERE id LIKE 'new-%'; \
     UPDATE organizations SET standard_runtime_enabled=false; \
     DROP TRIGGER environment_runtime_profile_default ON environments; \
     DROP FUNCTION codewire_environment_runtime_profile_default(); \
     DROP TRIGGER environment_systemd_record_immutable ON environments; \
     ALTER TABLE environments \
       DROP CONSTRAINT environments_runtime_profile_check, \
       DROP COLUMN runtime_profile; \
     CREATE OR REPLACE FUNCTION codewire_environment_systemd_record_immutable() \
       RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog', 'pg_temp' AS $$ \
     BEGIN \
         IF ROW(NEW.systemd_workspace, NEW.systemd_runtime_profile) \
            IS DISTINCT FROM \
            ROW(OLD.systemd_workspace, OLD.systemd_runtime_profile) THEN \
             RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'an environment''s systemd record is written once, at create'; \
         END IF; \
         RETURN NEW; \
     END; \
     $$; \
     CREATE TRIGGER environment_systemd_record_immutable \
       BEFORE UPDATE OF systemd_workspace, systemd_runtime_profile ON environments \
       FOR EACH ROW EXECUTE FUNCTION codewire_environment_systemd_record_immutable(); \
     ALTER TABLE organizations DROP COLUMN standard_runtime_enabled;";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_backfill_records_every_existing_environment_and_the_rollback_restores_0047()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let (pool, previous) = upgraded(&db).await?;
        let backfilled = profiles(&pool).await?;
        anyhow::ensure!(
            backfilled
                == pairs([
                    ("old-confidential", "confidential"),
                    ("old-plain", "commodity"),
                    ("old-systemd-commodity", "commodity"),
                    ("old-systemd-standard", "standard"),
                    ("old-systemd-unrecorded", "commodity"),
                ]),
            "backfill: {backfilled:?}"
        );
        let moved: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organizations WHERE standard_runtime_enabled")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(moved == 0, "{moved} organizations were moved by the upgrade");

        sqlx::raw_sql(ROLLBACK).execute(&pool).await?;
        let restored: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT id, systemd_runtime_profile FROM environments WHERE systemd_workspace ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            restored
                == [
                    ("old-systemd-commodity", Some("commodity")),
                    ("old-systemd-standard", Some("standard")),
                    ("old-systemd-unrecorded", None),
                ]
                .map(|(id, profile)| (id.to_owned(), profile.map(str::to_owned))),
            "rollback: {restored:?}"
        );
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_insert_records_its_profile_and_the_check_refuses_any_other() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let (pool, _) = upgraded(&db).await?;
        // An insert records its profile. One that leaves the default on the
        // confidential tier is recorded `confidential`, and an older Pod's,
        // naming only 0047's column, records that profile.
        insert_new(&pool).await?;
        let recorded: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, runtime_profile FROM environments WHERE id LIKE 'new-%' ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            recorded
                == pairs([
                    ("new-confidential", "confidential"),
                    ("new-default", "commodity"),
                    ("new-older-pod", "standard"),
                    ("new-standard", "standard"),
                    ("new-systemd", "standard"),
                    ("new-unprofiled", ""),
                ]),
            "inserts: {recorded:?}"
        );
        // No other profile, nothing but `confidential` on that tier, and no
        // systemd workspace on it.
        for statement in [
            format!("{COLUMNS},runtime_profile) VALUES ('kata',{VALUES},'standard',false,'kata')"),
            format!(
                "{COLUMNS},runtime_profile) \
                 VALUES ('confidential-standard',{VALUES},'confidential',false,'standard')"
            ),
            format!(
                "{COLUMNS},runtime_profile) \
                 VALUES ('systemd-confidential',{VALUES},'confidential',true,'confidential')"
            ),
        ] {
            anyhow::ensure!(refused(&pool, &statement).await? == "23514", "{statement}");
        }
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn the_record_is_written_once() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let (pool, _) = upgraded(&db).await?;
        insert_new(&pool).await?;
        // No update changes the profile, 0047's column or the systemd flag.
        for statement in [
            "UPDATE environments SET runtime_profile='standard' WHERE id='old-plain'",
            "UPDATE environments SET runtime_profile='commodity' WHERE id='new-standard'",
            "UPDATE environments SET systemd_workspace=false WHERE id='new-systemd'",
            "UPDATE environments SET systemd_workspace=true WHERE id='new-default'",
            "UPDATE environments SET systemd_runtime_profile='commodity' WHERE id='old-systemd-standard'",
            "UPDATE environments SET systemd_runtime_profile=NULL WHERE id='new-older-pod'",
        ] {
            anyhow::ensure!(refused(&pool, statement).await? == "23514", "{statement}");
        }
        // An update that leaves the record as it is still works, and so does
        // moving an organization.
        sqlx::raw_sql(
            "UPDATE environments SET runtime_profile='standard', state='running' \
             WHERE id='new-standard'; \
             UPDATE environments SET state='running' WHERE id='old-plain'; \
             UPDATE organizations SET standard_runtime_enabled=true WHERE id='profile-org';",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
