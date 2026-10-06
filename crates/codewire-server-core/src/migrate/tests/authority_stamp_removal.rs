//! Authority stamp removal (migration 36): accepted prior history and
//! disposable database proof that migration 36 drops every object migration
//! 35 created and nothing else, so the schema it leaves is the version-34
//! schema; that a held lock, a failure or a drifted schema leaves version 35
//! intact; and that both rollback boundaries work: re-running migration 35 in
//! place, and replaying version 35 into a disposable application schema.

use std::time::Instant;

use super::*;

const VERSION: i64 = 36;
const STAMP_VERSION: i64 = 35;
// Measured from accepted canonical main a4d598aca65c1ffcfffa57cdae775df29e99473a,
// not the edited branch: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL34))
// and SHA384(SQL34).
const PRIOR_HISTORY34: &str = "2513689128f703bffca25e18a45a238a0f2cb774a394be9e45f44001f6008b0ce3d39f5b9c394d2e8826b1c8501e7a5a";
const PRIOR34: &str = "8cca018f2f40699d2a852d6bf8e0301e0732bb651fad0c86ef04dfc21945aa4db2b892098d7fb2b93b0fbe0a2b51d2e6";
// Measured from accepted canonical main ca5e0598f3e0c96a4f9e1029fc61f13a4ecd19ed,
// not the edited branch: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL35))
// and SHA384(SQL35), the migration 35 bytes Dev applied.
const PRIOR_HISTORY35: &str = "997389d904a7411aad52b04b735731daa3dd22f369b3558f48be517722cce638e2f464a900de9534bac1de87250a32ab";
const PRIOR35: &str = "28d8713c5ea4a390fce5ceb9de39b06ffc129e26970b172119d6a6d8873411c65a3222ca65a6f84830650928398a8d0a";

pub(super) fn assert_accepted_prior34() -> anyhow::Result<()> {
    workspace_binding::assert_accepted_prior33()?;
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR
        .iter()
        .filter(|m| m.version < STAMP_VERSION)
        .collect();
    anyhow::ensure!(prior.len() == 34);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == PRIOR_HISTORY34,
        "migration1..34 differs from accepted canonical a4d598aca"
    );
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(prior[33].sql.as_bytes())) == PRIOR34,
        "migration34 differs from accepted canonical a4d598aca"
    );
    Ok(())
}

pub(super) fn assert_accepted_prior35() -> anyhow::Result<()> {
    assert_accepted_prior34()?;
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR.iter().filter(|m| m.version < VERSION).collect();
    anyhow::ensure!(prior.len() == 35);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == PRIOR_HISTORY35,
        "migration1..35 differs from accepted canonical ca5e0598f"
    );
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(prior[34].sql.as_bytes())) == PRIOR35,
        "migration35 differs from accepted canonical ca5e0598f"
    );
    Ok(())
}

#[test]
fn authority_stamp_removal_pins_the_accepted35_history() -> anyhow::Result<()> {
    assert_accepted_prior35()
}

#[test]
fn authority_stamp_removal_restores_the_accepted34_fingerprint() {
    // The database fixtures below measure both values; this keeps the pins
    // themselves from drifting apart. Version 36's schema is the one
    // migration 37 starts from.
    assert_eq!(
        ACCEPTED_PRE_SSH_HOST_KEY_SCHEMA_FINGERPRINT,
        ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
    );
    assert_ne!(
        ACCEPTED_AUTHORITY_STAMP_SCHEMA_FINGERPRINT,
        ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
    );
}

/// Migration 35's SQL as embedded (and pinned above), which the in-place
/// rollback of migration 36 re-runs.
fn stamp_sql() -> anyhow::Result<&'static str> {
    assert_accepted_prior35()?;
    Ok(MIGRATOR
        .iter()
        .find(|migration| migration.version == STAMP_VERSION)
        .context("migration35 is missing")?
        .sql
        .as_ref())
}

/// The documented in-place rollback of migration 36: re-run migration 35's
/// body and delete ledger version 36, in one transaction. Ledger version 35
/// keeps its original row.
fn authority_stamp_removal_down() -> anyhow::Result<String> {
    Ok(format!(
        "BEGIN;\n{}\nDELETE FROM public._sqlx_migrations WHERE version = 36;\nCOMMIT;",
        stamp_sql()?
    ))
}

async fn connect(url: &str) -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new().max_connections(1).connect(url).await?)
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// What the table fingerprint does not cover: every function in `public` that
/// no extension owns, with its ACL and definition; every non-internal trigger,
/// with its enabled state and definition; and every relation's ACL.
async fn catalog(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT entry FROM ( \
             SELECT 'function:' || p.oid::regprocedure::text || ':' || COALESCE(p.proacl::text, '') \
                 || ':' || pg_get_functiondef(p.oid) AS entry \
             FROM pg_proc p \
             WHERE p.pronamespace = 'public'::regnamespace AND p.prokind IN ('f', 'p') \
               AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass \
                   AND d.objid = p.oid AND d.deptype = 'e') \
             UNION ALL \
             SELECT 'trigger:' || c.relname || ':' || t.tgname || ':' || t.tgenabled::text \
                 || ':' || pg_get_triggerdef(t.oid) \
             FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
             WHERE c.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal \
             UNION ALL \
             SELECT 'acl:' || c.relname || ':' || COALESCE(c.relacl::text, '') \
             FROM pg_class c \
             WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'S', 'v', 'm') \
         ) AS catalog ORDER BY entry",
    )
    .fetch_all(pool)
    .await?)
}

/// The catalog without migration 35's objects.
fn without_stamp(catalog: &[String]) -> Vec<String> {
    catalog
        .iter()
        .filter(|entry| {
            !entry.contains("codewire_stamp_authority_")
                && !entry.contains("codewire_platform_authority_")
                && !entry.contains("platform_authority_generation")
        })
        .cloned()
        .collect()
}

/// No object of migration 35 remains.
async fn absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regclass('public.platform_authority_generations') IS NULL \
         AND to_regclass('public.platform_authority_generation_seq') IS NULL \
         AND NOT EXISTS (SELECT 1 FROM pg_proc WHERE starts_with(proname, 'codewire_platform_authority_')) \
         AND NOT EXISTS (SELECT 1 FROM pg_trigger WHERE starts_with(tgname, 'codewire_stamp_authority_') \
             OR starts_with(tgname, 'codewire_platform_authority_'))",
    )
    .fetch_one(pool)
    .await?)
}

/// Every scope generation row, as `kind:id`.
async fn generations(pool: &PgPool) -> anyhow::Result<Vec<(String, i64)>> {
    Ok(sqlx::query_as(
        "SELECT scope_kind || ':' || scope_id, generation \
         FROM public.platform_authority_generations ORDER BY 1",
    )
    .fetch_all(pool)
    .await?)
}

/// Every table migration 35 stamped, in the application's lock order.
const STAMPED_TABLES: [&str; 12] = [
    "users",
    "organizations",
    "org_members",
    "environments",
    "sandbox_environment_backend",
    "sandbox_workspace_bindings",
    "platform_environment_access_bindings",
    "platform_access_profiles",
    "platform_access_profile_revisions",
    "platform_access_profile_entries",
    "platform_credentials",
    "secret_projects",
];

const USER: &str = "stamp-removal-user";
const ORG: &str = "stamp-removal-org";
const ENV: &str = "stamp-removal-env";
const PROFILE: &str = "stamp-removal-profile";
const POD: &str = "5f2c4b63-7a1e-4d8f-8b9c-2d3e4f5a6b71";
const CLAIM: &str = "5f2c4b63-7a1e-4d8f-8b9c-2d3e4f5a6b72";
const SANDBOX: &str = "5f2c4b63-7a1e-4d8f-8b9c-2d3e4f5a6b73";

/// At least one row in every stamped table: a user with membership, a running
/// environment with backend, live binding and profile binding, a profile
/// revision and entry, a credential and a secret project.
async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(&format!(
        "INSERT INTO users(id,email) VALUES ('{USER}','stamp-removal@example.test'); \
         INSERT INTO organizations(id,name,slug,created_by) VALUES \
             ('{ORG}','Stamp removal','stamp-removal-org-slug','{USER}'); \
         INSERT INTO org_members(id,org_id,user_id,role) VALUES \
             ('stamp-removal-member','{ORG}','{USER}','member'); \
         INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES \
             ('stamp-removal-preset','{ORG}','Stamp removal','stamp-removal', \
              '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state, \
             environment_operation_generation,project_spec) VALUES \
             ('{ENV}','{ORG}','{USER}','sandbox','stamp-removal-preset','running','started',3, \
              '{{\"schema_version\":1,\"working_directory\":\"/workspace\"}}'::jsonb); \
         INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name, \
             sandbox_claim_uid,pod_name,setup_complete) VALUES \
             ('{ENV}','stamp-removal-sandboxes','sandbox-stamp-removal','{CLAIM}', \
              'sandbox-stamp-removal',true); \
         INSERT INTO sandbox_workspace_bindings(pod_uid,environment_id,namespace,pod_name,claim_uid, \
             sandbox_uid,operation_generation,managed_credential_clients,credential_scope) VALUES \
             ('{POD}','{ENV}','stamp-removal-sandboxes','sandbox-stamp-removal','{CLAIM}', \
              '{SANDBOX}',3,'codex','pod'); \
         UPDATE sandbox_environment_backend SET pod_uid='{POD}', bound_at=now() \
             WHERE environment_id='{ENV}'; \
         INSERT INTO platform_credentials(id,user_id,organization_id,provider,authentication_kind, \
             display_name,account_hint,status,revocation_generation,material_generation) VALUES \
             ('stamp-removal-codex','{USER}',NULL,'openai','oauth','Codex','account','active',1,1); \
         INSERT INTO platform_access_profiles(id,user_id,organization_id,name,current_revision) VALUES \
             ('{PROFILE}','{USER}',NULL,'Stamp removal',1); \
         INSERT INTO platform_access_profile_revisions(profile_id,revision) VALUES ('{PROFILE}',1); \
         INSERT INTO platform_access_profile_entries(profile_id,revision,capability_slot,credential_id) \
             VALUES ('{PROFILE}',1,'codex','stamp-removal-codex'); \
         INSERT INTO platform_environment_access_bindings(environment_id,profile_id,profile_revision, \
             personal_owner_confirmed_by) VALUES ('{ENV}','{PROFILE}',1,'{USER}'); \
         INSERT INTO secret_projects(id,org_id,name) VALUES ('stamp-removal-project','{ORG}','Stamp');"
    ))
    .execute(pool)
    .await?;
    Ok(())
}

/// Every row of every stamped table.
async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    for table in STAMPED_TABLES {
        let table_rows: String = sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text \
             FROM public.{table} t"
        ))
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(table_rows != "[]", "{table} has no row to keep");
        result.push(table_rows);
    }
    Ok(result)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_removal_fresh_schema_is_the_version34_schema() -> anyhow::Result<()> {
    let admin_url = std::env::var("TEST_DATABASE_URL")?;
    let fresh = TestDatabase::create(&admin_url).await?;
    let prior = TestDatabase::create(&admin_url).await?;
    let result = async {
        // Exactly 1..=36, and exactly 1..=34, through the ordinary migrator.
        apply_migrations_before(&fresh.url, VERSION + 1).await?;
        apply_migrations_before(&prior.url, STAMP_VERSION).await?;
        let fresh_pool = connect(&fresh.url).await?;
        let prior_pool = connect(&prior.url).await?;
        let ledger = applied_migrations(&fresh_pool).await?;
        let prior_ledger = applied_migrations(&prior_pool).await?;
        anyhow::ensure!(ledger.len() == 36 && ledger[..34] == prior_ledger);
        anyhow::ensure!(ledger[34].0 == STAMP_VERSION && ledger[35].0 == VERSION);
        let measured = fingerprint(&fresh_pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
                && fingerprint(&prior_pool).await?
                    == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT,
            "version-36 measured fingerprint: {measured}"
        );
        anyhow::ensure!(absent(&fresh_pool).await?);
        // Every function, trigger and ACL matches a database that never had
        // the stamp.
        anyhow::ensure!(catalog(&fresh_pool).await? == catalog(&prior_pool).await?);
        fresh_pool.close().await;
        prior_pool.close().await;
        Ok(())
    }
    .await;
    let fresh_dropped = fresh.drop().await;
    let prior_dropped = prior.drop().await;
    result.and(fresh_dropped).and(prior_dropped)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_removal_upgrade_drops_every_stamp_object_and_keeps35_rows()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, STAMP_VERSION).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        let schema34 = catalog(&pool).await?;
        pool.close().await;

        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 35 && before[34].0 == STAMP_VERSION);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_AUTHORITY_STAMP_SCHEMA_FINGERPRINT);
        // Migration 35 added only its own objects: 36 triggers, the table's
        // two guards, three functions and the table and sequence ACLs.
        let schema35 = catalog(&pool).await?;
        anyhow::ensure!(without_stamp(&schema35) == schema34);
        anyhow::ensure!(schema35.len() == schema34.len() + 36 + 2 + 3 + 2);
        // Version-35 writers fill the generation table.
        seed(&pool).await?;
        let scopes: Vec<String> = generations(&pool)
            .await?
            .into_iter()
            .map(|(scope, _)| scope)
            .collect();
        anyhow::ensure!(
            scopes
                == [
                    format!("creds:user:{USER}"),
                    format!("env:{ENV}"),
                    "global:".to_owned(),
                    format!("org:{ORG}"),
                    format!("profile:{PROFILE}"),
                    format!("user:{USER}"),
                ],
            "{scopes:?}"
        );
        let original = rows(&pool).await?;
        pool.close().await;

        // Exactly migration 36, through the ordinary migrator.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(after.len() == 36 && after[..35] == before && after[35].0 == VERSION);
        anyhow::ensure!(absent(&pool).await?);
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT,
            "authority stamp removal measured fingerprint: {measured}"
        );
        anyhow::ensure!(catalog(&pool).await? == schema34);
        anyhow::ensure!(rows(&pool).await? == original);
        // Version-36 writers fire no stamp trigger.
        sqlx::query("UPDATE environments SET state='stopping' WHERE id=$1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        let written = rows(&pool).await?;
        pool.close().await;

        // A later startup keeps everything migration 36 left.
        ensure_schema(&db.url).await?;
        let pool = connect(&db.url).await?;
        let restarted = applied_migrations(&pool).await?;
        anyhow::ensure!(restarted.len() == MIGRATOR.iter().count() && restarted[..36] == after);
        anyhow::ensure!(absent(&pool).await? && rows(&pool).await? == written);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// Version 35 exactly as it was: ledger, rows, generations, every function,
/// trigger and ACL, and the table fingerprint.
struct Version35 {
    ledger: Vec<(i64, String, bool, Vec<u8>)>,
    rows: Vec<String>,
    generations: Vec<(String, i64)>,
    catalog: Vec<String>,
}

impl Version35 {
    async fn capture(pool: &PgPool) -> anyhow::Result<Self> {
        let state = Self {
            ledger: applied_migrations(pool).await?,
            rows: rows(pool).await?,
            generations: generations(pool).await?,
            catalog: catalog(pool).await?,
        };
        anyhow::ensure!(state.ledger.len() == 35 && state.ledger[34].0 == STAMP_VERSION);
        Ok(state)
    }

    async fn unchanged(&self, pool: &PgPool) -> anyhow::Result<()> {
        anyhow::ensure!(
            applied_migrations(pool).await? == self.ledger,
            "ledger changed"
        );
        anyhow::ensure!(rows(pool).await? == self.rows, "rows changed");
        anyhow::ensure!(
            generations(pool).await? == self.generations,
            "generations changed"
        );
        anyhow::ensure!(catalog(pool).await? == self.catalog, "catalog changed");
        anyhow::ensure!(
            fingerprint(pool).await? == ACCEPTED_AUTHORITY_STAMP_SCHEMA_FINGERPRINT,
            "fingerprint changed"
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn authority_stamp_removal_lock_timeout_and_failure_keep35_then_retry() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        let version35 = Version35::capture(&pool).await?;

        // A reader holding the last table in the lock order: the migration
        // waits for at most its 5 s lock timeout, then gives up and releases
        // the locks it took on the first eleven tables.
        let mut holder = PgConnection::connect(&db.url).await?;
        let mut held = holder.begin().await?;
        sqlx::query("SELECT count(*) FROM public.secret_projects")
            .execute(&mut *held)
            .await?;
        let started = Instant::now();
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("migration36 ran through a held lock")?;
        let waited = started.elapsed();
        anyhow::ensure!(
            format!("{error:#}").contains("lock timeout"),
            "{error:#}"
        );
        anyhow::ensure!(
            waited >= Duration::from_secs(5) && waited < Duration::from_secs(30),
            "migration36 waited {waited:?}"
        );
        held.rollback().await?;
        holder.close().await?;
        version35.unchanged(&pool).await?;

        // A failure on the last statement rolls back every drop.
        sqlx::raw_sql(
            "CREATE SCHEMA migration_failure; CREATE FUNCTION migration_failure.reject_last_drop() \
             RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN \
             RAISE EXCEPTION 'synthetic failure after the last stamp drop'; END; $$; \
             CREATE EVENT TRIGGER stamp_removal_failure ON ddl_command_end WHEN TAG IN ('DROP SEQUENCE') \
             EXECUTE FUNCTION migration_failure.reject_last_drop();",
        )
        .execute(&pool)
        .await?;
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("forced migration36 failure accepted")?;
        anyhow::ensure!(
            format!("{error:#}").contains("synthetic failure after the last stamp drop"),
            "{error:#}"
        );
        sqlx::raw_sql(
            "DROP EVENT TRIGGER stamp_removal_failure; DROP SCHEMA migration_failure CASCADE;",
        )
        .execute(&pool)
        .await?;
        version35.unchanged(&pool).await?;
        pool.close().await;

        // A clean retry.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(absent(&pool).await?);
        anyhow::ensure!(applied_migrations(&pool).await?[..35] == version35.ledger);
        anyhow::ensure!(rows(&pool).await? == version35.rows);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(catalog(&pool).await? == without_stamp(&version35.catalog));
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_removal_fails_loudly_on_a_drifted_schema() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        let version35 = Version35::capture(&pool).await?;

        // A stamp object is already missing: no IF EXISTS hides it.
        sqlx::raw_sql("DROP TRIGGER codewire_stamp_authority_truncate ON public.secret_projects")
            .execute(&pool)
            .await?;
        let drifted = catalog(&pool).await?;
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("migration36 accepted a missing stamp trigger")?;
        anyhow::ensure!(
            format!("{error:#}").contains(
                "trigger \"codewire_stamp_authority_truncate\" for table \"secret_projects\" does not exist"
            ),
            "{error:#}"
        );
        anyhow::ensure!(applied_migrations(&pool).await? == version35.ledger);
        anyhow::ensure!(catalog(&pool).await? == drifted);
        anyhow::ensure!(rows(&pool).await? == version35.rows);
        // Restore it exactly as migration 35 created it.
        sqlx::raw_sql(
            "CREATE TRIGGER codewire_stamp_authority_truncate AFTER TRUNCATE ON public.secret_projects \
             FOR EACH STATEMENT EXECUTE FUNCTION public.codewire_platform_authority_row_changed('global')",
        )
        .execute(&pool)
        .await?;
        version35.unchanged(&pool).await?;

        // Something new depends on a stamp object: no CASCADE removes it.
        sqlx::raw_sql(
            "CREATE TRIGGER drifted_stamp_dependent AFTER INSERT ON public.environment_presets \
             FOR EACH ROW EXECUTE FUNCTION public.codewire_platform_authority_row_changed('org', 'org_id')",
        )
        .execute(&pool)
        .await?;
        let drifted = catalog(&pool).await?;
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("migration36 cascaded past a dependent trigger")?;
        anyhow::ensure!(
            format!("{error:#}").contains("because other objects depend on it"),
            "{error:#}"
        );
        anyhow::ensure!(applied_migrations(&pool).await? == version35.ledger);
        anyhow::ensure!(catalog(&pool).await? == drifted);
        anyhow::ensure!(rows(&pool).await? == version35.rows);
        sqlx::raw_sql("DROP TRIGGER drifted_stamp_dependent ON public.environment_presets")
            .execute(&pool)
            .await?;
        version35.unchanged(&pool).await?;
        pool.close().await;

        // Once the schema matches migration 35 again, migration 36 applies.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(absent(&pool).await? && rows(&pool).await? == version35.rows);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_removal_down_reruns35_in_place_and_keeps_every_other_row()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        let ledger35 = applied_migrations(&pool).await?;
        let schema35 = catalog(&pool).await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let ledger36 = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger36.len() == 36 && ledger36[..35] == ledger35);

        // Stop version 36, re-run migration 35 in place, delete ledger 36.
        sqlx::raw_sql(&authority_stamp_removal_down()?)
            .execute(&pool)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger35);
        anyhow::ensure!(catalog(&pool).await? == schema35);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(rows(&pool).await? == original);
        // Only the installation bump; no scope is backfilled.
        let installed = generations(&pool).await?;
        anyhow::ensure!(installed.len() == 1 && installed[0].0 == "global:");
        pool.close().await;

        // A version-35 binary starts: nothing to apply, every checksum matches.
        let binary35 = Migrator {
            migrations: Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= STAMP_VERSION)
                    .cloned()
                    .collect(),
            ),
            ..Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        binary35.run(&mut connection).await?;
        connection.close().await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger35);
        // Its writers stamp again.
        sqlx::query("UPDATE environments SET state='stopping' WHERE id=$1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        let stamped: Vec<i64> = sqlx::query_scalar(
            "SELECT generations FROM public.codewire_platform_authority_stamp(ARRAY['env'], ARRAY[$1])",
        )
        .bind(ENV)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(stamped.len() == 1 && stamped[0] > installed[0].1);
        let rolled_back = rows(&pool).await?;
        pool.close().await;

        // Rolling forward applies 36 cleanly again.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger36);
        anyhow::ensure!(absent(&pool).await? && rows(&pool).await? == rolled_back);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(catalog(&pool).await? == without_stamp(&schema35));
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn authority_stamp_removal_rollback_replays35_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..35]);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=35 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == PRIOR35);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_AUTHORITY_STAMP_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS(SELECT 1 FROM environments) \
                 AND NOT EXISTS(SELECT 1 FROM platform_credentials)"
            )
            .fetch_one(&pool)
            .await?
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, i32>("SELECT id FROM rollback_boundary.keep")
                .fetch_one(&pool)
                .await?
                == 1
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
