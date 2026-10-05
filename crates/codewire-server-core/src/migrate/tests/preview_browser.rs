//! Additive preview capability migration: immutable prior history and disposable DB proof.

use super::*;

const VERSION: i64 = 31;
// Independently measured from accepted canonical3ac1cfcb3b840aef5d96af55246897d552a094dd,
// not the edited branch: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL30)).
const PRIOR_HISTORY: &str = "44242ee270e7df0aa8923a545e6006dbf1d7e4cc1e16e48aa95f478173b5c73a1e532f9103a0a3e02e6ca1f79203cd0e";
const PRIOR30: &str = "cbb5f6589d208bd7b8d786fbf99961bad266bf37b624f7592ae5e07882d4bf3305e0e305d758b907c622f6b6b8fd087e";

pub(super) fn assert_accepted_prior30() -> anyhow::Result<()> {
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR.iter().filter(|m| m.version < VERSION).collect();
    anyhow::ensure!(prior.len() == 30);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == PRIOR_HISTORY,
        "migration1..30 differs from accepted canonical3ac1cfcb3"
    );
    anyhow::ensure!(format!("{:x}", Sha384::digest(prior[29].sql.as_bytes())) == PRIOR30);
    Ok(())
}

#[test]
fn preview_upgrade_pins_the_accepted_canonical30_history() -> anyhow::Result<()> {
    assert_accepted_prior30()
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// Every helper except migration34's workspace-binding trigger function and
/// migration37's cw-runtime trigger function, which have their own proof and
/// replace no prior helper.
async fn helpers(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n \
        ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'codewire_') \
        AND p.proname <> 'codewire_workspace_binding_immutable' \
        AND p.proname <> 'codewire_cw_runtime_request_immutable' \
        ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)",
    )
    .fetch_all(pool)
    .await?)
}

async fn rows(pool: &PgPool, include_preview: bool) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    let mut tables = vec![
        "users",
        "organizations",
        "sessions",
        "environment_presets",
        "environments",
        "environment_ports",
        "tenant_secret_deks",
        "tenant_secrets",
        "platform_credentials",
        "platform_credential_material",
    ];
    if include_preview {
        tables.extend(["preview_auth_challenges", "preview_browser_grants"]);
    }
    for table in tables {
        result.push(sqlx::query_scalar(&format!("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text FROM public.{table} t"))
            .fetch_one(pool).await?);
    }
    Ok(result)
}

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    seed_platform_credential(
        pool,
        "preview-retained",
        Some("credential-user-a"),
        None,
        "Retained",
    )
    .await?;
    seed_platform_credential_material(pool, "preview-retained", 1).await?;
    seed_test_tenant_secret_dek(pool, "preview-dek", "user", "credential-user-a").await?;
    sqlx::raw_sql("INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
        VALUES('/users/credential-user-a','PREVIEW_RETAINED','preview-dek','user','credential-user-a',decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1); \
        INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES('preview-session','credential-user-a',repeat('a',64),NOW()+interval '1 hour'); \
        INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('preview-preset','credential-org-a','Preview','preview','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
        INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
        VALUES('preview-env','credential-org-a','credential-user-a','sandbox','preview-preset','running','started',1,'{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
        INSERT INTO environment_ports(id,environment_id,port,label,access) VALUES('preview-port','preview-env',3000,'app','creator');")
        .execute(pool).await?;
    Ok(())
}

async fn seed_capabilities(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("INSERT INTO preview_auth_challenges(id,nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,code_hash,code_expires_at,consumed_at) \
        VALUES('preview-challenge',repeat('b',64),repeat('c',64),'credential-org-a','preview-env','preview-port','app.example.test','/nested?q=1',NOW(),NOW()+interval '5 minutes','preview-session',repeat('d',64),NOW()+interval '1 minute',NOW()); \
        INSERT INTO preview_browser_grants(token_hash,session_id,organization_id,environment_id,port_id,host) \
        VALUES(repeat('e',64),'preview-session','credential-org-a','preview-env','preview-port','app.example.test');")
        .execute(pool).await?;
    Ok(())
}

async fn absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regclass('public.preview_auth_challenges') IS NULL \
        AND to_regclass('public.preview_browser_grants') IS NULL",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_fresh_schema_constrains_digests_lifetimes_bindings_and_indexes()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(embedded_max_version()? >= VERSION);
        seed(&pool).await?;
        seed_capabilities(&pool).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT, "preview31 measured fingerprint: {measured}");
        // Each failure uses a separate transaction: one rejected statement must
        // not hide another assertion behind PostgreSQL's aborted-transaction state.
        for (table, assignment, code) in [
            ("preview_auth_challenges", "nonce_hash='raw-capability'", "23514"),
            ("preview_auth_challenges", "client_hash=repeat('A',64)", "23514"),
            ("preview_auth_challenges", "code_hash=repeat('d',63)", "23514"),
            ("preview_auth_challenges", "host=''", "23514"),
            ("preview_auth_challenges", "host=repeat('h',254)", "23514"),
            ("preview_auth_challenges", "return_path='https://elsewhere.test/'", "23514"),
            ("preview_auth_challenges", "return_path='/'||repeat('x',4096)", "23514"),
            ("preview_auth_challenges", "expires_at=created_at", "23514"),
            ("preview_auth_challenges", "expires_at=created_at+interval '5 minutes 1 second'", "23514"),
            ("preview_auth_challenges", "session_id=NULL", "23514"),
            ("preview_auth_challenges", "code_hash=NULL", "23514"),
            ("preview_auth_challenges", "code_expires_at=NULL", "23514"),
            ("preview_auth_challenges", "code_expires_at=expires_at+interval '1 second'", "23514"),
            ("preview_auth_challenges", "consumed_at=expires_at+interval '1 second'", "23514"),
            ("preview_auth_challenges", "session_id=NULL,code_hash=NULL,code_expires_at=NULL,consumed_at=created_at", "23514"),
            ("preview_auth_challenges", "session_id='missing'", "23503"),
            ("preview_auth_challenges", "organization_id='missing'", "23503"),
            ("preview_auth_challenges", "environment_id='missing'", "23503"),
            ("preview_auth_challenges", "port_id='missing'", "23503"),
            ("preview_browser_grants", "token_hash='raw-token'", "23514"),
            ("preview_browser_grants", "host=''", "23514"),
            ("preview_browser_grants", "host=repeat('h',254)", "23514"),
            ("preview_browser_grants", "session_id='missing'", "23503"),
            ("preview_browser_grants", "organization_id='missing'", "23503"),
            ("preview_browser_grants", "environment_id='missing'", "23503"),
            ("preview_browser_grants", "port_id='missing'", "23503"),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!("UPDATE {table} SET {assignment}"))
                .execute(&mut *tx).await.expect_err("invalid preview state accepted");
            anyhow::ensure!(error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code), "{table}/{assignment}: {error}");
            tx.rollback().await?;
        }
        let duplicate = sqlx::query("INSERT INTO preview_auth_challenges SELECT 'duplicate',nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,code_hash,code_expires_at,consumed_at FROM preview_auth_challenges")
            .execute(&pool).await.expect_err("duplicate code digest accepted");
        anyhow::ensure!(duplicate.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        let duplicate_scope = sqlx::query("INSERT INTO preview_browser_grants(token_hash,session_id,organization_id,environment_id,port_id,host) SELECT repeat('f',64),session_id,organization_id,environment_id,port_id,host FROM preview_browser_grants")
            .execute(&pool).await.expect_err("duplicate preview scope accepted");
        anyhow::ensure!(duplicate_scope.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        let replay = sqlx::query("INSERT INTO preview_auth_challenges SELECT id,nonce_hash,client_hash,organization_id,environment_id,port_id,host,return_path,created_at,expires_at,session_id,repeat('f',64),code_expires_at,NULL FROM preview_auth_challenges")
            .execute(&pool).await.expect_err("consumed challenge ID reused");
        anyhow::ensure!(replay.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        // SQL permits the complete unbound tuple, not partial authorization or
        // an unbound consumed tombstone. The app allocates only after confirmation.
        sqlx::query("UPDATE preview_auth_challenges SET session_id=NULL,code_hash=NULL,code_expires_at=NULL,consumed_at=NULL").execute(&pool).await?;
        let indexes: Vec<String> = sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename IN ('preview_auth_challenges','preview_browser_grants') ORDER BY indexname")
            .fetch_all(&pool).await?;
        let mut expected = vec!["preview_auth_challenges_pkey", "preview_auth_challenges_code_hash_key", "preview_browser_grants_pkey", "preview_browser_grants_scope_key"];
        expected.extend(["preview_auth_challenges_client", "preview_auth_challenges_expiry", "preview_auth_challenges_session", "preview_auth_challenges_organization", "preview_auth_challenges_environment", "preview_auth_challenges_port", "preview_browser_grants_session", "preview_browser_grants_organization", "preview_browser_grants_environment", "preview_browser_grants_port"]);
        expected.sort_unstable();
        anyhow::ensure!(indexes == expected);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_upgrade_preserves30_rows_helpers_and_second_startup() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 30 && before[29].0 == 30);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_PREVIEW_SCHEMA_FINGERPRINT);
        seed(&pool).await?;
        let original = rows(&pool, false).await?;
        let old_helpers = helpers(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(after.len() == MIGRATOR.iter().filter(|m| m.migration_type.is_up_migration()).count() && after[..30] == before && after[30].0 == VERSION);
        anyhow::ensure!(rows(&pool, false).await? == original && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM preview_auth_challenges) AND NOT EXISTS(SELECT 1 FROM preview_browser_grants)").fetch_one(&pool).await?);
        seed_capabilities(&pool).await?;
        let all = rows(&pool, true).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT, "preview31 measured fingerprint: {measured}");
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after && rows(&pool, true).await? == all && helpers(&pool).await? == old_helpers);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_capabilities_cascade_on_session_port_environment_and_owner_removal()
-> anyhow::Result<()> {
    for deletion in [
        "DELETE FROM sessions WHERE id='preview-session'",
        "DELETE FROM environment_ports WHERE id='preview-port'",
        "DELETE FROM environments WHERE id='preview-env'",
        "DELETE FROM organizations WHERE id='credential-org-b'",
        "UPDATE users SET enabled=false WHERE id='credential-user-a'",
    ] {
        let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
        let result = async {
            ensure_schema(&db.url).await?;
            let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
            seed(&pool).await?;
            seed_capabilities(&pool).await?;
            if deletion.contains("organizations") {
                // Isolate the direct organization cascade: environment deletion
                // would otherwise remove both rows first, while its existing
                // organization FK itself intentionally restricts deletion.
                // Cross-resource ownership is separately enforced by the app.
                sqlx::raw_sql("UPDATE preview_auth_challenges SET organization_id='credential-org-b'; UPDATE preview_browser_grants SET organization_id='credential-org-b';")
                    .execute(&pool).await?;
            }
            sqlx::query(deletion).execute(&pool).await?;
            anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM preview_auth_challenges) AND NOT EXISTS(SELECT 1 FROM preview_browser_grants)").fetch_one(&pool).await?, "capability survives {deletion}");
            pool.close().await;
            Ok(())
        }.await;
        result.and(db.drop().await)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn preview_failed_forward_rolls_back_both_tables_and_ledger_then_retries()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        seed(&pool).await?;
        let original = rows(&pool, false).await?;
        sqlx::raw_sql("CREATE SCHEMA migration_failure; CREATE FUNCTION migration_failure.reject_preview() RETURNS event_trigger LANGUAGE plpgsql AS $$ \
            BEGIN IF to_regclass('public.preview_browser_grants') IS NOT NULL THEN RAISE EXCEPTION 'synthetic failure after preview tables'; END IF; END; $$; \
            CREATE EVENT TRIGGER preview_failure ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION migration_failure.reject_preview();")
            .execute(&pool).await?;
        pool.close().await;
        let error = ensure_schema(&db.url).await.err().context("forced migration31 failure accepted")?;
        anyhow::ensure!(format!("{error:#}").contains("synthetic failure after preview tables"));
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(absent(&pool).await? && applied_migrations(&pool).await? == before && rows(&pool, false).await? == original);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_PREVIEW_SCHEMA_FINGERPRINT);
        sqlx::raw_sql("DROP EVENT TRIGGER preview_failure; DROP SCHEMA migration_failure CASCADE;").execute(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(!absent(&pool).await? && applied_migrations(&pool).await?.len() == MIGRATOR.iter().filter(|m| m.migration_type.is_up_migration()).count() && rows(&pool, false).await? == original);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

/// The documented in-place rollback: the migration only adds two tables, so
/// removing them and their ledger row restores version 30 without touching
/// sessions, credentials or other rows. Preview grants are simply re-earned.
const PREVIEW_DOWN: &str = "BEGIN; \
    DROP TABLE public.preview_browser_grants; \
    DROP TABLE public.preview_auth_challenges; \
    DELETE FROM public._sqlx_migrations WHERE version = 31; \
    COMMIT;";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_down_restores30_in_place_and_keeps_every_other_row() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The down statement applies to a version-31 ledger, so stop there
        // even when later migrations exist.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed(&pool).await?;
        seed_capabilities(&pool).await?;
        let original = rows(&pool, false).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql(PREVIEW_DOWN).execute(&pool).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..30]);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_PREVIEW_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool, false).await? == original);
        pool.close().await;
        // Rolling forward again applies 31 cleanly.
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(
            applied_migrations(&pool).await?.len()
                == MIGRATOR
                    .iter()
                    .filter(|m| m.migration_type.is_up_migration())
                    .count()
        );
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool, false).await? == original);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn preview_rollback_replays30_only_in_disposable_application_schema() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        seed_capabilities(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql("CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            .execute(&pool).await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..30]);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_PREVIEW_SCHEMA_FINGERPRINT);
        anyhow::ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM platform_credentials) AND NOT EXISTS(SELECT 1 FROM platform_credential_material) AND NOT EXISTS(SELECT 1 FROM sessions)").fetch_one(&pool).await?);
        anyhow::ensure!(sqlx::query_scalar::<_, i32>("SELECT id FROM rollback_boundary.keep").fetch_one(&pool).await? == 1);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}
