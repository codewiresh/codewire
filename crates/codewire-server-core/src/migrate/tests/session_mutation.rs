//! Fresh-schema proof for exact browser-session credential-mutation authority.

use super::*;

const VERSION: i64 = 28;
// SHA-384 measured from migration27 at accepted canonical f0340e08f72d0bb9066e6f3c2ef1529beee4c911.
// This pins the staged predecessor bytes; it does not claim version27 alone was deployed.
const ACCEPTED_STAGED27: &str = "dc445947456e2cf18af0d3db348f1d4b5abb2bf21677551d7c99f369951e50db1a9c1ebcad837655d0ee4fb2dbd0b424";
const AUTHENTICATE_SIGNATURE: &str = "public.codewire_authenticate_credential_session(text)";
const LOCK_SIGNATURE: &str =
    "public.codewire_lock_credential_session_authority(text,text,text,timestamp with time zone)";

pub(super) fn assert_accepted_staged27() -> anyhow::Result<()> {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 27)
        .context("accepted staged migration27 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == ACCEPTED_STAGED27,
        "migration27 differs from accepted canonical f0340e08f"
    );
    Ok(())
}

#[test]
fn session_mutation_upgrade_retains_accepted_staged27() -> anyhow::Result<()> {
    owner_sources::assert_accepted_staged26()?;
    assert_accepted_staged27()
}

/// Helpers other than this migration's two and migration34's workspace-binding
/// trigger function, which has its own proof and replaces no prior helper.
async fn prior_helper_definitions(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p \
         JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace \
         WHERE n.nspname='public' AND starts_with(p.proname,'codewire_') \
         AND p.proname NOT IN ('codewire_authenticate_credential_session', \
         'codewire_lock_credential_session_authority','codewire_workspace_binding_immutable') \
         ORDER BY p.proname,p.oid",
    )
    .fetch_all(pool)
    .await?)
}

async fn retained_rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut rows = Vec::new();
    for table in [
        "users",
        "organizations",
        "sessions",
        "tenant_secret_deks",
        "tenant_secrets",
        "platform_credentials",
        "platform_credential_material",
    ] {
        // Version 30 adds an unset sessions column; retained rows are
        // compared without it.
        let value: String = sqlx::query_scalar(&format!(
            "SELECT COALESCE(jsonb_agg(r ORDER BY r::text),'[]'::jsonb)::text \
             FROM (SELECT to_jsonb(t) - 'two_factor_setup_skipped_at' AS r FROM public.{table} t) AS rows"
        ))
        .fetch_one(pool)
        .await?;
        rows.push(value);
    }
    Ok(rows)
}

async fn helpers_absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT to_regprocedure($1) IS NULL AND to_regprocedure($2) IS NULL")
            .bind(AUTHENTICATE_SIGNATURE)
            .bind(LOCK_SIGNATURE)
            .fetch_one(pool)
            .await?,
    )
}

async fn helpers_present(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regprocedure($1) IS NOT NULL AND to_regprocedure($2) IS NOT NULL",
    )
    .bind(AUTHENTICATE_SIGNATURE)
    .bind(LOCK_SIGNATURE)
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn session_mutation_helpers_are_private_exact_and_logout_fenced() -> anyhow::Result<()> {
    let admin_url = std::env::var("TEST_DATABASE_URL")
        .context("TEST_DATABASE_URL is required for migration tests")?;
    let database = TestDatabase::create(&admin_url).await?;
    let result = async {
        ensure_schema(&database.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database.url)
            .await?;
        anyhow::ensure!(embedded_max_version()? >= 28);
        let functions: Vec<(String, bool)> = sqlx::query_as(
            "SELECT p.proname, p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp','TimeZone=UTC']::text[] AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('codewire_authenticate_credential_session','codewire_lock_credential_session_authority') ORDER BY p.proname",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            functions
                == vec![
                    ("codewire_authenticate_credential_session".into(), true),
                    ("codewire_lock_credential_session_authority".into(), true),
                ]
        );
        sqlx::query("INSERT INTO users(id,email,is_admin) VALUES ('session-mutation-user','session-mutation@example.test',false)")
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES ('session-mutation-id','session-mutation-user',$1,NOW()+interval '1 hour')")
            .bind("a".repeat(64))
            .execute(&pool)
            .await?;
        let first: (String, String, bool, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT session_id,user_id,is_admin,expires_at FROM public.codewire_authenticate_credential_session($1)",
        )
        .bind("a".repeat(64))
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(first.0 == "session-mutation-id" && first.1 == "session-mutation-user");
        let slid_expiry: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
            "SELECT expires_at FROM public.codewire_authenticate_credential_session($1)",
        )
        .bind("a".repeat(64))
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(slid_expiry >= first.3);
        let mut tx = pool.begin().await?;
        let accepted: bool = sqlx::query_scalar(
            "SELECT public.codewire_lock_credential_session_authority($1,$2,$3,$4)",
        )
        .bind(&first.0)
        .bind("a".repeat(64))
        .bind(&first.1)
        .bind(first.3)
        .fetch_one(&mut *tx)
        .await?;
        anyhow::ensure!(accepted);
        tx.rollback().await?;
        sqlx::query("DELETE FROM sessions WHERE id=$1")
            .bind(&first.0)
            .execute(&pool)
            .await?;
        let denied: bool = sqlx::query_scalar(
            "SELECT public.codewire_lock_credential_session_authority($1,$2,$3,$4)",
        )
        .bind(&first.0)
        .bind("a".repeat(64))
        .bind(&first.1)
        .bind(first.3)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!denied);

        sqlx::query("INSERT INTO users(id,email,is_admin) VALUES ('disabled-session-user','disabled-session@example.test',false)")
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES ('disabled-session-id','disabled-session-user',$1,NOW()+interval '1 hour')")
            .bind("b".repeat(64))
            .execute(&pool)
            .await?;
        let disabled: (String, String, bool, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT session_id,user_id,is_admin,expires_at FROM public.codewire_authenticate_credential_session($1)",
        )
        .bind("b".repeat(64))
        .fetch_one(&pool)
        .await?;
        sqlx::query("UPDATE users SET enabled=false WHERE id=$1")
            .bind(&disabled.1)
            .execute(&pool)
            .await?;
        let disabled_authentication: Option<String> = sqlx::query_scalar(
            "SELECT session_id FROM public.codewire_authenticate_credential_session($1)",
        )
        .bind("b".repeat(64))
        .fetch_optional(&pool)
        .await?;
        anyhow::ensure!(disabled_authentication.is_none());
        let disabled_lock: bool = sqlx::query_scalar(
            "SELECT public.codewire_lock_credential_session_authority($1,$2,$3,$4)",
        )
        .bind(&disabled.0)
        .bind("b".repeat(64))
        .bind(&disabled.1)
        .bind(disabled.3)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!disabled_lock);
        pool.close().await;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    database.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn session_mutation_staged_upgrade_preserves27_rows_helpers_and_noop() -> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 27 && before[26].0 == 27);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=27 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED27);

        seed_platform_credential_owners(&pool).await?;
        seed_platform_credential(
            &pool,
            "session-retained",
            Some("credential-user-a"),
            None,
            "Retained",
        )
        .await?;
        seed_platform_credential_material(&pool, "session-retained", 1).await?;
        seed_test_tenant_secret_dek(&pool, "session-retained-dek", "user", "credential-user-a")
            .await?;
        sqlx::query(
            "INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
             VALUES('/users/credential-user-a','SESSION_RETAINED','session-retained-dek','user','credential-user-a',decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1)",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO sessions(id,user_id,token_hash,expires_at) \
             VALUES('session-retained-id','credential-user-a',$1,NOW()+interval '1 hour')",
        )
        .bind("c".repeat(64))
        .execute(&pool)
        .await?;
        let rows = retained_rows(&pool).await?;
        let old_helpers = prior_helper_definitions(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(
            after.len() == MIGRATOR.iter().count()
                && after[..27] == before
                && after[27].0 == VERSION
        );
        anyhow::ensure!(retained_rows(&pool).await? == rows);
        anyhow::ensure!(prior_helper_definitions(&pool).await? == old_helpers);
        anyhow::ensure!(helpers_present(&pool).await?);
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(retained_rows(&pool).await? == rows);
        anyhow::ensure!(prior_helper_definitions(&pool).await? == old_helpers);
        anyhow::ensure!(helpers_present(&pool).await?);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn session_mutation_failed_forward_rolls_back_both_helpers_and_ledger_then_retries()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        let old_helpers = prior_helper_definitions(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA migration_failure; \
             CREATE FUNCTION migration_failure.reject_session_mutation() RETURNS event_trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF to_regprocedure('public.codewire_lock_credential_session_authority(text,text,text,timestamp with time zone)') IS NOT NULL \
             THEN RAISE EXCEPTION 'synthetic failure after both session mutation helpers'; END IF; END; $$; \
             CREATE EVENT TRIGGER session_mutation_failure ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') \
             EXECUTE FUNCTION migration_failure.reject_session_mutation();",
        )
        .execute(&pool)
        .await?;
        pool.close().await;

        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("forced migration28 failure was accepted")?;
        anyhow::ensure!(
            format!("{error:#}").contains("synthetic failure after both session mutation helpers")
        );
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == before);
        anyhow::ensure!(helpers_absent(&pool).await?);
        anyhow::ensure!(prior_helper_definitions(&pool).await? == old_helpers);
        sqlx::raw_sql(
            "DROP EVENT TRIGGER session_mutation_failure; DROP SCHEMA migration_failure CASCADE;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(helpers_present(&pool).await?);
        anyhow::ensure!(applied_migrations(&pool).await?.len() == MIGRATOR.iter().count());
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn session_mutation_rollback_replays_staged27_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(helpers_present(&pool).await?);
        seed_platform_credential_owners(&pool).await?;
        seed_platform_credential(
            &pool,
            "session-discarded",
            Some("credential-user-a"),
            None,
            "Discarded",
        )
        .await?;
        seed_platform_credential_material(&pool, "session-discarded", 1).await?;
        let old_helpers = prior_helper_definitions(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;

        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 27 && ledger[26].0 == 27);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=27 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED27);
        anyhow::ensure!(helpers_absent(&pool).await?);
        anyhow::ensure!(prior_helper_definitions(&pool).await? == old_helpers);
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS(SELECT 1 FROM public.platform_credentials) \
                 AND NOT EXISTS(SELECT 1 FROM public.platform_credential_material)",
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
