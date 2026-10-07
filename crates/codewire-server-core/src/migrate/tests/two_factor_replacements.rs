//! Pending authenticator replacement and TOTP replay step: staged prior history
//! and disposable database proof.

use super::*;

const VERSION: i64 = 32;
// Measured at preview-login branch head
// da7bf6a031e98ffdf1df62bb8299d4947a13cdce, whose migration31 this work is
// stacked on: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL31)) and
// SHA384(SQL31). This pins staged predecessor bytes; it does not claim that
// version31 alone was deployed.
const STAGED_HISTORY31: &str = "df03ad590a6e2c74235c2284c969a5dce75279a78f6c1716074147b9e745672f504cdceec77c54a1d0df0d405a1bb489";
const STAGED31: &str = "d39f675b139aaf21c91ae2cd0d550d13ee2bad9d5fb6bda9214b9b93b4e2b525f92fcc817f25f5b3d5cebbbe0df3a274";

pub(super) fn assert_accepted_staged31() -> anyhow::Result<()> {
    preview_browser::assert_accepted_prior30()?;
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR.iter().filter(|m| m.version < VERSION).collect();
    anyhow::ensure!(prior.len() == 31);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == STAGED_HISTORY31,
        "migration1..31 differs from the staged preview browser authorization history"
    );
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(prior[30].sql.as_bytes())) == STAGED31,
        "migration31 differs from the staged preview browser authorization"
    );
    Ok(())
}

#[test]
fn two_factor_replacement_upgrade_pins_the_staged31_history() -> anyhow::Result<()> {
    assert_accepted_staged31()
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// Every helper except migration34's workspace-binding trigger function and
/// migration38's cw-runtime trigger function, which have their own proof and
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

/// Every pre-existing row this migration could touch. `two_factor` is compared
/// without the new step column, which upgrade leaves NULL.
async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    for (table, projection) in [
        ("users", "to_jsonb(t)"),
        ("sessions", "to_jsonb(t)"),
        ("two_factor", "to_jsonb(t) - 'last_totp_step'"),
        ("two_factor_tokens", "to_jsonb(t)"),
        ("organizations", "to_jsonb(t)"),
        ("tenant_secret_deks", "to_jsonb(t)"),
        ("tenant_secrets", "to_jsonb(t)"),
        ("platform_credentials", "to_jsonb(t)"),
        ("platform_credential_material", "to_jsonb(t)"),
    ] {
        result.push(
            sqlx::query_scalar(&format!(
                "SELECT COALESCE(jsonb_agg({projection} ORDER BY ({projection})::text),'[]'::jsonb)::text \
                 FROM public.{table} t"
            ))
            .fetch_one(pool)
            .await?,
        );
    }
    Ok(result)
}

// Ciphertext fixtures use the stored layout: base64(nonce || ciphertext || tag).
const ENROLLED_SECRET: &str = "AAECAwQFBgcICQoLLYY3dbWpcbc6RZ8ALjZtMW+NPilraGP3sMCB8lK85So=";
const PENDING_SECRET: &str = "DAsKCQgHBgUEAwIBAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj";

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    seed_platform_credential(
        pool,
        "replacement-retained",
        Some("credential-user-a"),
        None,
        "Retained",
    )
    .await?;
    seed_platform_credential_material(pool, "replacement-retained", 1).await?;
    seed_test_tenant_secret_dek(pool, "replacement-dek", "user", "credential-user-a").await?;
    sqlx::query(
        "INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
         VALUES('/users/credential-user-a','REPLACEMENT_RETAINED','replacement-dek','user','credential-user-a',\
         decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1)",
    )
    .execute(pool)
    .await?;
    sqlx::query("UPDATE users SET two_factor_enabled=true WHERE id='credential-user-a'")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES \
         ('replacement-session','credential-user-a',repeat('a',64),NOW()+interval '1 hour'), \
         ('replacement-other-session','credential-user-a',repeat('b',64),NOW()+interval '1 hour')",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO two_factor(id,user_id,secret,backup_codes) VALUES ('replacement-factor','credential-user-a',$1,$1)",
    )
    .bind(ENROLLED_SECRET)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO two_factor_tokens(id,user_id,token_hash,expires_at) \
         VALUES ('replacement-challenge','credential-user-a',repeat('c',64),NOW()+interval '10 minutes')",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn seed_pending(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO two_factor_replacements(id,user_id,session_id,secret,created_at,expires_at) \
         SELECT repeat('d',32),'credential-user-a','replacement-session',$1,now.t,now.t+interval '10 minutes' \
         FROM (SELECT clock_timestamp() AS t) AS now",
    )
    .bind(PENDING_SECRET)
    .execute(pool)
    .await?;
    sqlx::query("UPDATE two_factor SET last_totp_step=59000000 WHERE user_id='credential-user-a'")
        .execute(pool)
        .await?;
    Ok(())
}

async fn pending_count(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM public.two_factor_replacements")
            .fetch_one(pool)
            .await?,
    )
}

async fn absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regclass('public.two_factor_replacements') IS NULL AND NOT EXISTS (\
         SELECT 1 FROM information_schema.columns WHERE table_schema='public' \
         AND table_name='two_factor' AND column_name='last_totp_step')",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_replacement_fresh_schema_constrains_rows_trigger_and_indexes()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(embedded_max_version()? >= VERSION);
        seed(&pool).await?;
        seed_pending(&pool).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "two-factor replacement measured fingerprint: {measured}"
        );
        // Each failure uses a separate transaction: one rejected statement must
        // not hide another assertion behind PostgreSQL's aborted-transaction state.
        for (table, assignment, code) in [
            ("two_factor_replacements", "id='not-a-hex-id'", "23514"),
            ("two_factor_replacements", "id=repeat('D',32)", "23514"),
            ("two_factor_replacements", "secret='JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'", "23514"),
            ("two_factor_replacements", "secret=repeat('A',39)", "23514"),
            ("two_factor_replacements", "secret=repeat('A',1025)", "23514"),
            ("two_factor_replacements", "secret='plain text secret value that is long enough'", "23514"),
            ("two_factor_replacements", "attempts=-1", "23514"),
            ("two_factor_replacements", "attempts=6", "23514"),
            ("two_factor_replacements", "expires_at=created_at", "23514"),
            ("two_factor_replacements", "expires_at=created_at+interval '10 minutes 1 second'", "23514"),
            ("two_factor_replacements", "user_id='missing'", "23503"),
            ("two_factor_replacements", "session_id='missing'", "23503"),
            ("two_factor_replacements", "secret=NULL", "23502"),
            ("two_factor_replacements", "expires_at=NULL", "23502"),
            ("two_factor", "last_totp_step=-1", "23514"),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!("UPDATE {table} SET {assignment}"))
                .execute(&mut *tx)
                .await
                .expect_err("invalid two-factor replacement state accepted");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "{table}/{assignment}: {error}"
            );
            tx.rollback().await?;
        }
        // The full ten minutes and five attempts are valid.
        sqlx::query("UPDATE two_factor_replacements SET attempts=5, expires_at=created_at+interval '10 minutes'")
            .execute(&pool)
            .await?;
        // One pending replacement per account.
        let duplicate = sqlx::query(
            "INSERT INTO two_factor_replacements(id,user_id,session_id,secret,expires_at) \
             SELECT repeat('e',32),user_id,'replacement-other-session',secret,clock_timestamp()+interval '1 minute' \
             FROM two_factor_replacements",
        )
        .execute(&pool)
        .await
        .expect_err("second pending replacement accepted");
        anyhow::ensure!(duplicate.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"));
        // A disabled account cannot start one: the enabled-account trigger
        // rejects the insert even though every referenced row exists.
        sqlx::query("INSERT INTO users(id,email,enabled) VALUES ('replacement-disabled','disabled@example.test',false)")
            .execute(&pool)
            .await?;
        let disabled = sqlx::query(
            "INSERT INTO two_factor_replacements(id,user_id,session_id,secret,expires_at) \
             VALUES (repeat('9',32),'replacement-disabled','replacement-other-session',$1,clock_timestamp()+interval '1 minute')",
        )
        .bind(PENDING_SECRET)
        .execute(&pool)
        .await
        .expect_err("disabled account started a replacement");
        anyhow::ensure!(
            disabled.as_database_error().and_then(|e| e.code()).as_deref() == Some("28000"),
            "{disabled}"
        );
        let trigger: String = sqlx::query_scalar(
            "SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgrelid='public.two_factor_replacements'::regclass AND NOT tgisinternal",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            trigger.contains("BEFORE INSERT")
                && trigger.contains("codewire_require_enabled_account()"),
            "{trigger}"
        );
        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT indexname FROM pg_indexes WHERE schemaname='public' AND tablename='two_factor_replacements' ORDER BY indexname",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            indexes
                == [
                    "two_factor_replacements_expiry",
                    "two_factor_replacements_pkey",
                    "two_factor_replacements_session",
                    "two_factor_replacements_user_key",
                ],
            "{indexes:?}"
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_replacement_upgrade_preserves31_rows_helpers_and_second_startup()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 31 && before[30].0 == 31);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_TWO_FACTOR_REPLACEMENT_SCHEMA_FINGERPRINT
        );
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(
            after.len()
                == MIGRATOR
                    .iter()
                    .filter(|m| m.migration_type.is_up_migration())
                    .count()
                && after[..31] == before
                && after[31].0 == VERSION
        );
        // The existing factor, its sessions and challenge are untouched, and no
        // step is invented for it: the first later proof may use any step.
        anyhow::ensure!(rows(&pool).await? == original && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(
            sqlx::query_scalar::<_, Option<i64>>("SELECT last_totp_step FROM two_factor")
                .fetch_one(&pool)
                .await?
                .is_none()
        );
        anyhow::ensure!(pending_count(&pool).await? == 0);
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "two-factor replacement measured fingerprint: {measured}"
        );
        seed_pending(&pool).await?;
        let with_pending = rows(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(rows(&pool).await? == with_pending && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(pending_count(&pool).await? == 1);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_replacement_cascades_with_session_account_and_disablement() -> anyhow::Result<()>
{
    for removal in [
        "DELETE FROM sessions WHERE id='replacement-session'",
        "DELETE FROM users WHERE id='credential-user-b'",
        "UPDATE users SET enabled=false WHERE id='credential-user-b'",
    ] {
        let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
        let result = async {
            ensure_schema(&db.url).await?;
            let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
            seed(&pool).await?;
            if removal.contains("credential-user-b") {
                // Isolate the account cascade from the organizations that user A
                // owns: move the pending replacement and its session to user B.
                sqlx::query("UPDATE sessions SET user_id='credential-user-b' WHERE id='replacement-session'")
                    .execute(&pool)
                    .await?;
                sqlx::query(
                    "INSERT INTO two_factor_replacements(id,user_id,session_id,secret,expires_at) \
                     VALUES (repeat('d',32),'credential-user-b','replacement-session',$1,clock_timestamp()+interval '1 minute')",
                )
                .bind(PENDING_SECRET)
                .execute(&pool)
                .await?;
            } else {
                seed_pending(&pool).await?;
            }
            anyhow::ensure!(pending_count(&pool).await? == 1);
            sqlx::query(removal).execute(&pool).await?;
            anyhow::ensure!(
                pending_count(&pool).await? == 0,
                "pending replacement survives {removal}"
            );
            // The enrolled factor is never removed by losing a pending one.
            anyhow::ensure!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM two_factor WHERE user_id='credential-user-a'")
                    .fetch_one(&pool)
                    .await?
                    == 1
            );
            pool.close().await;
            Ok(())
        }
        .await;
        result.and(db.drop().await)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn two_factor_replacement_failed_forward_rolls_back_table_column_and_ledger_then_retries()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        seed(&pool).await?;
        let original = rows(&pool).await?;
        // Fail on the last statement, after the table, indexes and trigger exist.
        sqlx::raw_sql(
            "CREATE SCHEMA migration_failure; CREATE FUNCTION migration_failure.reject_step() RETURNS event_trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF to_regclass('public.two_factor_replacements') IS NOT NULL THEN RAISE EXCEPTION 'synthetic failure after replacement table'; END IF; END; $$; \
             CREATE EVENT TRIGGER replacement_failure ON ddl_command_end WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION migration_failure.reject_step();",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("forced migration32 failure accepted")?;
        anyhow::ensure!(format!("{error:#}").contains("synthetic failure after replacement table"));
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(
            absent(&pool).await?
                && applied_migrations(&pool).await? == before
                && rows(&pool).await? == original
        );
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_TWO_FACTOR_REPLACEMENT_SCHEMA_FINGERPRINT
        );
        sqlx::raw_sql("DROP EVENT TRIGGER replacement_failure; DROP SCHEMA migration_failure CASCADE;")
            .execute(&pool)
            .await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(
            !absent(&pool).await?
                && applied_migrations(&pool).await?.len() == MIGRATOR.iter().filter(|m| m.migration_type.is_up_migration()).count()
                && rows(&pool).await? == original
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// The documented in-place rollback: the migration only adds a table, its
/// trigger and one nullable column, so removing them and the ledger row restores
/// version 31 without touching factors, sessions or other rows. Pending
/// replacements are lost; their accounts keep the authenticator they had.
const TWO_FACTOR_REPLACEMENT_DOWN: &str = "BEGIN; \
    DROP TABLE public.two_factor_replacements; \
    ALTER TABLE public.two_factor DROP COLUMN last_totp_step; \
    DELETE FROM public._sqlx_migrations WHERE version = 32; \
    COMMIT;";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_replacement_down_restores31_in_place_and_keeps_every_other_row()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed(&pool).await?;
        seed_pending(&pool).await?;
        let original = rows(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 32 && ledger[31].0 == VERSION);
        sqlx::raw_sql(TWO_FACTOR_REPLACEMENT_DOWN)
            .execute(&pool)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..31]);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_TWO_FACTOR_REPLACEMENT_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(rows(&pool).await? == original);
        pool.close().await;
        // Rolling forward again applies 32 cleanly with no pending rows.
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
        anyhow::ensure!(rows(&pool).await? == original && pending_count(&pool).await? == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_replacement_rollback_replays31_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        seed_pending(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..31]);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=31 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == STAGED31);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_TWO_FACTOR_REPLACEMENT_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS(SELECT 1 FROM two_factor) AND NOT EXISTS(SELECT 1 FROM sessions) \
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
