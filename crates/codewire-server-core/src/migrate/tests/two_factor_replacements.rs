//! Pending authenticator replacement and TOTP replay step: disposable database proof.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_replacement_fresh_schema_constrains_rows_trigger_and_indexes()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
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
