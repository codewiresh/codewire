//! Proof for skipping two-factor setup for one browser session.

use super::*;

const VERSION: i64 = 30;
// SHA-384 of migration29 at W1 branch head
// 5991eabfdafb350c14c3e66960b507cfaf7fc8f6. This pins the staged predecessor
// bytes; it does not claim version29 alone was deployed.
const ACCEPTED_STAGED29: &str = "0cd6e50035f11bf7c0dea3ef51c8ec5368c0db95cc69c4ce0a9af5e3268b9e1338d965bac48bb8a4f476bb02dbe96875";

fn assert_accepted_staged29() -> anyhow::Result<()> {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 29)
        .context("accepted staged migration29 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == ACCEPTED_STAGED29,
        "migration29 differs from the accepted staged GitHub singleton"
    );
    Ok(())
}

#[test]
fn two_factor_setup_skip_upgrade_retains_accepted_staged29() -> anyhow::Result<()> {
    session_mutation::assert_accepted_staged27()?;
    github_singleton::assert_accepted_staged28()?;
    assert_accepted_staged29()
}

async fn seed_session(pool: &PgPool, id: &str, user_id: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
         VALUES ($1, $2, NOW() + interval '1 day', encode(sha256($1::bytea), 'hex'))",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn skip_column(pool: &PgPool) -> anyhow::Result<Option<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT data_type::text, is_nullable::text FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='sessions' \
           AND column_name='two_factor_setup_skipped_at'",
    )
    .fetch_optional(pool)
    .await?)
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_setup_skip_upgrade_keeps_sessions_and_adds_an_unset_choice()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        assert_accepted_staged29()?;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 29 && before[28].0 == 29);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_TWO_FACTOR_SKIP_SCHEMA_FINGERPRINT
        );
        seed_platform_credential_owners(&pool).await?;
        seed_session(&pool, "existing-session", "credential-user-a").await?;
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
                && after[..29] == before
                && after[29].0 == VERSION
        );
        anyhow::ensure!(
            skip_column(&pool).await? == Some(("timestamp without time zone".into(), "YES".into()))
        );
        // Existing sessions keep working and have not skipped setup.
        let existing: Option<Option<chrono::NaiveDateTime>> = sqlx::query_scalar(
            "SELECT two_factor_setup_skipped_at FROM sessions WHERE id='existing-session'",
        )
        .fetch_optional(&pool)
        .await?;
        anyhow::ensure!(existing == Some(None));
        let fingerprint = fingerprint(&pool).await?;
        anyhow::ensure!(
            fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "schema30 measured fingerprint: {fingerprint}"
        );
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn two_factor_setup_skip_rollback_replays_staged29_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed_platform_credential_owners(&pool).await?;
        seed_session(&pool, "skipped-session", "credential-user-a").await?;
        sqlx::query("UPDATE sessions SET two_factor_setup_skipped_at=NOW() WHERE id='skipped-session'")
            .execute(&pool)
            .await?;
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
        anyhow::ensure!(ledger.len() == 29 && ledger[28].0 == 29);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=29 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED29);
        anyhow::ensure!(skip_column(&pool).await?.is_none());
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_TWO_FACTOR_SKIP_SCHEMA_FINGERPRINT);
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM public.sessions)")
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
