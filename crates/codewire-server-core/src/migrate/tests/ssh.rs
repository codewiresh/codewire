//! Staged 24 -> 25 proof, not a claim that migration24 was deployed or merged.

use super::*;

const VERSION: i64 = 25;
// Frozen staged projection component accepted by root's PostgreSQL publication3
// + credential-service13 run (session46208). Versions1..23 retain independent
// accepted history pins; this is deliberately not labeled canonical history.
const ACCEPTED_STAGED24: &str = "0ac742efd684bd7b2959096bca594fdc0c7cef0b9ac5731a2fc873afc0214a5eef1cfc92c03308a47406fc03731cbe9d";

pub(super) fn assert_accepted_staged24() -> anyhow::Result<()> {
    let migration = MIGRATOR
        .iter()
        .find(|m| m.version == 24)
        .context("staged migration24 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == ACCEPTED_STAGED24,
        "migration24 differs from accepted staged component"
    );
    Ok(())
}

#[test]
fn ssh_upgrade_retains_independently_accepted_history_and_staged24() -> anyhow::Result<()> {
    assert_applied_broker_lock_history()?;
    let consent = MIGRATOR
        .iter()
        .find(|m| m.version == 22)
        .context("migration22 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(consent.sql.as_bytes())) == FROZEN_BINDING_CONSENT_CHECKSUM
    );
    projection::assert_accepted_prior23()?;
    assert_accepted_staged24()
}

async fn public_columns(pool: &PgPool) -> anyhow::Result<()> {
    let columns: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT column_name,data_type,is_nullable FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='platform_credentials' \
         AND column_name IN ('ssh_public_key','ssh_fingerprint') ORDER BY column_name",
    )
    .fetch_all(pool)
    .await?;
    anyhow::ensure!(
        columns
            == vec![
                ("ssh_fingerprint".into(), "text".into(), "YES".into()),
                ("ssh_public_key".into(), "text".into(), "YES".into()),
            ]
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_staged_upgrade_preserves_history_envelopes_locks_and_second_startup()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 24 && before[23].0 == 24);
        let fingerprint: String = sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint == ACCEPTED_PRE_SSH_SCHEMA_FINGERPRINT);
        seed_platform_credential_owners(&pool).await?;
        seed_platform_credential(&pool, "ssh-retained", Some("credential-user-a"), None, "Retained OAuth").await?;
        seed_platform_credential_material(&pool, "ssh-retained", 1).await?;
        let rows_sql = "SELECT (to_jsonb(c)-'ssh_public_key'-'ssh_fingerprint')::text,row_to_json(m)::text \
            FROM platform_credentials c JOIN platform_credential_material m ON m.credential_id=c.id WHERE c.id='ssh-retained'";
        let rows: (String,String) = sqlx::query_as(rows_sql).fetch_one(&pool).await?;
        let locks = assert_platform_broker_lock_authority(&pool, true).await?;
        let oauth = assert_oauth_publication_authority(&pool).await?;
        let projection = projection::definitions(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(after.len() == MIGRATOR.iter().count() && after[..24] == before && after[24].0 == VERSION);
        public_columns(&pool).await?;
        anyhow::ensure!(sqlx::query_as::<_,(String,String)>(rows_sql).fetch_one(&pool).await? == rows);
        let absent: bool = sqlx::query_scalar("SELECT ssh_public_key IS NULL AND ssh_fingerprint IS NULL FROM platform_credentials WHERE id='ssh-retained'").fetch_one(&pool).await?;
        anyhow::ensure!(absent, "upgrade inferred SSH identity from previous material");
        anyhow::ensure!(assert_platform_broker_lock_authority(&pool, true).await? == locks);
        anyhow::ensure!(assert_oauth_publication_authority(&pool).await? == oauth);
        anyhow::ensure!(projection::definitions(&pool).await? == projection);
        let fingerprint: String = sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT, "schema25 measured fingerprint: {fingerprint}");
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(sqlx::query_as::<_,(String,String)>(rows_sql).fetch_one(&pool).await? == rows);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_fresh_schema_rejects_partial_wrong_kind_and_unbounded_public_metadata()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        public_columns(&pool).await?;
        seed_platform_credential_owners(&pool).await?;
        seed_platform_credential(&pool, "ssh-schema", Some("credential-user-a"), None, "Synthetic SSH").await?;
        seed_platform_credential_material(&pool, "ssh-schema", 1).await?;
        sqlx::query("UPDATE platform_credentials SET account_hint=NULL WHERE id='ssh-schema'").execute(&pool).await?;
        for assignments in [
            "authentication_kind='ssh_key'",
            "provider='ssh'",
            "ssh_public_key='ssh-ed25519 AAAA'",
            "ssh_fingerprint='SHA256:'||repeat('A',43)",
            "provider='ssh',authentication_kind='ssh_key',ssh_public_key='ssh-ed25519 AAAA'",
            "provider='ssh',authentication_kind='ssh_key',ssh_public_key='ssh-ed25519 AAAA',ssh_fingerprint='bad'",
            "provider='ssh',authentication_kind='ssh_key',ssh_public_key='ssh-ed25519 '||repeat('A',4096),ssh_fingerprint='SHA256:'||repeat('A',43)",
            "provider='ssh',authentication_kind='ssh_key',ssh_public_key=E'ssh-ed25519 AAAA\\n',ssh_fingerprint='SHA256:'||repeat('A',43)",
            "provider='ssh',authentication_kind='ssh_key',ssh_public_key='ssh-ed25519 AAAA comment',ssh_fingerprint='SHA256:'||repeat('A',43)",
            "provider='ssh',authentication_kind='ssh_key',account_hint='not-an-SSH-field',ssh_public_key='ssh-ed25519 '||repeat('A',20),ssh_fingerprint='SHA256:'||repeat('A',43)",
        ] {
            let error = sqlx::query(&format!("UPDATE platform_credentials SET {assignments} WHERE id='ssh-schema'"))
                .execute(&pool).await.err().context("invalid SSH metadata accepted")?;
            anyhow::ensure!(error.as_database_error().and_then(|error| error.code()).as_deref() == Some("23514"));
        }
        // Database shape proof only: cryptographic consistency is checked by
        // the typed authority, not inferred from these synthetic public bytes.
        sqlx::query("UPDATE platform_credentials SET provider='ssh',authentication_kind='ssh_key',account_hint=NULL,ssh_public_key='ssh-ed25519 '||repeat('A',20),ssh_fingerprint='SHA256:'||repeat('A',43) WHERE id='ssh-schema'").execute(&pool).await?;
        let rows: (String,String) = sqlx::query_as("SELECT row_to_json(c)::text,row_to_json(m)::text FROM platform_credentials c JOIN platform_credential_material m ON m.credential_id=c.id WHERE c.id='ssh-schema'").fetch_one(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger);
        anyhow::ensure!(sqlx::query_as::<_,(String,String)>("SELECT row_to_json(c)::text,row_to_json(m)::text FROM platform_credentials c JOIN platform_credential_material m ON m.credential_id=c.id WHERE c.id='ssh-schema'").fetch_one(&pool).await? == rows);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_failed_forward_migration_rolls_back_columns_constraints_and_ledger()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        let old_constraint: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='platform_credentials'::regclass AND conname='platform_credentials_authentication_kind_check'").fetch_one(&pool).await?;
        sqlx::query("ALTER TABLE platform_credentials ADD CONSTRAINT platform_credentials_ssh_identity_check CHECK(true)").execute(&pool).await?;
        pool.close().await;
        anyhow::ensure!(ensure_schema(&db.url).await.is_err());
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == before);
        let added: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='platform_credentials' AND column_name IN('ssh_public_key','ssh_fingerprint')").fetch_one(&pool).await?;
        anyhow::ensure!(added == 0, "failed migration left additive columns");
        anyhow::ensure!(sqlx::query_scalar::<_,String>("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='platform_credentials'::regclass AND conname='platform_credentials_authentication_kind_check'").fetch_one(&pool).await? == old_constraint);
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_rollback_replays_staged24_only_in_disposable_application_schema() -> anyhow::Result<()>
{
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        public_columns(&pool).await?;
        sqlx::raw_sql("CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;").execute(&pool).await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 24 && ledger[23].0 == 24);
        let fingerprint: String = sqlx::query_scalar(include_str!("../../../tests/data/application_schema_fingerprint.sql")).fetch_one(&pool).await?;
        anyhow::ensure!(fingerprint == ACCEPTED_PRE_SSH_SCHEMA_FINGERPRINT);
        anyhow::ensure!(sqlx::query_scalar::<_,i32>("SELECT id FROM rollback_boundary.keep").fetch_one(&pool).await? == 1);
        anyhow::ensure!(sqlx::query_scalar::<_,bool>("SELECT NOT EXISTS(SELECT 1 FROM platform_credentials)").fetch_one(&pool).await?);
        projection::definitions(&pool).await?;
        pool.close().await;
        Ok(())
    }.await;
    result.and(db.drop().await)
}
