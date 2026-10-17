//! Typed SSH credential metadata: fresh-schema constraints.

use super::*;

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
