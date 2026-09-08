//! Fresh-schema proof for exact browser-session credential-mutation authority.

use super::*;

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
        anyhow::ensure!(embedded_max_version()? == 27);
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
        pool.close().await;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    database.drop().await?;
    result
}
