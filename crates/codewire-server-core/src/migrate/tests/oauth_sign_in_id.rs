//! The OAuth sign-in id (0057, #5688): an upgrade keeps every access and
//! refresh token as it was, with no sign-in; a token can name one; the
//! rollback (drop the column and its index on each table) restores the
//! earlier schema.

use super::*;

/// This migration's number. The tests run every migration below it first,
/// so renumbering it changes only this line.
const VERSION: i64 = 57;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so later migrations don't
/// change what this test measures.
fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

async fn tokens(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT token_hash, client_id FROM oidc_access_tokens \
         UNION ALL SELECT token_hash, client_id FROM oidc_refresh_tokens \
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn oauth_sign_in_id_upgrade_keeps_tokens_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(VERSION - 1).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO oidc_clients (id, redirect_uris) \
             VALUES ('sign-in-client', ARRAY['http://localhost/a']); \
             INSERT INTO oidc_access_tokens \
                 (token_hash, client_id, user_id, scopes, expires_at) \
             VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 'sign-in-client', 'credential-user-a', ARRAY['openid'], \
                 now() + interval '1 hour'); \
             INSERT INTO oidc_refresh_tokens \
                 (id, token_hash, client_id, user_id, scopes, auth_time, expires_at) \
             VALUES ('sign-in-refresh', \
                 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', \
                 'sign-in-client', 'credential-user-a', ARRAY['openid'], now(), \
                 now() + interval '1 hour');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        let before = tokens(&pool).await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "the migration changes the schema"
        );
        anyhow::ensure!(
            tokens(&pool).await? == before,
            "the upgrade changes no token"
        );
        let named: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM oidc_access_tokens WHERE sign_in_id IS NOT NULL) \
                  + (SELECT count(*) FROM oidc_refresh_tokens WHERE sign_in_id IS NOT NULL)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(named == 0, "a token from before names no sign-in");

        // A token names its sign-in, and the sign-in's tokens are found by it.
        sqlx::query("UPDATE oidc_refresh_tokens SET sign_in_id = 'sign-in-one'")
            .execute(&pool)
            .await?;
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM oidc_refresh_tokens \
             WHERE sign_in_id = 'sign-in-one'",
        )
        .fetch_optional(&pool)
        .await?;
        anyhow::ensure!(found.as_deref() == Some("sign-in-refresh"));
        let indexes: Vec<String> = sqlx::query_scalar(
            "SELECT indexname::text FROM pg_indexes \
             WHERE schemaname = 'public' AND indexname LIKE 'oidc_%_sign_in_id_idx' \
             ORDER BY 1",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            indexes
                == [
                    "oidc_access_tokens_sign_in_id_idx",
                    "oidc_refresh_tokens_sign_in_id_idx"
                ],
            "both tables index the sign-in: {indexes:?}"
        );

        // Rollback: dropping each column, and its index with it, restores the
        // earlier shape.
        sqlx::raw_sql(
            "ALTER TABLE oidc_access_tokens DROP COLUMN sign_in_id; \
             ALTER TABLE oidc_refresh_tokens DROP COLUMN sign_in_id;",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        anyhow::ensure!(tokens(&pool).await? == before);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
