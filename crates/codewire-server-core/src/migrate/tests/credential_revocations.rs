//! Credential revocations (#3586): after an upgrade, each loss that must end a
//! stream writes one log row and a wake-up, cleanup of expired credentials
//! writes none, rows older than an hour are pruned on the next write, and the
//! rollback restores the earlier schema.

use std::collections::BTreeSet;

use sqlx::postgres::PgListener;

use super::*;

/// The version of the migration this file tests.
const VERSION: i64 = 35;

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

async fn logged(pool: &PgPool) -> anyhow::Result<BTreeSet<(String, String, String)>> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT kind, credential_id, user_id FROM credential_revocations")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().collect())
}

fn row(kind: &str, credential_id: &str, user_id: &str) -> (String, String, String) {
    (kind.into(), credential_id.into(), user_id.into())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn credential_revocations_log_each_loss_once_and_roll_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(VERSION - 1).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES \
                 ('holder', 'holder@example.test'), \
                 ('to-disable', 'to-disable@example.test'), \
                 ('to-delete', 'to-delete@example.test'); \
             INSERT INTO sessions (id, user_id, expires_at, token_hash) VALUES \
                 ('s-live', 'holder', now() + interval '1 hour', repeat('a', 64)), \
                 ('s-expired', 'holder', now() - interval '1 minute', repeat('b', 64)); \
             INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at) VALUES \
                 ('t-live', 'cli', 'holder', ARRAY['openid'], now() + interval '1 hour'), \
                 ('t-expired', 'cli', 'holder', ARRAY['openid'], now() - interval '1 minute'); \
             INSERT INTO organizations (id, name, slug, created_by) \
                 VALUES ('org-holder', 'holder', 'holder-org', 'holder'); \
             INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix, disabled_at) VALUES \
                 ('k-disable', 'holder', 'org-holder', 'a', 'h1', 'cw_a', NULL), \
                 ('k-delete', 'holder', 'org-holder', 'b', 'h2', 'cw_b', NULL), \
                 ('k-dead', 'holder', 'org-holder', 'c', 'h3', 'cw_c', now());",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "the migration changes the schema"
        );
        let mut listener = PgListener::connect(&db.url).await?;
        listener.listen("credential_revocations").await?;

        sqlx::raw_sql(
            "DELETE FROM sessions WHERE id IN ('s-live', 's-expired'); \
             DELETE FROM oidc_access_tokens WHERE token_hash IN ('t-live', 't-expired'); \
             UPDATE api_keys SET disabled_at = now() WHERE id = 'k-disable'; \
             DELETE FROM api_keys WHERE id IN ('k-delete', 'k-dead'); \
             UPDATE users SET enabled = false WHERE id = 'to-disable'; \
             DELETE FROM users WHERE id = 'to-delete'; \
             SELECT codewire_revoke_oauth_grant('holder', 'cli');",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            logged(&pool).await?
                == BTreeSet::from([
                    row("session", "s-live", "holder"),
                    row("oauth_token", "t-live", "holder"),
                    row("api_key", "k-disable", "holder"),
                    row("api_key", "k-delete", "holder"),
                    row("user", "to-disable", "to-disable"),
                    row("user", "to-delete", "to-delete"),
                    row("oauth_grant", "cli", "holder"),
                ]),
            "each loss is logged once, and expired or already disabled credentials are not"
        );
        let wake = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .map_err(|_| anyhow::anyhow!("no wake-up on credential_revocations"))??;
        anyhow::ensure!(wake.payload().is_empty(), "the wake-up carries no payload");

        // A row older than an hour goes on the next write.
        sqlx::query(
            "UPDATE credential_revocations SET revoked_at = now() - interval '61 minutes' \
             WHERE kind = 'user'",
        )
        .execute(&pool)
        .await?;
        sqlx::query("SELECT codewire_revoke_oauth_grant('holder', 'desktop')")
            .execute(&pool)
            .await?;
        let kinds: BTreeSet<String> = logged(&pool)
            .await?
            .into_iter()
            .map(|(kind, _, _)| kind)
            .collect();
        anyhow::ensure!(!kinds.contains("user"), "rows older than an hour are pruned");

        // Rollback: the triggers, then the functions, then the table.
        listener.unlisten_all().await?;
        sqlx::raw_sql(
            "DROP TRIGGER users_revoke_streams_on_disable ON users; \
             DROP TRIGGER users_revoke_streams_on_delete ON users; \
             DROP TRIGGER sessions_revoke_streams_on_delete ON sessions; \
             DROP TRIGGER oidc_access_tokens_revoke_streams_on_delete ON oidc_access_tokens; \
             DROP TRIGGER api_keys_revoke_streams_on_disable ON api_keys; \
             DROP TRIGGER api_keys_revoke_streams_on_delete ON api_keys; \
             DROP FUNCTION codewire_revoke_user_streams(); \
             DROP FUNCTION codewire_revoke_session_streams(); \
             DROP FUNCTION codewire_revoke_access_token_streams(); \
             DROP FUNCTION codewire_revoke_api_key_streams(); \
             DROP FUNCTION codewire_revoke_oauth_grant(text, text); \
             DROP FUNCTION codewire_record_credential_revocation(text, text, text); \
             DROP TABLE credential_revocations;",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
