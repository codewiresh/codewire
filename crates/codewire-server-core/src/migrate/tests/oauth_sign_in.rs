//! Sign in with GitHub or Google (0016, #4062): an upgrade from 0015 adds the
//! partial unique index on provider identities and the `oauth_states` table,
//! leaves every existing row as it was (credential rows that share an
//! `account_id` stay valid), enforces one owner per provider identity and the
//! shape of each kind of round-trip row, and its rollback (drop both) restores
//! the 0015 shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn constraint(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|error| error.constraint())
        .map(str::to_owned)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn oauth_sign_in_upgrade_keeps_accounts_and_enforces_identities_and_states()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let migrator = |through: i64| sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= through)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        migrator(15).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;

        // Two credential rows share an account_id (an email reused after a
        // rename); the partial index must not reject them.
        sqlx::query(
            "INSERT INTO users (id, email) VALUES \
             ('first', 'first@example.test'), ('second', 'second@example.test')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO accounts (id, user_id, provider_id, account_id, password) VALUES \
             ('a1', 'first', 'credential', 'shared@example.test', 'h1'), \
             ('a2', 'second', 'credential', 'shared@example.test', 'h2')",
        )
        .execute(&pool)
        .await?;
        let accounts_before: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT id, user_id, provider_id, account_id FROM accounts ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        migrator(16).run(&pool).await?;
        let accounts_after: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT id, user_id, provider_id, account_id FROM accounts ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(accounts_after == accounts_before, "no account row changes");
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // One owner per provider identity; the same subject on the other
        // provider is a different identity.
        sqlx::query(
            "INSERT INTO accounts (id, user_id, provider_id, account_id) VALUES \
             ('g1', 'first', 'github', '42'), ('o1', 'second', 'google', '42')",
        )
        .execute(&pool)
        .await?;
        let duplicate = sqlx::query(
            "INSERT INTO accounts (id, user_id, provider_id, account_id) \
             VALUES ('g2', 'second', 'github', '42')",
        )
        .execute(&pool)
        .await
        .expect_err("a GitHub identity has one owner");
        anyhow::ensure!(constraint(&duplicate).as_deref() == Some("accounts_provider_identity_key"));

        let hash = |byte: char| byte.to_string().repeat(64);
        let verifier = "v".repeat(43);
        // Each kind of row in its shape.
        sqlx::query(
            "INSERT INTO oauth_states \
             (id, token_hash, provider, intent, pkce_verifier, nonce, return_to, expires_at) VALUES \
             ('s1', $1, 'github', 'sign_in', $3, NULL, '/device', NOW() + interval '10 minutes'), \
             ('s2', $2, 'google', 'sign_in', $3, 'nonce-nonce-nonce-1', NULL, NOW() + interval '10 minutes')",
        )
        .bind(hash('a'))
        .bind(hash('b'))
        .bind(&verifier)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO oauth_states \
             (id, token_hash, provider, intent, user_id, pkce_verifier, expires_at) VALUES \
             ('s3', $1, 'github', 'link', 'first', $2, NOW() + interval '10 minutes')",
        )
        .bind(hash('c'))
        .bind(&verifier)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO oauth_states \
             (id, token_hash, provider, intent, provider_identity, return_auth_request_id, expires_at) \
             VALUES ('s4', $1, 'google', 'sign_up', '{\"subject\":\"1\",\"email\":\"x@example.test\"}', \
                     'request-1', NOW() + interval '30 minutes')",
        )
        .bind(hash('d'))
        .execute(&pool)
        .await?;
        // A sign-in carries its client's keyed address hash; a link
        // confirmation names its account and identity, lives 30 minutes, and
        // a second one for the same account and provider replaces the first.
        sqlx::query(
            "INSERT INTO oauth_states \
             (id, token_hash, provider, intent, pkce_verifier, client_address_hash, expires_at) \
             VALUES ('s5', $1, 'github', 'sign_in', $2, $3, NOW() + interval '10 minutes')",
        )
        .bind(hash('5'))
        .bind(&verifier)
        .bind(hash('f'))
        .execute(&pool)
        .await?;
        let link_confirm = |id: &'static str, token: String| {
            sqlx::query(
                "INSERT INTO oauth_states \
                 (id, token_hash, provider, intent, user_id, provider_identity, requester_hash, \
                  expires_at) \
                 VALUES ($1, $2, 'github', 'link_confirm', 'second', \
                         '{\"subject\":\"7\",\"email\":\"second@example.test\"}', \
                         repeat('c', 64), NOW() + interval '30 minutes') \
                 ON CONFLICT (user_id, provider) WHERE intent = 'link_confirm' \
                 DO UPDATE SET id = EXCLUDED.id, token_hash = EXCLUDED.token_hash",
            )
            .bind(id)
            .bind(token)
        };
        link_confirm("s6", hash('6')).execute(&pool).await?;
        link_confirm("s7", hash('7')).execute(&pool).await?;
        let confirmations: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, token_hash FROM oauth_states WHERE intent = 'link_confirm'",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            confirmations == [("s7".to_owned(), hash('7'))],
            "{confirmations:?}"
        );

        // Rows outside their shape are refused.
        for (label, sql, expected) in [
            (
                "google sign-in without a nonce",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
                 VALUES ('x1', repeat('e', 64), 'google', 'sign_in', repeat('v', 43), NOW() + interval '1 minute')",
                "oauth_states_intent_shape_check",
            ),
            (
                "sign-up without an identity",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, expires_at) \
                 VALUES ('x2', repeat('e', 64), 'github', 'sign_up', NOW() + interval '1 minute')",
                "oauth_states_intent_shape_check",
            ),
            (
                "link without a user",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
                 VALUES ('x3', repeat('e', 64), 'github', 'link', repeat('v', 43), NOW() + interval '1 minute')",
                "oauth_states_intent_shape_check",
            ),
            (
                "an unknown provider",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
                 VALUES ('x4', repeat('e', 64), 'gitlab', 'sign_in', repeat('v', 43), NOW() + interval '1 minute')",
                "oauth_states_provider_check",
            ),
            (
                "a raw state instead of its hash",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
                 VALUES ('x5', 'raw-state', 'github', 'sign_in', repeat('v', 43), NOW() + interval '1 minute')",
                "oauth_states_token_hash_format_check",
            ),
            (
                "an absolute return target",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, return_to, expires_at) \
                 VALUES ('x6', repeat('e', 64), 'github', 'sign_in', repeat('v', 43), 'https://evil.example/', NOW() + interval '1 minute')",
                "oauth_states_return_to_check",
            ),
            (
                "a lifetime over an hour",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
                 VALUES ('x7', repeat('e', 64), 'github', 'sign_in', repeat('v', 43), NOW() + interval '2 hours')",
                "oauth_states_expiry_check",
            ),
            (
                "a link confirmation without an account",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, provider_identity, requester_hash, expires_at) \
                 VALUES ('x9', repeat('e', 64), 'github', 'link_confirm', '{}', repeat('c', 64), NOW() + interval '1 minute')",
                "oauth_states_intent_shape_check",
            ),
            (
                "a link confirmation over 30 minutes",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, user_id, provider_identity, requester_hash, expires_at) \
                 VALUES ('x10', repeat('e', 64), 'github', 'link_confirm', 'second', '{}', repeat('c', 64), NOW() + interval '31 minutes')",
                "oauth_states_intent_shape_check",
            ),
            (
                "a link confirmation with a PKCE verifier",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, user_id, provider_identity, requester_hash, pkce_verifier, expires_at) \
                 VALUES ('x11', repeat('e', 64), 'github', 'link_confirm', 'second', '{}', repeat('c', 64), repeat('v', 43), NOW() + interval '1 minute')",
                "oauth_states_intent_shape_check",
            ),
            (
                "a link confirmation not bound to a browser",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, user_id, provider_identity, expires_at) \
                 VALUES ('x14', repeat('e', 64), 'github', 'link_confirm', 'second', '{}', NOW() + interval '1 minute')",
                "oauth_states_requester_shape_check",
            ),
            (
                "a requester on a sign-in",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, requester_hash, expires_at) \
                 VALUES ('x15', repeat('e', 64), 'github', 'sign_in', repeat('v', 43), repeat('c', 64), NOW() + interval '1 minute')",
                "oauth_states_requester_shape_check",
            ),
            (
                "a raw requester secret",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, user_id, provider_identity, requester_hash, expires_at) \
                 VALUES ('x16', repeat('e', 64), 'github', 'link_confirm', 'second', '{}', 'raw-secret', NOW() + interval '1 minute')",
                "oauth_states_requester_hash_check",
            ),
            (
                "a raw client address",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, client_address_hash, expires_at) \
                 VALUES ('x12', repeat('e', 64), 'github', 'sign_in', repeat('v', 43), '203.0.113.7', NOW() + interval '1 minute')",
                "oauth_states_client_address_hash_check",
            ),
            (
                "a client address on a pending sign-up",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, provider_identity, client_address_hash, expires_at) \
                 VALUES ('x13', repeat('e', 64), 'github', 'sign_up', '{}', repeat('f', 64), NOW() + interval '1 minute')",
                "oauth_states_intent_shape_check",
            ),
            (
                "a state used twice",
                "INSERT INTO oauth_states (id, token_hash, provider, intent, pkce_verifier, expires_at) \
                 VALUES ('x8', repeat('a', 64), 'github', 'sign_in', repeat('v', 43), NOW() + interval '1 minute')",
                "oauth_states_token_hash_key",
            ),
        ] {
            let error = sqlx::query(sql)
                .execute(&pool)
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("{label} was accepted"))?;
            anyhow::ensure!(
                constraint(&error).as_deref() == Some(expected),
                "{label}: {error}"
            );
        }

        // A user's rows go with the user.
        sqlx::query("DELETE FROM users WHERE id = 'first'")
            .execute(&pool)
            .await?;
        let left: Vec<String> = sqlx::query_scalar("SELECT id FROM oauth_states ORDER BY id")
            .fetch_all(&pool)
            .await?;
        anyhow::ensure!(left == ["s1", "s2", "s4", "s5", "s7"], "{left:?}");

        // Rollback: dropping the table and the index restores the 0015 shape.
        sqlx::query("DROP TABLE oauth_states").execute(&pool).await?;
        sqlx::query("DROP INDEX accounts_provider_identity_key")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
