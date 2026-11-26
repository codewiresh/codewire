//! User tokens (0058, #5688): an upgrade adds an empty table and
//! changes no token; a row holds only a digest; deleting a live one records
//! a `user_token` revocation by its id, and removing an expired one doesn't;
//! disabling the account deletes its tokens and refuses new ones; rows go
//! with their user; the rollback restores the earlier schema.

use super::*;

/// This migration's number. The tests run every migration below it first,
/// so renumbering it changes only this line.
const VERSION: i64 = 58;

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

/// Stores a user token; the error names the refusing constraint.
async fn store(pool: &PgPool, id: &str, digest: &str, expires: &str) -> Result<(), Option<String>> {
    sqlx::query(&format!(
        "INSERT INTO oidc_user_tokens \
             (id, token_hash, client_id, user_id, sign_in_id, scopes, expires_at) \
         VALUES ($1, $2, 'user-token-client', 'credential-user-a', 'sign-in-one', \
                 ARRAY['codewire.api'], {expires})"
    ))
    .bind(id)
    .bind(digest)
    .execute(pool)
    .await
    .map(drop)
    .map_err(|error| match error {
        sqlx::Error::Database(error) => error.constraint().map(str::to_owned),
        _ => None,
    })
}

/// The baseline's `codewire_revoke_user_capabilities`, which the rollback
/// puts back, read from the baseline itself.
fn baseline_revoke_user_capabilities() -> String {
    let baseline = include_str!("../../../migrations/0001_baseline.sql");
    let start = baseline
        .find("CREATE FUNCTION public.codewire_revoke_user_capabilities()")
        .expect("the baseline defines the function");
    let body = &baseline[start..];
    let end = body.find("$$;").expect("the function ends") + "$$;".len();
    body[..end].replacen("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
}

/// A 64-hex digest of one repeated character.
fn digest(c: char) -> String {
    c.to_string().repeat(64)
}

/// Disabling the account deletes its user tokens, and none can be stored
/// while it is disabled.
async fn disabling_deletes_and_refuses(pool: &PgPool) -> anyhow::Result<()> {
    // Disabling the account deletes its user tokens, and none can be
    // stored while it is disabled.
    store(pool, "disabled", &digest('e'), "NULL")
        .await
        .map_err(|constraint| anyhow::anyhow!("a token was refused: {constraint:?}"))?;
    sqlx::query("UPDATE users SET enabled = false WHERE id = 'credential-user-a'")
        .execute(pool)
        .await?;
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_user_tokens")
        .fetch_one(pool)
        .await?;
    anyhow::ensure!(kept == 0, "a disable deletes the account's user tokens");
    anyhow::ensure!(
        store(pool, "while-disabled", &digest('f'), "NULL")
            .await
            .is_err(),
        "no user token is stored for a disabled account"
    );
    sqlx::query("UPDATE users SET enabled = true WHERE id = 'credential-user-a'")
        .execute(pool)
        .await?;
    Ok(())
}

/// The rollback, in the order the migration states: the baseline's disable
/// function first, then the table. Audit rows stay; they are data.
async fn roll_back(pool: &PgPool) -> anyhow::Result<()> {
    // Rollback, in the order the migration states: the baseline's disable
    // function first, then the table.
    sqlx::raw_sql(&baseline_revoke_user_capabilities())
        .execute(pool)
        .await?;
    sqlx::raw_sql(
        "DROP TRIGGER oidc_user_tokens_revoke_streams_on_delete ON oidc_user_tokens; \
         DROP TRIGGER codewire_require_enabled_oidc_user_token ON oidc_user_tokens; \
         DROP FUNCTION codewire_revoke_user_token_streams(); \
         DROP TABLE oidc_user_tokens; \
         DELETE FROM credential_revocations WHERE kind = 'user_token'; \
         ALTER TABLE credential_revocations \
             DROP CONSTRAINT credential_revocations_kind_check, \
             ADD CONSTRAINT credential_revocations_kind_check \
                 CHECK (kind IN ('user', 'session', 'oauth_token', 'oauth_grant', 'api_key', \
                                 'membership', 'organization'));",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn revoked(pool: &PgPool, id: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM credential_revocations \
         WHERE kind = 'user_token' AND credential_id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn oidc_user_tokens_upgrade_revokes_and_rolls_back() -> anyhow::Result<()> {
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
             VALUES ('user-token-client', ARRAY['http://localhost/a']); \
             INSERT INTO oidc_access_tokens \
                 (token_hash, client_id, user_id, scopes, expires_at, sign_in_id) \
             VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
                 'user-token-client', 'credential-user-a', ARRAY['codewire.api'], \
                 now() + interval '1 hour', 'sign-in-one');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        let access: Vec<String> =
            sqlx::query_scalar("SELECT token_hash FROM oidc_access_tokens ORDER BY 1")
                .fetch_all(&pool)
                .await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "the migration changes the schema"
        );
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_user_tokens")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(stored == 0, "the upgrade stores no user token");
        let after: Vec<String> =
            sqlx::query_scalar("SELECT token_hash FROM oidc_access_tokens ORDER BY 1")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(after == access, "the upgrade changes no access token");

        // A row holds only a digest, once; one with no expiry is allowed.
        store(&pool, "live", &digest('b'), "NULL")
            .await
            .map_err(|constraint| anyhow::anyhow!("a token was refused: {constraint:?}"))?;
        store(
            &pool,
            "expired",
            &digest('c'),
            "now() - interval '1 minute'",
        )
        .await
        .map_err(|constraint| anyhow::anyhow!("a token was refused: {constraint:?}"))?;
        anyhow::ensure!(
            store(&pool, "raw", "not-a-digest", "NULL").await
                == Err(Some("oidc_user_tokens_token_hash_format_check".into())),
            "a row holds only a digest"
        );
        anyhow::ensure!(
            store(&pool, "copy", &digest('b'), "NULL").await
                == Err(Some("oidc_user_tokens_token_hash_key".into())),
            "a digest is stored once"
        );

        // Deleting a live token ends its streams; removing an expired one is
        // not a revocation.
        sqlx::query("DELETE FROM oidc_user_tokens WHERE id IN ('live', 'expired')")
            .execute(&pool)
            .await?;
        anyhow::ensure!(
            revoked(&pool, "live").await? == 1,
            "a live token is revoked"
        );
        anyhow::ensure!(
            revoked(&pool, "expired").await? == 0,
            "an expired one is not"
        );
        let audited: Vec<(Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT user_id, metadata FROM audit_logs WHERE action = 'user_token.revoked'",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            audited.len() == 1
                && audited[0].0.as_deref() == Some("credential-user-a")
                && audited[0].1["user_token_id"] == "live"
                && audited[0].1["sign_in_id"] == "sign-in-one",
            "the live token's revocation is audited by id and sign-in: {audited:?}"
        );

        disabling_deletes_and_refuses(&pool).await?;

        // Rows go with their user.
        store(&pool, "owned", &digest('d'), "NULL")
            .await
            .map_err(|constraint| anyhow::anyhow!("a token was refused: {constraint:?}"))?;
        sqlx::query("DELETE FROM users WHERE id = 'credential-user-a'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_user_tokens")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 0, "deleting the user deletes their tokens");
        let orphaned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs \
             WHERE action = 'user_token.revoked' AND metadata->>'user_token_id' = 'owned' \
             AND user_id IS NULL",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            orphaned == 1,
            "a cascade from the user's delete is audited without them"
        );

        roll_back(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
