//! Consumed OIDC refresh tokens (0020): an upgrade from the shape before it
//! adds an empty table and changes no token; a record names a well-formed
//! digest and goes with its user or client; the rollback (drop the table)
//! restores the earlier schema.

use super::*;

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

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Records a consumed token; the error names the refusing constraint.
async fn record(
    pool: &PgPool,
    digest: &str,
    client: &str,
    user: &str,
) -> Result<(), Option<String>> {
    sqlx::query(
        "INSERT INTO oidc_consumed_refresh_tokens (token_hash, client_id, user_id, expires_at) \
         VALUES ($1, $2, $3, now() + interval '1 hour')",
    )
    .bind(digest)
    .bind(client)
    .bind(user)
    .execute(pool)
    .await
    .map(drop)
    .map_err(|error| match error {
        sqlx::Error::Database(error) => error.constraint().map(str::to_owned),
        _ => None,
    })
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn oidc_consumed_refresh_tokens_upgrade_records_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(19).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO oidc_clients (id, redirect_uris) \
             VALUES ('consumed-client-a', ARRAY['http://localhost/a']), \
                    ('consumed-client-b', ARRAY['http://localhost/b']); \
             INSERT INTO oidc_refresh_tokens \
                 (id, token_hash, client_id, user_id, scopes, auth_time, expires_at) \
             VALUES ('consumed-live', \
                 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', \
                 'consumed-client-a', 'credential-user-a', ARRAY['openid'], now(), \
                 now() + interval '1 hour');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        let tokens: Vec<(String, String)> =
            sqlx::query_as("SELECT id, token_hash FROM oidc_refresh_tokens ORDER BY id")
                .fetch_all(&pool)
                .await?;

        through(20).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "0020 changes the schema"
        );
        let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_consumed_refresh_tokens")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(recorded == 0, "the upgrade records no token");
        let after: Vec<(String, String)> =
            sqlx::query_as("SELECT id, token_hash FROM oidc_refresh_tokens ORDER BY id")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(after == tokens, "the upgrade changes no refresh token");

        // A record names a well-formed digest, once.
        record(&pool, DIGEST_A, "consumed-client-a", "credential-user-a")
            .await
            .map_err(|constraint| anyhow::anyhow!("a record was refused: {constraint:?}"))?;
        record(&pool, DIGEST_B, "consumed-client-b", "credential-user-a")
            .await
            .map_err(|constraint| anyhow::anyhow!("a record was refused: {constraint:?}"))?;
        anyhow::ensure!(
            record(
                &pool,
                "not-a-digest",
                "consumed-client-a",
                "credential-user-a"
            )
            .await
                == Err(Some(
                    "oidc_consumed_refresh_tokens_token_hash_format_check".into()
                )),
            "a record holds only a digest"
        );
        anyhow::ensure!(
            record(&pool, DIGEST_A, "consumed-client-a", "credential-user-a").await
                == Err(Some("oidc_consumed_refresh_tokens_pkey".into())),
            "a digest is recorded once"
        );

        // A record goes with its client, and with its user.
        sqlx::query("DELETE FROM oidc_clients WHERE id = 'consumed-client-b'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_consumed_refresh_tokens")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 1, "deleting the client deletes its records");
        sqlx::query("DELETE FROM users WHERE id = 'credential-user-a'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_consumed_refresh_tokens")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 0, "deleting the user deletes their records");

        // Rollback: dropping the table restores the earlier shape.
        sqlx::query("DROP TABLE oidc_consumed_refresh_tokens")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
