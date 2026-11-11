//! CLI sign-in marker (0014, the dashboard's Get started checklist, owner
//! 2026-11-10): an upgrade from 0013 adds `users.cli_signed_in_at`, marks an
//! account that already holds a token issued to a device-grant client at its
//! earliest such token, leaves every other account unmarked and every other
//! row as it was; its rollback (drop the column) restores the 0013 shape.

use super::*;

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

async fn marks(pool: &PgPool) -> anyhow::Result<Vec<(String, Option<i64>)>> {
    Ok(sqlx::query_as(
        "SELECT id, extract(epoch FROM cli_signed_in_at)::bigint FROM users ORDER BY id",
    )
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn cli_sign_in_upgrade_marks_device_grant_holders_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0014.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 14)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;

        // The CLI's device-grant client and a browser-style desktop client.
        sqlx::query(
            "INSERT INTO oidc_clients (id, redirect_uris, grant_types) VALUES \
             ('codewire-cli', ARRAY[]::text[], ARRAY[$1, 'refresh_token']), \
             ('codewire-desktop', ARRAY['http://localhost:9876/callback'], \
              ARRAY['authorization_code', 'refresh_token'])",
        )
        .bind(DEVICE_GRANT)
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO users (id, email) VALUES \
             ('cli-refresh', 'cli-refresh@example.test'), \
             ('cli-access', 'cli-access@example.test'), \
             ('desktop-only', 'desktop-only@example.test'), \
             ('no-tokens', 'no-tokens@example.test')",
        )
        .execute(&pool)
        .await?;
        // cli-refresh: two CLI refresh tokens and a later access token; the
        // earliest of the three marks it. cli-access: only an access token
        // left (its refresh token expired and was removed). desktop-only:
        // tokens, but never from a device-grant client.
        let token = |table: &str, hash: &str, client: &str, user: &str, at: i64| {
            let sql = match table {
                "refresh" => {
                    "INSERT INTO oidc_refresh_tokens \
                     (id, token_hash, client_id, user_id, scopes, auth_time, created_at) \
                     VALUES ($1, $1, $2, $3, ARRAY['openid'], to_timestamp($4), to_timestamp($4))"
                }
                _ => {
                    "INSERT INTO oidc_access_tokens \
                     (token_hash, client_id, user_id, scopes, expires_at, created_at) \
                     VALUES ($1, $2, $3, ARRAY['openid'], to_timestamp($4) + interval '1 hour', \
                             to_timestamp($4))"
                }
            };
            sqlx::query(sql)
                .bind(hash.to_owned())
                .bind(client.to_owned())
                .bind(user.to_owned())
                .bind(at as f64)
        };
        for query in [
            token(
                "refresh",
                "r1",
                "codewire-cli",
                "cli-refresh",
                1_790_000_200,
            ),
            token(
                "refresh",
                "r2",
                "codewire-cli",
                "cli-refresh",
                1_790_000_100,
            ),
            token("access", "a1", "codewire-cli", "cli-refresh", 1_790_000_300),
            token("access", "a2", "codewire-cli", "cli-access", 1_790_000_400),
            token(
                "refresh",
                "r3",
                "codewire-desktop",
                "desktop-only",
                1_790_000_500,
            ),
            token(
                "access",
                "a3",
                "codewire-desktop",
                "desktop-only",
                1_790_000_600,
            ),
        ] {
            query.execute(&pool).await?;
        }
        let users_before: Vec<(String, String)> =
            sqlx::query_as("SELECT id, email FROM users ORDER BY id")
                .fetch_all(&pool)
                .await?;
        let previous = fingerprint(&pool).await?;

        let through_0014 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= 14)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0014.run(&pool).await?;
        anyhow::ensure!(
            marks(&pool).await?
                == [
                    ("cli-access".to_owned(), Some(1_790_000_400)),
                    ("cli-refresh".to_owned(), Some(1_790_000_100)),
                    // 0007's "Deleted user" holds no token.
                    ("deleted-user".to_owned(), None),
                    ("desktop-only".to_owned(), None),
                    ("no-tokens".to_owned(), None),
                ],
            "only device-grant holders are marked, at their earliest token"
        );
        let users_after: Vec<(String, String)> =
            sqlx::query_as("SELECT id, email FROM users ORDER BY id")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(users_after == users_before);
        let tokens: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM oidc_refresh_tokens) \
                  + (SELECT count(*) FROM oidc_access_tokens)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(tokens == 6, "the backfill changes no token");
        let column: (String, String) = sqlx::query_as(
            "SELECT data_type, is_nullable FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'users' \
               AND column_name = 'cli_signed_in_at'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(column == ("timestamp with time zone".to_owned(), "YES".to_owned()));
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Rollback: dropping the column restores the 0013 shape.
        sqlx::query("ALTER TABLE users DROP COLUMN cli_signed_in_at")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
