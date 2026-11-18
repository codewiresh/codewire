//! OIDC `prompt` and `max_age` on authorization requests (#4785): an upgrade
//! from the shape before it adds two empty columns and changes no request;
//! `max_age` is never negative; the rollback restores the earlier schema.

use super::*;

/// The version of the migration this file tests.
const VERSION: i64 = 34;

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

/// Stores a request with `max_age`; the error names the refusing constraint.
async fn request(pool: &PgPool, id: &str, max_age: Option<i64>) -> Result<(), Option<String>> {
    sqlx::query(
        "INSERT INTO oidc_auth_requests \
             (id, client_id, scopes, redirect_uri, response_type, done, expires_at, prompt, max_age) \
         VALUES ($1, 'prompt-client', ARRAY['openid'], 'http://localhost/cb', 'code', false, \
                 now() + interval '10 minutes', 'login', $2)",
    )
    .bind(id)
    .bind(max_age)
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
async fn oidc_auth_request_prompt_max_age_upgrade_keeps_requests_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(VERSION - 1).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO oidc_clients (id, redirect_uris) \
             VALUES ('prompt-client', ARRAY['http://localhost/cb']); \
             INSERT INTO oidc_auth_requests \
                 (id, client_id, scopes, redirect_uri, response_type, done, expires_at) \
             VALUES ('prompt-before', 'prompt-client', ARRAY['openid'], 'http://localhost/cb', \
                     'code', false, now() + interval '10 minutes');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "the migration changes the schema"
        );
        let before: (Option<String>, Option<i64>) = sqlx::query_as(
            "SELECT prompt, max_age FROM oidc_auth_requests WHERE id = 'prompt-before'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            before == (None, None),
            "an earlier request gains neither value"
        );

        request(&pool, "prompt-login", None)
            .await
            .map_err(|constraint| anyhow::anyhow!("a request was refused: {constraint:?}"))?;
        request(&pool, "prompt-max-age", Some(0))
            .await
            .map_err(|constraint| anyhow::anyhow!("a request was refused: {constraint:?}"))?;
        anyhow::ensure!(
            request(&pool, "prompt-negative", Some(-1)).await
                == Err(Some("oidc_auth_requests_max_age_check".into())),
            "max_age is never negative"
        );

        // Rollback: dropping the constraint and the columns restores the earlier shape.
        sqlx::raw_sql(
            "ALTER TABLE oidc_auth_requests \
                 DROP CONSTRAINT oidc_auth_requests_max_age_check, \
                 DROP COLUMN prompt, \
                 DROP COLUMN max_age",
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
