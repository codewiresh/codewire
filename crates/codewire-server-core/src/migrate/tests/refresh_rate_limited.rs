//! A refresh the provider rate-limited (0037, #4975): a started attempt can
//! be closed as `rate_limited` with the time its wait ends, and an attempt can
//! say it began after such a wait. The upgrade keeps every row; the rollback
//! restores the 0036 shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

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

/// The constraint `statement` broke, if any.
async fn refused_by(pool: &PgPool, statement: &str) -> anyhow::Result<Option<String>> {
    match sqlx::query(statement).execute(pool).await {
        Ok(_) => Ok(None),
        Err(sqlx::Error::Database(error)) => Ok(error.constraint().map(str::to_owned)),
        Err(error) => Err(error.into()),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_started_refresh_can_be_rate_limited_with_its_wait_and_the_shape_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(36).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query("INSERT INTO users (id, email, email_verified) VALUES ('owner', 'owner@example.test', true)")
            .execute(&pool)
            .await?;
        for credential in ["started", "cancelled"] {
            sqlx::query(
                "INSERT INTO platform_credentials (id, user_id, provider, authentication_kind, display_name, \
                 status, revocation_generation, material_generation) \
                 VALUES ($1, 'owner', 'openai', 'oauth', $1, 'active', 1, 1)",
            )
            .bind(credential)
            .execute(&pool)
            .await?;
        }
        sqlx::query(
            "INSERT INTO platform_credential_refresh_attempts (credential_id, attempt_id, \
             expected_revocation_generation, expected_material_generation, state, reserved_until, \
             started_at, started_until) VALUES \
             ('started', gen_random_uuid(), 1, 1, 'started', now(), now(), now() + interval '5 minutes')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO platform_credential_refresh_attempts (credential_id, attempt_id, \
             expected_revocation_generation, expected_material_generation, state, reserved_until) \
             VALUES ('cancelled', gen_random_uuid(), 1, 1, 'cancelled', now())",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(37).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let rows: Vec<(String, String, bool, bool)> = sqlx::query_as(
            "SELECT credential_id, state, rate_limited_until IS NULL, after_rate_limit \
             FROM platform_credential_refresh_attempts ORDER BY credential_id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            rows == [
                ("cancelled".to_owned(), "cancelled".to_owned(), true, false),
                ("started".to_owned(), "started".to_owned(), true, false),
            ],
            "0037 changes no row: {rows:?}"
        );

        // Only a started attempt's state, with its wait, after it started.
        for (statement, constraint) in [
            (
                "UPDATE platform_credential_refresh_attempts SET state = 'rate_limited' WHERE credential_id = 'started'",
                "platform_credential_refresh_attempts_rate_limited_check",
            ),
            (
                "UPDATE platform_credential_refresh_attempts SET rate_limited_until = now() + interval '1 minute' \
                 WHERE credential_id = 'started'",
                "platform_credential_refresh_attempts_rate_limited_check",
            ),
            (
                "UPDATE platform_credential_refresh_attempts SET state = 'rate_limited', \
                 rate_limited_until = started_at - interval '1 second' WHERE credential_id = 'started'",
                "platform_credential_refresh_attempts_rate_limited_check",
            ),
            (
                "UPDATE platform_credential_refresh_attempts SET state = 'rate_limited', \
                 rate_limited_until = now() + interval '1 minute' WHERE credential_id = 'cancelled'",
                "platform_credential_refresh_attempts_started_check",
            ),
        ] {
            anyhow::ensure!(
                refused_by(&pool, statement).await?.as_deref() == Some(constraint),
                "{statement} is refused by {constraint}"
            );
        }
        sqlx::query(
            "UPDATE platform_credential_refresh_attempts SET state = 'rate_limited', \
             rate_limited_until = clock_timestamp() + interval '1 minute' WHERE credential_id = 'started'",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "UPDATE platform_credential_refresh_attempts SET after_rate_limit = true WHERE credential_id = 'cancelled'",
        )
        .execute(&pool)
        .await?;

        // Rollback: forget the rate-limited attempt, restore the two checks,
        // then drop the new constraint and columns.
        for statement in [
            "DELETE FROM platform_credential_refresh_attempts WHERE state = 'rate_limited'",
            "ALTER TABLE platform_credential_refresh_attempts \
             DROP CONSTRAINT platform_credential_refresh_attempts_rate_limited_check, \
             DROP CONSTRAINT platform_credential_refresh_attempts_state_check, \
             ADD CONSTRAINT platform_credential_refresh_attempts_state_check CHECK ((state = ANY (ARRAY[\
             'reserved'::text, 'started'::text, 'staged'::text, 'committed'::text, 'unknown'::text, \
             'cancelled'::text]))), \
             DROP CONSTRAINT platform_credential_refresh_attempts_started_check, \
             ADD CONSTRAINT platform_credential_refresh_attempts_started_check CHECK ((((state = ANY \
             (ARRAY['reserved'::text, 'cancelled'::text])) AND (started_at IS NULL) AND (started_until IS NULL)) \
             OR ((state = ANY (ARRAY['started'::text, 'staged'::text, 'committed'::text, 'unknown'::text])) \
             AND (started_at IS NOT NULL) AND (started_until IS NOT NULL) AND (started_until > started_at)))), \
             DROP COLUMN rate_limited_until, DROP COLUMN after_rate_limit",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
