//! Resend verification purpose (0019, #4322): `verifications` accepts the
//! `resend_verification` purpose, for the single-use token sign-in gives an
//! account that never verified its email. The upgrade keeps every row; the
//! rollback deletes those tokens and restores the 0017 check and shape.

use super::*;

/// The purpose check as 0001_baseline.sql creates it, the shape before 0019.
const BASELINE_CHECK: &str = "ALTER TABLE verifications ADD CONSTRAINT verifications_purpose_check CHECK ((purpose = ANY (ARRAY['email_verification'::text, 'password_reset'::text])))";

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

/// Stores a verification with this purpose; the error names the refusing
/// constraint.
async fn store(pool: &PgPool, id: &str, purpose: &str) -> Result<(), Option<String>> {
    sqlx::query(
        "INSERT INTO verifications (id, identifier, purpose, token_hash, expires_at) \
         VALUES ($1, 'user-or-email', $2, repeat('a', 64), NOW() + interval '10 minutes')",
    )
    .bind(id)
    .bind(purpose)
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
async fn resend_verification_purpose_upgrade_accepts_the_token_and_rolls_back() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(18).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        store(&pool, "link", "email_verification")
            .await
            .map_err(|c| anyhow::anyhow!("email_verification: {c:?}"))?;
        anyhow::ensure!(
            store(&pool, "early", "resend_verification").await
                == Err(Some("verifications_purpose_check".to_owned())),
            "0017 accepts no resend token"
        );
        let previous = fingerprint(&pool).await?;

        let before: Vec<(String, String)> =
            sqlx::query_as("SELECT id, purpose FROM verifications ORDER BY id")
                .fetch_all(&pool)
                .await?;
        through(19).run(&pool).await?;
        let after: Vec<(String, String)> =
            sqlx::query_as("SELECT id, purpose FROM verifications ORDER BY id")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(after == before, "0019 changes no row");
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        store(&pool, "resend", "resend_verification")
            .await
            .map_err(|c| anyhow::anyhow!("resend_verification: {c:?}"))?;
        anyhow::ensure!(
            store(&pool, "other", "magic_link").await
                == Err(Some("verifications_purpose_check".to_owned())),
            "0019 accepts only the one new purpose"
        );

        // Rollback: drop the resend tokens, then the 0017 check restores the
        // 0017 shape.
        sqlx::query("DELETE FROM verifications WHERE purpose = 'resend_verification'")
            .execute(&pool)
            .await?;
        sqlx::query("ALTER TABLE verifications DROP CONSTRAINT verifications_purpose_check")
            .execute(&pool)
            .await?;
        sqlx::query(BASELINE_CHECK).execute(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
