//! Invite-only sign-up (0023, #4121): `users.email_vouched_by` records who
//! vouched for an address on a server with no mail, never together with a
//! verified address. The upgrade keeps every row; the rollback restores the
//! 0022 shape.

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

/// Runs a statement; the error names the refusing constraint.
async fn run(pool: &PgPool, statement: &str) -> Result<(), Option<String>> {
    sqlx::query(statement)
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
async fn invite_only_sign_up_upgrade_keeps_vouching_apart_from_verification_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(22).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        for (id, verified) in [("verified", true), ("unverified", false)] {
            sqlx::query("INSERT INTO users (id, email, email_verified) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(format!("{id}@example.test"))
                .bind(verified)
                .execute(&pool)
                .await?;
        }
        let previous = fingerprint(&pool).await?;
        let before: Vec<(String, Option<bool>)> =
            sqlx::query_as("SELECT id, email_verified FROM users ORDER BY id")
                .fetch_all(&pool)
                .await?;

        through(23).run(&pool).await?;
        let after: Vec<(String, Option<bool>, Option<String>)> =
            sqlx::query_as("SELECT id, email_verified, email_vouched_by FROM users ORDER BY id")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(
            after
                .iter()
                .map(|(id, verified, _)| (id.clone(), *verified))
                .eq(before),
            "0023 changes no row"
        );
        anyhow::ensure!(after.iter().all(|(_, _, vouched)| vouched.is_none()));
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Each vouch is recorded on an unverified address only.
        for vouch in ["invitation", "bootstrap", "admin"] {
            run(
                &pool,
                &format!("UPDATE users SET email_vouched_by = '{vouch}' WHERE id = 'unverified'"),
            )
            .await
            .map_err(|c| anyhow::anyhow!("{vouch}: {c:?}"))?;
        }
        anyhow::ensure!(
            run(
                &pool,
                "UPDATE users SET email_vouched_by = 'mailbox' WHERE id = 'unverified'"
            )
            .await
                == Err(Some("users_email_vouched_by_check".to_owned())),
            "only the three vouches"
        );
        anyhow::ensure!(
            run(
                &pool,
                "UPDATE users SET email_vouched_by = 'admin' WHERE id = 'verified'"
            )
            .await
                == Err(Some("users_email_vouched_not_verified".to_owned())),
            "a verified address is not vouched"
        );
        // A mailbox verification as code before 0023 writes it fails on a
        // vouched account instead of verifying it.
        anyhow::ensure!(
            run(
                &pool,
                "UPDATE users SET email_verified = true WHERE id = 'unverified'"
            )
            .await
                == Err(Some("users_email_vouched_not_verified".to_owned())),
            "a vouched address is not verified by an old writer"
        );

        // Rollback: drop the checks and the column.
        for statement in [
            "ALTER TABLE users DROP CONSTRAINT users_email_vouched_not_verified",
            "ALTER TABLE users DROP CONSTRAINT users_email_vouched_by_check",
            "ALTER TABLE users DROP COLUMN email_vouched_by",
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
