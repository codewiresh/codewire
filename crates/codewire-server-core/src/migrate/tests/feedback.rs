//! CLI feedback (0013, #4061): an upgrade from 0012 keeps every existing row
//! and adds the feedback table; its constraints refuse what the service
//! never stores; deleting an account deletes its feedback while deleting an
//! organization only forgets it; and the rollback (drop the table) restores
//! the 0012 shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Inserts one row from its column list and values; the error is the
/// constraint's refusal.
async fn insert(pool: &PgPool, columns: &str, values: &str) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "INSERT INTO feedback (message, cli_version, os, arch{columns}) \
         VALUES ('works', '0.42.0', 'linux', 'x86_64'{values}) RETURNING id"
    ))
    .fetch_one(pool)
    .await
}

fn constraint(result: Result<String, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_owned),
        _ => None,
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn feedback_upgrade_keeps_existing_rows_constrains_new_ones_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0013, with an account and an organization.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(12).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query(
            "INSERT INTO users (id, email) VALUES \
             ('feedback-sender', 'sender@example.test'), \
             ('feedback-owner', 'owner@example.test')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('feedback-org', 'Feedback', 'feedback-org', 'feedback-owner')",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        let through_0013 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(13).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0013.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let kept: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM users WHERE id LIKE 'feedback-%') \
                  + (SELECT count(*) FROM organizations WHERE id = 'feedback-org')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(kept == 3, "existing rows are kept: {kept}");

        // What the service stores fits.
        let anonymous = insert(&pool, ", client_address_hash", &format!(", '{HASH}'")).await?;
        let signed_in = insert(
            &pool,
            ", user_id, organization_id, placement, environment_id",
            ", 'feedback-sender', 'feedback-org', 'local', 'env-1'",
        )
        .await?;
        let at_limit = format!(", '{}'", "x".repeat(10240));
        sqlx::query_scalar::<_, String>(&format!(
            "INSERT INTO feedback (message, cli_version, os, arch) \
             VALUES ({}, '1', 'linux', 'x86_64') RETURNING id",
            &at_limit[2..]
        ))
        .fetch_one(&pool)
        .await?;

        // What it never stores is refused, naming the constraint.
        for (columns, values, expected) in [
            ("", "".to_owned(), None),
            (
                ", organization_id",
                ", 'feedback-org'".to_owned(),
                Some("feedback_organization_needs_user_check"),
            ),
            (
                ", placement",
                ", 'mars'".to_owned(),
                Some("feedback_placement_check"),
            ),
            (
                ", environment_id",
                ", '-x'".to_owned(),
                Some("feedback_environment_id_check"),
            ),
            (
                ", client_address_hash",
                ", '203.0.113.9'".to_owned(),
                Some("feedback_client_address_hash_check"),
            ),
            (
                ", user_id",
                ", 'no-such-user'".to_owned(),
                Some("feedback_user_id_fkey"),
            ),
        ] {
            let refused = constraint(insert(&pool, columns, &values).await);
            anyhow::ensure!(refused.as_deref() == expected, "{columns}: {refused:?}");
        }
        for message in ["''", "E' \\n\\t '", &format!("'{}'", "x".repeat(10241))] {
            let refused = sqlx::query(&format!(
                "INSERT INTO feedback (message, cli_version, os, arch) \
                 VALUES ({message}, '1', 'linux', 'x86_64')"
            ))
            .execute(&pool)
            .await;
            anyhow::ensure!(
                matches!(&refused, Err(sqlx::Error::Database(error))
                    if error.constraint() == Some("feedback_message_check")),
                "message {} bytes was not refused",
                message.len()
            );
        }

        // Deleting the organization keeps the feedback without it; deleting
        // the account deletes the account's feedback.
        sqlx::query("DELETE FROM organizations WHERE id = 'feedback-org'")
            .execute(&pool)
            .await?;
        let organization: Option<String> =
            sqlx::query_scalar("SELECT organization_id FROM feedback WHERE id = $1")
                .bind(&signed_in)
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(organization.is_none());
        sqlx::query("DELETE FROM users WHERE id = 'feedback-sender'")
            .execute(&pool)
            .await?;
        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT id FROM feedback WHERE id = ANY($1) ORDER BY id")
                .bind(vec![anonymous.clone(), signed_in])
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(remaining == [anonymous]);

        // Rollback: dropping the table restores the 0012 shape.
        sqlx::query("DROP TABLE feedback").execute(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
