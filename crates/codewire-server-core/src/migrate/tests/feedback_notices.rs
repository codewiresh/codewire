//! The operator's feedback email outbox (0039, #5466): an upgrade from the
//! shape before it adds an empty table and changes no feedback; a row
//! belongs to one piece of feedback, holds only the statuses and bounds the
//! sender writes, and goes with its feedback and its sender's account; the
//! rollback (drop the table) restores the earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// 0039 from the shape before it after later migrations land.
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

/// Inserts a pending outbox row for `feedback`, then applies `update` (an
/// SQL `SET` list) to it in the same transaction; the error names the
/// refusing constraint, and a refusal leaves no row.
async fn outbox(pool: &PgPool, feedback: &str, update: Option<&str>) -> Result<(), Option<String>> {
    let constraint = |error: sqlx::Error| match error {
        sqlx::Error::Database(error) => error.constraint().map(str::to_owned),
        _ => None,
    };
    let mut tx = pool.begin().await.map_err(|_| None)?;
    sqlx::query("INSERT INTO feedback_notices (feedback_id) VALUES ($1)")
        .bind(feedback)
        .execute(&mut *tx)
        .await
        .map_err(constraint)?;
    if let Some(update) = update {
        sqlx::query(&format!(
            "UPDATE feedback_notices SET {update} WHERE feedback_id = $1"
        ))
        .bind(feedback)
        .execute(&mut *tx)
        .await
        .map_err(constraint)?;
    }
    tx.commit().await.map_err(constraint)
}

/// A new outbox row's state.
#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct Fresh {
    status: String,
    attempts: i32,
    due: bool,
    claimed: bool,
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn feedback_notices_upgrade_constrains_rows_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(38).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO feedback (id, user_id, message, cli_version, os, arch) VALUES \
             ('notice-a', 'credential-user-b', 'a', '1', 'linux', 'x86_64'), \
             ('notice-b', NULL, 'b', '1', 'linux', 'x86_64'), \
             ('notice-c', NULL, 'c', '1', 'linux', 'x86_64');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        let feedback: Vec<String> = sqlx::query_scalar("SELECT id FROM feedback ORDER BY id")
            .fetch_all(&pool)
            .await?;

        through(39).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "0039 changes the schema"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM feedback_notices")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(rows == 0, "the upgrade queues no email");
        let after: Vec<String> = sqlx::query_scalar("SELECT id FROM feedback ORDER BY id")
            .fetch_all(&pool)
            .await?;
        anyhow::ensure!(after == feedback, "0039 changes no feedback");

        // A new row is pending, unclaimed and due at once.
        outbox(&pool, "notice-a", None)
            .await
            .map_err(|c| anyhow::anyhow!("first row: {c:?}"))?;
        let fresh: Fresh = sqlx::query_as(
            "SELECT status, attempts, next_attempt_at <= now() AS due, \
                    claimed_until IS NOT NULL AS claimed \
             FROM feedback_notices WHERE feedback_id = 'notice-a'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            fresh
                == Fresh {
                    status: "pending".into(),
                    attempts: 0,
                    due: true,
                    claimed: false
                }
        );

        let refusals = [
            (
                "notice-a",
                None,
                "feedback_notices_pkey",
                "a piece of feedback has one email",
            ),
            (
                "notice-missing",
                None,
                "feedback_notices_feedback_id_fkey",
                "an email belongs to a piece of feedback",
            ),
            (
                "notice-b",
                Some("status = 'sending'"),
                "feedback_notices_status_check",
                "the status is one the sender writes",
            ),
            (
                "notice-b",
                Some("attempts = -1"),
                "feedback_notices_attempts_check",
                "attempts never go below zero",
            ),
            (
                "notice-b",
                Some("status = 'sent'"),
                "feedback_notices_sent_at_check",
                "a sent email records when",
            ),
            (
                "notice-b",
                Some("sent_at = now()"),
                "feedback_notices_sent_at_check",
                "only a sent email records when",
            ),
            (
                "notice-b",
                Some("status = 'skipped', claimed_until = now()"),
                "feedback_notices_claim_check",
                "only a pending email is claimed",
            ),
        ];
        for (feedback, update, constraint, why) in refusals {
            anyhow::ensure!(
                outbox(&pool, feedback, update).await == Err(Some(constraint.to_owned())),
                "{why}"
            );
        }
        outbox(
            &pool,
            "notice-b",
            Some("status = 'sent', sent_at = now(), attempts = 1"),
        )
        .await
        .map_err(|c| anyhow::anyhow!("sent row: {c:?}"))?;
        outbox(&pool, "notice-c", None)
            .await
            .map_err(|c| anyhow::anyhow!("third row: {c:?}"))?;

        // A row goes with its feedback, and so with its sender's account.
        sqlx::query("DELETE FROM users WHERE id = 'credential-user-b'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM feedback WHERE id = 'notice-c'")
            .execute(&pool)
            .await?;
        let left: Vec<String> = sqlx::query_scalar("SELECT feedback_id FROM feedback_notices")
            .fetch_all(&pool)
            .await?;
        anyhow::ensure!(
            left == ["notice-b"],
            "deleting the account or the feedback deletes its email"
        );

        // Rollback: dropping the table restores the earlier shape.
        sqlx::query("DROP TABLE feedback_notices")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
