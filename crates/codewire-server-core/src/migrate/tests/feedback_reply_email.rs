//! An anonymous sender's reply address (0040, #5466): the upgrade keeps every
//! feedback row without an address; only an anonymous row holds one, and only
//! a bounded, printable one; the rollback (drop the column) restores the
//! earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to and including `version`, so this test keeps proving
/// 0040 from the shape before it after later migrations land.
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

/// Inserts one piece of feedback from `user` with `reply_email`; the error
/// names the refusing constraint.
async fn insert(
    pool: &PgPool,
    user: Option<&str>,
    reply_email: Option<&str>,
) -> Result<(), Option<String>> {
    sqlx::query(
        "INSERT INTO feedback (user_id, message, cli_version, os, arch, reply_email) \
         VALUES ($1, 'm', '1', 'linux', 'x86_64', $2)",
    )
    .bind(user)
    .bind(reply_email)
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
async fn feedback_reply_email_is_anonymous_bounded_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(39).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO feedback (id, user_id, message, cli_version, os, arch) VALUES \
             ('reply-a', 'credential-user-a', 'a', '1', 'linux', 'x86_64'), \
             ('reply-b', NULL, 'b', '1', 'linux', 'x86_64');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(40).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? != previous,
            "0040 changes the schema"
        );
        let addresses: i64 =
            sqlx::query_scalar("SELECT count(*) FROM feedback WHERE reply_email IS NOT NULL")
                .fetch_one(&pool)
                .await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM feedback")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            rows == 2 && addresses == 0,
            "the upgrade keeps every row and gives none an address"
        );

        insert(&pool, None, Some("walker@example.test"))
            .await
            .map_err(|c| anyhow::anyhow!("anonymous with an address: {c:?}"))?;
        insert(&pool, Some("credential-user-a"), None)
            .await
            .map_err(|c| anyhow::anyhow!("signed in without one: {c:?}"))?;
        let refusals = [
            (
                Some("credential-user-a"),
                "walker@example.test".to_owned(),
                "feedback_reply_email_anonymous_check",
                "a signed-in row holds no reply address",
            ),
            (
                None,
                "a@b".repeat(100),
                "feedback_reply_email_check",
                "the address is at most 254 characters",
            ),
            (
                None,
                "walker@example.test\r\nBcc: eve@example.test".to_owned(),
                "feedback_reply_email_check",
                "the address is printable ASCII without spaces",
            ),
            (
                None,
                String::new(),
                "feedback_reply_email_check",
                "an address is never empty",
            ),
        ];
        for (user, address, constraint, why) in refusals {
            anyhow::ensure!(
                insert(&pool, user, Some(&address)).await == Err(Some(constraint.to_owned())),
                "{why}"
            );
        }

        // Rollback: dropping the column restores the earlier shape.
        sqlx::query("ALTER TABLE feedback DROP COLUMN reply_email")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
