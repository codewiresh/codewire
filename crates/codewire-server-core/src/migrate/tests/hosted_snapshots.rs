//! Hosted snapshots (0009, #3046): an upgrade from 0008 adds the table and
//! changes nothing else; it refuses an unknown state, a second name for one
//! creator in an organization, and a failed row without its reason; it holds
//! an organization's deletion back while a snapshot remains; and its rollback
//! restores the 0008 schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn violates(error: sqlx::Error, code: &str) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
        == Some(code)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn hosted_snapshots_upgrade_constraints_and_rollback() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0009: the baseline and 0002 to 0008, with
        // organizations.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(8).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        // Through 0009 only, so its rollback restores the 0008 shape; later
        // migrations prove their own upgrade and rollback.
        let through_0009 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(9).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0009.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM hosted_snapshots")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(existing == 0);

        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('snapshot-org','Snapshots','snapshot-org','credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let insert = |id: &'static str, creator: &'static str, name: &'static str| {
            sqlx::query(
                "INSERT INTO hosted_snapshots(id,org_id,created_by,source_environment_id,name) \
                 VALUES ($1,'snapshot-org',$2,'gone-environment',$3)",
            )
            .bind(id)
            .bind(creator)
            .bind(name)
        };
        // A new row is capturing, and its creator and source need no row of
        // their own: a snapshot outlives both.
        insert("s1", "no-such-user", "one").execute(&pool).await?;
        let state: String = sqlx::query_scalar("SELECT state FROM hosted_snapshots WHERE id='s1'")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(state == "capturing");
        // A creator's name is unique in the organization; another creator may
        // use it.
        let taken = insert("s2", "no-such-user", "one")
            .execute(&pool)
            .await
            .expect_err("a creator's second snapshot of one name");
        anyhow::ensure!(violates(taken, "23505"));
        insert("s3", "another-user", "one").execute(&pool).await?;

        let unknown = sqlx::query("UPDATE hosted_snapshots SET state='lost' WHERE id='s1'")
            .execute(&pool)
            .await
            .expect_err("an unknown state");
        anyhow::ensure!(violates(unknown, "23514"));
        let silent = sqlx::query("UPDATE hosted_snapshots SET state='failed' WHERE id='s1'")
            .execute(&pool)
            .await
            .expect_err("a failure without its reason");
        anyhow::ensure!(violates(silent, "23514"));
        sqlx::query(
            "UPDATE hosted_snapshots SET state='failed', failure_code='clearing_failed' \
             WHERE id='s1'",
        )
        .execute(&pool)
        .await?;
        // A failed row being deleted keeps its reason.
        sqlx::query("UPDATE hosted_snapshots SET state='deleting' WHERE id='s1'")
            .execute(&pool)
            .await?;

        // An organization can't go while a snapshot names it.
        let held = sqlx::query("DELETE FROM organizations WHERE id='snapshot-org'")
            .execute(&pool)
            .await
            .expect_err("an organization with snapshots");
        anyhow::ensure!(violates(held, "23503"));

        // Rollback: with no rows left, dropping the table restores the 0008
        // schema.
        sqlx::raw_sql(
            "DROP TABLE hosted_snapshots; \
             DELETE FROM organizations WHERE id='snapshot-org';",
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
