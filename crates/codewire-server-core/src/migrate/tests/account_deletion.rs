//! Account deletion (0007, #3679): an upgrade from 0006 adds the disabled
//! "Deleted user" and the operation table, which refuses a second live
//! operation for one user and a completed operation that still holds the
//! user or their address; neither the "Deleted user" nor an account being
//! deleted can be enabled; and its rollback restores the 0006 schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_deletion_upgrade_adds_a_disabled_deleted_user_and_one_operation_per_user()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0007: the baseline and 0002 to 0006.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(6).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        let through_0007 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(7).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0007.run(&pool).await?;
        let deleted: (String, bool) =
            sqlx::query_as("SELECT name, enabled FROM users WHERE id = 'deleted-user'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(deleted == ("Deleted user".into(), false), "{deleted:?}");
        let credentials: i64 =
            sqlx::query_scalar("SELECT count(*) FROM accounts WHERE user_id = 'deleted-user'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(credentials == 0);

        sqlx::query(
            "INSERT INTO users (id, email, name) VALUES ('u-0007', 'u-0007@example.test', 'U')",
        )
        .execute(&pool)
        .await?;
        sqlx::query("UPDATE users SET enabled = false WHERE id = 'u-0007'")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO account_deletion_operations (id, user_id, workflow_id, email) \
             VALUES ('account-deletion/a', 'u-0007', 'account-deletion/a', 'u-0007@example.test')",
        )
        .execute(&pool)
        .await?;

        // Each refusal in its own transaction.
        for (sql, code) in [
            // A second live operation for the same user.
            (
                "INSERT INTO account_deletion_operations (id, user_id, workflow_id) \
                 VALUES ('account-deletion/b', 'u-0007', 'account-deletion/b')",
                "23505",
            ),
            // The user deleted while the operation still names them.
            (
                "UPDATE account_deletion_operations SET phase = 'user_deleted'",
                "23514",
            ),
            // Completed while still holding the address.
            (
                "UPDATE account_deletion_operations SET phase = 'completed', \
                 state = 'completed', completed_at = NOW(), user_id = NULL",
                "23514",
            ),
            (
                "UPDATE account_deletion_operations SET phase = 'gone'",
                "23514",
            ),
            // Re-enabled while being deleted, and the "Deleted user" ever.
            (
                "UPDATE users SET enabled = true WHERE id IN ('u-0007', 'deleted-user')",
                "23514",
            ),
            (
                "UPDATE users SET enabled = true WHERE id = 'deleted-user'",
                "23514",
            ),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .expect_err("invalid operation accepted");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "{sql}: {error}"
            );
            tx.rollback().await?;
        }
        // A completed operation holds neither the user nor the address.
        sqlx::query(
            "UPDATE account_deletion_operations SET phase = 'completed', state = 'completed', \
             completed_at = NOW(), user_id = NULL, email = NULL",
        )
        .execute(&pool)
        .await?;

        // Once the operation no longer names the user, they can be enabled.
        sqlx::query("UPDATE users SET enabled = true WHERE id = 'u-0007'")
            .execute(&pool)
            .await?;

        // Rollback: drop the trigger, its function and the table, and the
        // unreferenced "Deleted user".
        sqlx::raw_sql(
            "DROP TRIGGER users_account_deletion_keeps_disabled ON users; \
             DROP FUNCTION codewire_account_deletion_keeps_disabled(); \
             DROP TABLE account_deletion_operations; \
             DELETE FROM users WHERE id IN ('deleted-user', 'u-0007');",
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
