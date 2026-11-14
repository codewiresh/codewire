//! Account deletion initiator (0024, #4541): who began a deletion, whether
//! its mail is sent, and the admin who asked. A deletion that was already
//! in progress keeps its meaning (the account itself, mail sent); an
//! admin's names the admin, and the purge never sends mail. The rollback
//! drops the columns and restores the previous shape.

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

/// The refusing constraint's name, or `None` when the statement succeeded.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.constraint().unwrap_or("?").to_owned()),
        Err(error) => Some(error.to_string()),
    }
}

fn operation(id: &str, user: &str, columns: &str, values: &str) -> String {
    format!(
        "INSERT INTO account_deletion_operations (id, user_id, workflow_id, email{columns}) \
         VALUES ('{id}', '{user}', '{id}', '{user}@example.test'{values})"
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn account_deletion_initiator_upgrade_keeps_running_deletions_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(23).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;
        sqlx::query(&operation("account-deletion/running", "running", "", ""))
            .execute(&pool)
            .await?;

        through(24).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let running: (String, bool, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT initiator, notify_email, actor_user_id, actor_email \
             FROM account_deletion_operations WHERE id = 'account-deletion/running'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(running == ("self".into(), true, None, None));

        let initiator_check = Some("account_deletion_operations_initiator_check".to_owned());
        let actor_check = Some("account_deletion_operations_actor_check".to_owned());
        for (user, columns, values, expected) in [
            (
                "unknown",
                ", initiator",
                ", 'support'",
                initiator_check.clone(),
            ),
            (
                "admin-alone",
                ", initiator",
                ", 'admin'",
                actor_check.clone(),
            ),
            (
                "self-with-actor",
                ", actor_user_id, actor_email",
                ", 'admin', 'admin@example.test'",
                actor_check.clone(),
            ),
            (
                "admin-no-email",
                ", initiator, actor_user_id",
                ", 'admin', 'admin'",
                actor_check.clone(),
            ),
            (
                "purge-mailing",
                ", initiator",
                ", 'unverified_purge'",
                actor_check.clone(),
            ),
            (
                "admin",
                ", initiator, notify_email, actor_user_id, actor_email",
                ", 'admin', false, 'admin', 'admin@example.test'",
                None,
            ),
            (
                "purge",
                ", initiator, notify_email",
                ", 'unverified_purge', false",
                None,
            ),
        ] {
            let sql = operation(&format!("account-deletion/{user}"), user, columns, values);
            anyhow::ensure!(refused(&pool, &sql).await == expected, "{user}");
        }

        // Rollback: drop the columns and their constraints.
        sqlx::query(
            "ALTER TABLE account_deletion_operations \
             DROP COLUMN initiator, DROP COLUMN notify_email, \
             DROP COLUMN actor_user_id, DROP COLUMN actor_email",
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
