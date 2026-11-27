//! Organization agent chat (0064): an upgrade before 0064 leaves every existing
//! organization with agent chat off, and a new organization starts with agent
//! chat off. Its rollback (drop the column) restores the previous schema.

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
async fn organization_agent_chat_upgrade_leaves_every_organization_disabled() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0064: every migration strictly before 64.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 64)
                    .cloned()
                    .collect(),
            ),
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
        let organizations: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            organizations > 0,
            "the upgrade needs existing organizations"
        );

        // Through 0064 only, so its rollback restores the pre-0064 shape.
        let through_0064 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= 64)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0064.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let enabled: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organizations WHERE agent_chat")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(enabled == 0, "{enabled} organizations enabled agent_chat");
        // A new organization starts disabled, and the column is never null.
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('agent-chat-new-org','New','agent-chat-new-org','credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let new: bool = sqlx::query_scalar(
            "SELECT agent_chat FROM organizations WHERE id='agent-chat-new-org'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!new);
        let null =
            sqlx::query("UPDATE organizations SET agent_chat=NULL WHERE id='agent-chat-new-org'")
                .execute(&pool)
                .await
                .expect_err("agent_chat is never null");
        anyhow::ensure!(
            null.as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23502")
        );

        // Rollback: dropping the column restores the 0061 schema.
        sqlx::raw_sql(
            "DELETE FROM organizations WHERE id='agent-chat-new-org'; \
             ALTER TABLE organizations DROP COLUMN agent_chat;",
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
