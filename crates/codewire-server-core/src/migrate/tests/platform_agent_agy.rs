//! Platform managed agent support for Antigravity CLI (`agy`) (0065):
//! widens `environment_platform_agent_conversations_agent_check` to accept
//! `'agy'` while still rejecting unknown agent names, and its rollback
//! restores the previous schema.

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
async fn platform_agent_agy_widens_agent_check_and_rolls_back_cleanly() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 65)
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
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        let through_0065 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= 65)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0065.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        let check_def: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
             WHERE conname = 'environment_platform_agent_conversations_agent_check'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            check_def.contains("'codex'::text")
                && check_def.contains("'claude'::text")
                && check_def.contains("'agy'::text"),
            "unexpected agent check definition: {check_def}"
        );

        // Rollback restores the pre-0065 constraint definition.
        sqlx::raw_sql(
            "ALTER TABLE public.environment_platform_agent_conversations \
                 DROP CONSTRAINT environment_platform_agent_conversations_agent_check, \
                 ADD CONSTRAINT environment_platform_agent_conversations_agent_check \
                     CHECK ((agent = ANY (ARRAY['codex'::text, 'claude'::text])));",
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
