//! Environment error code (0011, #3635): an upgrade from 0010 leaves every
//! existing environment without a code, and its rollback (drop the column)
//! restores the 0010 schema.

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
async fn environment_error_code_upgrade_is_null_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0011.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(10).cloned().collect()),
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
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('error-code-org','Org','error-code-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('error-code-preset','error-code-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec,error_reason) \
             VALUES ('error-code-env','error-code-org','credential-user-a','error-code-preset', \
             'sandbox','error','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,'old reason');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);

        // Through 0011 only, so its rollback restores the 0010 shape; later
        // migrations prove their own upgrade and rollback.
        let through_0011 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(11).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0011.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        // An existing error keeps its reason and gains no code.
        let (code, reason): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT error_code, error_reason FROM environments WHERE id='error-code-env'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(code.is_none() && reason.as_deref() == Some("old reason"));

        // Rollback: dropping the column restores the 0010 schema.
        sqlx::raw_sql("ALTER TABLE environments DROP COLUMN error_code;")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
