//! Sign-up credit setting (0012, #3381): an upgrade from 0011 adds the setting
//! at 0, which is off, and leaves every other setting as it was; its rollback
//! (delete the row) restores the 0011 shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

async fn settings(pool: &PgPool) -> anyhow::Result<Vec<(String, i32)>> {
    Ok(sqlx::query_as(
        "SELECT setting_key, int_value FROM billing_catalog_settings ORDER BY setting_key",
    )
    .fetch_all(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn signup_credit_setting_upgrade_is_off_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0012, with a setting an admin already changed.
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(11).cloned().collect()),
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
            "UPDATE billing_catalog_settings SET int_value = 21 WHERE setting_key = 'trial_days'",
        )
        .execute(&pool)
        .await?;
        let previous_settings = settings(&pool).await?;
        let previous = fingerprint(&pool).await?;

        let through_0012 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(12).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0012.run(&pool).await?;
        let mut expected = previous_settings.clone();
        expected.push(("signup_credit_cents".to_owned(), 0));
        expected.sort();
        anyhow::ensure!(settings(&pool).await? == expected);
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Rollback: deleting the row restores the 0011 shape.
        sqlx::query(
            "DELETE FROM billing_catalog_settings WHERE setting_key = 'signup_credit_cents'",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(settings(&pool).await? == previous_settings);
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
