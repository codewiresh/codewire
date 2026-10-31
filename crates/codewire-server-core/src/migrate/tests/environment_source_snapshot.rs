//! An environment's source snapshot (0010, #3046): an upgrade from 0009 adds one
//! nullable column and changes nothing else, a row keeps naming a snapshot that
//! has been deleted, and its rollback restores the 0009 schema.

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
async fn environment_source_snapshot_upgrade_and_rollback() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(9).cloned().collect()),
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

        // Through 0010 only, so its rollback restores the 0009 shape; later
        // migrations are checked by the accepted fingerprint.
        let through = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(MIGRATOR.iter().take(10).cloned().collect()),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let nullable: String = sqlx::query_scalar(
            "SELECT is_nullable FROM information_schema.columns
              WHERE table_name = 'environments' AND column_name = 'source_snapshot_id'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(nullable == "YES", "existing rows must stay valid");

        // No key to the snapshot: its row can go while the environment lives.
        let keys: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint
              WHERE conrelid = 'public.environments'::regclass AND contype = 'f'
                AND pg_get_constraintdef(oid) LIKE '%source_snapshot_id%'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(keys == 0);

        sqlx::raw_sql("ALTER TABLE environments DROP COLUMN source_snapshot_id;")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
