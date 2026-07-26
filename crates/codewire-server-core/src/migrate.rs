//! Standard SQLx migration entrypoint shared by the Rust services.

use anyhow::Context;
use sqlx::migrate::Migrator;
use sqlx::{Connection, PgConnection};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Return the single embedded application-schema migration history.
///
/// Services that must validate the accepted SQLx ledger use this accessor
/// instead of embedding a second migration path.
pub fn application_migrator() -> &'static Migrator {
    &MIGRATOR
}

/// Apply the immutable application migration history.
///
/// SQLx owns the migration table, advisory lock, ordering, checksums, dirty
/// state, and transaction boundaries. Keep this function as a thin entrypoint;
/// schema inference and migration-ledger repair do not belong in services.
pub async fn ensure_schema(database_url: &str) -> anyhow::Result<()> {
    let mut connection = PgConnection::connect(database_url)
        .await
        .context("connect for SQLx database migrations")?;
    application_migrator()
        .run(&mut connection)
        .await
        .context("run SQLx database migrations")?;
    connection
        .close()
        .await
        .context("close SQLx migration connection")?;
    Ok(())
}

/// Apply migrations and expose a clear startup boundary in service logs.
pub async fn ensure_schema_logged(database_url: &str) -> anyhow::Result<()> {
    tracing::info!("ensuring database schema");
    ensure_schema(database_url).await?;
    tracing::info!("database schema ready");
    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::{PgPool, postgres::PgPoolOptions};

    use super::*;

    const ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT: &str =
        "19a356668dea83f08fd2e476d7ba3113860ab47ff0a559afea375417d0beb197";

    async fn startup(database_url: String) -> anyhow::Result<()> {
        ensure_schema(&database_url).await
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_applies_history_and_second_run_is_noop() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let first = applied_migrations(&pool).await?;
            let embedded: Vec<_> = MIGRATOR
                .iter()
                .map(|migration| {
                    (
                        migration.version,
                        migration.description.to_string(),
                        true,
                        migration.checksum.to_vec(),
                    )
                })
                .collect();
            anyhow::ensure!(
                first == embedded,
                "SQLx ledger does not match embedded history"
            );

            let fingerprint: String = sqlx::query_scalar(include_str!(
                "../tests/data/application_schema_fingerprint.sql"
            ))
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
                "application schema fingerprint changed: {fingerprint}"
            );
            pool.close().await;

            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let second = applied_migrations(&pool).await?;
            anyhow::ensure!(
                second == first,
                "second SQLx run changed the migration ledger"
            );
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_serializes_concurrent_startups() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            let (first, second, third, fourth) = tokio::join!(
                startup(test_db.url.clone()),
                startup(test_db.url.clone()),
                startup(test_db.url.clone()),
                startup(test_db.url.clone()),
            );
            first?;
            second?;
            third?;
            fourth?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let applied = applied_migrations(&pool).await?;
            anyhow::ensure!(applied.len() == MIGRATOR.iter().count());
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_rejects_checksum_drift() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let version = MIGRATOR
                .iter()
                .next()
                .context("embedded migration history is empty")?
                .version;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = $1",
            )
            .bind(version)
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("modified migration checksum must fail closed");
            anyhow::ensure!(
                format!("{error:#}").contains("previously applied but has been modified")
            );
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_rejects_dirty_ledger() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let future = embedded_max_version()? + 1;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                r#"
                INSERT INTO _sqlx_migrations
                    (version, description, success, checksum, execution_time)
                VALUES ($1, 'dirty migration', false, decode('00', 'hex'), 0)
                "#,
            )
            .bind(future)
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("dirty migration ledger must fail closed");
            anyhow::ensure!(format!("{error:#}").contains("partially applied"));
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_rejects_missing_history() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let unknown = embedded_max_version()? + 1;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                r#"
                INSERT INTO _sqlx_migrations
                    (version, description, success, checksum, execution_time)
                VALUES ($1, 'unknown applied migration', true, decode('00', 'hex'), 0)
                "#,
            )
            .bind(unknown)
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("applied migration absent from source must fail closed");
            anyhow::ensure!(format!("{error:#}").contains("previously applied but is missing"));
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    async fn applied_migrations(
        pool: &PgPool,
    ) -> anyhow::Result<Vec<(i64, String, bool, Vec<u8>)>> {
        Ok(sqlx::query_as(
            r#"
            SELECT version, description, success, checksum
            FROM _sqlx_migrations
            ORDER BY version
            "#,
        )
        .fetch_all(pool)
        .await?)
    }

    fn embedded_max_version() -> anyhow::Result<i64> {
        MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .context("embedded migration history is empty")
    }

    struct TestDatabase {
        admin_url: String,
        name: String,
        url: String,
    }

    impl TestDatabase {
        async fn create(admin_url: &str) -> anyhow::Result<Self> {
            static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let name = format!("cw_sqlx_migration_{}_{sequence}_{now}", std::process::id());
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(admin_url)
                .await?;
            sqlx::query(&format!("CREATE DATABASE {}", quote_ident(&name)))
                .execute(&admin)
                .await?;
            admin.close().await;

            let mut url = url::Url::parse(admin_url)?;
            url.set_path(&name);
            Ok(Self {
                admin_url: admin_url.to_string(),
                name,
                url: url.to_string(),
            })
        }

        async fn drop(self) -> anyhow::Result<()> {
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.admin_url)
                .await?;
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                quote_ident(&self.name)
            ))
            .execute(&admin)
            .await?;
            admin.close().await;
            Ok(())
        }
    }

    fn quote_ident(identifier: &str) -> String {
        format!(r#""{}""#, identifier.replace('"', r#""""#))
    }
}
