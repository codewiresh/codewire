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
    use std::borrow::Cow;

    use sqlx::{PgPool, postgres::PgPoolOptions};

    use super::*;

    const ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT: &str =
        "7efec7387c7f419ac77ada50f0658202f60dbe50040d3d9f8aab231eb9ac7093";
    const RETIRE_MESH_OIDC_CLIENT_VERSION: i64 = 5;

    async fn startup(database_url: String) -> anyhow::Result<()> {
        ensure_schema(&database_url).await
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn standard_migrator_applies_history_retires_mesh_oidc_client_and_second_run_is_noop()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, RETIRE_MESH_OIDC_CLIENT_VERSION).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            seed_retired_mesh_oidc_client(&pool).await?;
            pool.close().await;

            ensure_schema(&test_db.url).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            anyhow::ensure!(
                oidc_client_row_counts(&pool, "codewire-mesh").await? == (0, 0, 0, 0, 0),
                "retired Mesh OIDC client or dependent rows remain"
            );
            anyhow::ensure!(
                oidc_client_row_counts(&pool, "retained-client").await? == (1, 1, 0, 0, 0),
                "primary OIDC migration changed an unrelated client or token"
            );

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
            assert_tenant_secret_envelope_schema(&pool).await?;
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

    async fn assert_tenant_secret_envelope_schema(pool: &PgPool) -> anyhow::Result<()> {
        let authority: (String, i64) = sqlx::query_as(
            "SELECT state, generation FROM tenant_secret_control WHERE singleton = true",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(authority == ("infisical".into(), 0));

        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek, wrapped_nonce) \
             VALUES ('dek-org-1', 'org', 'org_1', 'keyring', 'tenant-dek', 1, \
                     repeat('A', 64), decode(repeat('00', 12), 'hex'))",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce) \
             VALUES ('/projects/org_1/project_1', 'API_TOKEN', 'dek-org-1', 'org', 'org_1', \
                     decode(repeat('11', 16), 'hex'), decode(repeat('22', 12), 'hex'))",
        )
        .execute(pool)
        .await?;

        let crossed_scope = sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce) \
             VALUES ('/users/user_1', 'API_TOKEN', 'dek-org-1', 'org', 'org_1', \
                     decode(repeat('11', 16), 'hex'), decode(repeat('22', 12), 'hex'))",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(crossed_scope.is_err(), "cross-scope path was accepted");

        let mismatched_version = sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-user-2', 'user', 'user_2', 'openbao-transit', 'tenant-dek', 2, \
                     'vault:v3:generated')",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            mismatched_version.is_err(),
            "mismatched OpenBao key version was accepted"
        );

        let premature_dek_delete =
            sqlx::query("DELETE FROM tenant_secret_deks WHERE dek_id = 'dek-org-1'")
                .execute(pool)
                .await;
        anyhow::ensure!(
            premature_dek_delete.is_err(),
            "DEK deletion with live tenant secrets was accepted"
        );

        sqlx::query(
            "INSERT INTO tenant_secret_kek_canary \
             (provider, key_name, key_version, wrapped_dek, wrapped_nonce, plaintext_sha256) \
             VALUES ('keyring', 'tenant-dek', 1, repeat('A', 64), \
                     decode(repeat('33', 12), 'hex'), decode(repeat('44', 32), 'hex'))",
        )
        .execute(pool)
        .await?;
        let authority_free_transit_canary = sqlx::query(
            "UPDATE tenant_secret_kek_canary \
             SET provider = 'openbao-transit', wrapped_dek = 'vault:v1:generated', \
                 wrapped_nonce = NULL \
             WHERE singleton = true",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            authority_free_transit_canary.is_err(),
            "OpenBao canary without an expected authority was accepted"
        );

        let unfenced_transition = sqlx::query(
            "UPDATE tenant_secret_control SET state = 'importing' WHERE singleton = true",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            unfenced_transition.is_err(),
            "import transition without source evidence was accepted"
        );
        sqlx::query(
            "UPDATE tenant_secret_control \
             SET state = 'postgres-readonly', generation = 1, source_revision = 'test-revision', \
                 transition_started_at = now() \
             WHERE singleton = true",
        )
        .execute(pool)
        .await?;
        let unverified_cutover = sqlx::query(
            "UPDATE tenant_secret_control SET state = 'postgres' WHERE singleton = true",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            unverified_cutover.is_err(),
            "unverified Postgres cutover was accepted"
        );

        sqlx::query("DELETE FROM tenant_secrets WHERE dek_id = 'dek-org-1'")
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM tenant_secret_deks WHERE dek_id = 'dek-org-1'")
            .execute(pool)
            .await?;
        Ok(())
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

    async fn apply_migrations_before(database_url: &str, version: i64) -> anyhow::Result<()> {
        anyhow::ensure!(
            MIGRATOR.version_exists(version),
            "embedded migration {version} is missing"
        );
        // Construct the exact SQLx ledger state immediately before the
        // migration under test, then let the normal application migrator
        // apply it with its ordinary checksum and locking behavior.
        let prior = Migrator {
            migrations: Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < version)
                    .cloned()
                    .collect(),
            ),
            ..Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(database_url).await?;
        prior.run_direct(&mut connection).await?;
        connection.close().await?;
        Ok(())
    }

    async fn seed_retired_mesh_oidc_client(pool: &PgPool) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO oidc_clients (id, name, redirect_uris)
            VALUES
                ('codewire-mesh', 'Retired Mesh', ARRAY['https://mesh.invalid/callback']),
                ('retained-client', 'Retained client', ARRAY['https://retained.invalid/callback'])
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO users (id, email)
            VALUES
                ('mesh-user', 'mesh-user@example.invalid'),
                ('retained-user', 'retained-user@example.invalid')
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scopes, expires_at)
            VALUES
                ('retired-mesh-access-token', 'codewire-mesh', 'mesh-user', ARRAY['openid'], NOW() + INTERVAL '1 hour'),
                ('retained-access-token', 'retained-client', 'retained-user', ARRAY['openid'], NOW() + INTERVAL '1 hour')
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO oidc_auth_requests (id, client_id, scopes, redirect_uri, expires_at)
            VALUES ('retired-mesh-request', 'codewire-mesh', ARRAY['openid'], 'https://mesh.invalid/callback', NOW() + INTERVAL '1 hour')
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO oidc_refresh_tokens (id, token_hash, client_id, user_id, scopes, auth_time, expires_at)
            VALUES ('retired-mesh-refresh', 'retired-mesh-refresh-token', 'codewire-mesh', 'mesh-user', ARRAY['openid'], NOW(), NOW() + INTERVAL '1 hour')
            "#,
        )
        .execute(pool)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO oidc_device_authorizations (device_code, user_code, client_id, scopes, expires_at)
            VALUES ('retired-mesh-device', 'RETIRED-MESH', 'codewire-mesh', ARRAY['openid'], NOW() + INTERVAL '1 hour')
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn oidc_client_row_counts(
        pool: &PgPool,
        client_id: &str,
    ) -> anyhow::Result<(i64, i64, i64, i64, i64)> {
        Ok((
            sqlx::query_scalar("SELECT COUNT(*) FROM oidc_clients WHERE id = $1")
                .bind(client_id)
                .fetch_one(pool)
                .await?,
            sqlx::query_scalar("SELECT COUNT(*) FROM oidc_access_tokens WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(pool)
                .await?,
            sqlx::query_scalar("SELECT COUNT(*) FROM oidc_auth_requests WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(pool)
                .await?,
            sqlx::query_scalar("SELECT COUNT(*) FROM oidc_refresh_tokens WHERE client_id = $1")
                .bind(client_id)
                .fetch_one(pool)
                .await?,
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM oidc_device_authorizations WHERE client_id = $1",
            )
            .bind(client_id)
            .fetch_one(pool)
            .await?,
        ))
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
