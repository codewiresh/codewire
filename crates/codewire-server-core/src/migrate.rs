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
        "28770e4ec7b79a5f0bb8883f7d7e6b374c6e74cbed731177ebce88e9a17c86ab";
    const RETIRE_MESH_OIDC_CLIENT_VERSION: i64 = 5;
    const ORGANIZATION_ROUTE_SLUGS_VERSION: i64 = 11;
    const OPENBAO_SECRET_AUTHORITY_VERSION: i64 = 12;
    const APPLIED_OPENBAO_SECRET_AUTHORITY_CHECKSUM: &str = "cbd3494fde9235aaf507236bd18440f2d0c87fe6c42f9b1ce3af78f327b044aa968149229acd1bf064b6d4e67c54ed40";
    const OPENBAO_NATIVE_SECRETS_VERSION: i64 = 13;

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
            assert_organization_route_slug_schema(&pool).await?;
            assert_openbao_native_secret_schema(&pool).await?;
            assert_confidential_storage_manifest_schema(&pool).await?;
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
    async fn deployed_openbao_expansion_ledger_advances_to_current_history() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, OPENBAO_NATIVE_SECRETS_VERSION).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let checksum: String = sqlx::query_scalar(
                "SELECT encode(checksum, 'hex') FROM _sqlx_migrations WHERE version = $1",
            )
            .bind(OPENBAO_SECRET_AUTHORITY_VERSION)
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                checksum == APPLIED_OPENBAO_SECRET_AUTHORITY_CHECKSUM,
                "migration 12 no longer matches the deployed SQLx ledger"
            );
            pool.close().await;

            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            anyhow::ensure!(
                applied_migrations(&pool).await?.len() == MIGRATOR.iter().count(),
                "deployed migration 12 ledger did not advance to current history"
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
    async fn openbao_finalization_rejects_retained_plaintext_atomically() -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, OPENBAO_NATIVE_SECRETS_VERSION).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "INSERT INTO local_secrets (path, key, value) \
                 VALUES ('/users/preflight', 'RETAINED', 'must-not-migrate')",
            )
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("retained plaintext rows must reject finalization");
            anyhow::ensure!(
                format!("{error:#}").contains("requires local_secrets=0"),
                "finalization failure was not classified: {error:#}"
            );

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM local_secrets")
                .fetch_one(&pool)
                .await?;
            anyhow::ensure!(
                retained == 1,
                "failed finalization mutated the retained plaintext row"
            );
            let applied: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = $1)",
            )
            .bind(OPENBAO_NATIVE_SECRETS_VERSION)
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(!applied, "failed finalization entered the SQLx ledger");
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn openbao_finalization_preserves_confidential_storage_metadata() -> anyhow::Result<()> {
        const ENVIRONMENT_ID: &str = "be31063a-8ec8-46d5-aa17-75cda1729370";
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, OPENBAO_SECRET_AUTHORITY_VERSION).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "INSERT INTO users (id, email) \
                 VALUES ('openbao-storage-user', 'openbao-storage@example.test')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) \
                 VALUES ('org-openbao-storage', 'OpenBao Storage', \
                         'openbao-storage', 'openbao-storage-user')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO environment_presets (id, org_id, name, slug) \
                 VALUES ('preset-openbao-storage', 'org-openbao-storage', \
                         'OpenBao Storage', 'openbao-storage')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO environments (id, org_id, created_by, type, preset_id) \
                 VALUES ($1, 'org-openbao-storage', 'openbao-storage-user', 'sandbox', \
                         'preset-openbao-storage')",
            )
            .bind(ENVIRONMENT_ID)
            .execute(&pool)
            .await?;
            let kbs_uri = format!("kbs:///default/codewire-workspace-luks/{ENVIRONMENT_ID}");
            let historical_path = format!("/confidential-storage/{ENVIRONMENT_ID}");
            let openbao_path = format!("confidential-storage/{ENVIRONMENT_ID}");
            // Migration 9's table has twelve columns. Seed that exact historical
            // row shape positionally, then let migrations 12 and 13 expand and
            // finalize it through the standard SQLx path.
            sqlx::query(
                "INSERT INTO confidential_storage_keys \
                 VALUES ($1, $2, $3, DEFAULT, NULL, DEFAULT, NULL, \
                         DEFAULT, DEFAULT, NULL, NULL, NULL)",
            )
            .bind(ENVIRONMENT_ID)
            .bind(&kbs_uri)
            .bind(&historical_path)
            .execute(&pool)
            .await?;
            pool.close().await;

            ensure_schema(&test_db.url).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let retained: (String, String) = sqlx::query_as(
                "SELECT kbs_uri, openbao_path FROM confidential_storage_keys \
                 WHERE environment_id = $1",
            )
            .bind(ENVIRONMENT_ID)
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                retained == (kbs_uri, openbao_path),
                "OpenBao confidential-storage identity changed during finalization"
            );
            let authority_path_columns: Vec<String> = sqlx::query_scalar(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'public' \
                   AND table_name = 'confidential_storage_keys' \
                   AND column_name LIKE '%path%' ORDER BY column_name",
            )
            .fetch_all(&pool)
            .await?;
            anyhow::ensure!(
                authority_path_columns == vec!["openbao_path".to_owned()],
                "unexpected confidential-storage authority path columns remain"
            );
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    async fn assert_tenant_secret_envelope_schema(pool: &PgPool) -> anyhow::Result<()> {
        let retired_tables_absent: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.local_secrets') IS NULL \
                    AND to_regclass('public.tenant_secret_control') IS NULL",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(retired_tables_absent, "retired secret stores remain");

        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-org-1', 'org', 'org_1', 'openbao-transit', 'tenant-dek', 1, \
                     'vault:v1:generated')",
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

        let retired_provider = sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-user-keyring', 'user', 'user_keyring', 'keyring', 'tenant-dek', 1, \
                     'vault:v1:generated')",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            retired_provider.is_err(),
            "retired keyring provider was accepted"
        );

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

        let authority_free_transit_canary = sqlx::query(
            "INSERT INTO tenant_secret_kek_canary \
             (provider, key_name, key_version, wrapped_dek, plaintext_sha256) \
             VALUES ('openbao-transit', 'tenant-dek', 1, 'vault:v1:generated', \
                     decode(repeat('44', 32), 'hex'))",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            authority_free_transit_canary.is_err(),
            "OpenBao canary without an expected authority was accepted"
        );
        sqlx::query(
            "INSERT INTO tenant_secret_kek_canary \
             (provider, key_name, key_version, wrapped_dek, expected_authority_id, \
              plaintext_sha256) \
             VALUES ('openbao-transit', 'tenant-dek', 1, 'vault:v1:generated', \
                     'test-openbao', decode(repeat('44', 32), 'hex'))",
        )
        .execute(pool)
        .await?;

        sqlx::query("DELETE FROM tenant_secret_kek_canary")
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM tenant_secrets WHERE dek_id = 'dek-org-1'")
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM tenant_secret_deks WHERE dek_id = 'dek-org-1'")
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn assert_openbao_native_secret_schema(pool: &PgPool) -> anyhow::Result<()> {
        let openbao_column: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'confidential_storage_keys' \
               AND column_name = 'openbao_path' AND data_type = 'text' \
               AND is_nullable = 'NO')",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(openbao_column, "required OpenBao recovery path is absent");

        let retired_nonce_columns: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.columns \
             WHERE table_schema = 'public' \
               AND table_name IN ('tenant_secret_deks', 'tenant_secret_kek_canary') \
               AND column_name = 'wrapped_nonce'",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_nonce_columns == 0,
            "retired keyring nonce columns remain"
        );
        Ok(())
    }

    async fn assert_confidential_storage_manifest_schema(pool: &PgPool) -> anyhow::Result<()> {
        const ENVIRONMENT_ID: &str = "be31063a-8ec8-46d5-aa17-75cda1729370";
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('org-confidential-storage', 'Confidential Storage', \
                     'confidential-storage', 'retained-user')",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, slug) \
             VALUES ('preset-confidential-storage', 'org-confidential-storage', \
                     'Confidential Storage', 'confidential-storage')",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO environments (id, org_id, created_by, type, preset_id) \
             VALUES ($1, 'org-confidential-storage', 'retained-user', 'sandbox', \
                     'preset-confidential-storage')",
        )
        .bind(ENVIRONMENT_ID)
        .execute(pool)
        .await?;

        // OpenBao is the only recovery authority. The manifest-aware source
        // fills the complete storage tuple later.
        sqlx::query(
            "INSERT INTO confidential_storage_keys \
             (environment_id, kbs_uri, openbao_path) \
             VALUES ($1, $2, $3)",
        )
        .bind(ENVIRONMENT_ID)
        .bind(format!(
            "kbs:///default/codewire-workspace-luks/{ENVIRONMENT_ID}"
        ))
        .bind(format!("confidential-storage/{ENVIRONMENT_ID}"))
        .execute(pool)
        .await?;

        let partial_tuple = sqlx::query(
            "UPDATE confidential_storage_keys \
             SET volume_id = $1 WHERE environment_id = $1",
        )
        .bind(ENVIRONMENT_ID)
        .execute(pool)
        .await;
        anyhow::ensure!(
            partial_tuple.is_err(),
            "partial confidential storage manifest tuple was accepted"
        );

        sqlx::query(
            "UPDATE confidential_storage_keys SET \
                 volume_id = $1, volume_version = $2, \
                 manifest_schema_version = 2, device_size_bytes = 21474836480, \
                 luks_uuid = 'f617a73e-b03d-4b58-b1ae-354c72276ea0', \
                 protection_profile = 'luks2-integrity-rw', \
                 backing_claim_name = 'workspace' \
             WHERE environment_id = $1",
        )
        .bind(ENVIRONMENT_ID)
        .bind(format!("{ENVIRONMENT_ID}-v2"))
        .execute(pool)
        .await?;

        let partial_content = sqlx::query(
            "UPDATE confidential_storage_keys \
             SET manifest_sha256_fingerprint = $2 WHERE environment_id = $1",
        )
        .bind(ENVIRONMENT_ID)
        .bind("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        .execute(pool)
        .await;
        anyhow::ensure!(
            partial_content.is_err(),
            "partial confidential storage content binding was accepted"
        );

        const KEY_FINGERPRINT: &str =
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        const MANIFEST_FINGERPRINT: &str =
            "60303ae22b9988617223d5f367ee8e6c13a85f16f27f80a93b868276a58c286d";
        sqlx::query(
            "UPDATE confidential_storage_keys SET \
                 sha256_fingerprint = $2, \
                 manifest_sha256_fingerprint = $3, \
                 manifest_uri = \
                   'kbs:///default/codewire-storage-manifests/sha256-' || $3 \
             WHERE environment_id = $1",
        )
        .bind(ENVIRONMENT_ID)
        .bind(KEY_FINGERPRINT)
        .bind(MANIFEST_FINGERPRINT)
        .execute(pool)
        .await?;

        for (column, statement) in [
            (
                "volume_version",
                "UPDATE confidential_storage_keys SET volume_version = 'mutable-alias' \
                 WHERE environment_id = $1",
            ),
            (
                "protection_profile",
                "UPDATE confidential_storage_keys \
                 SET protection_profile = 'host-selected-profile' WHERE environment_id = $1",
            ),
            (
                "device_size_bytes",
                "UPDATE confidential_storage_keys SET device_size_bytes = 21474836481 \
                 WHERE environment_id = $1",
            ),
            (
                "aligned_device_size_bytes",
                "UPDATE confidential_storage_keys SET device_size_bytes = 42949672960 \
                 WHERE environment_id = $1",
            ),
            (
                "luks_uuid",
                "UPDATE confidential_storage_keys \
                 SET luks_uuid = '00112233-4455-6677-8899-aabbccddeeff' \
                 WHERE environment_id = $1",
            ),
            (
                "manifest_sha256_fingerprint",
                "UPDATE confidential_storage_keys \
                 SET manifest_sha256_fingerprint = 'not-a-sha256' WHERE environment_id = $1",
            ),
            (
                "valid_manifest_sha256_fingerprint",
                "UPDATE confidential_storage_keys \
                 SET manifest_sha256_fingerprint = \
                     'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
                 WHERE environment_id = $1",
            ),
            (
                "key_fingerprint",
                "UPDATE confidential_storage_keys \
                 SET sha256_fingerprint = \
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
                 WHERE environment_id = $1",
            ),
            (
                "manifest_uri",
                "UPDATE confidential_storage_keys \
                 SET manifest_uri = \
                     'kbs:///default/codewire-storage-manifests/sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
                 WHERE environment_id = $1",
            ),
        ] {
            let rejected = sqlx::query(statement)
                .bind(ENVIRONMENT_ID)
                .execute(pool)
                .await;
            anyhow::ensure!(
                rejected.is_err(),
                "invalid confidential storage {column} was accepted"
            );
        }

        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(ENVIRONMENT_ID)
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM environment_presets WHERE id = 'preset-confidential-storage'")
            .execute(pool)
            .await?;
        sqlx::query("DELETE FROM organizations WHERE id = 'org-confidential-storage'")
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn assert_organization_route_slug_schema(pool: &PgPool) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('org-route-safe', 'Route Safe', 'route-safe', 'retained-user')",
        )
        .execute(pool)
        .await?;

        for (id, slug) in [
            ("org-route-reserved", "admin"),
            ("org-route-uppercase", "Route-Unsafe"),
            ("org-route-double-hyphen", "route--unsafe"),
        ] {
            let rejected = sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $2, 'retained-user')",
            )
            .bind(id)
            .bind(slug)
            .execute(pool)
            .await;
            anyhow::ensure!(rejected.is_err(), "organization slug {slug:?} was accepted");
        }

        sqlx::query("DELETE FROM organizations WHERE id = 'org-route-safe'")
            .execute(pool)
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn organization_route_slug_migration_rejects_conflicting_existing_data_atomically()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, ORGANIZATION_ROUTE_SLUGS_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query("INSERT INTO users (id, email) VALUES ('route-user', 'route@example.test')")
                .execute(&pool)
                .await?;
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) \
                 VALUES ('org-route-conflict', 'Conflict', 'admin', 'route-user')",
            )
            .execute(&pool)
            .await?;
            pool.close().await;

            let error = ensure_schema(&test_db.url)
                .await
                .expect_err("reserved existing slug must fail migration preflight");
            anyhow::ensure!(
                format!("{error:#}")
                    .contains("organization slug data conflicts with canonical dashboard routes")
            );

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let slug: String = sqlx::query_scalar(
                "SELECT slug FROM organizations WHERE id = 'org-route-conflict'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(slug == "admin", "conflicting row changed during failed migration");
            let constraint_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_constraint WHERE conname = 'organizations_route_slug_check'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                constraint_count == 0,
                "failed migration left the route-slug constraint behind"
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
