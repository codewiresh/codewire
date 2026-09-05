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
    use std::{borrow::Cow, time::Duration};

    use sha2::{Digest, Sha384};
    use sqlx::{PgPool, postgres::PgPoolOptions};

    use super::*;

    // Replace only after the synthetic database gate computes migration 18's
    // complete schema fingerprint; preparation must not claim accepted proof.
    const ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT: &str =
        "ab823697675ec3b378dddda17d3de6bd7f62c2d6070977409158a9d42f97b10b";
    const ACCEPTED_PRE_PLATFORM_SCHEMA_FINGERPRINT: &str =
        "89054bb58aa891438dc98b13dc89a353480982506e91c43ce1ad5d5047377ce8";
    const APPLIED_BASELINE_CHECKSUM: &str = "3c739196dff29f03ccbe05af6dc45b0be2327bca39dbafaa9d29601ba3873aa99affe0492bfb4f0e3de7579d2e5da8fb";
    // SHA-384 of the concatenated SHA-384 SQL checksums for versions 1..=17,
    // bound to canonical b794652d12ed1732215f0dc93b69a87dd87ffe46, not this branch.
    const APPLIED_PRE_PLATFORM_HISTORY_CHECKSUM: &str = "743aaf2f7fcafc2b1d100870505abbd09a7c184e0cbe39bea0b3e942c5d4427e6027a49e62dc0830ff448bfefe7bd130";
    const RETIRE_MESH_OIDC_CLIENT_VERSION: i64 = 5;
    const ORGANIZATION_ROUTE_SLUGS_VERSION: i64 = 11;
    const OPENBAO_SECRET_AUTHORITY_VERSION: i64 = 12;
    const APPLIED_OPENBAO_SECRET_AUTHORITY_CHECKSUM: &str = "cbd3494fde9235aaf507236bd18440f2d0c87fe6c42f9b1ce3af78f327b044aa968149229acd1bf064b6d4e67c54ed40";
    const OPENBAO_NATIVE_SECRETS_VERSION: i64 = 13;
    const CONFIDENTIAL_STORAGE_PROFILE_VERSION: i64 = 15;
    const PROJECT_SPEC_CUTOVER_VERSION: i64 = 16;
    const OPAQUE_AUTH_CAPABILITIES_VERSION: i64 = 17;
    const PLATFORM_CREDENTIALS_VERSION: i64 = 18;
    const LEGACY_USER_CREDENTIAL_SECRET_ERROR: &str =
        "credential product cutover requires legacy user credential secrets to be absent";

    async fn startup(database_url: String) -> anyhow::Result<()> {
        ensure_schema(&database_url).await
    }

    #[test]
    fn embedded_baseline_matches_the_applied_pre_cutover_history() -> anyhow::Result<()> {
        assert_applied_baseline_checksum()
    }

    #[test]
    fn embedded_pre_platform_history_matches_the_accepted_release() -> anyhow::Result<()> {
        assert_applied_pre_platform_history()
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
            assert_project_spec_schema(&pool).await?;
            assert_opaque_auth_capability_schema(&pool).await?;
            assert_platform_credential_schema(&pool).await?;
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
            assert_confidential_storage_profile_upgrade(&admin_url).await?;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn platform_credentials_upgrade_preserves_version_17_data_and_second_run_is_noop()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, PLATFORM_CREDENTIALS_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_pre_platform_credential_schema(&pool).await?;
            let before = applied_migrations(&pool).await?;
            anyhow::ensure!(before.len() == 17 && before.last().map(|row| row.0) == Some(17));
            seed_platform_credential_owners(&pool).await?;
            let owners_before: Vec<(String, String)> =
                sqlx::query_as("SELECT id, email FROM users ORDER BY id")
                    .fetch_all(&pool)
                    .await?;
            let organizations_before: Vec<(String, String, String, String)> =
                sqlx::query_as("SELECT id, name, slug, created_by FROM organizations ORDER BY id")
                    .fetch_all(&pool)
                    .await?;
            pool.close().await;

            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_platform_credential_schema(&pool).await?;
            let after = applied_migrations(&pool).await?;
            anyhow::ensure!(
                after.len() == 18 && after[..17] == before && after[17].0 == 18,
                "migration 18 did not append to the exact accepted prior ledger"
            );
            let owners_after: Vec<(String, String)> =
                sqlx::query_as("SELECT id, email FROM users ORDER BY id")
                    .fetch_all(&pool)
                    .await?;
            let organizations_after: Vec<(String, String, String, String)> =
                sqlx::query_as("SELECT id, name, slug, created_by FROM organizations ORDER BY id")
                    .fetch_all(&pool)
                    .await?;
            anyhow::ensure!(
                owners_after == owners_before && organizations_after == organizations_before
            );
            let empty: bool = sqlx::query_scalar(
                "SELECT NOT EXISTS(SELECT 1 FROM platform_credentials) \
                 AND NOT EXISTS(SELECT 1 FROM platform_credential_material)",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(empty, "additive migration imported credential records");
            seed_platform_credential(&pool, "credential", Some("credential-user-a"), None, "Work")
                .await?;
            seed_platform_credential_material(&pool, "credential", 1).await?;
            let rows_before: (String, String) = sqlx::query_as(
                "SELECT row_to_json(c)::text, row_to_json(m)::text \
                 FROM platform_credentials c JOIN platform_credential_material m \
                 ON m.credential_id = c.id WHERE c.id = 'credential'",
            )
            .fetch_one(&pool)
            .await?;
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
            anyhow::ensure!(applied_migrations(&pool).await? == after);
            let rows_after: (String, String) = sqlx::query_as(
                "SELECT row_to_json(c)::text, row_to_json(m)::text \
                 FROM platform_credentials c JOIN platform_credential_material m \
                 ON m.credential_id = c.id WHERE c.id = 'credential'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                rows_after == rows_before,
                "no-op startup changed credential storage"
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
    async fn platform_credentials_schema_fences_owners_names_envelopes_and_generations()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_platform_credential_schema(&pool).await?;
            seed_platform_credential_owners(&pool).await?;
            for (id, user_id, organization_id) in [
                ("user-a", Some("credential-user-a"), None),
                ("user-b", Some("credential-user-b"), None),
                ("org-a", None, Some("credential-org-a")),
                ("org-b", None, Some("credential-org-b")),
            ] {
                // Identical names are valid in different user/org scopes.
                seed_platform_credential(&pool, id, user_id, organization_id, "Work").await?;
                seed_platform_credential_material(&pool, id, 1).await?;
            }
            seed_platform_credential(&pool, "user-extra", Some("credential-user-a"), None, "Other").await?;
            seed_platform_credential(&pool, "org-extra", None, Some("credential-org-a"), "Other").await?;
            for query in [
                "UPDATE platform_credentials SET display_name = 'wOrK' WHERE id = 'user-extra'",
                "UPDATE platform_credentials SET display_name = 'wOrK' WHERE id = 'org-extra'",
            ] {
                assert_platform_credential_rejected(&pool, query, "23505").await?;
            }
            for assignment in [
                "user_id = NULL",
                "organization_id = 'credential-org-a'",
                "authentication_kind = 'unsupported'",
                "status = 'unsupported'",
                "display_name = ''",
                "display_name = repeat('x', 257)",
                "display_name = repeat('é', 129)",
                "account_hint = ''",
                "account_hint = repeat('x', 257)",
                "account_hint = repeat('é', 129)",
                "expires_at_unix = -1",
                "revocation_generation = 0",
                "revocation_generation = -1",
                "material_generation = 0",
                "material_generation = -1",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credentials SET {assignment} WHERE id = 'user-a'"),
                    "23514",
                ).await?;
            }
            for assignment in ["user_id = 'absent-user'", "material_generation = 2"] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credentials SET {assignment} WHERE id = 'user-a'"),
                    "23503",
                ).await?;
            }
            for column in [
                "id", "provider", "authentication_kind", "display_name", "status",
                "revocation_generation", "material_generation", "created_at", "updated_at",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credentials SET {column} = NULL WHERE id = 'user-a'"),
                    "23502",
                ).await?;
            }
            assert_platform_credential_rejected(
                &pool,
                "UPDATE platform_credentials SET organization_id = 'absent-org' WHERE id = 'org-a'",
                "23503",
            ).await?;
            for kind in ["oauth", "api_key", "access_token", "github_app"] {
                sqlx::query("UPDATE platform_credentials SET authentication_kind = $1 WHERE id = 'user-a'")
                    .bind(kind).execute(&pool).await?;
            }
            for status in ["active", "expired", "refresh_failed", "revoked"] {
                sqlx::query("UPDATE platform_credentials SET status = $1 WHERE id = 'user-a'")
                    .bind(status).execute(&pool).await?;
            }
            sqlx::query("UPDATE platform_credentials SET expires_at_unix = 0 WHERE id = 'user-a'")
                .execute(&pool).await?;
            sqlx::query("UPDATE platform_credentials SET expires_at_unix = NULL WHERE id = 'user-a'")
                .execute(&pool).await?;
            sqlx::query(
                "UPDATE platform_credentials SET display_name = repeat('é', 128), \
                 account_hint = repeat('é', 128) WHERE id = 'user-a'",
            ).execute(&pool).await?;

            for assignment in [
                "material_generation = 0",
                "kek_provider = 'unsupported'",
                "key_version = 0",
                "key_version = -1",
                "key_version = 4294967296",
                "wrapped_dek = decode('', 'hex')",
                "wrapped_dek = decode(repeat('00', 65537), 'hex')",
                "wrapped_format = 0",
                "wrapped_format = 2",
                "ciphertext = decode(repeat('00', 15), 'hex')",
                "ciphertext = decode(repeat('00', 1048593), 'hex')",
                "nonce = decode(repeat('00', 11), 'hex')",
                "nonce = decode(repeat('00', 13), 'hex')",
                "format = 0",
                "format = 2",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credential_material SET {assignment} WHERE credential_id = 'user-a'"),
                    "23514",
                ).await?;
            }
            for assignment in ["material_generation = 2", "credential_id = 'absent-credential'"] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credential_material SET {assignment} WHERE credential_id = 'user-a'"),
                    "23503",
                ).await?;
            }
            for column in [
                "credential_id", "material_generation", "kek_provider", "key_name", "key_version",
                "wrapped_dek", "wrapped_format", "ciphertext", "nonce", "format",
            ] {
                assert_platform_credential_rejected(
                    &pool,
                    &format!("UPDATE platform_credential_material SET {column} = NULL WHERE credential_id = 'user-a'"),
                    "23502",
                ).await?;
            }
            assert_platform_credential_rejected(
                &pool,
                "INSERT INTO platform_credential_material SELECT * \
                 FROM platform_credential_material WHERE credential_id = 'user-a'",
                "23505",
            ).await?;
            sqlx::query(
                "UPDATE platform_credential_material SET key_version = 4294967295, \
                 wrapped_dek = decode(repeat('00', 65536), 'hex'), \
                 ciphertext = decode(repeat('00', 1048592), 'hex') WHERE credential_id = 'user-a'",
            ).execute(&pool).await?;

            // A failed or cancelled replacement must retain the old complete
            // pair; the successful sequence needs no deferred FK or trigger.
            let mut replacement = pool.begin().await?;
            sqlx::query("DELETE FROM platform_credential_material WHERE credential_id = 'user-b'")
                .execute(&mut *replacement).await?;
            sqlx::query("UPDATE platform_credentials SET material_generation = 2 WHERE id = 'user-b'")
                .execute(&mut *replacement).await?;
            replacement.rollback().await?;
            let generations: (i64, i64) = sqlx::query_as(
                "SELECT c.material_generation, m.material_generation FROM platform_credentials c \
                 JOIN platform_credential_material m ON m.credential_id = c.id WHERE c.id = 'user-b'",
            ).fetch_one(&pool).await?;
            anyhow::ensure!(generations == (1, 1), "rolled-back replacement changed stored generations");
            let mut replacement = pool.begin().await?;
            sqlx::query("DELETE FROM platform_credential_material WHERE credential_id = 'user-b'")
                .execute(&mut *replacement).await?;
            sqlx::query("UPDATE platform_credentials SET material_generation = 2 WHERE id = 'user-b'")
                .execute(&mut *replacement).await?;
            sqlx::query(
                "INSERT INTO platform_credential_material \
                 (credential_id, material_generation, kek_provider, key_name, key_version, \
                  wrapped_dek, wrapped_format, ciphertext, nonce, format) \
                 VALUES ('user-b', 2, 'openbao-transit', 'credential-key', 1, \
                         decode('01', 'hex'), 1, decode(repeat('00', 16), 'hex'), \
                         decode(repeat('00', 12), 'hex'), 1)",
            ).execute(&mut *replacement).await?;
            replacement.commit().await?;
            let generations: (i64, i64) = sqlx::query_as(
                "SELECT c.material_generation, m.material_generation FROM platform_credentials c \
                 JOIN platform_credential_material m ON m.credential_id = c.id WHERE c.id = 'user-b'",
            ).fetch_one(&pool).await?;
            anyhow::ensure!(generations == (2, 2));

            // Explicit credential deletion and both owner cascades remove
            // ciphertext without touching another owner's records.
            sqlx::query("DELETE FROM platform_credentials WHERE id = 'user-a'").execute(&pool).await?;
            sqlx::query("DELETE FROM organizations WHERE id = 'credential-org-a'").execute(&pool).await?;
            sqlx::query("DELETE FROM users WHERE id = 'credential-user-b'").execute(&pool).await?;
            let remaining: Vec<String> = sqlx::query_scalar("SELECT id FROM platform_credentials ORDER BY id")
                .fetch_all(&pool).await?;
            let remaining_material: Vec<String> = sqlx::query_scalar(
                "SELECT credential_id FROM platform_credential_material ORDER BY credential_id",
            ).fetch_all(&pool).await?;
            anyhow::ensure!(remaining == ["org-b", "user-extra"]);
            anyhow::ensure!(remaining_material == ["org-b"]);
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn platform_credentials_rollback_recreates_only_the_disposable_application_schema()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_platform_credential_schema(&pool).await?;
            seed_platform_credential_owners(&pool).await?;
            seed_platform_credential(
                &pool,
                "rollback-credential",
                Some("credential-user-a"),
                None,
                "Work",
            )
            .await?;
            seed_platform_credential_material(&pool, "rollback-credential", 1).await?;
            sqlx::query("CREATE SCHEMA rollback_boundary")
                .execute(&pool)
                .await?;
            sqlx::query("CREATE TABLE rollback_boundary.retained (id integer PRIMARY KEY)")
                .execute(&pool)
                .await?;
            sqlx::query("INSERT INTO rollback_boundary.retained VALUES (1)")
                .execute(&pool)
                .await?;
            // No down migration or ledger rewrite: the selected prior release
            // rebuilds only this test database's disposable public schema.
            sqlx::query("DROP SCHEMA public CASCADE")
                .execute(&pool)
                .await?;
            sqlx::query("CREATE SCHEMA public").execute(&pool).await?;
            pool.close().await;

            apply_migrations_before(&test_db.url, PLATFORM_CREDENTIALS_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_pre_platform_credential_schema(&pool).await?;
            let history = applied_migrations(&pool).await?;
            anyhow::ensure!(history.len() == 17 && history.last().map(|row| row.0) == Some(17));
            let retained: Vec<i32> =
                sqlx::query_scalar("SELECT id FROM rollback_boundary.retained")
                    .fetch_all(&pool)
                    .await?;
            anyhow::ensure!(
                retained == [1],
                "rollback crossed the application-schema boundary"
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
    async fn opaque_auth_capability_cutover_invalidates_issued_values_and_preserves_pending_auth_requests()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, OPAQUE_AUTH_CAPABILITIES_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;

            sqlx::query(
                "INSERT INTO users (id, email) VALUES \
                 ('opaque-user', 'opaque-user@example.test')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) VALUES \
                 ('opaque-org', 'Opaque Org', 'opaque-org', 'opaque-user')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO oidc_clients (id, redirect_uris) VALUES \
                 ('opaque-client', ARRAY['https://client.example/callback'])",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                r#"INSERT INTO oidc_auth_requests
                       (id, client_id, scopes, redirect_uri, code, done, expires_at)
                   VALUES
                       ('pending-auth', 'opaque-client', ARRAY['openid'],
                        'https://client.example/callback', NULL, false, NOW() + INTERVAL '1 hour'),
                       ('issued-auth', 'opaque-client', ARRAY['openid'],
                        'https://client.example/callback', 'raw-code-marker', true,
                        NOW() + INTERVAL '1 hour')"#,
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO verifications (id, identifier, value, expires_at) VALUES \
                 ('verification', 'opaque-user@example.test', 'raw-verification-marker', NOW() + INTERVAL '1 hour')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO two_factor_tokens (id, user_id, token, expires_at) VALUES \
                 ('two-factor', 'opaque-user', 'raw-two-factor-marker', NOW() + INTERVAL '1 hour')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO oidc_device_authorizations \
                 (device_code, user_code, client_id, scopes, expires_at) VALUES \
                 ('raw-device-marker', 'USER-CODE', 'opaque-client', ARRAY['openid'], NOW() + INTERVAL '1 hour')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO org_invitations \
                 (id, org_id, email, role, invited_by, token, expires_at) VALUES \
                 ('invitation', 'opaque-org', 'invitee@example.test', 'member', \
                  'opaque-user', 'raw-invitation-marker', NOW() + INTERVAL '1 hour')",
            )
            .execute(&pool)
            .await?;
            pool.close().await;

            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_opaque_auth_capability_schema(&pool).await?;

            let pending: (i64, i64) = sqlx::query_as(
                "SELECT \
                    COUNT(*) FILTER (WHERE id = 'pending-auth'), \
                    COUNT(*) FILTER (WHERE id = 'pending-auth' AND code_hash IS NULL) \
                 FROM oidc_auth_requests",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(pending == (1, 1), "pending auth request was not preserved");
            let issued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM oidc_auth_requests WHERE id = 'issued-auth'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(issued == 0, "issued authorization code survived cutover");
            for table in [
                "verifications",
                "two_factor_tokens",
                "oidc_device_authorizations",
                "org_invitations",
            ] {
                let count: i64 = sqlx::query_scalar(&format!(
                    "SELECT COUNT(*) FROM {}",
                    quote_ident(table)
                ))
                .fetch_one(&pool)
                .await?;
                anyhow::ensure!(count == 0, "{table} capability rows survived cutover");
            }

            let invalid_verification = sqlx::query(
                "INSERT INTO verifications \
                 (id, identifier, purpose, token_hash, expires_at) VALUES \
                 ('invalid-verification', 'opaque-user@example.test', \
                  'email_verification', 'raw-capability', NOW() + INTERVAL '1 hour')",
            )
            .execute(&pool)
            .await;
            anyhow::ensure!(
                invalid_verification.is_err(),
                "verifications accepted a non-digest capability"
            );
            let invalid_device = sqlx::query(
                "INSERT INTO oidc_device_authorizations \
                 (device_code_hash, user_code_hash, client_id, scopes, expires_at) VALUES \
                 ('raw-device', 'raw-user-code', 'opaque-client', ARRAY['openid'], \
                  NOW() + INTERVAL '1 hour')",
            )
            .execute(&pool)
            .await;
            anyhow::ensure!(
                invalid_device.is_err(),
                "device authorization accepted non-digest capabilities"
            );

            pool.close().await;
            Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn project_spec_cutover_rejects_each_noncanonical_or_populated_input_before_mutation()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;

        for (table, expected_error) in [
            (
                "environment_presets",
                "canonical ProjectSpec cutover requires environment_presets to be empty",
            ),
            (
                "environments",
                "canonical ProjectSpec cutover requires environments to be empty",
            ),
            (
                "repo_configs",
                "canonical ProjectSpec cutover requires repo_configs to be empty",
            ),
            (
                "tenant_secrets",
                "canonical workload-secret key cutover requires all tenant_secrets keys to be canonical",
            ),
            (
                "user_login_keys",
                "credential product cutover requires user_login_keys to be empty",
            ),
            (
                "user_ssh_keys",
                "credential product cutover requires user_ssh_keys to be empty",
            ),
            (
                "user_git_credentials",
                "credential product cutover requires user_git_credentials to be empty",
            ),
            (
                "github_oauth_states",
                "credential product cutover requires github_oauth_states to be empty",
            ),
            (
                "user_github_tokens",
                "credential product cutover requires user_github_tokens to be empty",
            ),
        ] {
            let test_db = TestDatabase::create(&admin_url).await?;
            let result = async {
                apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&test_db.url)
                    .await?;

                if table != "environment_presets" {
                    sqlx::query(
                        "INSERT INTO users (id, email) \
                         VALUES ('project-spec-user', 'project-spec@example.test')",
                    )
                    .execute(&pool)
                    .await?;
                    sqlx::query(
                        "INSERT INTO organizations (id, name, slug, created_by) \
                         VALUES ('project-spec-org', 'Project Spec', 'project-spec', \
                                 'project-spec-user')",
                    )
                    .execute(&pool)
                    .await?;
                }

                match table {
                    "environment_presets" => {
                        sqlx::query(
                            "INSERT INTO environment_presets (id, name) \
                             VALUES ('project-spec-preset', 'Project Spec')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "environments" => {
                        // Isolate the environments preflight without creating
                        // a preset row that would trip the earlier guard.
                        sqlx::query("ALTER TABLE environments DROP CONSTRAINT chk_env_preset_id")
                            .execute(&pool)
                            .await?;
                        sqlx::query(
                            "INSERT INTO environments (id, org_id, created_by, type) \
                             VALUES ('project-spec-environment', 'project-spec-org', \
                                     'project-spec-user', 'sandbox')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "repo_configs" => {
                        sqlx::query(
                            "INSERT INTO repo_configs \
                             (id, org_id, repo_url, created_by) \
                             VALUES ('project-spec-repo', 'project-spec-org', \
                                     'https://example.test/project.git', 'project-spec-user')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "tenant_secrets" => {
                        sqlx::query(
                            "INSERT INTO tenant_secret_deks \
                             (dek_id, scope, scope_id, provider, key_name, key_version, \
                              wrapped_dek) \
                             VALUES ('project-spec-dek', 'org', 'project-spec-org', \
                                     'openbao-transit', 'tenant-dek', 1, \
                                     'vault:v1:generated')",
                        )
                        .execute(&pool)
                        .await?;
                        sqlx::query(
                            "INSERT INTO tenant_secrets \
                             (path, key, dek_id, scope, scope_id, ciphertext, nonce) \
                             VALUES ('/org-secrets/project-spec-org', '1DIGIT_FIRST', \
                                     'project-spec-dek', 'org', 'project-spec-org', \
                                     decode(repeat('11', 16), 'hex'), \
                                     decode(repeat('22', 12), 'hex'))",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "user_login_keys" => {
                        sqlx::query(
                            "INSERT INTO user_login_keys \
                             (user_id, name, public_key, fingerprint) \
                             VALUES ('project-spec-user', 'Synthetic', \
                                     'ssh-ed25519 synthetic', 'SHA256:synthetic')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "user_ssh_keys" => {
                        sqlx::query(
                            "INSERT INTO user_ssh_keys \
                             (user_id, public_key, key_fingerprint) \
                             VALUES ('project-spec-user', 'ssh-ed25519 synthetic', \
                                     'SHA256:synthetic')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "user_git_credentials" => {
                        sqlx::query(
                            "INSERT INTO user_git_credentials \
                             (user_id, name, host, auth_type) \
                             VALUES ('project-spec-user', 'Synthetic', \
                                     'git.example.test', 'basic')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "github_oauth_states" => {
                        sqlx::query(
                            "INSERT INTO github_oauth_states \
                             (state, user_id, expires_at) \
                             VALUES ('synthetic-state', 'project-spec-user', NOW())",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    "user_github_tokens" => {
                        sqlx::query(
                            "INSERT INTO user_github_tokens (user_id, access_token) \
                             VALUES ('project-spec-user', 'synthetic-token')",
                        )
                        .execute(&pool)
                        .await?;
                    }
                    _ => unreachable!("fixed cutover table matrix"),
                }
                pool.close().await;

                let error = ensure_schema(&test_db.url)
                    .await
                    .expect_err("a populated retired table must reject the ProjectSpec cutover");
                anyhow::ensure!(
                    format!("{error:#}").contains(expected_error),
                    "{table} rejection was not classified: {error:#}"
                );

                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&test_db.url)
                    .await?;
                let retained: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                    .fetch_one(&pool)
                    .await?;
                anyhow::ensure!(retained == 1, "failed cutover changed {table}");
                assert_pre_cutover_project_spec_schema(&pool).await?;
                if table == "tenant_secrets" {
                    assert_tenant_secret_key_constraint(&pool, "^[A-Za-z0-9_]+$", "pre-cutover")
                        .await?;
                }
                let applied: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = $1)",
                )
                .bind(PROJECT_SPEC_CUTOVER_VERSION)
                .fetch_one(&pool)
                .await?;
                anyhow::ensure!(!applied, "failed cutover entered the SQLx ledger");
                pool.close().await;
                anyhow::Ok(())
            }
            .await;
            let cleanup = test_db.drop().await;
            result.and(cleanup)?;
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn project_spec_cutover_preserves_canonical_tenant_secret_metadata() -> anyhow::Result<()>
    {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_pre_cutover_project_spec_schema(&pool).await?;
            sqlx::query(
                "INSERT INTO tenant_secret_deks \
                 (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
                 VALUES ('canonical-dek', 'org', 'canonical-org', 'openbao-transit', \
                         'tenant-dek', 1, 'vault:v1:generated')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce) \
                 VALUES ('/org-secrets/canonical-org', '_CANONICAL_1', 'canonical-dek', \
                         'org', 'canonical-org', decode(repeat('11', 16), 'hex'), \
                         decode(repeat('22', 12), 'hex'))",
            )
            .execute(&pool)
            .await?;
            pool.close().await;

            ensure_schema(&test_db.url).await?;

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let retained: (i64, Option<i16>) = sqlx::query_as(
                "SELECT COUNT(*), MIN(storage_contract_version) \
                 FROM tenant_secrets WHERE key = '_CANONICAL_1'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                retained == (1, Some(1)),
                "canonical tenant-secret metadata was changed or not backfilled: {retained:?}"
            );
            assert_tenant_secret_key_constraint(&pool, "^[A-Za-z_][A-Za-z0-9_]*$", "post-cutover")
                .await?;
            assert_project_spec_schema(&pool).await?;
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn project_spec_cutover_rejects_legacy_user_credential_secrets_atomically()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;

        for key in ["SSH_PRIVATE_KEY", "GIT_TOKEN_GIT_EXAMPLE_TEST"] {
            let test_db = TestDatabase::create(&admin_url).await?;
            let result = async {
                apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&test_db.url)
                    .await?;
                seed_test_tenant_secret_dek(&pool, "legacy-user-dek", "user", "legacy-user")
                    .await?;
                sqlx::query(
                    "INSERT INTO tenant_secrets \
                     (path, key, dek_id, scope, scope_id, ciphertext, nonce) \
                     VALUES ('/users/legacy-user', $1, 'legacy-user-dek', 'user', \
                             'legacy-user', decode(repeat('11', 16), 'hex'), \
                             decode(repeat('22', 12), 'hex'))",
                )
                .bind(key)
                .execute(&pool)
                .await?;
                pool.close().await;

                let error = ensure_schema(&test_db.url)
                    .await
                    .expect_err("legacy user credential material must reject the cutover");
                anyhow::ensure!(
                    format!("{error:#}").contains(LEGACY_USER_CREDENTIAL_SECRET_ERROR),
                    "legacy secret {key} rejection was not classified: {error:#}"
                );

                let pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&test_db.url)
                    .await?;
                let retained: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM tenant_secrets \
                     WHERE path = '/users/legacy-user' AND key = $1",
                )
                .bind(key)
                .fetch_one(&pool)
                .await?;
                anyhow::ensure!(
                    retained == 1,
                    "failed cutover changed the legacy secret {key}"
                );
                assert_pre_cutover_project_spec_schema(&pool).await?;
                assert_tenant_secret_key_constraint(&pool, "^[A-Za-z0-9_]+$", "pre-cutover")
                    .await?;
                assert_project_spec_cutover_not_applied(&pool).await?;
                pool.close().await;
                anyhow::Ok(())
            }
            .await;
            let cleanup = test_db.drop().await;
            result.and(cleanup)?;
        }

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn project_spec_cutover_observes_a_writer_that_commits_before_its_table_lock()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(4)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "INSERT INTO users (id, email) \
                 VALUES ('pre-lock-user', 'pre-lock-user@example.test')",
            )
            .execute(&pool)
            .await?;

            let mut writer = pool.begin().await?;
            sqlx::query(
                "INSERT INTO user_login_keys (user_id, name, public_key, fingerprint) \
                 VALUES ('pre-lock-user', 'Synthetic', 'ssh-ed25519 synthetic', \
                         'SHA256:pre-lock')",
            )
            .execute(&mut *writer)
            .await?;

            let migration_url = test_db.url.clone();
            let (migration_result, writer_result) =
                tokio::time::timeout(Duration::from_secs(20), async {
                    tokio::join!(ensure_schema(&migration_url), async {
                        wait_for_relation_lock(
                            &pool,
                            "user_login_keys",
                            "AccessExclusiveLock",
                            false,
                        )
                        .await?;
                        writer.commit().await?;
                        anyhow::Ok(())
                    })
                })
                .await
                .context("timed out proving the pre-lock writer ordering")?;
            writer_result?;
            let error = migration_result
                .expect_err("the committed pre-lock writer must be visible to the preflight");
            anyhow::ensure!(
                format!("{error:#}")
                    .contains("credential product cutover requires user_login_keys to be empty"),
                "committed pre-lock writer rejection was not classified: {error:#}"
            );

            let retained: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM user_login_keys WHERE user_id = $1")
                    .bind("pre-lock-user")
                    .fetch_one(&pool)
                    .await?;
            anyhow::ensure!(retained == 1, "pre-lock writer commit was not retained");
            assert_pre_cutover_project_spec_schema(&pool).await?;
            assert_project_spec_cutover_not_applied(&pool).await?;
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn project_spec_cutover_queues_then_rejects_an_old_secret_writer_after_its_lock()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&test_db.url)
                .await?;
            seed_test_tenant_secret_dek(&pool, "post-lock-dek", "user", "post-lock-user").await?;

            let mut blocker = pool.begin().await?;
            sqlx::query("LOCK TABLE public.user_github_tokens IN ACCESS SHARE MODE")
                .execute(&mut *blocker)
                .await?;

            let migration_url = test_db.url.clone();
            let (migration_result, controller_result) =
                tokio::time::timeout(Duration::from_secs(20), async {
                    tokio::join!(ensure_schema(&migration_url), async {
                        wait_for_relation_lock(
                            &pool,
                            "user_github_tokens",
                            "AccessExclusiveLock",
                            false,
                        )
                        .await?;

                        let granted_locks: Vec<String> = sqlx::query_scalar(
                            "SELECT DISTINCT c.relname::text \
                         FROM pg_catalog.pg_locks l \
                         JOIN pg_catalog.pg_class c ON c.oid = l.relation \
                         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                         WHERE n.nspname = 'public' AND l.mode = 'AccessExclusiveLock' \
                           AND l.granted AND c.relname IN ( \
                               'environment_presets', 'environments', 'repo_configs', \
                               'tenant_secrets', 'user_login_keys', 'user_ssh_keys', \
                               'user_git_credentials', 'github_oauth_states' \
                           ) \
                         ORDER BY c.relname::text",
                        )
                        .fetch_all(&pool)
                        .await?;
                        anyhow::ensure!(
                            granted_locks
                                == vec![
                                    "environment_presets".to_owned(),
                                    "environments".to_owned(),
                                    "github_oauth_states".to_owned(),
                                    "repo_configs".to_owned(),
                                    "tenant_secrets".to_owned(),
                                    "user_git_credentials".to_owned(),
                                    "user_login_keys".to_owned(),
                                    "user_ssh_keys".to_owned(),
                                ],
                            "cutover did not hold the exact preceding lock set: {granted_locks:?}"
                        );

                        let old_writer_pool = pool.clone();
                        let (old_writer_result, release_result) = tokio::join!(
                            async move {
                                sqlx::query(
                                    "INSERT INTO tenant_secrets \
                                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format) \
                                 VALUES ('/users/post-lock-user', 'SSH_PRIVATE_KEY', \
                                         'post-lock-dek', 'user', 'post-lock-user', \
                                         decode(repeat('11', 16), 'hex'), \
                                         decode(repeat('22', 12), 'hex'), 1)",
                                )
                                .execute(&old_writer_pool)
                                .await
                            },
                            async {
                                wait_for_relation_lock(
                                    &pool,
                                    "tenant_secrets",
                                    "RowExclusiveLock",
                                    false,
                                )
                                .await?;
                                blocker.commit().await?;
                                anyhow::Ok(())
                            }
                        );
                        release_result?;
                        anyhow::Ok(old_writer_result)
                    })
                })
                .await
                .context("timed out proving the post-lock writer ordering")?;
            migration_result?;
            let old_writer_error = controller_result?
                .expect_err("an old writer queued after the cutover lock must fail closed");
            assert_storage_contract_violation(&old_writer_error)?;

            let retained: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_secrets \
                 WHERE path = '/users/post-lock-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                retained == 0,
                "queued old writer persisted credential material"
            );
            assert_project_spec_schema(&pool).await?;
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn tenant_secret_writer_fence_rejects_omitted_version_before_on_conflict()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            seed_test_tenant_secret_dek(&pool, "current-user-dek", "user", "current-user").await?;

            sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, \
                  storage_contract_version) \
                 VALUES ('/users/current-user', 'SSH_PRIVATE_KEY', 'current-user-dek', \
                         'user', 'current-user', decode(repeat('11', 16), 'hex'), \
                         decode(repeat('22', 12), 'hex'), 1, 1)",
            )
            .execute(&pool)
            .await?;

            let old_upsert = sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format) \
                 VALUES ('/users/current-user', 'SSH_PRIVATE_KEY', 'current-user-dek', \
                         'user', 'current-user', decode(repeat('33', 16), 'hex'), \
                         decode(repeat('44', 12), 'hex'), 1) \
                 ON CONFLICT (path, key) DO UPDATE SET \
                   dek_id = EXCLUDED.dek_id, scope = EXCLUDED.scope, \
                   scope_id = EXCLUDED.scope_id, ciphertext = EXCLUDED.ciphertext, \
                   nonce = EXCLUDED.nonce, format = EXCLUDED.format, updated_at = now()",
            )
            .execute(&pool)
            .await
            .expect_err("an omitted-version ON CONFLICT candidate must fail its check first");
            assert_storage_contract_violation(&old_upsert)?;

            let unchanged: (Vec<u8>, i16) = sqlx::query_as(
                "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
                 WHERE path = '/users/current-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                unchanged == (vec![0x11; 16], 1),
                "rejected omitted-version upsert changed stored ciphertext or version"
            );

            sqlx::query(
                "INSERT INTO tenant_secrets \
                 (path, key, dek_id, scope, scope_id, ciphertext, nonce, format, \
                  storage_contract_version) \
                 VALUES ('/users/current-user', 'SSH_PRIVATE_KEY', 'current-user-dek', \
                         'user', 'current-user', decode(repeat('55', 16), 'hex'), \
                         decode(repeat('66', 12), 'hex'), 1, 1) \
                 ON CONFLICT (path, key) DO UPDATE SET \
                   dek_id = EXCLUDED.dek_id, scope = EXCLUDED.scope, \
                   scope_id = EXCLUDED.scope_id, ciphertext = EXCLUDED.ciphertext, \
                   nonce = EXCLUDED.nonce, format = EXCLUDED.format, updated_at = now()",
            )
            .execute(&pool)
            .await?;
            let current: (Vec<u8>, i16) = sqlx::query_as(
                "SELECT ciphertext, storage_contract_version FROM tenant_secrets \
                 WHERE path = '/users/current-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            let current_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_secrets \
                 WHERE path = '/users/current-user' AND key = 'SSH_PRIVATE_KEY'",
            )
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                current_count == 1 && current == (vec![0x55; 16], 1),
                "explicit current insert/upsert did not preserve the writer contract: {current:?}"
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
    async fn project_spec_cutover_rollback_recreates_schema_for_the_prior_source_release()
    -> anyhow::Result<()> {
        let admin_url = std::env::var("TEST_DATABASE_URL")
            .context("TEST_DATABASE_URL is required for migration tests")?;
        let test_db = TestDatabase::create(&admin_url).await?;
        let result = async {
            ensure_schema(&test_db.url).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_project_spec_schema(&pool).await?;

            // There is no in-place down migration. The supported pre-launch
            // rollback destroys only the disposable application schema, then
            // the prior source release replays the history it embeds.
            sqlx::query("DROP SCHEMA public CASCADE")
                .execute(&pool)
                .await?;
            sqlx::query("CREATE SCHEMA public").execute(&pool).await?;
            pool.close().await;

            apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            assert_pre_cutover_project_spec_schema(&pool).await?;
            let applied = applied_migrations(&pool).await?;
            anyhow::ensure!(
                applied.last().map(|migration| migration.0)
                    == Some(CONFIDENTIAL_STORAGE_PROFILE_VERSION),
                "prior source release did not stop at its embedded migration boundary"
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

            apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;

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

    async fn assert_platform_credential_schema(pool: &PgPool) -> anyhow::Result<()> {
        for (table, expected) in [
            (
                "platform_credentials",
                &[
                    "id",
                    "user_id",
                    "organization_id",
                    "provider",
                    "authentication_kind",
                    "display_name",
                    "account_hint",
                    "status",
                    "expires_at_unix",
                    "revocation_generation",
                    "material_generation",
                    "created_at",
                    "updated_at",
                ][..],
            ),
            (
                "platform_credential_material",
                &[
                    "credential_id",
                    "material_generation",
                    "kek_provider",
                    "key_name",
                    "key_version",
                    "wrapped_dek",
                    "wrapped_format",
                    "ciphertext",
                    "nonce",
                    "format",
                ][..],
            ),
        ] {
            let columns: Vec<String> = sqlx::query_scalar(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
            )
            .bind(table)
            .fetch_all(pool)
            .await?;
            anyhow::ensure!(
                columns == expected,
                "{table} columns changed; metadata must contain neither envelope nor protected reference"
            );
        }
        let material_fk: (String, bool, bool) = sqlx::query_as(
            "SELECT pg_get_constraintdef(oid), condeferrable, condeferred \
             FROM pg_catalog.pg_constraint \
             WHERE conrelid = 'public.platform_credential_material'::regclass \
               AND conname = 'platform_credential_material_generation_fkey'",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            material_fk == (
                "FOREIGN KEY (credential_id, material_generation) REFERENCES platform_credentials(id, material_generation) ON DELETE CASCADE".to_owned(),
                false,
                false,
            ),
            "protected material lost its immediate metadata-generation foreign key"
        );
        Ok(())
    }

    async fn assert_pre_platform_credential_schema(pool: &PgPool) -> anyhow::Result<()> {
        let absent: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.platform_credentials') IS NULL \
             AND to_regclass('public.platform_credential_material') IS NULL",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            absent,
            "pre-platform schema already contains typed credentials"
        );
        let fingerprint: String = sqlx::query_scalar(include_str!(
            "../tests/data/application_schema_fingerprint.sql"
        ))
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            fingerprint == ACCEPTED_PRE_PLATFORM_SCHEMA_FINGERPRINT,
            "accepted version-17 schema changed: {fingerprint}"
        );
        Ok(())
    }

    async fn seed_platform_credential_owners(pool: &PgPool) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO users (id, email) VALUES \
             ('credential-user-a', 'credential-a@example.test'), \
             ('credential-user-b', 'credential-b@example.test')",
        )
        .execute(pool)
        .await?;
        // Both organizations belong to user A so deletion of user B isolates
        // the user cascade from the independent organization-cascade proof.
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES \
             ('credential-org-a', 'Credential A', 'credential-a', 'credential-user-a'), \
             ('credential-org-b', 'Credential B', 'credential-b', 'credential-user-a')",
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn seed_platform_credential(
        pool: &PgPool,
        id: &str,
        user_id: Option<&str>,
        organization_id: Option<&str>,
        display_name: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO platform_credentials \
             (id, user_id, organization_id, provider, authentication_kind, display_name, \
              status, revocation_generation, material_generation) \
             VALUES ($1, $2, $3, 'openai', 'oauth', $4, 'active', 1, 1)",
        )
        .bind(id)
        .bind(user_id)
        .bind(organization_id)
        .bind(display_name)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn seed_platform_credential_material(
        pool: &PgPool,
        id: &str,
        generation: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO platform_credential_material \
             (credential_id, material_generation, kek_provider, key_name, key_version, \
              wrapped_dek, wrapped_format, ciphertext, nonce, format) \
             VALUES ($1, $2, 'openbao-transit', 'credential-key', 1, decode('01', 'hex'), \
                     1, decode(repeat('00', 16), 'hex'), decode(repeat('00', 12), 'hex'), 1)",
        )
        .bind(id)
        .bind(generation)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn assert_platform_credential_rejected(
        pool: &PgPool,
        query: &str,
        expected_code: &str,
    ) -> anyhow::Result<()> {
        let error = sqlx::query(query)
            .execute(pool)
            .await
            .expect_err("invalid synthetic credential storage must be rejected");
        let code = error.as_database_error().and_then(|error| error.code());
        anyhow::ensure!(
            code.as_deref() == Some(expected_code),
            "credential constraint returned SQLSTATE {code:?}, expected {expected_code}"
        );
        Ok(())
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
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, storage_contract_version) \
             VALUES ('/projects/org_1/project_1', 'API_TOKEN', 'dek-org-1', 'org', 'org_1', \
                     decode(repeat('11', 16), 'hex'), decode(repeat('22', 12), 'hex'), 1)",
        )
        .execute(pool)
        .await?;

        let digit_first_key = sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, storage_contract_version) \
             VALUES ('/projects/org_1/project_1', '1DIGIT_FIRST', 'dek-org-1', 'org', \
                     'org_1', decode(repeat('11', 16), 'hex'), \
                     decode(repeat('22', 12), 'hex'), 1)",
        )
        .execute(pool)
        .await;
        anyhow::ensure!(
            digit_first_key.is_err(),
            "post-cutover database accepted a digit-first tenant-secret key"
        );
        assert_tenant_secret_key_constraint(pool, "^[A-Za-z_][A-Za-z0-9_]*$", "post-cutover")
            .await?;

        let crossed_scope = sqlx::query(
            "INSERT INTO tenant_secrets \
             (path, key, dek_id, scope, scope_id, ciphertext, nonce, storage_contract_version) \
             VALUES ('/users/user_1', 'API_TOKEN', 'dek-org-1', 'org', 'org_1', \
                     decode(repeat('11', 16), 'hex'), decode(repeat('22', 12), 'hex'), 1)",
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

    async fn assert_tenant_secret_key_constraint(
        pool: &PgPool,
        expected_grammar: &str,
        phase: &str,
    ) -> anyhow::Result<()> {
        let definition: Option<String> = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) \
             FROM pg_catalog.pg_constraint \
             WHERE conrelid = 'public.tenant_secrets'::regclass \
               AND conname = 'tenant_secrets_key_check'",
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            definition
                .as_deref()
                .is_some_and(|definition| definition.contains(expected_grammar)),
            "{phase} tenant-secret key constraint is absent or malformed: {definition:?}"
        );
        Ok(())
    }

    async fn seed_test_tenant_secret_dek(
        pool: &PgPool,
        dek_id: &str,
        scope: &str,
        scope_id: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ($1, $2, $3, 'openbao-transit', 'tenant-dek', 1, \
                     'vault:v1:generated')",
        )
        .bind(dek_id)
        .bind(scope)
        .bind(scope_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn assert_project_spec_cutover_not_applied(pool: &PgPool) -> anyhow::Result<()> {
        let applied: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version = $1)")
                .bind(PROJECT_SPEC_CUTOVER_VERSION)
                .fetch_one(pool)
                .await?;
        anyhow::ensure!(!applied, "failed cutover entered the SQLx ledger");
        Ok(())
    }

    fn assert_storage_contract_violation(error: &sqlx::Error) -> anyhow::Result<()> {
        let constraint = error
            .as_database_error()
            .and_then(|database_error| database_error.constraint());
        anyhow::ensure!(
            constraint == Some("tenant_secrets_storage_contract_version_check"),
            "old tenant-secret writer failed for the wrong reason: {error}"
        );
        Ok(())
    }

    async fn wait_for_relation_lock(
        pool: &PgPool,
        relation: &str,
        mode: &str,
        granted: bool,
    ) -> anyhow::Result<()> {
        let qualified_relation = format!("public.{relation}");
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            let observed: bool = sqlx::query_scalar(
                "SELECT EXISTS ( \
                     SELECT 1 FROM pg_catalog.pg_locks \
                     WHERE locktype = 'relation' \
                       AND relation = to_regclass($1)::oid \
                       AND mode = $2 AND granted = $3 \
                 )",
            )
            .bind(&qualified_relation)
            .bind(mode)
            .bind(granted)
            .fetch_one(pool)
            .await?;
            if observed {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        anyhow::bail!("timed out waiting for {mode} on {qualified_relation} with granted={granted}")
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
            "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
             VALUES ('preset-confidential-storage', 'org-confidential-storage', \
                     'Confidential Storage', 'confidential-storage', \
                     '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
        )
        .execute(pool)
        .await?;
        sqlx::query(
            "INSERT INTO environments \
             (id, org_id, created_by, type, preset_id, project_spec) \
             VALUES ($1, 'org-confidential-storage', 'retained-user', 'sandbox', \
                     'preset-confidential-storage', \
                     '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
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

        let retired_schema = sqlx::query(
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
        .await;
        anyhow::ensure!(
            retired_schema.is_err(),
            "active schema-2 confidential storage was accepted"
        );

        sqlx::query(
            "UPDATE confidential_storage_keys SET \
                 volume_id = $1, volume_version = $2, \
                 manifest_schema_version = 3, device_size_bytes = 21474836480, \
                 luks_uuid = 'f617a73e-b03d-4b58-b1ae-354c72276ea0', \
                 protection_profile = 'luks2-integrity-rw', \
                 protection_profile_version = 1, \
                 backing_claim_name = 'workspace' \
             WHERE environment_id = $1",
        )
        .bind(ENVIRONMENT_ID)
        .bind(format!("{ENVIRONMENT_ID}-v3"))
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
                "protection_profile_version",
                "UPDATE confidential_storage_keys \
                 SET protection_profile_version = 2 WHERE environment_id = $1",
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

    async fn assert_confidential_storage_profile_upgrade(admin_url: &str) -> anyhow::Result<()> {
        const ENVIRONMENT_ID: &str = "88a00a61-f96b-4db2-8217-1842d29ac9ee";
        let test_db = TestDatabase::create(admin_url).await?;
        let result = async {
            apply_migrations_before(&test_db.url, CONFIDENTIAL_STORAGE_PROFILE_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "INSERT INTO users (id, email) \
                 VALUES ('profile-upgrade-user', 'profile-upgrade@example.test')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO organizations (id, name, slug, created_by) \
                 VALUES ('org-profile-upgrade', 'Profile Upgrade', \
                         'profile-upgrade', 'profile-upgrade-user')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO environment_presets (id, org_id, name, slug) \
                 VALUES ('preset-profile-upgrade', 'org-profile-upgrade', \
                         'Profile Upgrade', 'profile-upgrade')",
            )
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO environments (id, org_id, created_by, type, preset_id) \
                 VALUES ($1, 'org-profile-upgrade', 'profile-upgrade-user', 'sandbox', \
                         'preset-profile-upgrade')",
            )
            .bind(ENVIRONMENT_ID)
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO confidential_storage_keys \
                     (environment_id, kbs_uri, openbao_path, state, volume_id, \
                      volume_version, manifest_schema_version, device_size_bytes, \
                      luks_uuid, protection_profile, backing_claim_name) \
                 VALUES ($1, $2, $3, 'ready', $1, $4, 2, 21474836480, \
                         'f617a73e-b03d-4b58-b1ae-354c72276ea0', \
                         'luks2-integrity-rw', 'workspace')",
            )
            .bind(ENVIRONMENT_ID)
            .bind(format!(
                "kbs:///default/codewire-workspace-luks/{ENVIRONMENT_ID}"
            ))
            .bind(format!("confidential-storage/{ENVIRONMENT_ID}"))
            .bind(format!("{ENVIRONMENT_ID}-v2"))
            .execute(&pool)
            .await?;
            pool.close().await;

            let active_error = ensure_schema(&test_db.url).await.unwrap_err();
            anyhow::ensure!(
                format!("{active_error:#}").contains(
                    "schema-3 confidential storage admission requires no active schema-2 volumes"
                ),
                "profile migration did not fail at the active schema-2 boundary: {active_error:#}"
            );

            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            sqlx::query(
                "UPDATE confidential_storage_keys SET state = 'deleting' \
                 WHERE environment_id = $1",
            )
            .bind(ENVIRONMENT_ID)
            .execute(&pool)
            .await?;
            pool.close().await;

            apply_migrations_before(&test_db.url, PROJECT_SPEC_CUTOVER_VERSION).await?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_db.url)
                .await?;
            let profile_version: Option<i32> = sqlx::query_scalar(
                "SELECT protection_profile_version FROM confidential_storage_keys \
                 WHERE environment_id = $1",
            )
            .bind(ENVIRONMENT_ID)
            .fetch_one(&pool)
            .await?;
            anyhow::ensure!(
                profile_version.is_none(),
                "schema-2 lifecycle history was rewritten as profile 1"
            );
            let reactivate = sqlx::query(
                "UPDATE confidential_storage_keys SET state = 'ready' \
                 WHERE environment_id = $1",
            )
            .bind(ENVIRONMENT_ID)
            .execute(&pool)
            .await;
            anyhow::ensure!(
                reactivate.is_err(),
                "retired schema-2 confidential storage was reactivated"
            );
            sqlx::query(
                "UPDATE confidential_storage_keys SET state = 'deleted' \
                 WHERE environment_id = $1",
            )
            .bind(ENVIRONMENT_ID)
            .execute(&pool)
            .await?;
            pool.close().await;
            anyhow::Ok(())
        }
        .await;
        let cleanup = test_db.drop().await;
        result.and(cleanup)
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

    async fn assert_project_spec_schema(pool: &PgPool) -> anyhow::Result<()> {
        let canonical_columns: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT table_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name IN ('environment_presets', 'environments', 'repo_configs')
              AND column_name = 'project_spec'
            ORDER BY table_name
            "#,
        )
        .fetch_all(pool)
        .await?;
        anyhow::ensure!(
            canonical_columns
                == vec![
                    (
                        "environment_presets".to_owned(),
                        "jsonb".to_owned(),
                        "NO".to_owned(),
                    ),
                    (
                        "environments".to_owned(),
                        "jsonb".to_owned(),
                        "NO".to_owned(),
                    ),
                    (
                        "repo_configs".to_owned(),
                        "jsonb".to_owned(),
                        "NO".to_owned(),
                    ),
                ],
            "canonical ProjectSpec columns are incomplete: {canonical_columns:?}"
        );

        let auto_image_column: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'environment_presets'
              AND column_name = 'auto_image_ref'
            "#,
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            auto_image_column == Some(("text".to_owned(), "YES".to_owned())),
            "auto-image preset identity column is absent or malformed: {auto_image_column:?}"
        );
        let auto_image_index: Option<(bool, Option<String>)> = sqlx::query_as(
            r#"
            SELECT i.indisunique, pg_get_expr(i.indpred, i.indrelid)
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid
            WHERE c.relname = 'idx_environment_presets_auto_image_org'
            "#,
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            auto_image_index
                .as_ref()
                .is_some_and(|(unique, predicate)| *unique
                    && predicate
                        .as_deref()
                        .is_some_and(|value| value.contains("auto_image_ref IS NOT NULL"))),
            "auto-image preset uniqueness index is absent or malformed: {auto_image_index:?}"
        );
        let auto_image_constraints: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM pg_catalog.pg_constraint
            WHERE conname IN (
                'environment_presets_auto_image_ref_nonempty',
                'environment_presets_auto_image_matches_project_spec'
            )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            auto_image_constraints == 2,
            "auto-image preset invariants are incomplete: {auto_image_constraints}"
        );

        let preset_scope_column: Option<String> = sqlx::query_scalar(
            r#"
            SELECT is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'environment_presets'
              AND column_name = 'official'
            "#,
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            preset_scope_column.as_deref() == Some("NO"),
            "preset official scope column remains nullable: {preset_scope_column:?}"
        );
        let preset_scope_constraint: Option<(bool, String)> = sqlx::query_as(
            r#"
            SELECT convalidated, pg_get_constraintdef(oid)
            FROM pg_catalog.pg_constraint
            WHERE conname = 'environment_presets_scope_consistent'
            "#,
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            preset_scope_constraint
                .as_ref()
                .is_some_and(|(validated, definition)| *validated
                    && definition.contains("official = (org_id IS NULL)")),
            "preset scope constraint is absent or malformed: {preset_scope_constraint:?}"
        );
        let official_slug_index: Option<(bool, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT i.indisunique, pg_get_indexdef(i.indexrelid),
                   pg_get_expr(i.indpred, i.indrelid)
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid
            WHERE c.relname = 'idx_environment_presets_official_slug'
            "#,
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            official_slug_index
                .as_ref()
                .is_some_and(|(unique, definition, predicate)| *unique
                    && definition.contains("(slug)")
                    && predicate.as_deref().is_some_and(|value| {
                        value.contains("official")
                            && value.contains("org_id IS NULL")
                            && value.contains("slug IS NOT NULL")
                    })),
            "official preset slug index is absent or malformed: {official_slug_index:?}"
        );

        let retired_columns: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                    (table_name = 'environment_presets' AND column_name IN (
                        'default_cpu_millicores', 'default_memory_mb', 'default_disk_gb',
                        'default_setup_config', 'default_secret_project_id'
                    ))
                 OR (table_name = 'environments' AND column_name IN (
                        'auth_token', 'setup_config', 'secret_project_id'
                    ))
                 OR (table_name = 'repo_configs' AND column_name IN (
                        'preset_id', 'setup_config'
                    ))
                 OR (table_name = 'sandbox_template_config' AND column_name = 'warm_pool_size')
              )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_columns == 0,
            "retired project intent columns remain"
        );

        let retired_constraints: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM pg_catalog.pg_constraint
            WHERE conname IN (
                'environment_presets_default_secret_project_id_fkey',
                'environments_secret_project_id_fkey',
                'repo_configs_preset_id_fkey'
            )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_constraints == 0,
            "retired project intent constraints remain"
        );

        let retired_credential_tables_absent: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.user_login_keys') IS NULL \
                    AND to_regclass('public.user_ssh_keys') IS NULL \
                    AND to_regclass('public.user_git_credentials') IS NULL \
                    AND to_regclass('public.github_oauth_states') IS NULL \
                    AND to_regclass('public.user_github_tokens') IS NULL",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_credential_tables_absent,
            "retired account credential metadata tables remain"
        );

        let storage_contract_column: Option<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT data_type, is_nullable, column_default \
             FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'tenant_secrets' \
               AND column_name = 'storage_contract_version'",
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            storage_contract_column.as_ref().is_some_and(
                |(data_type, is_nullable, column_default)| data_type == "smallint"
                    && is_nullable == "NO"
                    && column_default
                        .as_deref()
                        .is_some_and(|default| default.contains('0'))
            ),
            "tenant-secret storage contract column is absent or malformed: \
             {storage_contract_column:?}"
        );
        let storage_contract_constraint: Option<(bool, String)> = sqlx::query_as(
            "SELECT convalidated, pg_get_constraintdef(oid) \
             FROM pg_catalog.pg_constraint \
             WHERE conrelid = 'public.tenant_secrets'::regclass \
               AND conname = 'tenant_secrets_storage_contract_version_check'",
        )
        .fetch_optional(pool)
        .await?;
        anyhow::ensure!(
            storage_contract_constraint
                .as_ref()
                .is_some_and(|(validated, definition)| *validated
                    && definition.contains("storage_contract_version = 1")),
            "tenant-secret storage contract constraint is absent or malformed: \
             {storage_contract_constraint:?}"
        );
        Ok(())
    }

    async fn assert_opaque_auth_capability_schema(pool: &PgPool) -> anyhow::Result<()> {
        let current_columns: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                    (table_name = 'verifications'
                     AND ((column_name = 'purpose' AND is_nullable = 'NO')
                          OR (column_name = 'token_hash' AND is_nullable = 'NO')))
                 OR (table_name = 'two_factor_tokens'
                     AND column_name = 'token_hash' AND is_nullable = 'NO')
                 OR (table_name = 'oidc_auth_requests'
                     AND column_name = 'code_hash' AND is_nullable = 'YES')
                 OR (table_name = 'oidc_device_authorizations'
                     AND column_name IN ('device_code_hash', 'user_code_hash')
                     AND is_nullable = 'NO')
                 OR (table_name = 'org_invitations'
                     AND column_name = 'token_hash' AND is_nullable = 'NO')
              )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            current_columns == 7,
            "opaque capability columns are absent or nullable: {current_columns}"
        );

        let retired_columns: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                    (table_name = 'verifications' AND column_name = 'value')
                 OR (table_name = 'two_factor_tokens' AND column_name = 'token')
                 OR (table_name = 'oidc_auth_requests' AND column_name = 'code')
                 OR (table_name = 'oidc_device_authorizations'
                     AND column_name IN ('device_code', 'user_code'))
                 OR (table_name = 'org_invitations' AND column_name = 'token')
              )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_columns == 0,
            "raw opaque capability columns remain: {retired_columns}"
        );

        let required_constraints: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM pg_catalog.pg_constraint
            WHERE conname IN (
                'verifications_purpose_check',
                'verifications_token_hash_format_check',
                'two_factor_tokens_token_hash_format_check',
                'oidc_auth_requests_code_hash_format_check',
                'oidc_device_authorizations_device_code_hash_format_check',
                'oidc_device_authorizations_user_code_hash_format_check',
                'org_invitations_token_hash_format_check'
            )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            required_constraints == 7,
            "opaque capability constraints are incomplete: {required_constraints}"
        );
        Ok(())
    }

    async fn assert_pre_cutover_project_spec_schema(pool: &PgPool) -> anyhow::Result<()> {
        let canonical_columns: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name IN ('environment_presets', 'environments', 'repo_configs')
              AND column_name = 'project_spec'
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            canonical_columns == 0,
            "pre-cutover schema unexpectedly contains ProjectSpec columns"
        );
        let auto_image_columns: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'environment_presets'
              AND column_name = 'auto_image_ref'
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            auto_image_columns == 0,
            "pre-cutover schema unexpectedly contains auto-image identity"
        );
        let storage_contract_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'tenant_secrets' \
               AND column_name = 'storage_contract_version'",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            storage_contract_columns == 0,
            "pre-cutover schema unexpectedly contains the tenant-secret writer fence"
        );

        let retired_columns: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND (
                    (table_name = 'environment_presets' AND column_name IN (
                        'default_cpu_millicores', 'default_memory_mb', 'default_disk_gb',
                        'default_setup_config', 'default_secret_project_id'
                    ))
                 OR (table_name = 'environments' AND column_name IN (
                        'auth_token', 'setup_config', 'secret_project_id'
                    ))
                 OR (table_name = 'repo_configs' AND column_name IN (
                        'preset_id', 'setup_config'
                    ))
                 OR (table_name = 'sandbox_template_config' AND column_name = 'warm_pool_size')
              )
            "#,
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_columns == 11,
            "pre-cutover project intent columns changed: {retired_columns}"
        );
        let retired_credential_tables_present: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.user_login_keys') IS NOT NULL \
                    AND to_regclass('public.user_ssh_keys') IS NOT NULL \
                    AND to_regclass('public.user_git_credentials') IS NOT NULL \
                    AND to_regclass('public.github_oauth_states') IS NOT NULL \
                    AND to_regclass('public.user_github_tokens') IS NOT NULL",
        )
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            retired_credential_tables_present,
            "pre-cutover account credential metadata tables changed"
        );
        Ok(())
    }

    fn assert_applied_baseline_checksum() -> anyhow::Result<()> {
        let baseline = MIGRATOR
            .iter()
            .find(|migration| migration.version == 1)
            .context("embedded baseline migration is missing")?;
        let checksum = format!("{:x}", Sha384::digest(baseline.sql.as_bytes()));
        anyhow::ensure!(
            checksum == APPLIED_BASELINE_CHECKSUM,
            "migration 1 no longer matches the applied pre-cutover history"
        );
        Ok(())
    }

    fn assert_applied_pre_platform_history() -> anyhow::Result<()> {
        let mut digest = Sha384::new();
        let mut count = 0;
        for migration in MIGRATOR
            .iter()
            .filter(|migration| migration.version < PLATFORM_CREDENTIALS_VERSION)
        {
            count += 1;
            anyhow::ensure!(
                migration.version == count,
                "accepted prior migration ordering changed"
            );
            digest.update(Sha384::digest(migration.sql.as_bytes()));
        }
        anyhow::ensure!(count == 17, "accepted version-17 history is incomplete");
        anyhow::ensure!(
            format!("{:x}", digest.finalize()) == APPLIED_PRE_PLATFORM_HISTORY_CHECKSUM,
            "migrations 1 through 17 no longer match canonical accepted history"
        );
        Ok(())
    }

    async fn apply_migrations_before(database_url: &str, version: i64) -> anyhow::Result<()> {
        // Do not manufacture an apparently valid old ledger from a baseline
        // rewritten by the same branch whose upgrade is being tested.
        assert_applied_baseline_checksum()?;
        assert_applied_pre_platform_history()?;
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
        let checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum, 'hex') FROM _sqlx_migrations WHERE version = 1 AND success",
        )
        .fetch_one(&mut connection)
        .await?;
        anyhow::ensure!(
            checksum == APPLIED_BASELINE_CHECKSUM,
            "prior-source fixture did not record the canonical migration 1 checksum"
        );
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
