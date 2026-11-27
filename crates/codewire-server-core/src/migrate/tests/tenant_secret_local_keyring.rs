//! Self-hosted local-keyring KEK provider support (0066):
//! widens `tenant_secret_deks` and `tenant_secret_kek_canary` constraints to
//! accept `'local-keyring'` bound strictly to `local:vN:...` wrapped DEKs,
//! while keeping `'openbao-transit'` bound strictly to `vault:vN:...`, and
//! rejecting cross-provider mixtures.

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
async fn tenant_secret_local_keyring_widens_constraints_without_allowing_mixing()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 66)
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

        let through_0066 = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= 66)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        through_0066.run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Local-keyring DEK and canary rows are accepted with matching `local:vN:` shape.
        sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-local-1', 'org', 'org_local', 'local-keyring', 'tenant-dek', 1, \
                     'local:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO tenant_secret_kek_canary \
             (provider, key_name, key_version, wrapped_dek, expected_authority_id, plaintext_sha256) \
             VALUES ('local-keyring', 'tenant-dek', 1, \
                     'local:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', \
                     'local-keyring', decode(repeat('11', 32), 'hex'))",
        )
        .execute(&pool)
        .await?;

        // Cross-provider prefix mixing must be rejected by CHECK constraints.
        let wrong_local_prefix = sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-mix-1', 'org', 'org_mix1', 'local-keyring', 'tenant-dek', 1, \
                     'vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')",
        )
        .execute(&pool)
        .await;
        anyhow::ensure!(wrong_local_prefix.is_err());

        let wrong_bao_prefix = sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-mix-2', 'org', 'org_mix2', 'openbao-transit', 'tenant-dek', 1, \
                     'local:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')",
        )
        .execute(&pool)
        .await;
        anyhow::ensure!(wrong_bao_prefix.is_err());

        let unknown_provider = sqlx::query(
            "INSERT INTO tenant_secret_deks \
             (dek_id, scope, scope_id, provider, key_name, key_version, wrapped_dek) \
             VALUES ('dek-bad', 'org', 'org_bad', 'plaintext', 'tenant-dek', 1, \
                     'local:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')",
        )
        .execute(&pool)
        .await;
        anyhow::ensure!(unknown_provider.is_err());

        // Clean up local-keyring test rows before proving constraint rollback.
        sqlx::query("DELETE FROM tenant_secret_deks WHERE dek_id = 'dek-local-1'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM tenant_secret_kek_canary")
            .execute(&pool)
            .await?;

        // Rollback restores the pre-0066 constraint definitions.
        sqlx::raw_sql(
            "ALTER TABLE public.tenant_secret_deks \
                 DROP CONSTRAINT tenant_secret_deks_provider_check, \
                 DROP CONSTRAINT tenant_secret_deks_wrapped_shape_check, \
                 ADD CONSTRAINT tenant_secret_deks_provider_check \
                     CHECK ((provider = 'openbao-transit'::text)), \
                 ADD CONSTRAINT tenant_secret_deks_wrapped_shape_check \
                     CHECK ((((length(wrapped_dek) >= 12) AND (length(wrapped_dek) <= 4096)) \
                             AND (wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text) \
                             AND (split_part(wrapped_dek, ':'::text, 2) = ('v'::text || (key_version)::text)))); \
             ALTER TABLE public.tenant_secret_kek_canary \
                 DROP CONSTRAINT tenant_secret_kek_canary_provider_check, \
                 DROP CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check, \
                 ADD CONSTRAINT tenant_secret_kek_canary_provider_check \
                     CHECK ((provider = 'openbao-transit'::text)), \
                 ADD CONSTRAINT tenant_secret_kek_canary_wrapped_shape_check \
                     CHECK ((((length(expected_authority_id) >= 1) AND (length(expected_authority_id) <= 255)) \
                             AND (expected_authority_id ~ '^[A-Za-z0-9_.:-]+$'::text) \
                             AND ((length(wrapped_dek) >= 12) AND (length(wrapped_dek) <= 4096)) \
                             AND (wrapped_dek ~ '^vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}$'::text) \
                             AND (split_part(wrapped_dek, ':'::text, 2) = ('v'::text || (key_version)::text))));",
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
