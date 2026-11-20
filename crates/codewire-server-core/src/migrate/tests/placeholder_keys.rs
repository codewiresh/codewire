//! Hosted placeholder keys (0038, #4001): one sealed key per environment,
//! shaped like credential material, deleted with its environment, with no
//! privilege for PUBLIC; the rollback restores the earlier shape.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

/// The SQLSTATE of a refused statement, or `None` when it succeeded.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.code().unwrap_or_default().into_owned()),
        Err(error) => Some(error.to_string()),
    }
}

/// One sealed key row for `environment` with `ciphertext_bytes` of ciphertext.
fn key(environment: &str, ciphertext_bytes: usize) -> String {
    format!(
        "INSERT INTO platform_placeholder_keys (environment_id, kek_provider, key_name, \
         key_version, wrapped_dek, wrapped_format, ciphertext, nonce, format) VALUES \
         ('{environment}', 'openbao-transit', 'codewire-credentials', 1, '\\x01', 1, \
          decode(repeat('00', {ciphertext_bytes}), 'hex'), decode(repeat('00', 12), 'hex'), 1)"
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn placeholder_keys_upgrade_holds_one_sealed_key_per_environment_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(37).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES ('key-admin', 'admin@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) VALUES \
               ('key-org', 'Keys', 'key-org', 'key-admin'); \
             INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) VALUES \
               ('key-preset', 'key-org', 'Preset', 'ready', '{}'::jsonb); \
             INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) VALUES \
               ('key-env', 'key-org', 'key-admin', 'sandbox', 'key-preset', '{}'::jsonb), \
               ('key-other', 'key-org', 'key-admin', 'sandbox', 'key-preset', '{}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        through(38).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        anyhow::ensure!(refused(&pool, &key("key-env", 48)).await.is_none());
        // One key per environment, only for an environment that exists, and
        // only a sealed 32-byte key.
        anyhow::ensure!(refused(&pool, &key("key-env", 48)).await.as_deref() == Some("23505"));
        anyhow::ensure!(refused(&pool, &key("key-missing", 48)).await.as_deref() == Some("23503"));
        anyhow::ensure!(refused(&pool, &key("key-other", 47)).await.as_deref() == Some("23514"));
        anyhow::ensure!(
            refused(
                &pool,
                &key("key-other", 48).replace("'openbao-transit'", "'local'")
            )
            .await
            .as_deref()
                == Some("23514")
        );
        let public: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.role_table_grants \
             WHERE table_name = 'platform_placeholder_keys' AND grantee = 'PUBLIC')",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!public, "PUBLIC holds a privilege on placeholder keys");

        // Destroying the environment deletes its key.
        sqlx::query("DELETE FROM environments WHERE id = 'key-env'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM platform_placeholder_keys")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 0);

        sqlx::raw_sql("DROP TABLE platform_placeholder_keys")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
