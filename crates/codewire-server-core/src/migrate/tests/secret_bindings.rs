//! Secret bindings (#4003): an upgrade leaves every existing secret plain, at
//! binding generation 0 and value version 1; the check refuses a binding with
//! no binding ID, a binding that isn't an object, a negative generation and a
//! value version below 1; and the rollback (drop the four columns and the
//! check) restores the earlier schema.

use super::*;

/// This migration's version.
const VERSION: i64 = 67;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn constraint<T>(result: Result<T, sqlx::Error>) -> Option<String> {
    match result {
        Err(sqlx::Error::Database(error)) => error.constraint().map(str::to_owned),
        _ => None,
    }
}

/// The history up to and including `version`, so this test keeps proving
/// the migration from the shape before it after later migrations land.
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn secret_bindings_upgrade_leaves_secrets_plain_checks_bindings_and_rolls_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(VERSION - 1).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        seed_test_tenant_secret_dek(&pool, "binding-dek", "user", "credential-user-a").await?;
        sqlx::raw_sql(
            "INSERT INTO tenant_secrets(path,key,dek_id,scope,scope_id,ciphertext,nonce,format,storage_contract_version) \
             VALUES('/users/credential-user-a','BINDING_EXISTING','binding-dek','user','credential-user-a',\
             decode(repeat('01',32),'hex'),decode(repeat('02',12),'hex'),1,1)",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // An existing secret is plain, at generation 0 and value version 1.
        let (binding, binding_id, generation, value_version): (
            Option<serde_json::Value>,
            Option<uuid::Uuid>,
            i64,
            i64,
        ) = sqlx::query_as(
            "SELECT binding, binding_id, binding_generation, value_version \
             FROM tenant_secrets WHERE key='BINDING_EXISTING'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            binding.is_none() && binding_id.is_none() && generation == 0 && value_version == 1,
            "an existing secret changed: {binding:?} {binding_id:?} {generation} {value_version}"
        );

        // A binding with its ID is accepted.
        sqlx::query(
            "UPDATE tenant_secrets SET binding='{\"hosts\":[\"api.example.test\"]}'::jsonb, \
             binding_id=gen_random_uuid(), binding_generation=1 WHERE key='BINDING_EXISTING'",
        )
        .execute(&pool)
        .await?;

        // The check refuses each shape that breaks it.
        for change in [
            "binding_id=NULL",
            "binding='[\"api.example.test\"]'::jsonb",
            "binding_generation=-1",
            "value_version=0",
        ] {
            let refused = constraint(
                sqlx::query(&format!(
                    "UPDATE tenant_secrets SET {change} WHERE key='BINDING_EXISTING'"
                ))
                .execute(&pool)
                .await,
            );
            anyhow::ensure!(
                refused.as_deref() == Some("tenant_secrets_binding_check"),
                "{change} was not refused: {refused:?}"
            );
        }

        // Rollback: make every bound secret plain, then drop the columns and
        // the check.
        sqlx::raw_sql(
            "UPDATE tenant_secrets SET binding=NULL; \
             ALTER TABLE tenant_secrets DROP CONSTRAINT tenant_secrets_binding_check, \
               DROP COLUMN binding, DROP COLUMN binding_id, \
               DROP COLUMN binding_generation, DROP COLUMN value_version;",
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
