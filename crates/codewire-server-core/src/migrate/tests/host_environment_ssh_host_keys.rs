//! Host environments' SSH host keys (0068, #3609 slice 3): one key per
//! environment and operation generation, an exact ed25519 key line, a
//! positive generation, rows that go with their environment and with their
//! host, and a rollback that restores the shape before 0068.

use super::*;

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

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

async fn record(
    pool: &PgPool,
    environment: &str,
    generation: i64,
    key: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO host_environment_ssh_host_keys \
         (environment_id, operation_generation, host_id, public_key) \
         VALUES ($1, $2, (SELECT id FROM hosts WHERE name = 'keys-box'), $3)",
    )
    .bind(environment)
    .bind(generation)
    .bind(key)
    .execute(pool)
    .await
}

async fn keys(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM host_environment_ssh_host_keys")
            .fetch_one(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn host_environment_ssh_host_keys_are_written_once_bounded_owned_and_roll_back()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let before = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 68)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        before.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&db.url)
            .await?;
        let previous = fingerprint(&pool).await?;
        sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version <= 68)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        }
        .run(&pool)
        .await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        sqlx::query("INSERT INTO users (id, email) VALUES ('keys-owner', 'keys@example.test')")
            .execute(&pool)
            .await?;
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('keys-org', 'Keys', 'keys-org', 'keys-owner')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, \
             public_key) VALUES ('keys-org', 'keys-owner', 'keys-box', 'linux-x86_64-kvm', 3, \
             decode(repeat('07', 32), 'hex'))",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
             VALUES ('keys-preset', 'keys-org', 'Preset', 'ready', '{}'::jsonb)",
        )
        .execute(&pool)
        .await?;
        for id in ["keys-env-1", "keys-env-2"] {
            sqlx::query(
                "INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) \
                 VALUES ($1, 'keys-org', 'keys-owner', 'sandbox', 'keys-preset', '{}'::jsonb)",
            )
            .bind(id)
            .execute(&pool)
            .await?;
        }

        // One key per environment and operation generation.
        record(&pool, "keys-env-1", 1, KEY).await?;
        record(&pool, "keys-env-1", 2, OTHER_KEY).await?;
        anyhow::ensure!(
            constraint(record(&pool, "keys-env-1", 1, OTHER_KEY).await).as_deref()
                == Some("host_environment_ssh_host_keys_pkey")
        );
        // A positive generation, and exactly one ed25519 key line.
        anyhow::ensure!(
            constraint(record(&pool, "keys-env-2", 0, KEY).await).as_deref()
                == Some("host_environment_ssh_host_keys_generation_check")
        );
        for bad in [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
            "ssh-ed25519 AAAA",
            &format!("{KEY} comment"),
            &format!("{KEY}\n"),
        ] {
            anyhow::ensure!(
                constraint(record(&pool, "keys-env-2", 1, bad).await).as_deref()
                    == Some("host_environment_ssh_host_keys_public_key_check"),
                "{bad:?}"
            );
        }
        record(&pool, "keys-env-2", 1, KEY).await?;
        anyhow::ensure!(keys(&pool).await? == 3);

        // Rows go with their environment, and with their host.
        sqlx::query("DELETE FROM environments WHERE id = 'keys-env-1'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(keys(&pool).await? == 1);
        sqlx::query("DELETE FROM hosts WHERE name = 'keys-box'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(keys(&pool).await? == 0);

        // The rollback restores the shape before 0068.
        sqlx::query("DROP TABLE host_environment_ssh_host_keys")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
