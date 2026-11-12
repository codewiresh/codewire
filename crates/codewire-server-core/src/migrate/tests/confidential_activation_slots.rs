//! Confidential activation slots (0018, #4281): an upgrade from the shape
//! before it adds an empty table and changes no row; a slot belongs to one
//! environment, holds a lease that ends after it starts, and goes with its
//! environment; the rollback (drop the table) restores the earlier schema.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The schema through 0018, measured on disposable PostgreSQL when 0018 was
/// the newest migration (#4295); later migrations don't change it.
const SCHEMA_THROUGH_0018_FINGERPRINT: &str =
    "4870c8102f939b14da23d5e1eeae410c991958a0502d589966d9ac75f4081f16";

fn before_0018() -> sqlx::migrate::Migrator {
    through(17)
}

/// The history up to and including `version`, so later migrations don't
/// change what this test measures.
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

/// Inserts a slot; the error names the refusing constraint.
async fn hold(pool: &PgPool, environment: &str, lease: &str) -> Result<(), Option<String>> {
    sqlx::query(&format!(
        "INSERT INTO confidential_activation_slots (environment_id, expires_at) \
         VALUES ($1, now() + interval '{lease}')"
    ))
    .bind(environment)
    .execute(pool)
    .await
    .map(drop)
    .map_err(|error| match error {
        sqlx::Error::Database(error) => error.constraint().map(str::to_owned),
        _ => None,
    })
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn confidential_activation_slots_upgrade_holds_leases_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        before_0018().run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('slots-org','Org','slots-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('slots-preset','slots-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec) \
             VALUES ('slots-env-a','slots-org','credential-user-a','slots-preset', \
             'sandbox','creating','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb), \
             ('slots-env-b','slots-org','credential-user-a','slots-preset', \
             'sandbox','starting','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        let environments: Vec<(String, String)> =
            sqlx::query_as("SELECT id, state FROM environments ORDER BY id")
                .fetch_all(&pool)
                .await?;

        through(18).run(&pool).await?;
        anyhow::ensure!(
            fingerprint(&pool).await? == SCHEMA_THROUGH_0018_FINGERPRINT,
            "0018 builds the schema accepted with it"
        );
        let slots: i64 = sqlx::query_scalar("SELECT count(*) FROM confidential_activation_slots")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(slots == 0, "the upgrade holds no slot");
        let after: Vec<(String, String)> =
            sqlx::query_as("SELECT id, state FROM environments ORDER BY id")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(after == environments, "0018 changes no environment");

        // One slot per environment, with a lease that ends after it starts.
        hold(&pool, "slots-env-a", "35 minutes")
            .await
            .map_err(|c| anyhow::anyhow!("first slot: {c:?}"))?;
        anyhow::ensure!(
            hold(&pool, "slots-env-a", "35 minutes").await
                == Err(Some("confidential_activation_slots_pkey".to_owned())),
            "an environment holds one slot"
        );
        anyhow::ensure!(
            hold(&pool, "slots-env-b", "-1 minute").await
                == Err(Some("confidential_activation_slots_lease_check".to_owned())),
            "a lease ends after it starts"
        );
        anyhow::ensure!(
            hold(&pool, "slots-missing", "35 minutes").await
                == Err(Some(
                    "confidential_activation_slots_environment_id_fkey".to_owned()
                )),
            "a slot belongs to an environment"
        );

        // A slot goes with its environment.
        sqlx::query("DELETE FROM environments WHERE id = 'slots-env-a'")
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM confidential_activation_slots")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(left == 0, "deleting the environment deletes its slot");

        // Rollback: dropping the table restores the earlier shape.
        sqlx::query("DROP TABLE confidential_activation_slots")
            .execute(&pool)
            .await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
