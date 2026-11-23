//! Sandbox identity (0050, #4663, #4664; docs/dev/SANDBOX-IDENTITY.md): the
//! upgrade from 0049 keeps every environment and adds four empty tables; their
//! checks hold; each registration takes a new version from the sequence, a
//! registration made again after its removal included; groups and stops go
//! with their Sandbox while its mints stay; the rollback restores the 0049
//! shape.

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

/// Whether `statement` is refused by `constraint`.
async fn refused_by(pool: &PgPool, statement: &str, constraint: &str) -> anyhow::Result<bool> {
    Ok(match sqlx::query(statement).execute(pool).await {
        Err(sqlx::Error::Database(error)) => error.constraint() == Some(constraint),
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    })
}

async fn count(pool: &PgPool, table: &str) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn sandbox_identity_upgrade_is_checked_cascades_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(49).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('sid-org','Org','sid-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('sid-preset','sid-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec) \
             VALUES ('sid-env','sid-org','credential-user-a','sid-preset', \
             'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb), \
             ('sid-env-2','sid-org','credential-user-a','sid-preset', \
             'sandbox','running','started', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        through(50).run(&pool).await?;
        anyhow::ensure!(count(&pool, "environments").await? == 2);
        for table in [
            "environment_identity_groups",
            "identity_audiences",
            "identity_minting_stops",
            "identity_mints",
        ] {
            anyhow::ensure!(count(&pool, table).await? == 0, "{table} starts empty");
        }

        // Groups: at most 32 on a Sandbox, and a version above zero.
        sqlx::query(
            "INSERT INTO environment_identity_groups (environment_id, groups, version, updated_by) \
             VALUES ('sid-env', $1, 1, 'credential-user-a')",
        )
        .bind((0..32).map(|index| format!("g{index}")).collect::<Vec<_>>())
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            refused_by(
                &pool,
                "UPDATE environment_identity_groups SET groups = groups || '{g32}'::text[]",
                "environment_identity_groups_count",
            )
            .await?,
            "a 33rd group is refused"
        );
        anyhow::ensure!(
            refused_by(
                &pool,
                "UPDATE environment_identity_groups SET version = 0",
                "environment_identity_groups_version",
            )
            .await?,
            "version 0 is refused"
        );
        anyhow::ensure!(
            refused_by(
                &pool,
                "INSERT INTO environment_identity_groups (environment_id, groups, version, updated_by) \
                 VALUES ('no-such-env', '{}', 1, 'credential-user-a')",
                "environment_identity_groups_environment_fkey",
            )
            .await?,
            "groups name an existing environment"
        );

        // Audiences: one per organization, a lifetime of one to ten minutes,
        // and a file name used once in an organization. The version is the
        // sequence's, never the writer's.
        let audience = |audience: &str, lifetime: i32, file: Option<&str>| {
            format!(
                "INSERT INTO identity_audiences (org_id, audience, lifetime_seconds, file_name, \
                 created_by) VALUES ('sid-org', '{audience}', {lifetime}, {}, \
                 'credential-user-a')",
                file.map_or_else(|| "NULL".to_owned(), |file| format!("'{file}'"))
            )
        };
        sqlx::query(&audience("https://a.example", 60, Some("a")))
            .execute(&pool)
            .await?;
        sqlx::query(&audience("https://b.example", 600, None))
            .execute(&pool)
            .await?;
        sqlx::query(&audience("https://c.example", 300, None))
            .execute(&pool)
            .await?;
        let version = |audience: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "SELECT version FROM identity_audiences WHERE audience = $1",
                )
                .bind(audience)
                .fetch_one(&pool)
                .await
            }
        };
        let (a, b, c) = (
            version("https://a.example").await?,
            version("https://b.example").await?,
            version("https://c.example").await?,
        );
        anyhow::ensure!(0 < a && a < b && b < c, "versions rise: {a}, {b}, {c}");
        sqlx::query("DELETE FROM identity_audiences WHERE audience = 'https://b.example'")
            .execute(&pool)
            .await?;
        sqlx::query(&audience("https://b.example", 600, None))
            .execute(&pool)
            .await?;
        let again = version("https://b.example").await?;
        anyhow::ensure!(again > c, "registered again, it is not {b} but a new version: {again}");
        let (visible, lifetime, created_by, environment_name): (
            Option<Vec<String>>,
            i32,
            bool,
            bool,
        ) = sqlx::query_as(
            "SELECT visible_groups, lifetime_seconds, claim_created_by, claim_environment_name \
             FROM identity_audiences WHERE audience = 'https://b.example'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            (visible, lifetime, created_by, environment_name) == (None, 600, false, false),
            "a registration sees every group and opts in to no claim by default"
        );
        anyhow::ensure!(
            refused_by(
                &pool,
                &audience("https://a.example", 600, None),
                "identity_audiences_pkey"
            )
            .await?,
            "an audience is registered once per organization"
        );
        anyhow::ensure!(
            refused_by(
                &pool,
                &audience("https://d.example", 600, Some("a")),
                "identity_audiences_file_name_key"
            )
            .await?,
            "a file name is used once per organization"
        );
        for seconds in [0, 59, 601] {
            anyhow::ensure!(
                refused_by(
                    &pool,
                    &audience("https://e.example", seconds, None),
                    "identity_audiences_lifetime"
                )
                .await?,
                "a lifetime of {seconds} seconds is refused"
            );
        }

        // Stops: one row stops the organization, and one per Sandbox.
        sqlx::raw_sql(
            "INSERT INTO identity_minting_stops (org_id, environment_id, stopped_by) \
             VALUES ('sid-org', NULL, 'credential-user-a'), \
             ('sid-org', 'sid-env', 'credential-user-a');",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            refused_by(
                &pool,
                "INSERT INTO identity_minting_stops (org_id, environment_id, stopped_by) \
                 VALUES ('sid-org', NULL, 'credential-user-a')",
                "identity_minting_stops_org_key",
            )
            .await?,
            "an organization is stopped once"
        );
        anyhow::ensure!(
            refused_by(
                &pool,
                "INSERT INTO identity_minting_stops (org_id, environment_id, stopped_by) \
                 VALUES ('sid-org', 'sid-env', 'credential-user-a')",
                "identity_minting_stops_environment_key",
            )
            .await?,
            "a Sandbox is stopped once"
        );

        // Mints are kept after their Sandbox; its groups and stop are not.
        sqlx::query(
            "INSERT INTO identity_mints (jti, environment_id, org_id, audience, kid, \
             groups_version, audience_version) VALUES ('jti-1', 'sid-env', 'sid-org', \
             'https://a.example', 'sandbox-identity-1', 1, 1)",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(
            refused_by(
                &pool,
                "INSERT INTO identity_mints (jti, environment_id, org_id, audience, kid, \
                 groups_version, audience_version) VALUES ('jti-1', 'sid-env', 'sid-org', \
                 'https://a.example', 'sandbox-identity-1', 1, 1)",
                "identity_mints_pkey",
            )
            .await?,
            "a jti is logged once"
        );
        sqlx::query("DELETE FROM environments WHERE id = 'sid-env'")
            .execute(&pool)
            .await?;
        anyhow::ensure!(count(&pool, "environment_identity_groups").await? == 0);
        anyhow::ensure!(count(&pool, "identity_minting_stops").await? == 1);
        anyhow::ensure!(count(&pool, "identity_mints").await? == 1);

        // Rollback: drop the four tables.
        sqlx::raw_sql(
            "DROP TABLE public.identity_mints; \
             DROP TABLE public.identity_minting_stops; \
             DROP TABLE public.identity_audiences; \
             DROP SEQUENCE public.identity_audience_versions; \
             DROP TABLE public.environment_identity_groups;",
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
