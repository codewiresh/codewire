//! Systemd environments (0044, #5638): an upgrade from the migration before
//! it leaves every existing organization out and every existing environment
//! an ordinary one, and new rows start the same way. Its rollback (drop the
//! columns) restores the earlier schema.

use super::*;

const VERSION: i64 = 44;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// The history up to, or through, this migration, chosen by version so the
/// test does not depend on how many migrations come before it.
fn history(through: bool) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .take_while(|migration| {
                    migration.version < VERSION || (through && migration.version == VERSION)
                })
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn systemd_upgrade_leaves_every_organization_out_and_environment_ordinary()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        anyhow::ensure!(
            MIGRATOR
                .iter()
                .any(|migration| migration.version == VERSION),
            "migration {VERSION} is not embedded"
        );
        // The shape before 0044, with organizations.
        let mut connection = PgConnection::connect(&db.url).await?;
        history(false).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_platform_credential_owners(&pool).await?;
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('systemd-org','Org','systemd-org','credential-user-a'); \
             INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
             VALUES ('systemd-preset','systemd-org','P','p', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
             INSERT INTO environments(id,org_id,created_by,preset_id,type,state,desired_state, \
             project_spec) \
             VALUES ('systemd-env','systemd-org','credential-user-a','systemd-preset', \
             'sandbox','stopped','stopped', \
             '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb);",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        anyhow::ensure!(previous != ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        let organizations: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            organizations > 0,
            "the upgrade needs existing organizations"
        );

        // Through 0044 only, so its rollback restores the earlier shape; later
        // migrations prove their own upgrade and rollback.
        history(true).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);
        let opted_in: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organizations WHERE systemd_environments_enabled",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(opted_in == 0, "{opted_in} organizations were opted in");
        let systemd: i64 =
            sqlx::query_scalar("SELECT count(*) FROM environments WHERE systemd_workspace")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(
            systemd == 0,
            "{systemd} environments became systemd workspaces"
        );
        let null =
            sqlx::query("UPDATE environments SET systemd_workspace=NULL WHERE id='systemd-env'")
                .execute(&pool)
                .await
                .expect_err("systemd_workspace is never null");
        anyhow::ensure!(
            null.as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23502")
        );
        // A new organization starts out, and the column is never null.
        sqlx::raw_sql(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('systemd-new-org','New','systemd-new-org','credential-user-a');",
        )
        .execute(&pool)
        .await?;
        let new: bool = sqlx::query_scalar(
            "SELECT systemd_environments_enabled FROM organizations WHERE id='systemd-new-org'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(!new);
        let null = sqlx::query(
            "UPDATE organizations SET systemd_environments_enabled=NULL \
             WHERE id='systemd-new-org'",
        )
        .execute(&pool)
        .await
        .expect_err("systemd_environments_enabled is never null");
        anyhow::ensure!(
            null.as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23502")
        );

        // Rollback: dropping the columns restores the earlier schema.
        sqlx::raw_sql(
            "DELETE FROM organizations WHERE id='systemd-new-org'; \
             ALTER TABLE organizations DROP COLUMN systemd_environments_enabled; \
             ALTER TABLE environments DROP COLUMN systemd_workspace;",
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
