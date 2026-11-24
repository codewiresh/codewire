//! The built-in network policy `web` (0053, #3997): before it, a hosted
//! selection of `web` is refused; an upgrade with an organization policy
//! already named `web` fails and changes nothing; once none is, it keeps
//! every row, admits a `web` selection and refuses `web` as a policy's name;
//! and the rollback (0025's checks) restores the earlier shape.

use super::*;

/// This migration's version.
const VERSION: i64 = 53;

/// 0025's checks, the shape before this migration.
const PREVIOUS_CHECKS: &str = "ALTER TABLE platform_environment_network_policies \
       DROP CONSTRAINT platform_environment_network_policies_builtin_check, \
       ADD CONSTRAINT platform_environment_network_policies_builtin_check \
         CHECK (builtin = ANY (ARRAY['open'::text, 'locked'::text])); \
     ALTER TABLE platform_network_policies \
       DROP CONSTRAINT platform_network_policies_name_check, \
       ADD CONSTRAINT platform_network_policies_name_check CHECK ( \
         name ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$' \
         AND name <> ALL (ARRAY['open'::text, 'locked'::text, 'hosted-default'::text]));";

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

async fn select_builtin(pool: &PgPool, environment: &str, builtin: &str) -> Option<String> {
    constraint(
        sqlx::query(
            "INSERT INTO platform_environment_network_policies (environment_id, builtin) \
             VALUES ($1, $2)",
        )
        .bind(environment)
        .bind(builtin)
        .execute(pool)
        .await,
    )
}

async fn create_policy(pool: &PgPool, name: &str) -> Result<String, Option<String>> {
    sqlx::query_scalar(
        "INSERT INTO platform_network_policies (org_id, name, current_revision) \
         VALUES ('web-org', $1, 1) RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .map_err(|error| constraint::<()>(Err(error)))
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn network_policy_web_upgrade_admits_web_selections_reserves_the_name_and_rolls_back()
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
        sqlx::raw_sql(
            "INSERT INTO users (id, email) VALUES ('web-admin', 'web-admin@example.test'); \
             INSERT INTO organizations (id, name, slug, created_by) \
               VALUES ('web-org', 'Web', 'web-org', 'web-admin'); \
             INSERT INTO environment_presets (id, org_id, name, build_status, project_spec) \
               VALUES ('web-preset', 'web-org', 'Preset', 'ready', '{}'::jsonb); \
             INSERT INTO environments (id, org_id, created_by, type, preset_id, project_spec) VALUES \
               ('web-open', 'web-org', 'web-admin', 'sandbox', 'web-preset', '{}'::jsonb), \
               ('web-locked', 'web-org', 'web-admin', 'sandbox', 'web-preset', '{}'::jsonb), \
               ('web-web', 'web-org', 'web-admin', 'sandbox', 'web-preset', '{}'::jsonb); \
             INSERT INTO platform_environment_network_policies (environment_id, builtin) VALUES \
               ('web-open', 'open'), ('web-locked', 'locked');",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;

        // Before it, the selection table refuses `web`.
        let refused = select_builtin(&pool, "web-web", "web").await;
        anyhow::ensure!(
            refused.as_deref() == Some("platform_environment_network_policies_builtin_check"),
            "web was selectable before {VERSION}: {refused:?}"
        );

        // An organization policy already named `web` fails the upgrade, which
        // changes nothing; once it is deleted the upgrade runs.
        let named_web = create_policy(&pool, "web")
            .await
            .map_err(|refused| anyhow::anyhow!("web was refused before {VERSION}: {refused:?}"))?;
        anyhow::ensure!(
            through(VERSION).run(&pool).await.is_err(),
            "a policy named web did not fail the upgrade"
        );
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        sqlx::query("DELETE FROM platform_network_policies WHERE id = $1")
            .bind(&named_web)
            .execute(&pool)
            .await?;

        through(VERSION).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous, "{VERSION} changes the schema");
        let kept: Vec<(String, String)> = sqlx::query_as(
            "SELECT environment_id, builtin FROM platform_environment_network_policies \
             ORDER BY environment_id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(
            kept == [
                ("web-locked".to_owned(), "locked".to_owned()),
                ("web-open".to_owned(), "open".to_owned()),
            ],
            "the upgrade keeps every selection: {kept:?}"
        );

        // `web` is selectable now; a name that is no built-in still is not.
        anyhow::ensure!(select_builtin(&pool, "web-web", "web").await.is_none());
        sqlx::query("DELETE FROM platform_environment_network_policies WHERE environment_id = 'web-web'")
            .execute(&pool)
            .await?;
        for builtin in ["hosted-default", "Web", ""] {
            let refused = select_builtin(&pool, "web-web", builtin).await;
            anyhow::ensure!(
                refused.as_deref() == Some("platform_environment_network_policies_builtin_check"),
                "{builtin:?}: {refused:?}"
            );
        }

        // No policy may take a built-in's name, `web` included.
        for name in ["open", "web", "locked", "hosted-default"] {
            let refused = create_policy(&pool, name).await;
            anyhow::ensure!(
                refused == Err(Some("platform_network_policies_name_check".to_owned())),
                "{name}: {refused:?}"
            );
        }
        anyhow::ensure!(create_policy(&pool, "team-web").await.is_ok());

        // Rollback: 0025's checks, once no environment selects `web`.
        sqlx::query("UPDATE platform_environment_network_policies SET builtin = 'open' WHERE builtin = 'web'")
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM platform_network_policies WHERE name = 'team-web'")
            .execute(&pool)
            .await?;
        sqlx::raw_sql(PREVIOUS_CHECKS).execute(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
