//! Legal page slugs (0017, the public /privacy and /terms pages): the
//! database's route-slug check reserves `privacy` and `terms` as
//! `RESERVED_ORGANIZATION_SLUGS` does. An upgrade from 0016 fails, changing
//! nothing, while an organization still uses either slug; once none does it
//! keeps every row and refuses both slugs; the rollback (the 0016 check)
//! restores the 0016 shape.

use super::*;

/// The route-slug check as 0001_baseline.sql creates it, the shape before
/// 0017.
const BASELINE_CHECK: &str = "ALTER TABLE organizations ADD CONSTRAINT organizations_route_slug_check CHECK ((((length(slug) >= 3) AND (length(slug) <= 48)) AND (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'::text) AND (slug <> ALL (ARRAY['accept-invite'::text, 'admin'::text, 'api'::text, 'assets'::text, 'auth'::text, 'connect'::text, 'dashboard'::text, 'device'::text, 'docs'::text, 'forgot-password'::text, 'grpc'::text, 'healthz'::text, 'login'::text, 'oauth'::text, 'organizations'::text, 'preview'::text, 'reset-password'::text, 'settings'::text, 'setup-2fa'::text, 'signup'::text, 'ssh-proxy'::text, 'terminal'::text, 'two-factor'::text, 'verify-email'::text]))))";

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

/// Creates an organization with this slug; the error names the refusing
/// constraint.
async fn create(pool: &PgPool, slug: &str) -> Result<(), Option<String>> {
    sqlx::query(
        "INSERT INTO organizations (id, name, slug, created_by) \
         VALUES ($1, 'Legal slugs', $1, 'legal-slug-owner')",
    )
    .bind(slug)
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
async fn legal_page_slugs_upgrade_refuses_privacy_and_terms_and_rolls_back() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0017, where `privacy` is still a valid slug.
        let mut connection = PgConnection::connect(&db.url).await?;
        through(16).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query(
            "INSERT INTO users (id, email) VALUES ('legal-slug-owner', 'owner@example.test')",
        )
        .execute(&pool)
        .await?;
        create(&pool, "acme")
            .await
            .map_err(|c| anyhow::anyhow!("acme: {c:?}"))?;
        create(&pool, "privacy")
            .await
            .map_err(|c| anyhow::anyhow!("privacy before 0017: {c:?}"))?;
        let previous = fingerprint(&pool).await?;

        // An organization on a newly reserved slug stops the upgrade, which
        // changes nothing.
        let refused = through(17).run(&pool).await;
        anyhow::ensure!(
            refused.is_err(),
            "0017 applied over an organization named privacy"
        );
        let ledger: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(ledger == 16, "a refused 0017 is not recorded: {ledger}");
        anyhow::ensure!(fingerprint(&pool).await? == previous);

        // Renamed, the upgrade applies and keeps every row.
        sqlx::query("UPDATE organizations SET slug = 'privacy-team' WHERE slug = 'privacy'")
            .execute(&pool)
            .await?;
        let before: Vec<(String, String)> =
            sqlx::query_as("SELECT id, slug FROM organizations ORDER BY id")
                .fetch_all(&pool)
                .await?;
        through(17).run(&pool).await?;
        let after: Vec<(String, String)> =
            sqlx::query_as("SELECT id, slug FROM organizations ORDER BY id")
                .fetch_all(&pool)
                .await?;
        anyhow::ensure!(after == before, "0017 changes no row");
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // The database refuses exactly what the services refuse.
        for slug in ["privacy", "terms"] {
            let refusal = create(&pool, slug).await;
            anyhow::ensure!(
                refusal == Err(Some("organizations_route_slug_check".to_owned())),
                "{slug}: {refusal:?}"
            );
            anyhow::ensure!(!crate::organization_slug::valid_organization_slug(slug));
        }
        for slug in ["legal", "terms-of-use", "privacy2"] {
            create(&pool, slug)
                .await
                .map_err(|c| anyhow::anyhow!("{slug}: {c:?}"))?;
            anyhow::ensure!(crate::organization_slug::valid_organization_slug(slug));
        }
        sqlx::query(
            "DELETE FROM organizations WHERE slug IN ('legal', 'terms-of-use', 'privacy2')",
        )
        .execute(&pool)
        .await?;

        // Rollback: the 0016 check restores the 0016 shape.
        sqlx::query("ALTER TABLE organizations DROP CONSTRAINT organizations_route_slug_check")
            .execute(&pool)
            .await?;
        sqlx::query(BASELINE_CHECK).execute(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
