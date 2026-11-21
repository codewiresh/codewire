//! Credential names per provider (0043, #4928): the upgrade keeps every row,
//! a name stays unique within one owner's provider ignoring case, two
//! providers may share it, and the rollback fails until no two do.

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

#[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
struct CredentialRow {
    id: String,
    user_id: Option<String>,
    organization_id: Option<String>,
    provider: String,
    display_name: String,
}

async fn credentials(pool: &PgPool) -> anyhow::Result<Vec<CredentialRow>> {
    Ok(sqlx::query_as(
        "SELECT id, user_id, organization_id, provider, display_name \
         FROM platform_credentials ORDER BY id",
    )
    .fetch_all(pool)
    .await?)
}

/// Inserts one metadata row; no material is needed for the name indexes. An
/// API key avoids the SSH key columns and the one-GitHub-sign-in index.
async fn insert(
    pool: &PgPool,
    id: &str,
    owner: (&str, &str),
    provider: &str,
    name: &str,
) -> Result<(), sqlx::Error> {
    let (user_id, organization_id) = match owner {
        ("user", owner) => (Some(owner), None),
        (_, owner) => (None, Some(owner)),
    };
    sqlx::query(
        "INSERT INTO platform_credentials \
         (id, user_id, organization_id, provider, authentication_kind, display_name, \
          status, revocation_generation, material_generation) \
         VALUES ($1, $2, $3, $4, 'api_key', $5, 'active', 1, 1)",
    )
    .bind(id)
    .bind(user_id)
    .bind(organization_id)
    .bind(provider)
    .bind(name)
    .execute(pool)
    .await
    .map(|_| ())
}

fn unique_violation(result: &Result<impl std::fmt::Debug, sqlx::Error>, index: &str) -> bool {
    matches!(result, Err(sqlx::Error::Database(error))
        if error.code().as_deref() == Some("23505") && error.constraint() == Some(index))
}

const USER: (&str, &str) = ("user", "names-user");
const ORGANIZATION: (&str, &str) = ("organization", "names-org");
const USER_INDEX: &str = "platform_credentials_user_provider_display_name_key";
const ORGANIZATION_INDEX: &str = "platform_credentials_organization_provider_display_name_key";
const OLD_USER_INDEX: &str = "CREATE UNIQUE INDEX platform_credentials_user_display_name_key \
     ON public.platform_credentials (user_id, lower(display_name)) WHERE user_id IS NOT NULL";
const OLD_ORGANIZATION_INDEX: &str = "CREATE UNIQUE INDEX platform_credentials_organization_display_name_key \
     ON public.platform_credentials (organization_id, lower(display_name)) \
     WHERE organization_id IS NOT NULL";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn credential_names_are_unique_per_provider_and_the_rollback_needs_distinct_names()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(42).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        for statement in [
            "INSERT INTO users (id, email) VALUES ('names-user', 'names-user@example.test')",
            "INSERT INTO organizations (id, name, slug, created_by) \
             VALUES ('names-org', 'Names', 'names', 'names-user')",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        // Before 0043 one owner's names are unique across providers: these
        // are the shapes an upgraded database already holds.
        for (id, owner, provider, name) in [
            ("user-openai", USER, "openai", "n@example.com"),
            ("user-anthropic", USER, "anthropic", "Work"),
            ("user-github-literal", USER, "github", "github/work"),
            ("org-openai", ORGANIZATION, "openai", "n@example.com"),
            ("org-anthropic", ORGANIZATION, "anthropic", "Team"),
        ] {
            insert(&pool, id, owner, provider, name).await?;
        }
        anyhow::ensure!(
            unique_violation(
                &insert(&pool, "before", USER, "anthropic", "N@EXAMPLE.COM").await,
                "platform_credentials_user_display_name_key"
            ),
            "before 0043 a name is unique across one owner's providers"
        );
        let rows = credentials(&pool).await?;
        let previous = fingerprint(&pool).await?;

        through(43).run(&pool).await?;
        anyhow::ensure!(credentials(&pool).await? == rows, "0043 keeps every row");
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // Within one owner's provider a name stays unique, ignoring case.
        for (id, owner, provider, name, index) in [
            ("dup-user", USER, "openai", "N@Example.COM", USER_INDEX),
            ("dup-user-anthropic", USER, "anthropic", "wORK", USER_INDEX),
            (
                "dup-org",
                ORGANIZATION,
                "openai",
                "N@EXAMPLE.COM",
                ORGANIZATION_INDEX,
            ),
        ] {
            anyhow::ensure!(
                unique_violation(&insert(&pool, id, owner, provider, name).await, index),
                "{id} was not refused by {index}"
            );
        }
        // Another provider may share it, in any case; so may another owner.
        for (id, owner, provider, name) in [
            ("user-anthropic-email", USER, "anthropic", "N@EXAMPLE.com"),
            ("user-github-email", USER, "github", "n@example.com"),
            ("user-github-work", USER, "github", "work"),
            (
                "org-anthropic-email",
                ORGANIZATION,
                "anthropic",
                "n@EXAMPLE.com",
            ),
        ] {
            insert(&pool, id, owner, provider, name).await?;
        }
        // A rename meets the same index as an insert.
        anyhow::ensure!(
            unique_violation(
                &sqlx::query(
                    "UPDATE platform_credentials SET display_name = 'WORK' \
                     WHERE id = 'user-github-literal'",
                )
                .execute(&pool)
                .await,
                USER_INDEX
            ),
            "a rename into a provider's taken name was accepted"
        );

        // Rollback: the old indexes cannot be rebuilt while two providers of
        // one owner share a name; renaming one of each pair lets them.
        anyhow::ensure!(
            unique_violation(
                &sqlx::query(OLD_USER_INDEX).execute(&pool).await,
                "platform_credentials_user_display_name_key"
            ),
            "the user rollback index was built over shared names"
        );
        anyhow::ensure!(
            unique_violation(
                &sqlx::query(OLD_ORGANIZATION_INDEX).execute(&pool).await,
                "platform_credentials_organization_display_name_key"
            ),
            "the organization rollback index was built over shared names"
        );
        for id in [
            "user-anthropic-email",
            "user-github-email",
            "user-github-work",
            "org-anthropic-email",
        ] {
            sqlx::query("DELETE FROM platform_credentials WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await?;
        }
        for statement in [
            OLD_USER_INDEX,
            OLD_ORGANIZATION_INDEX,
            "DROP INDEX public.platform_credentials_user_provider_display_name_key",
            "DROP INDEX public.platform_credentials_organization_provider_display_name_key",
        ] {
            sqlx::query(statement).execute(&pool).await?;
        }
        anyhow::ensure!(credentials(&pool).await? == rows);
        anyhow::ensure!(fingerprint(&pool).await? == previous);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
