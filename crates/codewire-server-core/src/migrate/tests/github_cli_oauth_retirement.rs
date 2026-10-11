//! Proof for retiring gh CLI GitHub OAuth connections before native App login.

use super::*;

const VERSION: i64 = 40;
// SHA-384 over the per-migration SHA-384 digests of up migrations 1..39 at
// main 086c8b8ca (Core #2487): the accepted prior ledger, not this branch.
const ACCEPTED_HISTORY39: &str = "a15a009b4b83c417a189094a45df0533f1d8001675a8f6d97f861f458cd4851608f889ea52376f604df49d7e544d7e7c";

pub(super) fn assert_accepted_history39() -> anyhow::Result<()> {
    platform_managed_journal_pins_accepted_history38()?;
    let prior: Vec<_> = MIGRATOR
        .iter()
        .filter(|m| m.version < VERSION && m.migration_type.is_up_migration())
        .collect();
    anyhow::ensure!(prior.len() == 39);
    let mut digest = Sha384::new();
    for (index, m) in prior.iter().enumerate() {
        anyhow::ensure!(m.version == index as i64 + 1);
        digest.update(Sha384::digest(m.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == ACCEPTED_HISTORY39,
        "accepted history 1..39 changed"
    );
    Ok(())
}

#[test]
fn github_cli_oauth_retirement_pins_accepted_history39() -> anyhow::Result<()> {
    assert_accepted_history39()
}

async fn seed_credential(
    pool: &PgPool,
    id: &str,
    user_id: &str,
    provider: &str,
    kind: &str,
    status: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO platform_credentials \
         (id, user_id, organization_id, provider, authentication_kind, display_name, \
          status, revocation_generation, material_generation) \
         VALUES ($1, $2, NULL, $3, $4, $1, $5, 1, 1)",
    )
    .bind(id)
    .bind(user_id)
    .bind(provider)
    .bind(kind)
    .bind(status)
    .execute(pool)
    .await?;
    seed_platform_credential_material(pool, id, 1).await
}

async fn seed_refresh_attempt(pool: &PgPool, credential_id: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO platform_credential_refresh_attempts \
         (credential_id, attempt_id, expected_revocation_generation, \
          expected_material_generation, state, reserved_until) \
         VALUES ($1, gen_random_uuid(), 1, 1, 'reserved', now() + interval '1 minute')",
    )
    .bind(credential_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn rows(pool: &PgPool, table: &str, column: &str) -> anyhow::Result<Vec<String>> {
    Ok(
        sqlx::query_scalar(&format!("SELECT {column} FROM {table} ORDER BY 1"))
            .fetch_all(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn github_cli_oauth_retirement_removes_only_github_oauth_and_its_dependents()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 39 && before[38].0 == 39);
        seed_platform_credential_owners(&pool).await?;
        // gh CLI GitHub logins, active and revoked, with material and a refresh
        // attempt; a GitHub App installation; another provider's OAuth login.
        seed_credential(
            &pool,
            "gh-active",
            "credential-user-a",
            "github",
            "oauth",
            "active",
        )
        .await?;
        seed_credential(
            &pool,
            "gh-revoked",
            "credential-user-b",
            "github",
            "oauth",
            "revoked",
        )
        .await?;
        seed_refresh_attempt(&pool, "gh-active").await?;
        seed_credential(
            &pool,
            "gh-app",
            "credential-user-a",
            "github",
            "github_app",
            "active",
        )
        .await?;
        seed_credential(
            &pool,
            "codex",
            "credential-user-a",
            "openai",
            "oauth",
            "active",
        )
        .await?;
        seed_refresh_attempt(&pool, "codex").await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(
            after.len()
                == MIGRATOR
                    .iter()
                    .filter(|m| m.migration_type.is_up_migration())
                    .count()
                && after[..39] == before
                && after[39].0 == VERSION
        );
        anyhow::ensure!(rows(&pool, "platform_credentials", "id").await? == ["codex", "gh-app"]);
        anyhow::ensure!(
            rows(&pool, "platform_credential_material", "credential_id").await?
                == ["codex", "gh-app"]
        );
        anyhow::ensure!(
            rows(
                &pool,
                "platform_credential_refresh_attempts",
                "credential_id"
            )
            .await?
                == ["codex"]
        );
        // The owner connects GitHub again under the unchanged singleton index.
        seed_credential(
            &pool,
            "gh-new",
            "credential-user-a",
            "github",
            "oauth",
            "active",
        )
        .await?;
        let second = seed_credential(
            &pool,
            "gh-second",
            "credential-user-a",
            "github",
            "oauth",
            "active",
        )
        .await
        .err()
        .context("a second active GitHub connection was accepted")?;
        anyhow::ensure!(
            second
                .downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .and_then(|error| error.code())
                .as_deref()
                == Some("23505")
        );
        pool.close().await;

        // Applying the schema again is a no-op.
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
