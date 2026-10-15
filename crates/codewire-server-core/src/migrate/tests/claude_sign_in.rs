//! Proof for the Claude sign-in credential kind (#2559).

use super::*;

const VERSION: i64 = 41;
// SHA-384 over the per-migration SHA-384 digests of up migrations 1..40 at
// main e8e54d1bc: the accepted prior ledger, not this branch.
const ACCEPTED_HISTORY40: &str = "eccd642f0b1f8e966233643ef4efbbef7c8958e814af094510641d6219a1c9c6efc9cee8825c06b3fdad7147bd00e396";
const DOWN_SQL: &str = include_str!("../../../migrations/0041_claude_sign_in_credentials.down.sql");

pub(super) fn assert_accepted_history40() -> anyhow::Result<()> {
    github_cli_oauth_retirement::assert_accepted_history39()?;
    let prior: Vec<_> = MIGRATOR
        .iter()
        .filter(|m| m.version < VERSION && m.migration_type.is_up_migration())
        .collect();
    anyhow::ensure!(prior.len() == 40);
    let mut digest = Sha384::new();
    for (index, m) in prior.iter().enumerate() {
        anyhow::ensure!(m.version == index as i64 + 1);
        digest.update(Sha384::digest(m.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == ACCEPTED_HISTORY40,
        "accepted history 1..40 changed"
    );
    Ok(())
}

#[test]
fn claude_sign_in_pins_accepted_history40() -> anyhow::Result<()> {
    assert_accepted_history40()
}

async fn seed(
    pool: &PgPool,
    id: &str,
    user_id: Option<&str>,
    organization_id: Option<&str>,
    provider: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO platform_credentials \
         (id, user_id, organization_id, provider, authentication_kind, display_name, \
          status, revocation_generation, material_generation) \
         VALUES ($1, $2, $3, $4, $5, $1, 'active', 1, 1)",
    )
    .bind(id)
    .bind(user_id)
    .bind(organization_id)
    .bind(provider)
    .bind(kind)
    .execute(pool)
    .await
    .map(|_| ())
}

fn check_violation(result: Result<(), sqlx::Error>) -> anyhow::Result<()> {
    let error = result
        .err()
        .context("an invalid Claude sign-in row was accepted")?;
    anyhow::ensure!(
        error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("23514"),
        "unexpected rejection: {error}"
    );
    Ok(())
}

async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT to_jsonb(c)::text FROM platform_credentials c ORDER BY id")
            .fetch_all(pool)
            .await?,
    )
}

async fn kind_constraints(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conrelid = 'platform_credentials'::regclass \
           AND conname IN ('platform_credentials_authentication_kind_check', \
                           'platform_credentials_claude_sign_in_check') \
         ORDER BY conname",
    )
    .fetch_all(pool)
    .await?)
}

/// The upgrade keeps every existing row, Claude subscription tokens included,
/// admits only a person's Anthropic sign-in, and is a no-op on a second start.
/// The in-place rollback refuses while a sign-in exists and otherwise restores
/// the accepted version-40 constraint exactly.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn claude_sign_in_kind_is_additive_personal_anthropic_and_reversible_while_unused()
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
        anyhow::ensure!(before.len() == 40 && before[39].0 == 40);
        let constraints40 = kind_constraints(&pool).await?;
        anyhow::ensure!(constraints40.len() == 1);
        seed_platform_credential_owners(&pool).await?;
        // A Claude subscription token, a Codex login and an organization's
        // Anthropic API key, each with material.
        for (id, user, organization, provider, kind) in [
            (
                "setup-token",
                Some("credential-user-a"),
                None,
                "anthropic",
                "oauth",
            ),
            ("codex", Some("credential-user-a"), None, "openai", "oauth"),
            (
                "org-key",
                None,
                Some("credential-org-a"),
                "anthropic",
                "api_key",
            ),
        ] {
            seed(&pool, id, user, organization, provider, kind).await?;
            seed_platform_credential_material(&pool, id, 1).await?;
        }
        // The prior schema cannot hold a sign-in.
        check_violation(
            seed(
                &pool,
                "early",
                Some("credential-user-a"),
                None,
                "anthropic",
                "claude_sign_in",
            )
            .await,
        )?;
        let rows40 = rows(&pool).await?;
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
                && after[..40] == before
                && after[40].0 == VERSION
                && after[40].2
        );
        anyhow::ensure!(
            rows(&pool).await? == rows40,
            "upgrade changed an existing row"
        );
        let fingerprint: String = sqlx::query_scalar(include_str!(
            "../../../tests/data/application_schema_fingerprint.sql"
        ))
        .fetch_one(&pool)
        .await?;
        println!("CLAUDE_SIGN_IN_SCHEMA41_FINGERPRINT={fingerprint}");
        anyhow::ensure!(
            fingerprint == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "version-41 schema changed: {fingerprint}"
        );

        // Only a person's Anthropic credential can be a sign-in.
        seed(
            &pool,
            "sign-in",
            Some("credential-user-b"),
            None,
            "anthropic",
            "claude_sign_in",
        )
        .await?;
        seed_platform_credential_material(&pool, "sign-in", 1).await?;
        check_violation(
            seed(
                &pool,
                "org-sign-in",
                None,
                Some("credential-org-a"),
                "anthropic",
                "claude_sign_in",
            )
            .await,
        )?;
        check_violation(
            seed(
                &pool,
                "openai-sign-in",
                Some("credential-user-a"),
                None,
                "openai",
                "claude_sign_in",
            )
            .await,
        )?;
        check_violation(
            seed(
                &pool,
                "unknown-kind",
                Some("credential-user-a"),
                None,
                "anthropic",
                "claude",
            )
            .await,
        )?;
        pool.close().await;

        // A second start applies nothing.
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);

        // The rollback refuses to discard a person's sign-in, changing nothing.
        anyhow::ensure!(sqlx::raw_sql(DOWN_SQL).execute(&pool).await.is_err());
        anyhow::ensure!(kind_constraints(&pool).await?.len() == 2);
        // Without one it restores the accepted version-40 constraint exactly,
        // and the existing rows are untouched.
        sqlx::query("DELETE FROM platform_credentials WHERE id = 'sign-in'")
            .execute(&pool)
            .await?;
        sqlx::raw_sql(DOWN_SQL).execute(&pool).await?;
        anyhow::ensure!(kind_constraints(&pool).await? == constraints40);
        anyhow::ensure!(rows(&pool).await? == rows40);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
