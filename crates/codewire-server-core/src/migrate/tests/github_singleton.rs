//! Proof for the account-level GitHub singleton that every personal profile includes.

use super::*;

const VERSION: i64 = 29;
// SHA-384 measured from migration28 at accepted canonical
// 01c315c18bd48dd4a0b80226f32d904ee311cfab. This pins the staged predecessor
// bytes; it does not claim version28 alone was deployed.
const ACCEPTED_STAGED28: &str = "cbd725bc78e4c8ab5a2e1b68798ac3143fab453755bf7c8e09767af689b46f6e0dfc3dc86645cd4a356a20074cb9869f";

pub(super) fn assert_accepted_staged28() -> anyhow::Result<()> {
    let migration = MIGRATOR
        .iter()
        .find(|migration| migration.version == 28)
        .context("accepted staged migration28 missing")?;
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(migration.sql.as_bytes())) == ACCEPTED_STAGED28,
        "migration28 differs from accepted canonical 01c315c18"
    );
    Ok(())
}

#[test]
fn github_singleton_upgrade_retains_accepted_staged28() -> anyhow::Result<()> {
    session_mutation::assert_accepted_staged27()?;
    assert_accepted_staged28()
}

async fn seed_github(pool: &PgPool, id: &str, user_id: &str, status: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO platform_credentials \
         (id, user_id, organization_id, provider, authentication_kind, display_name, \
          status, revocation_generation, material_generation) \
         VALUES ($1, $2, NULL, 'github', 'oauth', $1, $3, 1, 1)",
    )
    .bind(id)
    .bind(user_id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

/// One profile with explicit historical revisions. Each revision lists its
/// `(slot, credential)` entries; the last revision is current.
async fn seed_profile(
    pool: &PgPool,
    id: &str,
    user_id: &str,
    revisions: &[&[(&str, &str)]],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO platform_access_profiles (id, user_id, name, current_revision) \
         VALUES ($1, $2, $1, $3)",
    )
    .bind(id)
    .bind(user_id)
    .bind(revisions.len() as i64)
    .execute(&mut *tx)
    .await?;
    for (index, entries) in revisions.iter().enumerate() {
        let revision = index as i64 + 1;
        sqlx::query(
            "INSERT INTO platform_access_profile_revisions (profile_id, revision) VALUES ($1, $2)",
        )
        .bind(id)
        .bind(revision)
        .execute(&mut *tx)
        .await?;
        for (slot, credential) in *entries {
            sqlx::query(
                "INSERT INTO platform_access_profile_entries \
                 (profile_id, revision, capability_slot, credential_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(id)
            .bind(revision)
            .bind(slot)
            .bind(credential)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn singleton_index_present(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT to_regclass('public.platform_credentials_user_github_singleton_key') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?)
}

async fn entries(pool: &PgPool) -> anyhow::Result<Vec<(String, i64, String, String)>> {
    Ok(sqlx::query_as(
        "SELECT profile_id, revision, capability_slot, credential_id \
           FROM platform_access_profile_entries ORDER BY 1, 2, 3",
    )
    .fetch_all(pool)
    .await?)
}

/// Legacy GitHub entries on current and historical revisions, an obsolete
/// revoked GitHub row, the one active GitHub row, and an unrelated Codex entry.
async fn seed_legacy_github(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    seed_platform_credential(pool, "codex-a", Some("credential-user-a"), None, "Codex").await?;
    seed_github(pool, "github-active", "credential-user-a", "active").await?;
    seed_github(pool, "github-revoked", "credential-user-a", "revoked").await?;
    seed_profile(
        pool,
        "work",
        "credential-user-a",
        &[
            &[("codex", "codex-a"), ("github", "github-revoked")],
            &[("codex", "codex-a")],
            &[("github", "github-active")],
        ],
    )
    .await?;
    seed_profile(
        pool,
        "plain",
        "credential-user-a",
        &[&[("codex", "codex-a")]],
    )
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn github_singleton_staged_upgrade_drops_pinned_entries_and_enforces_one_connection()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 28 && before[27].0 == 28);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=28 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED28);
        seed_legacy_github(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(
            after.len() == MIGRATOR.iter().filter(|m| m.migration_type.is_up_migration()).count()
                && after[..28] == before
                && after[28].0 == VERSION
        );
        // Pinned GitHub credential IDs are discarded; other entries remain.
        anyhow::ensure!(
            entries(&pool).await?
                == vec![
                    ("plain".into(), 1, "codex".into(), "codex-a".into()),
                    ("work".into(), 1, "codex".into(), "codex-a".into()),
                    ("work".into(), 2, "codex".into(), "codex-a".into()),
                ]
        );
        let current_revision: i64 = sqlx::query_scalar(
            "SELECT current_revision FROM platform_access_profiles WHERE id='work'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(current_revision == 3, "migration must not create revisions");
        // The obsolete revoked row is gone; the active connection is kept.
        let github: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, status FROM platform_credentials WHERE provider='github' ORDER BY id",
        )
        .fetch_all(&pool)
        .await?;
        anyhow::ensure!(github == vec![("github-active".into(), "active".into())]);

        // A profile can never pin GitHub again.
        let entry = sqlx::query(
            "INSERT INTO platform_access_profile_entries \
             (profile_id, revision, capability_slot, credential_id) \
             VALUES ('plain', 1, 'github', 'github-active')",
        )
        .execute(&pool)
        .await
        .err()
        .context("a GitHub profile entry was accepted")?;
        anyhow::ensure!(
            entry.as_database_error().and_then(|error| error.code()).as_deref() == Some("23514")
        );
        // One active GitHub connection per user.
        let second = seed_github(&pool, "github-second", "credential-user-a", "active")
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
        // Other users and revoked rows are unaffected by the singleton index.
        seed_github(&pool, "github-user-b", "credential-user-b", "active").await?;
        seed_github(&pool, "github-revoked-a", "credential-user-a", "revoked").await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn github_singleton_fails_closed_on_ambiguous_connections_then_retries() -> anyhow::Result<()>
{
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed_legacy_github(&pool).await?;
        // A second active connection for one user is ambiguous. The migration
        // must never choose a winner.
        seed_github(&pool, "github-duplicate", "credential-user-a", "active").await?;
        let before = applied_migrations(&pool).await?;
        let entries_before = entries(&pool).await?;
        pool.close().await;

        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("ambiguous GitHub connections were migrated")?;
        anyhow::ensure!(format!("{error:#}").contains("multiple active GitHub credentials"));
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == before);
        anyhow::ensure!(!singleton_index_present(&pool).await?);
        anyhow::ensure!(entries(&pool).await? == entries_before);
        let github: i64 =
            sqlx::query_scalar("SELECT count(*) FROM platform_credentials WHERE provider='github'")
                .fetch_one(&pool)
                .await?;
        anyhow::ensure!(github == 3, "failed migration removed GitHub rows");

        // The operator resolves the ambiguity explicitly, then retries.
        sqlx::query("DELETE FROM platform_credentials WHERE id='github-duplicate'")
            .execute(&pool)
            .await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(singleton_index_present(&pool).await?);
        anyhow::ensure!(
            applied_migrations(&pool).await?.len()
                == MIGRATOR
                    .iter()
                    .filter(|m| m.migration_type.is_up_migration())
                    .count()
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn github_singleton_rollback_replays_staged28_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let admin = std::env::var("TEST_DATABASE_URL").context("TEST_DATABASE_URL required")?;
    let db = TestDatabase::create(&admin).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(singleton_index_present(&pool).await?);
        seed_platform_credential_owners(&pool).await?;
        seed_github(&pool, "github-discarded", "credential-user-a", "active").await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;

        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 28 && ledger[27].0 == 28);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=28 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == ACCEPTED_STAGED28);
        anyhow::ensure!(!singleton_index_present(&pool).await?);
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS(SELECT 1 FROM public.platform_credentials)",
            )
            .fetch_one(&pool)
            .await?
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, i32>("SELECT id FROM rollback_boundary.keep")
                .fetch_one(&pool)
                .await?
                == 1
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
