//! The create limits against PostgreSQL (#3297): Sandbox creates stop at the
//! hourly count as well as the per-minute one, and organization creates stop
//! at the daily count, each refusing with the limit and when it resets.

use super::*;
use crate::api::organizations::create_organization;
use crate::test_database_support::TestDatabase;

async fn set_count(pool: &PgPool, name: &str, max: i32) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
         VALUES ($1, $2, 'create-limit-test')",
    )
    .bind(name)
    .bind(max)
    .execute(pool)
    .await?;
    Ok(())
}

/// The refusal's code and detail, or None when the request was admitted.
fn refusal(outcome: AppResult<()>) -> Option<(String, String)> {
    match outcome {
        Ok(()) => None,
        Err(AppError::Coded { code, detail, .. }) => Some((code.to_owned(), detail.into_owned())),
        Err(other) => Some(("other".into(), format!("{other:?}"))),
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_sandbox_creates_stop_at_the_hourly_count_under_the_per_minute_one() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = &db.pool;
        // Room a minute, two an hour: the hourly count is the one that stops.
        set_count(pool, "sandbox_create", 100).await?;
        set_count(pool, "sandbox_create_hourly", 2).await?;
        for n in 0..2 {
            anyhow::ensure!(
                refusal(take_create_limits(pool, "create-limit-user").await).is_none(),
                "create {n} was refused"
            );
        }
        let (code, detail) = refusal(take_create_limits(pool, "create-limit-user").await)
            .ok_or_else(|| anyhow::anyhow!("the third create was admitted"))?;
        anyhow::ensure!(code == "rate_limited", "{code}");
        anyhow::ensure!(
            detail.starts_with("at most 2 sandbox creates an hour; try again after "),
            "{detail}"
        );
        // Another user has their own allowance.
        anyhow::ensure!(refusal(take_create_limits(pool, "create-limit-other").await).is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Creates an organization through the same path the API does, after the
/// name and slug are valid.
async fn create_org(pool: &PgPool, user_id: &str, slug: &str) -> AppResult<()> {
    create_organization(pool, user_id, "Limit Lab", slug)
        .await
        .map(|_| ())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_organization_creates_stop_at_the_daily_count_and_a_taken_slug_spends_none()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let pool = &db.pool;
        for id in ["org-limit-user", "org-limit-other"] {
            sqlx::query(
                "INSERT INTO users (id, email, name, email_verified) \
                 VALUES ($1, $1 || '@example.test', $1, true)",
            )
            .bind(id)
            .execute(pool)
            .await?;
        }
        set_count(pool, "org_create", 2).await?;
        anyhow::ensure!(refusal(create_org(pool, "org-limit-user", "limit-lab-a").await).is_none());
        // A slug that is taken is refused before the create counts.
        match create_org(pool, "org-limit-user", "limit-lab-a").await {
            Err(AppError::Conflict(_)) => {}
            other => anyhow::bail!("a taken slug was not refused as taken: {other:?}"),
        }
        anyhow::ensure!(
            refusal(create_org(pool, "org-limit-user", "limit-lab-b").await).is_none(),
            "the taken slug spent a create"
        );
        let (code, detail) = refusal(create_org(pool, "org-limit-user", "limit-lab-c").await)
            .ok_or_else(|| anyhow::anyhow!("the third organization create was admitted"))?;
        anyhow::ensure!(code == "rate_limited", "{code}");
        anyhow::ensure!(
            detail.starts_with("at most 2 organization creates a day; try again after "),
            "{detail}"
        );
        let refused: i64 =
            sqlx::query_scalar("SELECT count(*) FROM organizations WHERE slug = 'limit-lab-c'")
                .fetch_one(pool)
                .await?;
        anyhow::ensure!(refused == 0, "the refused create wrote its organization");
        // Another user has their own allowance.
        anyhow::ensure!(
            refusal(create_org(pool, "org-limit-other", "limit-lab-d").await).is_none()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
