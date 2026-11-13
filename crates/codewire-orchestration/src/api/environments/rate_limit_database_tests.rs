//! What the shared counter promises (#3297, #3923): `max` requests in a fixed
//! window that starts at the first request, counted atomically, with the
//! admin's counts in force over the code defaults.

use super::*;
use crate::test_database_support::TestDatabase;
use chrono::{DateTime, Utc};

const SECOND: i64 = 1000;
const WINDOW_SECS: i64 = 60;
const MAX: i32 = 10;
const START: i64 = 1_793_712_000_000;

fn at(ms: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_millis(ms).unwrap()
}

async fn in_force(pool: &PgPool, user: Option<&str>) -> anyhow::Result<i32> {
    let mut connection = pool.acquire().await?;
    Ok(rate_limit::max_in_force(&mut connection, &rate_limit::SANDBOX_CREATE, user).await?)
}

async fn allowed(pool: &PgPool, key: &str, ms: i64) -> bool {
    let mut connection = pool.acquire().await.unwrap();
    rate_limit::consume(&mut connection, key, WINDOW_SECS, MAX, at(ms))
        .await
        .unwrap()
        .allowed
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_steady_caller_under_the_limit_is_never_refused() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        // One every 12 s is 5 a minute, half the limit, for 10 minutes.
        for request in 0..50 {
            let ms = START + request * 12 * SECOND;
            anyhow::ensure!(
                allowed(&db.pool, "steady", ms).await,
                "request {request} was refused at 5 a minute"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_limit_refuses_past_the_maximum_until_the_window_ends() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        for request in 0..MAX {
            let ms = START + i64::from(request) * SECOND;
            anyhow::ensure!(allowed(&db.pool, "burst", ms).await, "request {request}");
        }
        anyhow::ensure!(!allowed(&db.pool, "burst", START + 10 * SECOND).await);
        // A refused request counts but doesn't extend the wait.
        anyhow::ensure!(!allowed(&db.pool, "burst", START + 59 * SECOND).await);
        anyhow::ensure!(allowed(&db.pool, "burst", START + 61 * SECOND).await);
        // That started a new window with a full allowance.
        for request in 1..MAX {
            let ms = START + (61 + i64::from(request)) * SECOND;
            anyhow::ensure!(allowed(&db.pool, "burst", ms).await, "new window {request}");
        }
        anyhow::ensure!(!allowed(&db.pool, "burst", START + 72 * SECOND).await);
        // The refusal says when the window resets: its start plus the window.
        let mut connection = db.pool.acquire().await?;
        let refused = rate_limit::consume(
            &mut connection,
            "burst",
            WINDOW_SECS,
            MAX,
            at(START + 73 * SECOND),
        )
        .await?;
        anyhow::ensure!(refused.resets_at == at(START + 121 * SECOND), "{refused:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_each_key_has_its_own_allowance() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        for request in 0..MAX {
            anyhow::ensure!(allowed(&db.pool, "one", START).await, "request {request}");
        }
        anyhow::ensure!(!allowed(&db.pool, "one", START).await);
        anyhow::ensure!(allowed(&db.pool, "other", START).await);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_concurrent_requests_never_overshoot_the_limit() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        let attempts = (0..40).map(|_| {
            let pool = db.pool.clone();
            tokio::spawn(async move { allowed(&pool, "race", START).await })
        });
        let mut admitted = 0;
        for attempt in attempts {
            if attempt.await? {
                admitted += 1;
            }
        }
        anyhow::ensure!(admitted == MAX, "{admitted} admitted at a limit of {MAX}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_users_override_wins_over_the_global_count_and_the_default() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        sqlx::query("INSERT INTO users (id, email) VALUES ('limited', 'limited@example.test')")
            .execute(&db.pool)
            .await?;
        let limit = rate_limit::SANDBOX_CREATE;
        anyhow::ensure!(in_force(&db.pool, Some("limited")).await? == limit.default_max);
        sqlx::query(
            "INSERT INTO rate_limit_settings (name, max_requests, updated_by) \
             VALUES ('sandbox_create', 25, 'admin')",
        )
        .execute(&db.pool)
        .await?;
        anyhow::ensure!(in_force(&db.pool, Some("limited")).await? == 25);
        anyhow::ensure!(in_force(&db.pool, None).await? == 25);
        sqlx::query(
            "INSERT INTO rate_limit_overrides (user_id, name, max_requests, updated_by) \
             VALUES ('limited', 'sandbox_create', 2, 'admin')",
        )
        .execute(&db.pool)
        .await?;
        anyhow::ensure!(in_force(&db.pool, Some("limited")).await? == 2);
        // The override decides the user's refusals.
        let mut connection = db.pool.acquire().await?;
        for request in 0..2 {
            let decision = rate_limit::take_for_user(&mut connection, &limit, "limited").await?;
            anyhow::ensure!(decision.allowed, "request {request}");
        }
        let refused = rate_limit::take_for_user(&mut connection, &limit, "limited").await?;
        anyhow::ensure!(!refused.allowed && refused.max == 2, "{refused:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
