//! What `check_rate_limit` promises: `max` requests a minute, whatever the
//! pace. A steady caller under the limit is never refused (#3923).

use super::*;
use crate::test_database_support::TestDatabase;

const SECOND: i64 = 1000;
const WINDOW_SECS: i64 = 60;
const MAX: i32 = 10;
const START: i64 = 1_793_712_000_000;

async fn allowed(pool: &PgPool, key: &str, at: i64) -> bool {
    rate_limit_at(pool, key, WINDOW_SECS, MAX, at)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_steady_caller_under_the_limit_is_never_refused() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        // One every 12 s is 5 a minute, half the limit, for 10 minutes.
        for request in 0..50 {
            let at = START + request * 12 * SECOND;
            anyhow::ensure!(
                allowed(&db.pool, "steady", at).await,
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
            let at = START + i64::from(request) * SECOND;
            anyhow::ensure!(allowed(&db.pool, "burst", at).await, "request {request}");
        }
        anyhow::ensure!(!allowed(&db.pool, "burst", START + 10 * SECOND).await);
        // A refused request doesn't extend the wait.
        anyhow::ensure!(!allowed(&db.pool, "burst", START + 59 * SECOND).await);
        anyhow::ensure!(allowed(&db.pool, "burst", START + 61 * SECOND).await);
        // That started a new window with a full allowance.
        for request in 1..MAX {
            let at = START + (61 + i64::from(request)) * SECOND;
            anyhow::ensure!(allowed(&db.pool, "burst", at).await, "new window {request}");
        }
        anyhow::ensure!(!allowed(&db.pool, "burst", START + 72 * SECOND).await);
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
