//! Sandbox identity's mint log is kept 30 days (docs/dev/SANDBOX-IDENTITY.md,
//! "Minting"). At most once an hour the reconciler's leader deletes the rows
//! minted longer ago than that, a bounded number per pass; anything left
//! waits for the next pass. Logs carry counts only.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use super::WorkerContext;

pub const RETENTION: chrono::Duration = chrono::Duration::days(30);
/// The reconciler runs every 30 s; this sweep is due once an hour.
const INTERVAL: Duration = Duration::from_secs(60 * 60);
const BATCH: i64 = 10_000;
const MAX_BATCHES_PER_PASS: usize = 10;

static LAST_RUN: Mutex<Option<Instant>> = Mutex::new(None);

fn due(now: Instant) -> bool {
    let mut last = LAST_RUN.lock().unwrap_or_else(PoisonError::into_inner);
    match *last {
        Some(previous) if now.duration_since(previous) < INTERVAL => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

pub(super) async fn delete_expired_identity_mints(ctx: &WorkerContext) {
    if !due(Instant::now()) {
        return;
    }
    match delete_minted_before(&ctx.pool, Utc::now() - RETENTION).await {
        Ok(0) => {}
        Ok(deleted) => tracing::info!(
            deleted,
            "reconciler: deleted sandbox identity mint rows older than 30 days"
        ),
        Err(error) => tracing::warn!(
            error = %error,
            "reconciler: sandbox identity mint retention failed"
        ),
    }
}

/// Deletes up to [`MAX_BATCHES_PER_PASS`] batches of rows minted before
/// `cutoff`, oldest first, and returns how many went.
pub(crate) async fn delete_minted_before(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
) -> Result<u64, sqlx::Error> {
    let full_batch = u64::try_from(BATCH).unwrap_or(u64::MAX);
    let mut deleted = 0_u64;
    for _ in 0..MAX_BATCHES_PER_PASS {
        let batch = sqlx::query(
            "DELETE FROM identity_mints WHERE jti IN ( \
                 SELECT jti FROM identity_mints WHERE minted_at < $1 \
                  ORDER BY minted_at LIMIT $2)",
        )
        .bind(cutoff)
        .bind(BATCH)
        .execute(pool)
        .await?
        .rows_affected();
        deleted = deleted.saturating_add(batch);
        if batch < full_batch {
            break;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
#[path = "identity_mints_database_tests.rs"]
mod database_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sweep_is_due_once_an_hour() {
        let start = Instant::now();
        // Another test in this process may have run it already.
        *LAST_RUN.lock().unwrap() = None;
        assert!(due(start));
        assert!(!due(start + Duration::from_secs(60 * 60 - 1)));
        assert!(due(start + INTERVAL));
    }
}
