//! Settles what an environment runtime lease's owner left behind when its
//! process died (#4518, #4523). A rollout's kill, a node failure or an OOM
//! kill can stop a detached owner mid-request. Its lease then stays active,
//! which stops the environment's sandbox from being replaced or destroyed,
//! and nothing else would ever settle it.
//!
//! Each feature that holds the lease from a detached owner is one kind here.
//! It knows how long its owner can still act, and settles a request older
//! than that into a state its own journal already has. Nothing here observes
//! a sandbox or dispatches to one. What an abandoned effect did is decided
//! later, from the sandbox, by the feature's next request under a user's own
//! authority.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codewire_server_core::AppResult;

use super::WorkerContext;
use super::loops::Leadership;
use crate::api::cw_runtime::owner::RuntimeJournal;
use crate::confidential_storage::FeatureFlags;

const SWEEP_INTERVAL: Duration = Duration::from_secs(300);
/// Requests one kind settles in a pass; the rest wait for the next pass.
const SWEEP_LIMIT: i64 = 32;

/// One feature that holds environment runtime leases from detached owners.
#[async_trait]
pub trait AbandonedLeases: Send + Sync {
    /// The feature, for logs.
    fn kind(&self) -> &'static str;

    /// Settles at most `limit` requests whose owner can no longer act, and
    /// returns how many it settled.
    async fn sweep(&self, limit: i64) -> AppResult<usize>;
}

pub(super) async fn abandoned_leases_loop(ctx: Arc<WorkerContext>, leadership: Arc<Leadership>) {
    // Settling authorizes nothing; with confidential storage disabled here,
    // anything that did consult it would refuse.
    let kinds: [Box<dyn AbandonedLeases>; 1] = [Box::new(RuntimeJournal::new(
        ctx.pool.clone(),
        FeatureFlags { enabled: false },
    ))];
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(_pass) = leadership.pass() else {
            continue;
        };
        sweep(&kinds).await;
    }
}

async fn sweep(kinds: &[Box<dyn AbandonedLeases>]) {
    for kind in kinds {
        match kind.sweep(SWEEP_LIMIT).await {
            Ok(0) => {}
            Ok(settled) => tracing::info!(
                kind = kind.kind(),
                settled,
                "abandoned leases: settled requests whose owner died"
            ),
            Err(error) => tracing::warn!(
                kind = kind.kind(),
                error = %error,
                "abandoned leases: sweep failed"
            ),
        }
    }
}
