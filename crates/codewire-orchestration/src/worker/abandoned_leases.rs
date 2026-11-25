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
use codewire_server_core::org_deletion::mark_organization_mutation_resolution_required;
use codewire_server_core::{AppError, AppResult};
use sqlx::PgPool;

use super::WorkerContext;
use super::loops::Leadership;
use crate::api::cw_runtime::owner::RuntimeJournal;
use crate::api::platform_agents::journal::ManagedJournal;
use crate::confidential_storage::FeatureFlags;
use crate::lease_owner::INCARNATION_GRACE;

const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
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
    let kinds: [Box<dyn AbandonedLeases>; 3] = [
        Box::new(RuntimeJournal::new(
            ctx.pool.clone(),
            FeatureFlags { enabled: false },
        )),
        Box::new(OwnerlessLeases::new(ctx.pool.clone(), INCARNATION_GRACE)),
        Box::new(ManagedAgentLeases::new(ctx.pool.clone(), INCARNATION_GRACE)),
    ];
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

/// The code an owner-lost lease is left with; destroy and organization
/// deletion resolve it as they resolve any ambiguous runtime dispatch.
const OWNER_LOST: &str = "environment_runtime_dispatch_owner_lost";

/// The clause naming a lease `l` whose owner process is gone (#4523): joined
/// to its heartbeat as `o`, it has written none for `$1` seconds, and the lease
/// itself is that old, since its owner was alive when it admitted it. Every
/// time is the database's own, so the leader's memory plays no part. An owner
/// gone that long has died, or fenced at most about 77 s after its last
/// heartbeat and stopped acting for its leases.
pub(crate) const OWNER_GONE: &str = "GREATEST(COALESCE(o.last_seen, l.admitted_at), l.admitted_at) \
    < LOCALTIMESTAMP - make_interval(secs => $1)";

/// Environment runtime leases no journal holds (a dashboard terminal, an SSH
/// port-forward, a daemon repair) whose owner is gone, by [`OWNER_GONE`].
/// They become `resolution_required`, which destroy and organization deletion
/// resolve as they resolve any ambiguous runtime dispatch.
pub(crate) struct OwnerlessLeases {
    pool: PgPool,
    grace: Duration,
}

impl OwnerlessLeases {
    pub(crate) fn new(pool: PgPool, grace: Duration) -> Self {
        Self { pool, grace }
    }
}

/// The clause naming a runtime lease `l` that records its owner and that no
/// journal holds.
const JOURNALLESS: &str = "l.state='active' AND l.mutation_class='environment_runtime_dispatch' \
    AND l.owner_incarnation IS NOT NULL \
    AND NOT EXISTS (SELECT 1 FROM environment_cw_runtime_requests r WHERE r.mutation_lease_id=l.id) \
    AND NOT EXISTS (SELECT 1 FROM environment_platform_agent_requests p WHERE p.mutation_lease_id=l.id)";

#[async_trait]
impl AbandonedLeases for OwnerlessLeases {
    fn kind(&self) -> &'static str {
        "ownerless_runtime_lease"
    }

    async fn sweep(&self, limit: i64) -> AppResult<usize> {
        let leases: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT l.id FROM organization_mutation_leases l \
             LEFT JOIN lease_owner_heartbeats o ON o.incarnation = l.owner_incarnation \
             WHERE {JOURNALLESS} AND {OWNER_GONE} ORDER BY l.admitted_at, l.id LIMIT $2"
        ))
        .bind(self.grace.as_secs_f64())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(AppError::from)?;
        let mut settled = 0;
        for lease in leases {
            // Only a lease still active is marked; one its owner settled
            // meanwhile is refused here and left as it is.
            match mark_organization_mutation_resolution_required(&self.pool, &lease, OWNER_LOST)
                .await
            {
                Ok(_) => settled += 1,
                Err(error) => tracing::warn!(
                    lease,
                    error = %error,
                    "abandoned leases: an ownerless lease could not be settled"
                ),
            }
        }
        // A day-old heartbeat with no active lease left is of no further use.
        sqlx::query(
            "DELETE FROM lease_owner_heartbeats o WHERE o.last_seen < LOCALTIMESTAMP - interval '1 day' \
             AND NOT EXISTS (SELECT 1 FROM organization_mutation_leases l \
                             WHERE l.owner_incarnation = o.incarnation AND l.state = 'active')",
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;
        Ok(settled)
    }
}

/// How long a request whose settlement failed is passed over, so a few that
/// always fail cannot take every pass's turn from the rest.
const FAILED_PASSED_OVER: Duration = Duration::from_secs(10 * 60);

/// Managed platform agents' open requests whose owner is gone, by
/// [`OWNER_GONE`], settled through their own journal (#4523). It remembers
/// only which settlements failed lately, to pass over them for a while; the
/// decision itself is the database's.
pub(crate) struct ManagedAgentLeases {
    journal: ManagedJournal,
    grace: Duration,
    failed: std::sync::Mutex<std::collections::HashMap<uuid::Uuid, std::time::Instant>>,
}

impl ManagedAgentLeases {
    pub(crate) fn new(pool: PgPool, grace: Duration) -> Self {
        Self {
            // Settling authorizes nothing, as for the cw runtime journal.
            journal: ManagedJournal::new(pool, FeatureFlags { enabled: false }),
            grace,
            failed: Default::default(),
        }
    }
}

#[async_trait]
impl AbandonedLeases for ManagedAgentLeases {
    fn kind(&self) -> &'static str {
        "managed_agent"
    }

    async fn sweep(&self, limit: i64) -> AppResult<usize> {
        let skip: Vec<uuid::Uuid> = {
            let mut failed = self.failed.lock().unwrap_or_else(|e| e.into_inner());
            failed.retain(|_, at| at.elapsed() < FAILED_PASSED_OVER);
            failed.keys().copied().collect()
        };
        let (settled, failed) = self
            .journal
            .settle_abandoned(self.grace, limit, &skip)
            .await?;
        let now = std::time::Instant::now();
        let mut passed_over = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        for request in failed {
            passed_over.insert(request, now);
        }
        Ok(settled)
    }
}

#[cfg(test)]
#[path = "abandoned_leases_database_tests.rs"]
mod database_tests;
