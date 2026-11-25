//! The Sandbox audit log (#6189; SPEC.md "Sandbox audit log"): what happened
//! to each hosted Sandbox and through it, kept 90 days. This module is its
//! only writer; the recorders across orchestration call [`record`] and
//! [`open_session`], and the leader's `audit-log` loop keeps the partitions,
//! moves what is finished and expires what is old.

pub mod allowed_since;
mod bound;
mod event;
pub mod read;
mod store;

pub use event::{
    Actor, Credentials, Kind, Lifecycle, PlatformReason, Policy, Protocol, Refusal,
    RefusalOverflow, RefusalSource, Role, Size, Surface, What,
};
pub use store::{AuditError, Event, OpenSession, close_session, open_session, record};

#[cfg(test)]
mod bound_database_tests;
#[cfg(test)]
mod event_tests;
#[cfg(test)]
mod read_database_tests;
#[cfg(test)]
mod store_database_tests;

use std::sync::Arc;
use std::time::Duration;

use crate::lease_owner::INCARNATION_GRACE;
use crate::worker::WorkerContext;
use crate::worker::loops::Leadership;

/// How long events are kept.
pub const RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// How often finished folds and sessions move into the events. A read covers
/// both tables, so this bounds only how long a row waits, not what a reader
/// sees.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);
/// How often partitions are made ahead and old events expire.
const EXPIRE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The leader's upkeep of the log. Partitions are made at start, before the
/// first pass, so no write waits on a month that doesn't exist; each one made
/// covers two months ahead, so a day's failures lose nothing.
pub(crate) async fn audit_log_loop(ctx: Arc<WorkerContext>, leadership: Arc<Leadership>) {
    if let Err(error) = store::ensure_partitions(&ctx.pool).await {
        tracing::warn!(%error, "audit log: making partitions failed");
    }
    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    let mut expire = tokio::time::interval(EXPIRE_INTERVAL);
    loop {
        tokio::select! {
            _ = flush.tick() => {
                let Some(_pass) = leadership.pass() else { continue };
                if let Err(error) = store::flush(&ctx.pool, INCARNATION_GRACE).await {
                    tracing::warn!(%error, "audit log: flush failed");
                }
            }
            _ = expire.tick() => {
                let Some(_pass) = leadership.pass() else { continue };
                if let Err(error) = store::ensure_partitions(&ctx.pool).await {
                    tracing::warn!(%error, "audit log: making partitions failed");
                }
                if let Err(error) = store::expire(&ctx.pool, RETENTION).await {
                    tracing::warn!(%error, "audit log: expiry failed");
                }
            }
        }
    }
}
