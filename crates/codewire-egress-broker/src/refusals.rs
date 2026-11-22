//! The broker's refusals, folded until its reporter sends them (#5058): one
//! row per destination, protocol, port and reason, with the latest address
//! and the policy it was last refused under. The workload chooses the
//! destinations and how often, so a refusal only raises a count, and the
//! fold never holds more than [`REFUSAL_FOLD_LIMIT`] rows.
//!
//! Only refusals are folded, never a pass, so the owner's log shows no pass
//! even while learn mode records them (#4015). Nor the refusals a worker
//! asks for to prove each IPC session (`BrokerIpcClient::verify_sessions`),
//! which are its own, not the workload's.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::{Destination, EGRESS_RECORD_LIMIT, Transport};
use tokio::sync::Notify;

/// The most rows the fold holds between reports: as many as the runner's
/// log keeps, so one report can carry them all.
pub const REFUSAL_FOLD_LIMIT: usize = EGRESS_RECORD_LIMIT;

/// The dial a worker proves each IPC session with: a protected loopback
/// destination the policy refuses before any upstream effect.
pub const SESSION_PROBE_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
/// The lookup a worker proves each DNS session with: a protected name.
pub const SESSION_PROBE_NAME: &str = "localhost";

/// Whether a refusal is of a session probe, which the fold leaves out. The
/// guest never reaches either through the broker: its own loopback stays in
/// the guest, and `localhost` resolves there.
fn is_session_probe(destination: &Destination, transport: Transport) -> bool {
    match (destination, transport) {
        (Destination::Name(name), Transport::Dns) => name == SESSION_PROBE_NAME,
        (Destination::Address(address), Transport::Tcp { port }) => {
            SocketAddr::new(*address, port) == SESSION_PROBE_ADDRESS
        }
        _ => false,
    }
}

/// Refusals of one destination, protocol, port and reason since the last
/// report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedRow {
    pub destination: Destination,
    /// The latest address refused, when there is one.
    pub address: Option<IpAddr>,
    pub transport: Transport,
    pub reason: RefusalReason,
    /// The policy the latest refusal was decided under.
    pub policy_digest: PolicyDigest,
    /// Refusals since the last report: a delta, never a running total.
    pub count: u64,
}

/// What changed since the last report: the rows, and how many rows the
/// fold dropped to stay within its bound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefusalBatch {
    pub rows: Vec<RefusedRow>,
    pub dropped: u64,
}

impl RefusalBatch {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.dropped == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RowKey {
    destination: Destination,
    transport: Transport,
    reason: RefusalReason,
}

#[derive(Debug)]
struct PendingRow {
    address: Option<IpAddr>,
    policy_digest: PolicyDigest,
    count: u64,
    /// When the row was last refused, in refusals since the fold began.
    last_seen: u64,
}

#[derive(Debug, Default)]
struct Pending {
    rows: HashMap<RowKey, PendingRow>,
    dropped: u64,
    seen: u64,
}

#[derive(Debug, Default)]
pub struct RefusalFold {
    pending: Mutex<Pending>,
    changed: Notify,
}

impl RefusalFold {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one refusal. A full fold drops its least recently refused row
    /// first and counts it.
    pub fn record(
        &self,
        destination: Destination,
        address: Option<IpAddr>,
        transport: Transport,
        reason: RefusalReason,
        policy_digest: PolicyDigest,
    ) {
        if is_session_probe(&destination, transport) {
            return;
        }
        let mut pending = self.lock();
        pending.seen = pending.seen.wrapping_add(1);
        let seen = pending.seen;
        let key = RowKey {
            destination,
            transport,
            reason,
        };
        if let Some(row) = pending.rows.get_mut(&key) {
            row.address = address.or(row.address);
            row.policy_digest = policy_digest;
            row.count = row.count.saturating_add(1);
            row.last_seen = seen;
        } else {
            if pending.rows.len() >= REFUSAL_FOLD_LIMIT {
                let oldest = pending
                    .rows
                    .iter()
                    .min_by_key(|(_, row)| row.last_seen)
                    .map(|(key, _)| key.clone());
                if let Some(oldest) = oldest {
                    pending.rows.remove(&oldest);
                    pending.dropped = pending.dropped.saturating_add(1);
                }
            }
            pending.rows.insert(
                key,
                PendingRow {
                    address,
                    policy_digest,
                    count: 1,
                    last_seen: seen,
                },
            );
        }
        drop(pending);
        self.changed.notify_one();
    }

    /// Everything since the last call, which starts the fold empty.
    pub fn take(&self) -> RefusalBatch {
        let mut pending = self.lock();
        let rows = std::mem::take(&mut pending.rows);
        let dropped = std::mem::take(&mut pending.dropped);
        RefusalBatch {
            rows: rows
                .into_iter()
                .map(|(key, row)| RefusedRow {
                    destination: key.destination,
                    address: row.address,
                    transport: key.transport,
                    reason: key.reason,
                    policy_digest: row.policy_digest,
                    count: row.count,
                })
                .collect(),
            dropped,
        }
    }

    /// Resolves once something was recorded since the last wait, or at once
    /// when that happened before the wait began.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// The fold stays consistent if a holder panicked: every change is one
    /// map operation plus counters.
    fn lock(&self) -> MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    fn digest(byte: u8) -> PolicyDigest {
        PolicyDigest::from_bytes([byte; 32])
    }

    fn refuse(fold: &RefusalFold, name: &str, port: u16, policy: u8) {
        fold.record(
            Destination::checked_name(name),
            Some(ADDRESS),
            Transport::Tcp { port },
            RefusalReason::PortNotAllowed,
            digest(policy),
        );
    }

    #[test]
    fn many_refusals_of_one_destination_are_one_row_with_their_count() {
        let fold = RefusalFold::new();
        for _ in 0..5 {
            refuse(&fold, "example.com", 8080, 1);
        }
        refuse(&fold, "example.com", 8080, 2);
        let batch = fold.take();
        assert_eq!(
            batch.rows,
            [RefusedRow {
                destination: Destination::Name("example.com".to_owned()),
                address: Some(ADDRESS),
                transport: Transport::Tcp { port: 8080 },
                reason: RefusalReason::PortNotAllowed,
                policy_digest: digest(2),
                count: 6,
            }]
        );
        assert_eq!(batch.dropped, 0);
        assert!(fold.take().is_empty());
    }

    #[test]
    fn past_its_bound_the_fold_drops_the_least_recently_refused_and_counts_it() {
        let fold = RefusalFold::new();
        for index in 0..1_100 {
            refuse(&fold, &format!("h{index}.example.com"), 443, 1);
            if index == 0 {
                continue;
            }
            // h0 stays the most recently refused.
            refuse(&fold, "h0.example.com", 443, 1);
        }
        let batch = fold.take();
        assert_eq!(batch.rows.len(), 1_000);
        assert_eq!(batch.dropped, 100);
        let names: Vec<_> = batch.rows.iter().map(|row| &row.destination).collect();
        assert!(names.contains(&&Destination::Name("h0.example.com".to_owned())));
        assert!(!names.contains(&&Destination::Name("h1.example.com".to_owned())));
        assert!(names.contains(&&Destination::Name("h1099.example.com".to_owned())));
    }

    #[test]
    fn a_workers_session_probes_are_never_folded() {
        let fold = RefusalFold::new();
        fold.record(
            Destination::checked_name("localhost"),
            None,
            Transport::Dns,
            RefusalReason::NameNotAllowed,
            digest(1),
        );
        fold.record(
            Destination::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Tcp { port: 1 },
            RefusalReason::ProtectedAddress,
            digest(1),
        );
        assert!(fold.take().is_empty());
        // The same address on another port is the workload's.
        fold.record(
            Destination::Address(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Transport::Tcp { port: 80 },
            RefusalReason::ProtectedAddress,
            digest(1),
        );
        assert_eq!(fold.take().rows.len(), 1);
    }

    #[tokio::test]
    async fn a_recorded_refusal_wakes_the_reporter() {
        let fold = RefusalFold::new();
        refuse(&fold, "example.com", 22, 1);
        tokio::time::timeout(std::time::Duration::from_secs(1), fold.changed())
            .await
            .expect("a refusal recorded before the wait wakes it");
    }
}
