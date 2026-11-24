//! Refusals folded until a reporter sends them (#5058): the egress broker's
//! here, one row per destination, protocol, port and reason, with the latest
//! address and the policy it was last refused under, and an intercepted
//! host's front door's through the same [`Fold`]. The workload chooses the
//! destinations and how often, so a refusal only raises a count, a fold never
//! holds more rows than its limit, and [`report_folded`] sends at most once a
//! second.
//!
//! Only refusals are folded, never a pass, so the owner's log shows no pass
//! even while learn mode records them (#4015). Nor the refusals a worker
//! asks for to prove each IPC session (`BrokerIpcClient::verify_sessions`),
//! which are its own, not the workload's.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::lease::RefusalReason;
use codewire_egress_policy::record::{Destination, EGRESS_RECORD_LIMIT, Transport};
use tokio::sync::Notify;

/// The most rows the egress broker's fold holds between reports: as many as
/// the runner's log keeps, so one report can carry them all.
pub const REFUSAL_FOLD_LIMIT: usize = EGRESS_RECORD_LIMIT;

/// A reporter sends at most one report in this long.
pub const REFUSAL_REPORT_INTERVAL: Duration = Duration::from_secs(1);

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

/// One folded row: its key, what its latest refusal carried, and how many
/// refusals since the last report, a delta, never a running total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Folded<K, V> {
    pub key: K,
    pub value: V,
    pub count: u64,
}

/// What changed since the last report: the rows, and how many rows the fold
/// dropped to stay within its limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldBatch<K, V> {
    pub rows: Vec<Folded<K, V>>,
    pub dropped: u64,
}

impl<K, V> FoldBatch<K, V> {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.dropped == 0
    }
}

#[derive(Debug)]
struct PendingRow<V> {
    value: V,
    count: u64,
    /// When the row was last refused, in refusals since the fold began.
    last_seen: u64,
}

#[derive(Debug)]
struct Pending<K, V> {
    rows: HashMap<K, PendingRow<V>>,
    dropped: u64,
    seen: u64,
}

/// Refusals folded by key until [`Self::take`], at most `limit` rows: a new
/// key in a full fold drops the least recently refused row first and counts
/// it.
#[derive(Debug)]
pub struct Fold<K, V> {
    pending: Mutex<Pending<K, V>>,
    changed: Notify,
    limit: usize,
}

impl<K: Eq + Hash + Clone, V> Fold<K, V> {
    pub fn new(limit: usize) -> Self {
        Self {
            pending: Mutex::new(Pending {
                rows: HashMap::new(),
                dropped: 0,
                seen: 0,
            }),
            changed: Notify::new(),
            limit,
        }
    }

    /// Folds one refusal of `key`. A row already held takes `value` through
    /// `merge`, which is given the row's value and the new one.
    pub fn add(&self, key: K, value: V, merge: impl FnOnce(&mut V, V)) {
        let mut pending = self.lock();
        pending.seen = pending.seen.wrapping_add(1);
        let seen = pending.seen;
        if let Some(row) = pending.rows.get_mut(&key) {
            merge(&mut row.value, value);
            row.count = row.count.saturating_add(1);
            row.last_seen = seen;
        } else {
            if pending.rows.len() >= self.limit {
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
                    value,
                    count: 1,
                    last_seen: seen,
                },
            );
        }
        drop(pending);
        self.changed.notify_one();
    }

    /// Everything since the last call, which starts the fold empty.
    pub fn take(&self) -> FoldBatch<K, V> {
        let mut pending = self.lock();
        let rows = std::mem::take(&mut pending.rows);
        let dropped = std::mem::take(&mut pending.dropped);
        FoldBatch {
            rows: rows
                .into_iter()
                .map(|(key, row)| Folded {
                    key,
                    value: row.value,
                    count: row.count,
                })
                .collect(),
            dropped,
        }
    }

    /// Resolves once something was folded since the last wait, or at once
    /// when that happened before the wait began.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// The fold stays consistent if a holder panicked: every change is one
    /// map operation plus counters.
    fn lock(&self) -> MutexGuard<'_, Pending<K, V>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The reporter for `fold`: each time a refusal is folded, `send` everything
/// folded since the last report, then wait [`REFUSAL_REPORT_INTERVAL`]
/// before the next. It returns only when `send` fails.
pub async fn report_folded<K, V, E, F, Fut>(fold: &Fold<K, V>, mut send: F) -> Result<(), E>
where
    K: Eq + Hash + Clone,
    F: FnMut(FoldBatch<K, V>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    loop {
        fold.changed().await;
        let batch = fold.take();
        if !batch.is_empty() {
            send(batch).await?;
        }
        tokio::time::sleep(REFUSAL_REPORT_INTERVAL).await;
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

/// An egress refusal's key in the fold.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RowKey {
    destination: Destination,
    transport: Transport,
    reason: RefusalReason,
}

/// What an egress refusal's latest observation carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Latest {
    address: Option<IpAddr>,
    policy_digest: PolicyDigest,
}

impl From<FoldBatch<RowKey, Latest>> for RefusalBatch {
    fn from(batch: FoldBatch<RowKey, Latest>) -> Self {
        Self {
            rows: batch
                .rows
                .into_iter()
                .map(|row| RefusedRow {
                    destination: row.key.destination,
                    address: row.value.address,
                    transport: row.key.transport,
                    reason: row.key.reason,
                    policy_digest: row.value.policy_digest,
                    count: row.count,
                })
                .collect(),
            dropped: batch.dropped,
        }
    }
}

/// The egress broker's fold, bounded at [`REFUSAL_FOLD_LIMIT`] rows.
#[derive(Debug)]
pub struct RefusalFold(Fold<RowKey, Latest>);

impl Default for RefusalFold {
    fn default() -> Self {
        Self::new()
    }
}

impl RefusalFold {
    pub fn new() -> Self {
        Self(Fold::new(REFUSAL_FOLD_LIMIT))
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
        self.0.add(
            RowKey {
                destination,
                transport,
                reason,
            },
            Latest {
                address,
                policy_digest,
            },
            |held, newer| {
                held.address = newer.address.or(held.address);
                held.policy_digest = newer.policy_digest;
            },
        );
    }

    /// Everything since the last call, which starts the fold empty.
    pub fn take(&self) -> RefusalBatch {
        self.0.take().into()
    }

    /// Resolves once something was recorded since the last wait, or at once
    /// when that happened before the wait began.
    pub async fn changed(&self) {
        self.0.changed().await;
    }

    /// The fold underneath, for [`report_folded`].
    pub fn fold(&self) -> &Fold<RowKey, Latest> {
        &self.0
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
