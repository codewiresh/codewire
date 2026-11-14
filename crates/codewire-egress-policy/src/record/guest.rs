//! The records as the environment itself may read them (#4015). The guest
//! never learns which names or addresses are protected: a protected refusal
//! reads as the not-allowed refusal of the same kind, so the log is no oracle
//! for the platform's protected names and ranges. Only the owner's
//! `cw policy log` shows the raw reason. Every guest-facing path (the local
//! guest file and the hosted guest read) projects through `guest_records`.

use std::collections::HashMap;
use std::net::IpAddr;

use super::{Destination, EgressRecord, Outcome, Transport};
use crate::lease::RefusalReason;

/// A refusal as the guest sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GuestRefusal {
    NameNotAllowed,
    PortNotAllowed,
    AddressNotAllowed,
    /// The address's name no longer answers it; resolving again may help.
    LeaseExpired,
    /// The destination is handled by a component that is not running.
    Unavailable,
}

impl GuestRefusal {
    /// Exhaustive on purpose: a new reason must choose what the guest sees.
    pub const fn from_reason(reason: RefusalReason) -> Self {
        match reason {
            RefusalReason::NameNotAllowed | RefusalReason::ProtectedAnswersOnly => {
                Self::NameNotAllowed
            }
            RefusalReason::PortNotAllowed => Self::PortNotAllowed,
            RefusalReason::AddressNotAllowed | RefusalReason::ProtectedAddress => {
                Self::AddressNotAllowed
            }
            RefusalReason::LeaseExpired => Self::LeaseExpired,
            RefusalReason::InterceptUnavailable => Self::Unavailable,
        }
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::NameNotAllowed => "name_not_allowed",
            Self::PortNotAllowed => "port_not_allowed",
            Self::AddressNotAllowed => "address_not_allowed",
            Self::LeaseExpired => "lease_expired",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GuestOutcome {
    Passed,
    Refused(GuestRefusal),
}

/// One record as the guest sees it. It names the policy but not its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestEgressRecord {
    pub destination: Destination,
    pub address: Option<IpAddr>,
    pub transport: Transport,
    pub outcome: GuestOutcome,
    pub policy_name: String,
    pub policy_revision: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub count: u64,
}

/// The address the guest may see for a record. A name refused because it
/// answers only protected addresses carries one of those answers, which the
/// guest never received; it is dropped. Any other address is one the guest
/// dialled or was answered.
fn guest_address(record: &EgressRecord) -> Option<IpAddr> {
    match record.outcome {
        Outcome::Refused(RefusalReason::ProtectedAnswersOnly) => None,
        Outcome::Passed | Outcome::Refused(_) => record.address,
    }
}

/// Projects host records, in any order, into the guest's view, newest
/// first. Records that differ only by a reason the guest cannot see are
/// merged, so the count of a merged record reveals nothing either.
pub fn guest_records(records: &[EgressRecord]) -> Vec<GuestEgressRecord> {
    let mut newest_first: Vec<&EgressRecord> = records.iter().collect();
    newest_first.sort_by_key(|record| std::cmp::Reverse(record.last_seen_unix_ms));
    let mut merged: Vec<GuestEgressRecord> = Vec::with_capacity(records.len());
    let mut index: HashMap<(Destination, Transport, GuestOutcome), usize> = HashMap::new();
    for record in newest_first {
        let outcome = match record.outcome {
            Outcome::Passed => GuestOutcome::Passed,
            Outcome::Refused(reason) => GuestOutcome::Refused(GuestRefusal::from_reason(reason)),
        };
        let address = guest_address(record);
        let key = (record.destination.clone(), record.transport, outcome);
        if let Some(&at) = index.get(&key) {
            let into = &mut merged[at];
            into.first_seen_unix_ms = into.first_seen_unix_ms.min(record.first_seen_unix_ms);
            into.count = into.count.saturating_add(record.count);
            // `into` is the newest record of the group: it keeps its policy
            // and last-seen time, and takes an older address only when its
            // own was dropped or absent.
            into.address = into.address.or(address);
            continue;
        }
        index.insert(key, merged.len());
        merged.push(GuestEgressRecord {
            destination: record.destination.clone(),
            address,
            transport: record.transport,
            outcome,
            policy_name: record.policy.name.clone(),
            policy_revision: record.policy.revision,
            first_seen_unix_ms: record.first_seen_unix_ms,
            last_seen_unix_ms: record.last_seen_unix_ms,
            count: record.count,
        });
    }
    merged
}
