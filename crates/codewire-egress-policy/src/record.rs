//! What an environment's broker decided for each destination, folded into a
//! bounded log (design §8; #4000, #4015). `cw policy log` and the command
//! inside the environment read it. It holds no payloads and no headers.
//!
//! The log is placement-neutral and owns no clock: the caller passes the time
//! of each observation. The local supervisor and hosted `cw-egress` each keep
//! one log per environment.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;

use crate::PolicyDigest;
use crate::lease::RefusalReason;

mod guest;
pub use guest::{GuestEgressRecord, GuestOutcome, GuestRefusal, guest_records};

/// The most records one environment's log keeps. When it is full, the record
/// seen least recently is dropped.
pub const EGRESS_RECORD_LIMIT: usize = 1_000;

/// The longest name a record keeps: a DNS name's bound.
pub const MAX_RECORDED_NAME_BYTES: usize = 253;

/// What a decision was about. A dial is attributed to a name by the broker's
/// DNS lease; a dial to an address no lease names has none.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Destination {
    /// A name, checked with [`Destination::checked_name`] before it is kept.
    Name(String),
    Address(IpAddr),
    /// A name that failed the check, kept for its reason and count but never
    /// its text, so a name the workload built can't reach a terminal (#5058).
    Withheld,
}

impl Destination {
    /// `host` as a record may keep it: printable ASCII without spaces, at
    /// most [`MAX_RECORDED_NAME_BYTES`], lowercased and without a trailing
    /// dot. Anything else is [`Destination::Withheld`].
    pub fn checked_name(host: &str) -> Self {
        let name = host.strip_suffix('.').unwrap_or(host);
        if name.is_empty()
            || name.len() > MAX_RECORDED_NAME_BYTES
            || !name.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Self::Withheld;
        }
        Self::Name(name.to_ascii_lowercase())
    }
}

/// The protocol, and the destination port where the protocol has one. A DNS
/// question is about a name, not a port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Transport {
    Dns,
    Tcp { port: u16 },
    Udp { port: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Outcome {
    /// Recorded only while the log is learning.
    Passed,
    Refused(RefusalReason),
}

/// What a log's records are folded by besides their destination and
/// transport: [`Outcome`] for a broker's own log, or another closed set for
/// a log that merges other sources' refusals (#5058).
pub trait RecordOutcome: Copy + Debug + Eq + Hash + Ord {
    /// Whether this is a pass, which a log keeps only while learning.
    fn is_pass(self) -> bool;
}

impl RecordOutcome for Outcome {
    fn is_pass(self) -> bool {
        self == Self::Passed
    }
}

/// The policy a decision was made under, as its owner names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLabel {
    pub name: String,
    pub revision: u64,
    pub digest: PolicyDigest,
}

/// One decision as the broker reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressObservation<O = Outcome> {
    pub destination: Destination,
    /// The address dialled or answered, when there is one.
    pub address: Option<IpAddr>,
    pub transport: Transport,
    pub outcome: O,
}

/// Every observation with the same destination, transport and outcome,
/// folded into one record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRecord<O = Outcome> {
    pub destination: Destination,
    /// The address of the latest observation that had one.
    pub address: Option<IpAddr>,
    pub transport: Transport,
    pub outcome: O,
    /// The policy of the latest observation.
    pub policy: PolicyLabel,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RecordKey<O> {
    destination: Destination,
    transport: Transport,
    outcome: O,
}

/// One environment's bounded log. Refusals are always recorded; passes only
/// while learning, so a lock can propose exactly what was reached since
/// learning began.
#[derive(Debug)]
pub struct EgressRecordLog<O = Outcome> {
    records: HashMap<RecordKey<O>, EgressRecord<O>>,
    policy: PolicyLabel,
    learning_since_unix_ms: Option<u64>,
    generation: u64,
    dropped: u64,
}

impl EgressRecordLog {
    pub fn new(policy: PolicyLabel) -> Self {
        Self::with_policy(policy)
    }
}

impl<O: RecordOutcome> EgressRecordLog<O> {
    /// An empty log of `O` outcomes, recording under `policy`.
    pub fn with_policy(policy: PolicyLabel) -> Self {
        Self {
            records: HashMap::new(),
            policy,
            learning_since_unix_ms: None,
            generation: 0,
            dropped: 0,
        }
    }

    /// The policy later observations are recorded under. Existing records
    /// keep the policy they were last seen under.
    pub fn set_policy(&mut self, policy: PolicyLabel) {
        self.policy = policy;
    }

    /// Starts learning at `now_unix_ms`, dropping passes recorded before, so
    /// every pass in the log was seen since learning began.
    pub fn start_learning(&mut self, now_unix_ms: u64) {
        self.records.retain(|key, _| !key.outcome.is_pass());
        self.learning_since_unix_ms = Some(now_unix_ms);
        self.bump();
    }

    /// Stops recording passes. The passes already recorded stay readable.
    pub fn stop_learning(&mut self) {
        if self.learning_since_unix_ms.take().is_some() {
            self.bump();
        }
    }

    pub fn learning_since_unix_ms(&self) -> Option<u64> {
        self.learning_since_unix_ms
    }

    /// Records one observation. Returns false for a pass while not learning,
    /// which is not recorded.
    pub fn record(&mut self, observation: EgressObservation<O>, now_unix_ms: u64) -> bool {
        let policy = self.policy.clone();
        self.fold(observation, policy, 1, now_unix_ms)
    }

    /// Records `count` observations seen together under `policy`, as a
    /// reporter that folded them first sends them. A count of zero records
    /// nothing.
    pub fn fold(
        &mut self,
        observation: EgressObservation<O>,
        policy: PolicyLabel,
        count: u64,
        now_unix_ms: u64,
    ) -> bool {
        if count == 0 || (observation.outcome.is_pass() && self.learning_since_unix_ms.is_none()) {
            return false;
        }
        let key = RecordKey {
            destination: observation.destination,
            transport: observation.transport,
            outcome: observation.outcome,
        };
        if let Some(record) = self.records.get_mut(&key) {
            record.address = observation.address.or(record.address);
            record.policy = policy;
            record.last_seen_unix_ms = record.last_seen_unix_ms.max(now_unix_ms);
            record.count = record.count.saturating_add(count);
        } else {
            if self.records.len() >= EGRESS_RECORD_LIMIT {
                self.evict_least_recent();
            }
            let record = EgressRecord {
                destination: key.destination.clone(),
                address: observation.address,
                transport: key.transport,
                outcome: key.outcome,
                policy,
                first_seen_unix_ms: now_unix_ms,
                last_seen_unix_ms: now_unix_ms,
                count,
            };
            self.records.insert(key, record);
        }
        self.bump();
        true
    }

    /// At most `limit` records, the most recently seen first.
    pub fn list(&self, limit: usize) -> Vec<EgressRecord<O>> {
        let mut records: Vec<&EgressRecord<O>> = self.records.values().collect();
        records.sort_by(|a, b| {
            b.last_seen_unix_ms
                .cmp(&a.last_seen_unix_ms)
                .then_with(|| a.destination.cmp(&b.destination))
                .then_with(|| a.transport.cmp(&b.transport))
                .then_with(|| a.outcome.cmp(&b.outcome))
        });
        records.into_iter().take(limit).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether a record of `destination`, `transport` and `outcome` is held.
    pub fn holds(&self, destination: &Destination, transport: Transport, outcome: O) -> bool {
        self.records.contains_key(&RecordKey {
            destination: destination.clone(),
            transport,
            outcome,
        })
    }

    /// How many records match `outcome`.
    pub fn count_where(&self, matches: impl Fn(O) -> bool) -> usize {
        self.records
            .keys()
            .filter(|key| matches(key.outcome))
            .count()
    }

    /// Records dropped to keep the log within [`EGRESS_RECORD_LIMIT`].
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Rises on every change a reader would see: a record added, folded or
    /// dropped, or learning started or stopped.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn evict_least_recent(&mut self) {
        let oldest = self
            .records
            .iter()
            .min_by_key(|(_, record)| record.last_seen_unix_ms)
            .map(|(key, _)| key.clone());
        if let Some(key) = oldest {
            self.records.remove(&key);
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests;
