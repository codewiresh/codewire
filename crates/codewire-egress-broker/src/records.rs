//! One environment's egress records, shared between the broker that writes
//! them and the readers that list or follow them (#4000, #4015). The local
//! supervisor and hosted `cw-egress` each hold one per environment.

use std::sync::{Mutex, MutexGuard, PoisonError};

use codewire_egress_policy::record::{
    EgressObservation, EgressRecord, EgressRecordLog, PolicyLabel,
};
use tokio::sync::watch;

#[derive(Debug)]
pub struct EgressRecords {
    log: Mutex<EgressRecordLog>,
    generation: watch::Sender<u64>,
}

impl EgressRecords {
    pub fn new(policy: PolicyLabel) -> Self {
        let log = EgressRecordLog::new(policy);
        let (generation, _) = watch::channel(log.generation());
        Self {
            log: Mutex::new(log),
            generation,
        }
    }

    /// Records one observation. Returns false for a pass while not learning.
    pub fn record(&self, observation: EgressObservation, now_unix_ms: u64) -> bool {
        self.change(|log| log.record(observation, now_unix_ms))
    }

    pub fn set_policy(&self, policy: PolicyLabel) {
        self.change(|log| log.set_policy(policy));
    }

    pub fn start_learning(&self, now_unix_ms: u64) {
        self.change(|log| log.start_learning(now_unix_ms));
    }

    pub fn stop_learning(&self) {
        self.change(EgressRecordLog::stop_learning);
    }

    pub fn learning_since_unix_ms(&self) -> Option<u64> {
        self.lock().learning_since_unix_ms()
    }

    /// At most `limit` records, the most recently seen first.
    pub fn list(&self, limit: usize) -> Vec<EgressRecord> {
        self.lock().list(limit)
    }

    /// A generation that rises on every change a reader of `list` would see,
    /// so a reader pushes a fresh copy only when there is one.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    fn change<T>(&self, apply: impl FnOnce(&mut EgressRecordLog) -> T) -> T {
        let mut log = self.lock();
        let result = apply(&mut log);
        let generation = log.generation();
        self.generation.send_if_modified(|current| {
            let changed = *current != generation;
            *current = generation;
            changed
        });
        result
    }

    /// The log stays consistent if a holder panicked: every change is one
    /// map operation plus a counter.
    fn lock(&self) -> MutexGuard<'_, EgressRecordLog> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use codewire_egress_policy::PolicyDigest;
    use codewire_egress_policy::lease::RefusalReason;
    use codewire_egress_policy::record::{Destination, Outcome, Transport};

    use super::*;

    fn records() -> EgressRecords {
        EgressRecords::new(PolicyLabel {
            name: "web".to_owned(),
            revision: 1,
            digest: PolicyDigest::from_bytes([1; 32]),
        })
    }

    fn observation(outcome: Outcome) -> EgressObservation {
        EgressObservation {
            destination: Destination::Name("example.com".to_owned()),
            address: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            transport: Transport::Tcp { port: 443 },
            outcome,
        }
    }

    #[test]
    fn a_subscriber_sees_a_recorded_change_and_not_an_unrecorded_pass() {
        let records = records();
        let mut changes = records.subscribe();

        assert!(!records.record(observation(Outcome::Passed), 1));
        assert!(!changes.has_changed().unwrap());

        assert!(records.record(
            observation(Outcome::Refused(RefusalReason::NameNotAllowed)),
            2
        ));
        assert!(changes.has_changed().unwrap());
        changes.mark_unchanged();

        records.start_learning(3);
        assert!(changes.has_changed().unwrap());
        assert_eq!(records.learning_since_unix_ms(), Some(3));
        assert_eq!(records.list(10).len(), 1);
    }
}
