//! A Pod's refusal reports, labelled (SPEC.md "The refusal path"): each row
//! the broker folded becomes an egress record under the policy reference and
//! revision this supervisor sent that broker for the row's digest.
//!
//! A row is kept only under a digest this supervisor sent the broker for an
//! environment. A row under a policy an unbound warm member ran belongs to no
//! environment, and a digest it never sent is not a policy it can name; both
//! are dropped and counted. Each count is a delta, as the broker folded it.

use std::collections::VecDeque;

use codewire_egress_broker::refusals::RefusalBatch;
use codewire_egress_policy::PolicyDigest;
use codewire_egress_policy::record::{EgressRecord, Outcome, PolicyLabel};

/// The policies one pair's broker was sent, newest last. A row arrives at
/// most a second after its refusal, so the policy before the newest is the
/// oldest a row can still name; a few more cover replacements in a burst.
const LABELS_KEPT: usize = 8;

/// What this supervisor sent one pair's broker, by digest.
#[derive(Debug, Default)]
pub(super) struct SentPolicies(VecDeque<(PolicyDigest, Option<PolicyLabel>)>);

impl SentPolicies {
    /// The broker now enforces `digest`, for an environment as `reference`
    /// at `revision`, or for none (`None`).
    pub(super) fn sent(&mut self, digest: PolicyDigest, label: Option<(&str, u32)>) {
        self.0.retain(|(sent, _)| *sent != digest);
        if self.0.len() >= LABELS_KEPT {
            self.0.pop_front();
        }
        let label = label.map(|(reference, revision)| PolicyLabel {
            name: reference.to_owned(),
            revision: u64::from(revision),
            digest,
        });
        self.0.push_back((digest, label));
    }

    fn label(&self, digest: PolicyDigest) -> Option<Option<&PolicyLabel>> {
        self.0
            .iter()
            .find(|(sent, _)| *sent == digest)
            .map(|(_, label)| label.as_ref())
    }
}

/// One report, labelled.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Labelled {
    pub(super) records: Vec<EgressRecord>,
    /// Refusals under a policy run for no environment.
    pub(super) unbound: u64,
    /// Refusals under a digest this supervisor never sent.
    pub(super) unknown: u64,
}

/// `batch` as records seen at `now_unix_ms`, each labelled from `sent`.
pub(super) fn label(batch: RefusalBatch, sent: &SentPolicies, now_unix_ms: u64) -> Labelled {
    let mut labelled = Labelled::default();
    for row in batch.rows {
        match sent.label(row.policy_digest) {
            Some(Some(policy)) => labelled.records.push(EgressRecord {
                destination: row.destination,
                address: row.address,
                transport: row.transport,
                outcome: Outcome::Refused(row.reason),
                policy: policy.clone(),
                first_seen_unix_ms: now_unix_ms,
                last_seen_unix_ms: now_unix_ms,
                count: row.count,
            }),
            Some(None) => labelled.unbound = labelled.unbound.saturating_add(row.count),
            None => labelled.unknown = labelled.unknown.saturating_add(row.count),
        }
    }
    labelled
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use codewire_egress_broker::refusals::RefusedRow;
    use codewire_egress_policy::lease::RefusalReason;
    use codewire_egress_policy::record::{Destination, Transport};

    use super::*;

    fn digest(byte: u8) -> PolicyDigest {
        PolicyDigest::from_bytes([byte; 32])
    }

    fn row(name: &str, policy: u8, count: u64) -> RefusedRow {
        RefusedRow {
            destination: Destination::checked_name(name),
            address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80))),
            transport: Transport::Tcp { port: 443 },
            reason: RefusalReason::NameNotAllowed,
            policy_digest: digest(policy),
            count,
        }
    }

    #[test]
    fn each_row_takes_the_reference_and_revision_sent_for_its_digest() {
        let mut sent = SentPolicies::default();
        sent.sent(digest(1), Some(("walk-docs", 1)));
        sent.sent(digest(2), Some(("walk-docs", 2)));
        let labelled = label(
            RefusalBatch {
                rows: vec![row("a.example.com", 1, 3), row("b.example.com", 2, 1)],
                dropped: 0,
            },
            &sent,
            5_000,
        );
        let labels: Vec<_> = labelled
            .records
            .iter()
            .map(|record| {
                (
                    record.policy.name.as_str(),
                    record.policy.revision,
                    record.count,
                )
            })
            .collect();
        assert_eq!(labels, [("walk-docs", 1, 3), ("walk-docs", 2, 1)]);
        let record = &labelled.records[0];
        assert_eq!(
            record.outcome,
            Outcome::Refused(RefusalReason::NameNotAllowed)
        );
        assert_eq!(record.policy.digest, digest(1));
        assert_eq!(
            (record.first_seen_unix_ms, record.last_seen_unix_ms),
            (5_000, 5_000)
        );
        assert_eq!((labelled.unbound, labelled.unknown), (0, 0));
    }

    #[test]
    fn a_row_under_no_environment_or_an_unsent_digest_is_dropped_and_counted() {
        let mut sent = SentPolicies::default();
        sent.sent(digest(1), None);
        sent.sent(digest(2), Some(("walk-docs", 4)));
        let labelled = label(
            RefusalBatch {
                rows: vec![
                    row("a.example.com", 1, 3),
                    row("b.example.com", 9, 5),
                    row("c.example.com", 2, 1),
                ],
                dropped: 0,
            },
            &sent,
            1,
        );
        assert_eq!(labelled.records.len(), 1);
        assert_eq!(labelled.records[0].policy.name, "walk-docs");
        assert_eq!((labelled.unbound, labelled.unknown), (3, 5));
    }

    #[test]
    fn only_the_newest_policies_are_kept_and_a_resend_relabels_its_digest() {
        let mut sent = SentPolicies::default();
        for revision in 0..=u8::try_from(LABELS_KEPT).unwrap() {
            sent.sent(digest(revision), Some(("p", u32::from(revision))));
        }
        assert_eq!(sent.label(digest(0)), None);
        assert!(sent.label(digest(1)).is_some());
        sent.sent(digest(1), Some(("renamed", 1)));
        assert_eq!(
            sent.label(digest(1))
                .flatten()
                .map(|label| label.name.as_str()),
            Some("renamed")
        );
    }
}
