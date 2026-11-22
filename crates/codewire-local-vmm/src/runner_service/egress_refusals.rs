//! The running generation's refusal log (#5058): what its egress broker
//! refused since it started, as the runner filed the broker's reports. Every
//! report on a runner's control channel is from the broker it started for
//! this boot, so the log is this environment's and no other.

use codewire_egress_policy::record::{Destination, EgressRecord, Outcome, Transport};

use super::*;
use crate::broker_control::RefusalLogSnapshot;

impl RunnerClient {
    /// The running `generation`'s refusal log; FailedPrecondition when the
    /// VM is not running that generation.
    pub async fn egress_refusals(
        &mut self,
        environment_id: Uuid,
        generation: u64,
    ) -> Result<v1::EgressRefusals, Status> {
        Ok(self
            .inner
            .get_egress_refusals(v1::GetEgressRefusalsRequest {
                environment_id: environment_id.to_string(),
                generation,
            })
            .await?
            .into_inner())
    }
}

impl RunnerRpc {
    pub(super) async fn egress_refusals(
        &self,
        request: v1::GetEgressRefusalsRequest,
    ) -> Result<v1::EgressRefusals, Status> {
        let environment_id = parse_environment_id(&request.environment_id)?;
        let mut state = self.state.lock().await;
        state.retirement.require_active()?;
        state.require_adopted(environment_id)?;
        state
            .observe_exit()
            .await
            .map_err(|_| Status::internal("observe VMM state failed"))?;
        let log = (state.generation == request.generation
            && state.state == v1::EnvironmentState::Running)
            .then(|| state.running.as_ref().and_then(RunningVm::egress_refusals))
            .flatten()
            .ok_or_else(|| Status::failed_precondition("environment is not running"))?;
        Ok(refusals_proto(&log.snapshot()))
    }
}

impl RunnerState {
    /// How many requests the running VM's broker refused, and when the last
    /// was; none for a VM that isn't running or refused nothing.
    pub(super) fn egress_refusal_summary(&self) -> Option<v1::EgressRefusalSummary> {
        let snapshot = self.running.as_ref()?.egress_refusals()?.snapshot();
        summary(&snapshot)
    }
}

fn summary(snapshot: &RefusalLogSnapshot) -> Option<v1::EgressRefusalSummary> {
    let last = snapshot.last_unix_ms?;
    Some(v1::EgressRefusalSummary {
        refused: snapshot.refused,
        last_unix_ms: unix_ms(last),
    })
}

pub(super) fn refusals_proto(snapshot: &RefusalLogSnapshot) -> v1::EgressRefusals {
    v1::EgressRefusals {
        refusals: snapshot.records.iter().filter_map(refusal_proto).collect(),
        dropped: snapshot.dropped,
        started_unix_ms: unix_ms(snapshot.started_unix_ms),
        summary: summary(snapshot),
    }
}

/// One row, or `None` for a pass, which the broker never reports.
fn refusal_proto(record: &EgressRecord) -> Option<v1::EgressRefusal> {
    use v1::egress_refusal::Destination as Wire;
    let Outcome::Refused(reason) = record.outcome else {
        return None;
    };
    let (protocol, port) = match record.transport {
        Transport::Dns => (v1::EgressRefusalProtocol::Dns, 0),
        Transport::Tcp { port } => (v1::EgressRefusalProtocol::Tcp, port),
        Transport::Udp { port } => (v1::EgressRefusalProtocol::Udp, port),
    };
    Some(v1::EgressRefusal {
        destination: Some(match &record.destination {
            Destination::Name(name) => Wire::Name(name.clone()),
            Destination::Address(address) => Wire::AddressOnly(address.to_string()),
            Destination::Withheld => Wire::Withheld(true),
        }),
        address: record
            .address
            .map(|address| address.to_string())
            .unwrap_or_default(),
        protocol: protocol as i32,
        port: u32::from(port),
        reason: reason.code().to_owned(),
        policy_name: record.policy.name.clone(),
        policy_revision: u32::try_from(record.policy.revision).unwrap_or(u32::MAX),
        first_seen_unix_ms: unix_ms(record.first_seen_unix_ms),
        last_seen_unix_ms: unix_ms(record.last_seen_unix_ms),
        count: record.count,
    })
}

fn unix_ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use codewire_egress_broker::refusals::{RefusalBatch, RefusedRow};
    use codewire_egress_policy::PolicyDigest;
    use codewire_egress_policy::lease::RefusalReason;

    use super::*;
    use crate::broker_control::RunnerRefusalLog;

    #[test]
    fn rows_carry_the_policy_the_runner_applied_and_the_raw_reason() {
        let digest = PolicyDigest::from_bytes([3; 32]);
        let log = RunnerRefusalLog::new(1_000);
        log.label(digest, "walk-log".to_owned(), 1);
        let row = |destination, address, transport, reason| RefusedRow {
            destination,
            address,
            transport,
            reason,
            policy_digest: digest,
            count: 2,
        };
        log.file(
            RefusalBatch {
                rows: vec![
                    row(
                        Destination::checked_name("example.org"),
                        None,
                        Transport::Dns,
                        RefusalReason::NameNotAllowed,
                    ),
                    row(
                        Destination::checked_name("evil\x1b[2J.example.com"),
                        None,
                        Transport::Dns,
                        RefusalReason::NameNotAllowed,
                    ),
                    row(
                        Destination::Address(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
                        Some(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
                        Transport::Tcp { port: 80 },
                        RefusalReason::ProtectedAddress,
                    ),
                ],
                dropped: 4,
            },
            2_000,
        );
        let proto = refusals_proto(&log.snapshot());
        assert_eq!(proto.dropped, 4);
        assert_eq!(proto.started_unix_ms, 1_000);
        assert_eq!(
            proto.summary,
            Some(v1::EgressRefusalSummary {
                refused: 6,
                last_unix_ms: 2_000,
            })
        );
        assert_eq!(proto.refusals.len(), 3);
        for refusal in &proto.refusals {
            assert_eq!(
                (refusal.policy_name.as_str(), refusal.policy_revision),
                ("walk-log", 1)
            );
            assert_eq!(refusal.count, 2);
        }
        let protected = proto
            .refusals
            .iter()
            .find(|refusal| refusal.reason == "protected_address")
            .unwrap();
        assert_eq!(
            protected.destination,
            Some(v1::egress_refusal::Destination::AddressOnly(
                "169.254.169.254".to_owned()
            ))
        );
        assert_eq!(
            (protected.protocol, protected.port),
            (v1::EgressRefusalProtocol::Tcp as i32, 80)
        );
        let withheld = proto
            .refusals
            .iter()
            .filter(|refusal| {
                refusal.destination == Some(v1::egress_refusal::Destination::Withheld(true))
            })
            .count();
        assert_eq!(withheld, 1);
        let lookup = proto
            .refusals
            .iter()
            .find(|refusal| {
                refusal.destination
                    == Some(v1::egress_refusal::Destination::Name(
                        "example.org".to_owned(),
                    ))
            })
            .unwrap();
        assert_eq!(
            (lookup.protocol, lookup.port, lookup.address.as_str()),
            (v1::EgressRefusalProtocol::Dns as i32, 0, "")
        );
    }

    #[test]
    fn a_log_that_refused_nothing_has_no_summary() {
        let proto = refusals_proto(&RunnerRefusalLog::new(5).snapshot());
        assert!(proto.refusals.is_empty());
        assert_eq!(proto.summary, None);
    }
}
