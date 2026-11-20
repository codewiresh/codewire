//! The authority's recent broker lease decisions: a bounded, material-free
//! record kept for the life of the process.

use std::collections::VecDeque;

use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId, EnvironmentId,
};
use tokio::sync::Mutex;
use uuid::Uuid;

pub(crate) const MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS: usize = 4_096;
pub(crate) const MAX_BROKER_LEASE_AUDIT_LIST_LIMIT: usize = 256;

/// Material-free result of one exact authority lease decision. This recent
/// local ring is intentionally bounded and process-lifetime; #1922 owns the
/// final durable local/platform audit persistence contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrokerLeaseAuditDecision {
    Admitted,
    Denied,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerLeaseAuditEvent {
    pub sequence: u64,
    pub observed_at_unix_ms: u64,
    pub environment_id: EnvironmentId,
    pub environment_generation: u64,
    pub request_id: Uuid,
    pub capability_slot: CapabilitySlot,
    pub operation: BrokerOperationId,
    pub route: BrokerRouteId,
    pub decision: BrokerLeaseAuditDecision,
    pub credential_id: Option<CredentialId>,
    pub profile_id: Option<AccessProfileId>,
    pub profile_revision: Option<u64>,
    pub credential_revocation_generation: Option<u64>,
}

#[derive(Default)]
pub(crate) struct BrokerLeaseAuditLog {
    state: Mutex<BrokerLeaseAuditState>,
}

#[derive(Default)]
struct BrokerLeaseAuditState {
    next_sequence: u64,
    events: VecDeque<BrokerLeaseAuditEvent>,
}

impl BrokerLeaseAuditLog {
    pub(super) async fn record(&self, mut event: BrokerLeaseAuditEvent) {
        let mut state = self.state.lock().await;
        state.next_sequence = state.next_sequence.saturating_add(1).max(1);
        event.sequence = state.next_sequence;
        event.observed_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .unwrap_or(0);
        state.events.push_front(event);
        state.events.truncate(MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS);
    }

    #[cfg(test)]
    pub(crate) async fn recent(&self, limit: usize) -> Vec<BrokerLeaseAuditEvent> {
        self.recent_for(None, limit).await
    }

    /// The newest `limit` decisions, newest first: every environment's, or
    /// only `environment`'s when one is named, so that a busy environment
    /// cannot push another's decisions out of the answer.
    pub(crate) async fn recent_for(
        &self,
        environment: Option<&EnvironmentId>,
        limit: usize,
    ) -> Vec<BrokerLeaseAuditEvent> {
        self.state
            .lock()
            .await
            .events
            .iter()
            .filter(|event| environment.is_none_or(|id| event.environment_id == *id))
            .take(limit.min(MAX_BROKER_LEASE_AUDIT_LIST_LIMIT))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recent_lease_audit_ring_is_bounded_and_newest_first() {
        let audit = BrokerLeaseAuditLog::default();
        for _ in 0..(MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS + 3) {
            audit
                .record(BrokerLeaseAuditEvent {
                    sequence: 0,
                    observed_at_unix_ms: 0,
                    environment_id: EnvironmentId::parse("environment").unwrap(),
                    environment_generation: 1,
                    request_id: Uuid::new_v4(),
                    capability_slot: CapabilitySlot::codex(),
                    operation: BrokerOperationId::parse("responses").unwrap(),
                    route: BrokerRouteId::parse("openai-api").unwrap(),
                    decision: BrokerLeaseAuditDecision::Denied,
                    credential_id: None,
                    profile_id: None,
                    profile_revision: None,
                    credential_revocation_generation: None,
                })
                .await;
        }
        assert_eq!(
            audit.state.lock().await.events.len(),
            MAX_RECENT_BROKER_LEASE_AUDIT_EVENTS
        );
        let recent = audit.recent(16).await;
        assert_eq!(recent.len(), 16);
        assert!(
            recent
                .windows(2)
                .all(|pair| pair[0].sequence > pair[1].sequence)
        );
    }

    fn decision(environment: &str) -> BrokerLeaseAuditEvent {
        BrokerLeaseAuditEvent {
            sequence: 0,
            observed_at_unix_ms: 0,
            environment_id: EnvironmentId::parse(environment).unwrap(),
            environment_generation: 1,
            request_id: Uuid::new_v4(),
            capability_slot: CapabilitySlot::codex(),
            operation: BrokerOperationId::parse("responses").unwrap(),
            route: BrokerRouteId::parse("openai-api").unwrap(),
            decision: BrokerLeaseAuditDecision::Admitted,
            credential_id: None,
            profile_id: None,
            profile_revision: None,
            credential_revocation_generation: None,
        }
    }

    #[tokio::test]
    async fn a_named_environment_keeps_its_decisions_behind_a_busy_one() {
        let audit = BrokerLeaseAuditLog::default();
        audit.record(decision("quiet")).await;
        for _ in 0..(MAX_BROKER_LEASE_AUDIT_LIST_LIMIT + 1) {
            audit.record(decision("busy")).await;
        }
        let quiet = EnvironmentId::parse("quiet").unwrap();

        let everyone = audit
            .recent_for(None, MAX_BROKER_LEASE_AUDIT_LIST_LIMIT)
            .await;
        assert!(everyone.iter().all(|event| event.environment_id != quiet));

        let named = audit
            .recent_for(Some(&quiet), MAX_BROKER_LEASE_AUDIT_LIST_LIMIT)
            .await;
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].environment_id, quiet);
        assert_eq!(named[0].sequence, 1);
    }
}
