//! Reading the authority's recent broker lease decisions: identifiers and
//! policy metadata only, never material.

use codewire_access::EnvironmentId;
use tonic::Status;
use tonic::transport::Channel;

use super::{
    LocalCredentialClient, LocalCredentialControlClient, broker_lease_audit_event_from_proto,
};
use crate::BrokerLeaseAuditEvent;
use crate::broker_channel::MAX_BROKER_LEASE_AUDIT_LIST_LIMIT;
use crate::control::v1;
use crate::control::v1::local_credential_authority_service_client::LocalCredentialAuthorityServiceClient;

/// One environment's recent lease decisions, as far as the authority could
/// say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentLeaseAudit {
    /// Newest first.
    pub events: Vec<BrokerLeaseAuditEvent>,
    /// The authority is older than the environment filter, and its answer
    /// was full of every environment's decisions: older ones of this
    /// environment may be missing.
    pub crowded: bool,
}

impl LocalCredentialClient {
    /// Return newest-first, process-lifetime broker lease decisions. The
    /// bounded local ring contains identifiers and policy metadata only.
    pub async fn list_recent_broker_lease_audit_events(
        &mut self,
        limit: usize,
    ) -> Result<Vec<BrokerLeaseAuditEvent>, Status> {
        list(&mut self.inner, None, limit).await
    }
}

impl LocalCredentialControlClient {
    /// The newest `limit` lease decisions of one environment, newest first.
    pub async fn environment_lease_audit(
        &mut self,
        environment_id: &EnvironmentId,
        limit: usize,
    ) -> Result<EnvironmentLeaseAudit, Status> {
        let listed = list(&mut self.inner, Some(environment_id), limit).await?;
        let answered = listed.len();
        let events: Vec<_> = listed
            .into_iter()
            .filter(|event| event.environment_id == *environment_id)
            .collect();
        Ok(EnvironmentLeaseAudit {
            crowded: answered == limit && events.len() < answered,
            events,
        })
    }
}

async fn list(
    client: &mut LocalCredentialAuthorityServiceClient<Channel>,
    environment_id: Option<&EnvironmentId>,
    limit: usize,
) -> Result<Vec<BrokerLeaseAuditEvent>, Status> {
    let invalid_limit = || Status::invalid_argument("invalid broker audit list limit");
    if !(1..=MAX_BROKER_LEASE_AUDIT_LIST_LIMIT).contains(&limit) {
        return Err(invalid_limit());
    }
    let response = client
        .list_recent_broker_lease_audit_events(v1::ListRecentBrokerLeaseAuditEventsRequest {
            limit: u32::try_from(limit).map_err(|_| invalid_limit())?,
            environment_id: environment_id.map(ToString::to_string),
        })
        .await?
        .into_inner();
    let events = response
        .events
        .into_iter()
        .map(broker_lease_audit_event_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    if events
        .windows(2)
        .any(|pair| pair[0].sequence <= pair[1].sequence)
    {
        return Err(Status::data_loss(
            "local credential authority returned invalid broker audit ordering",
        ));
    }
    Ok(events)
}
