//! The access control plane of a host's tailnet peers (#3609, slice 3 design
//! §3). Each call goes out on whichever session is attached and its answer
//! comes back on it; a call that no session answers fails as retryable.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use codewire_client::hosts::{
    AccessAnswer, AccessCall, HostAccessGrant, HostAccessRefresh, HostAccessRefusal, HostKeyRecord,
    HostPeerRelayAllocate,
};
use codewire_daemon::access::{AccessFields, WorkspaceAccessGrant};
use codewire_workspace_access::daemon_access::{
    AccessControlPlane, ControlPlaneError, PeerRelayAllocation,
};
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;

use super::PeerKey;

/// How long a call waits for its answer, including for a session to
/// attach.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Calls waiting for the session loop.
const QUEUED_CALLS: usize = 64;

/// One call and where its answer goes.
pub(in crate::commands::hosts) struct Call {
    call: AccessCall,
    reply: oneshot::Sender<AccessAnswer>,
}

/// The peers' side of the host session.
#[derive(Clone)]
pub(in crate::commands::hosts) struct AccessLink {
    calls: mpsc::Sender<Call>,
}

/// The link, and the calls it sends, for the session loop to carry.
pub(in crate::commands::hosts) fn link() -> (AccessLink, mpsc::Receiver<Call>) {
    let (calls, queued) = mpsc::channel(QUEUED_CALLS);
    (AccessLink { calls }, queued)
}

impl AccessLink {
    async fn ask(&self, call: AccessCall) -> Result<AccessAnswer, ControlPlaneError> {
        let (reply, answer) = oneshot::channel();
        let asked = async {
            self.calls
                .send(Call { call, reply })
                .await
                .map_err(|_| ControlPlaneError::Retryable)?;
            answer.await.map_err(|_| ControlPlaneError::Retryable)
        };
        tokio::time::timeout(CALL_TIMEOUT, asked)
            .await
            .map_err(|_| ControlPlaneError::Retryable)?
    }
}

/// The calls one session sent that are not answered yet. Dropped with the
/// session, which fails each of them as retryable.
#[derive(Default)]
pub(in crate::commands::hosts) struct Pending {
    waiting: HashMap<String, oneshot::Sender<AccessAnswer>>,
}

impl Pending {
    /// The call to send, or `None` when its caller stopped waiting.
    pub(in crate::commands::hosts) fn take(&mut self, call: Call) -> Option<AccessCall> {
        self.waiting.retain(|_, reply| !reply.is_closed());
        if call.reply.is_closed() {
            return None;
        }
        self.waiting
            .insert(call.call.request_id().to_owned(), call.reply);
        Some(call.call)
    }

    /// Hands `answer` to the call it echoes; an answer to no call is dropped.
    pub(in crate::commands::hosts) fn answer(&mut self, answer: AccessAnswer) {
        if let Some(reply) = self.waiting.remove(answer.request_id()) {
            let _ = reply.send(answer);
        }
    }

    pub(in crate::commands::hosts) fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }
}

/// The access calls of one VM's peer, naming the environment, local ID and
/// boot generation it serves. The host never names the operation
/// generation: the control plane reads it, and a grant carries it.
pub(super) struct HostPlane {
    link: AccessLink,
    vm: PeerKey,
    /// Set by a refusal that is final at this generation; the peer stops.
    refused: watch::Sender<bool>,
}

impl HostPlane {
    pub(super) fn new(link: AccessLink, vm: PeerKey, refused: watch::Sender<bool>) -> Self {
        Self { link, vm, refused }
    }

    fn refusal(&self, refusal: &HostAccessRefusal) -> ControlPlaneError {
        if refusal.retryable {
            return ControlPlaneError::Retryable;
        }
        eprintln!(
            "environment {}: the tailnet peer stops: Codewire refused it ({})",
            self.vm.environment_id, refusal.code
        );
        self.refused.send_replace(true);
        ControlPlaneError::Refused
    }

    fn request_id() -> String {
        Uuid::new_v4().to_string()
    }
}

/// A host's grant, as the hosted daemon takes one. The peer serves no
/// application ports, whatever the grant lists: its daemon-side forwarder
/// dials this computer's loopback, not the VM's. A host has no published
/// direct UDP endpoint and no relay, so it finds its address with STUN.
pub(super) fn host_grant(grant: &HostAccessGrant, now: SystemTime) -> Option<WorkspaceAccessGrant> {
    WorkspaceAccessGrant::validate(
        &AccessFields {
            peer_token: &grant.peer_token,
            peer_token_expires_at: grant.peer_token_expires_at,
            operation_generation: grant.operation_generation,
            coordinator_url: &grant.coordinator_url,
            direct_udp_endpoints: &[],
            peer_relay_endpoints: &[],
            app_ports: &[],
            mesh: None,
            identity_files: None,
        },
        now,
    )
    .ok()
}

#[async_trait]
impl AccessControlPlane for HostPlane {
    async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, ControlPlaneError> {
        let call = AccessCall::Refresh(HostAccessRefresh {
            request_id: Self::request_id(),
            environment_id: self.vm.environment_id.to_string(),
            local_environment_id: self.vm.local_environment_id.to_string(),
            generation: self.vm.generation,
            ..Default::default()
        });
        match self.link.ask(call).await? {
            AccessAnswer::Grant(grant) => {
                host_grant(&grant, SystemTime::now()).ok_or(ControlPlaneError::Retryable)
            }
            AccessAnswer::Refused(refusal) => Err(self.refusal(&refusal)),
            _ => Err(ControlPlaneError::Retryable),
        }
    }

    async fn record_host_key(&self, public_key_openssh: &str) -> Result<(), ControlPlaneError> {
        let call = AccessCall::RecordKey(HostKeyRecord {
            request_id: Self::request_id(),
            environment_id: self.vm.environment_id.to_string(),
            local_environment_id: self.vm.local_environment_id.to_string(),
            generation: self.vm.generation,
            public_key_openssh: public_key_openssh.to_owned(),
            ..Default::default()
        });
        match self.link.ask(call).await? {
            AccessAnswer::KeyRecorded(_) => Ok(()),
            AccessAnswer::Refused(refusal) => Err(self.refusal(&refusal)),
            _ => Err(ControlPlaneError::Retryable),
        }
    }

    async fn allocate_peer_relay(
        &self,
        disco_keys: [String; 2],
        relay_generation: u32,
    ) -> Result<PeerRelayAllocation, ControlPlaneError> {
        let call = AccessCall::AllocateRelay(HostPeerRelayAllocate {
            request_id: Self::request_id(),
            environment_id: self.vm.environment_id.to_string(),
            local_environment_id: self.vm.local_environment_id.to_string(),
            generation: self.vm.generation,
            disco_keys: disco_keys.to_vec(),
            relay_generation,
            ..Default::default()
        });
        match self.link.ask(call).await? {
            AccessAnswer::RelayAllocation(allocation) => Ok(PeerRelayAllocation {
                relay_generation: allocation.relay_generation,
                server_disco_key: allocation.server_disco_key,
                disco_keys: allocation.disco_keys,
                lamport_id: allocation.lamport_id,
                vni: allocation.vni,
                bind_lifetime_ns: allocation.bind_lifetime_ns,
                steady_state_lifetime_ns: allocation.steady_state_lifetime_ns,
                addr_ports: allocation.addr_ports,
            }),
            // No relay leaves the peer on DERP; it doesn't stop it.
            AccessAnswer::Refused(refusal) if refusal.retryable => {
                Err(ControlPlaneError::Retryable)
            }
            AccessAnswer::Refused(_) => Err(ControlPlaneError::Refused),
            _ => Err(ControlPlaneError::Retryable),
        }
    }
}
