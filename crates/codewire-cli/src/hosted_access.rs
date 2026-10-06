//! Workspace access served by the bound hosted daemon (#2460).
//!
//! After binding, the daemon serves SSH (with SFTP and SCP) itself on
//! [`WORKSPACE_SSH_PORT`], reaching its own gRPC service in-process. Its SSH
//! host key is per binding generation and stays in the VM; only the public
//! line is recorded with orchestration. Access is marked ready once SSH
//! listens and the key is recorded. Only orchestration can reach the SSH
//! port (its NetworkPolicy); local processes reaching it gain nothing they do
//! not already have, because sessions run as the workspace user.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use codewire_daemon::DaemonAuthToken;
use codewire_daemon::access::WorkspaceAccessGrant;
use codewire_daemon::hosted_state::HostedStatePaths;
use codewire_daemon::local_transport::LocalDaemonConnector;
use codewire_gateway_proto::WORKSPACE_SSH_PORT;
use codewire_workspace_access::daemon::DaemonSessionClient;
use codewire_workspace_access::daemon_access::{
    AccessControlPlane, ControlPlaneError, DaemonSshRunners, HostKeyStore, PeerRelayAllocation,
    daemon_ssh_server_config, public_key_line, record_host_key_until_accepted, serve_ssh_listener,
};
use codewire_workspace_access::daemon_credential::DaemonCredential;
use connectrpc::ErrorCode;
use tokio::sync::watch;

use crate::hosted_binding::{AttemptError, BindingClient};

const RECORD_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const RECORD_MAX_BACKOFF: Duration = Duration::from_secs(5);

#[async_trait]
impl AccessControlPlane for BindingClient {
    async fn record_host_key(&self, public_key_openssh: &str) -> Result<(), ControlPlaneError> {
        BindingClient::record_host_key(self, public_key_openssh)
            .await
            .map_err(control_plane_error)
    }

    async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, ControlPlaneError> {
        BindingClient::refresh_access(self)
            .await
            .map_err(control_plane_error)
    }

    async fn allocate_peer_relay(
        &self,
        disco_keys: [String; 2],
        relay_generation: u32,
    ) -> Result<PeerRelayAllocation, ControlPlaneError> {
        let response = BindingClient::allocate_peer_relay(self, disco_keys, relay_generation)
            .await
            .map_err(control_plane_error)?;
        Ok(PeerRelayAllocation {
            relay_generation: response.relay_generation,
            server_disco_key: response.server_disco_key,
            disco_keys: response.disco_keys,
            lamport_id: response.lamport_id,
            vni: response.vni,
            bind_lifetime_ns: response.bind_lifetime_ns,
            steady_state_lifetime_ns: response.steady_state_lifetime_ns,
            addr_ports: response.addr_ports,
        })
    }
}

/// A permanent refusal is `failed_precondition`; anything else may pass.
fn control_plane_error(error: AttemptError) -> ControlPlaneError {
    match error {
        AttemptError::Rejected(ErrorCode::FailedPrecondition) => ControlPlaneError::Refused,
        _ => ControlPlaneError::Retryable,
    }
}

/// Serve workspace access for the accepted binding until `shutdown`.
pub(crate) async fn serve(
    paths: HostedStatePaths,
    generation: u64,
    daemon_credential: DaemonAuthToken,
    connector: LocalDaemonConnector,
    plane: Arc<BindingClient>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let daemon = DaemonSessionClient::connect_local(
        connector,
        DaemonCredential::rendered(daemon_credential),
    )
    .await
    .context("connect workspace access to the local daemon")?;
    let host_key = HostKeyStore::new(&paths.state_directory)
        .for_generation(generation)
        .context("prepare the workspace SSH host key")?;
    let public_key = public_key_line(&host_key);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((
        Ipv4Addr::UNSPECIFIED,
        WORKSPACE_SSH_PORT,
    )))
    .await
    .with_context(|| format!("listen workspace SSH on {WORKSPACE_SSH_PORT}"))?;
    let ssh = tokio::spawn(serve_ssh_listener(
        listener,
        Arc::new(daemon_ssh_server_config(host_key)),
        DaemonSshRunners::new(daemon),
        shutdown.clone(),
    ));
    tracing::info!(ssh_port = WORKSPACE_SSH_PORT, "workspace SSH listening");
    match record_host_key_until_accepted(
        plane.as_ref(),
        &public_key,
        RECORD_INITIAL_BACKOFF,
        RECORD_MAX_BACKOFF,
    )
    .await
    {
        Ok(()) => {
            paths
                .mark_access_ready()
                .context("mark workspace access ready")?;
            tracing::info!("workspace SSH host key recorded; access ready");
        }
        Err(_) => {
            // Another key is recorded for this generation: clients would
            // refuse this one, so access is never reported ready.
            tracing::error!(
                "workspace SSH host key refused for this generation; access is not ready"
            );
        }
    }
    ssh.await
        .context("workspace SSH listener task")?
        .context("serve workspace SSH")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_failed_precondition_is_a_permanent_refusal() {
        assert_eq!(
            control_plane_error(AttemptError::Rejected(ErrorCode::FailedPrecondition)),
            ControlPlaneError::Refused
        );
        for error in [
            AttemptError::NotFound,
            AttemptError::Rejected(ErrorCode::Unavailable),
            AttemptError::Rejected(ErrorCode::PermissionDenied),
            AttemptError::IdentityUnavailable,
            AttemptError::InvalidResponse,
        ] {
            assert_eq!(control_plane_error(error), ControlPlaneError::Retryable);
        }
    }
}
