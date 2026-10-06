//! Workspace access served by the bound hosted daemon (#2460).
//!
//! After binding, the daemon serves SSH (with SFTP and SCP) itself on
//! [`WORKSPACE_SSH_PORT`], reaching its own gRPC service in-process. Its SSH
//! host key is per binding generation and stays in the VM; only the public
//! line is recorded with orchestration. Access is marked ready once SSH
//! listens and the key is recorded. Only orchestration can reach the SSH
//! port (its NetworkPolicy); local processes reaching it gain nothing they do
//! not already have, because sessions run as the workspace user.
//!
//! The daemon is also the environment's tailnet peer, started in parallel
//! from the binding's access grant and not part of readiness; it serves the
//! same SSH server over the tailnet.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use codewire_daemon::DaemonAuthToken;
use codewire_daemon::access::WorkspaceAccessGrant;
use codewire_daemon::hosted_state::HostedStatePaths;
use codewire_daemon::local_transport::LocalDaemonConnector;
use codewire_gateway_proto::{WORKSPACE_SSH_PORT, WORKSPACE_TAILNET_UDP_PORT};
use codewire_workspace_access::daemon::DaemonSessionClient;
use codewire_workspace_access::daemon_access::{
    AccessControlPlane, ControlPlaneError, DaemonSshRunners, HostKeyStore, PeerRelayAllocation,
    daemon_ssh_server_config, public_key_line, record_host_key_until_accepted, serve_ssh_listener,
};
use codewire_workspace_access::daemon_credential::DaemonCredential;
use codewire_workspace_access::daemon_tailnet::{
    self, AccessGrants, DaemonTailnetConfig, PublicCoordinator, TailnetSsh,
    record_host_key_per_generation,
};
use connectrpc::ErrorCode;
use tokio::sync::watch;
use uuid::Uuid;

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

/// The accepted binding's identity, as workspace access needs it.
pub(crate) struct BoundAccess {
    pub environment_id: Uuid,
    pub generation: u64,
    pub daemon_credential: DaemonAuthToken,
    /// The tailnet grant; without one the daemon serves SSH only.
    pub grant: Option<WorkspaceAccessGrant>,
}

/// Serve workspace access for the accepted binding until `shutdown`.
pub(crate) async fn serve(
    paths: HostedStatePaths,
    bound: BoundAccess,
    connector: LocalDaemonConnector,
    plane: Arc<BindingClient>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let daemon = DaemonSessionClient::connect_local(
        connector,
        DaemonCredential::rendered(bound.daemon_credential),
    )
    .await
    .context("connect workspace access to the local daemon")?;
    let host_key = HostKeyStore::new(&paths.state_directory)
        .for_generation(bound.generation)
        .context("prepare the workspace SSH host key")?;
    let public_key = public_key_line(&host_key);
    let ssh_config = Arc::new(daemon_ssh_server_config(host_key));
    let runners = DaemonSshRunners::new(daemon);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((
        Ipv4Addr::UNSPECIFIED,
        WORKSPACE_SSH_PORT,
    )))
    .await
    .with_context(|| format!("listen workspace SSH on {WORKSPACE_SSH_PORT}"))?;
    let ssh = tokio::spawn(serve_ssh_listener(
        listener,
        ssh_config.clone(),
        runners.clone(),
        shutdown.clone(),
    ));
    tracing::info!(ssh_port = WORKSPACE_SSH_PORT, "workspace SSH listening");

    let plane: Arc<dyn AccessControlPlane> = plane;
    let grants = bound
        .grant
        .map(|grant| AccessGrants::new(plane.clone(), grant));
    let recorded_generation = grants
        .as_ref()
        .map(|grants| grants.current().operation_generation());
    match &grants {
        Some(grants) => {
            tokio::spawn(grants.clone().keep_fresh(shutdown.clone()));
            let tailnet = daemon_tailnet::run(
                DaemonTailnetConfig {
                    environment_id: bound.environment_id,
                    udp_listen_addr: SocketAddr::from((
                        Ipv4Addr::UNSPECIFIED,
                        WORKSPACE_TAILNET_UDP_PORT,
                    )),
                },
                grants.clone(),
                plane.clone(),
                Arc::new(PublicCoordinator::new()),
                TailnetSsh {
                    config: ssh_config,
                    runners,
                },
                shutdown.clone(),
            );
            tokio::spawn(async move {
                if let Err(error) = tailnet.await {
                    tracing::error!(error = %format!("{error:#}"), "workspace tailnet stopped");
                }
            });
        }
        None => tracing::info!("binding carries no tailnet access; serving SSH only"),
    }

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
    if let (Some(grants), Some(recorded)) = (grants, recorded_generation) {
        tokio::spawn(record_host_key_per_generation(
            plane,
            grants.subscribe(),
            public_key,
            recorded,
            shutdown,
        ));
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
