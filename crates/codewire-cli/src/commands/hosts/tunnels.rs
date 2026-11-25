//! The host agent's tunnels (#3609, slice 2, design §5.3). A daemon tunnel
//! the session asks for reaches the environment's guest daemon as `cw
//! --local` does, over the VM's hybrid vsock socket, and carries its bytes
//! until either side ends.
//!
//! The tunnel's `ready` carries the running generation's daemon capability.
//! The agent holds it in memory it wipes, only until it is sent.

use std::path::Path;

use codewire_client::hosts::{
    HostAgentClient, HostOpenTunnel, HostOperationFailure, HostTunnel, HostTunnelKind,
};
use codewire_local_vmm::control::v1 as local;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::operations::Placement;
use super::*;

/// The largest data frame sent to the control plane.
const MAX_FRAME_BYTES: usize = 32 * 1024;

fn failure(code: &str, message: impl Into<String>) -> HostOperationFailure {
    HostOperationFailure {
        code: code.to_owned(),
        message: message.into(),
        ..Default::default()
    }
}

/// Opens the tunnel `request` asks for and carries it to its end.
pub(super) async fn serve(
    agent: HostAgentClient,
    host_id: String,
    key: Arc<SigningKey>,
    placement: Placement,
    request: HostOpenTunnel,
) {
    let sign = |statement: &[u8]| key.sign(statement).to_bytes().to_vec();
    let mut tunnel = match agent.open_tunnel(&host_id, &request, sign).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            eprintln!(
                "tunnel {}: could not open: {}",
                request.tunnel_id,
                error.message()
            );
            return;
        }
    };
    let (socket, capability) = match reach(&request, &placement).await {
        Ok(reached) => reached,
        Err(failure) => {
            // The control plane hears why, if it is still there to hear.
            let _ = tunnel.failed(failure).await;
            return;
        }
    };
    if tunnel.ready(&capability).await.is_err() {
        return;
    }
    drop(capability);
    pump(socket, tunnel).await;
}

/// The daemon of the environment `request` names, when it is the one the
/// control plane last saw: the same VM, at the same generation, running.
async fn reach(
    request: &HostOpenTunnel,
    placement: &Placement,
) -> Result<(UnixStream, Zeroizing<String>), HostOperationFailure> {
    if request.kind.as_known() != Some(HostTunnelKind::HOST_TUNNEL_KIND_DAEMON_GRPC) {
        return Err(failure(
            "unsupported_tunnel",
            "this host opens daemon tunnels only",
        ));
    }
    let environment_id = Uuid::parse_str(&request.environment_id)
        .map_err(|_| failure("invalid_tunnel", "the environment ID is not a UUID"))?;
    let name = placement.vm_name(environment_id);
    let mut client = super::super::native::native_client()
        .await
        .map_err(|error| failure("supervisor_unavailable", format!("{error:#}")))?;
    let environment = client
        .get(&name)
        .await
        .map_err(|status| failure("environment_absent", status.message()))?;
    if environment.id != request.local_environment_id {
        return Err(failure(
            "environment_mismatch",
            "this host's environment of that name is a different one",
        ));
    }
    if environment.generation != request.generation {
        return Err(failure(
            "stale_generation",
            format!(
                "expected generation {}, the host has {}",
                request.generation, environment.generation
            ),
        ));
    }
    if local::EnvironmentState::try_from(environment.state) != Ok(local::EnvironmentState::Running)
    {
        return Err(failure("not_running", "the environment is not running"));
    }
    let access = client
        .daemon_access(&name)
        .await
        .map_err(|status| failure("daemon_unreachable", status.message()))?;
    let capability = Zeroizing::new(access.generation_capability);
    let socket = codewire_local_vmm::hybrid_vsock::connect_hybrid_vsock(
        Path::new(&access.hybrid_socket),
        access.guest_port,
    )
    .await
    .map_err(|error| failure("daemon_unreachable", error.to_string()))?;
    Ok((socket, capability))
}

/// Carries bytes between the daemon and the control plane until either
/// ends.
async fn pump(socket: UnixStream, mut tunnel: HostTunnel) {
    let (mut from_daemon, mut to_daemon) = socket.into_split();
    let mut buffer = vec![0; MAX_FRAME_BYTES];
    let mut daemon_open = true;
    loop {
        tokio::select! {
            read = from_daemon.read(&mut buffer), if daemon_open => match read {
                Ok(0) | Err(_) => {
                    // The daemon ended its side; the control plane still
                    // sends until it ends its own.
                    daemon_open = false;
                    tunnel.close_send();
                }
                Ok(read) => {
                    if tunnel.send(buffer[..read].to_vec()).await.is_err() {
                        return;
                    }
                }
            },
            received = tunnel.receive() => match received {
                Ok(Some(bytes)) => {
                    if to_daemon.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                Ok(None) | Err(_) => return,
            },
        }
    }
}
