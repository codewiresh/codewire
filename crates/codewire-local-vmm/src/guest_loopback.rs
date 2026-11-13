//! Connections to a local environment's workload loopback (#4347).
//!
//! The guest daemon's `ForwardTcp` connects to a loopback address inside the
//! workload's network namespace as the workload user, and refuses platform
//! listeners. A published host port reaches the guest this way
//! (`runner/host_port_forward.rs`), as Codewire's SSH forwards do, and
//! `cw ports --publish` checks the same path once to say whether anything
//! listens yet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use codewire_daemon::DaemonAuthToken;
use codewire_workspace_access::daemon::{DaemonClientError, DaemonSessionClient};
use tokio::io::DuplexStream;
use tonic::Code;

use crate::control::v1;
use crate::hybrid_vsock::HybridVsockTarget;

/// The workload loopback addresses a port is tried on, in order, as SSH's
/// `localhost` is: a server bound only to `::1` answers too.
const LOOPBACKS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
];

/// Why a connection to a guest port's loopback was not made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuestLoopbackError {
    #[error("the environment's daemon could not be reached")]
    DaemonUnreachable,
    #[error("nothing in the environment listens on 127.0.0.1:{0} or [::1]:{0}")]
    NothingListens(u16),
    /// The daemon's own reason: a platform listener, or a daemon that does
    /// not forward.
    #[error("{0}")]
    Refused(String),
}

impl GuestLoopbackError {
    /// The closed name a log records instead of the message.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DaemonUnreachable => "daemon_unreachable",
            Self::NothingListens(_) => "nothing_listens",
            Self::Refused(_) => "refused",
        }
    }
}

/// A stream to `guest_port` on the first workload loopback that accepts it.
pub async fn open_guest_loopback(
    client: &DaemonSessionClient,
    guest_port: u16,
) -> Result<DuplexStream, GuestLoopbackError> {
    for address in LOOPBACKS {
        match client
            .forward_tcp(SocketAddr::new(address, guest_port))
            .await
        {
            Ok(stream) => return Ok(stream),
            Err(error) => match failure(error, guest_port) {
                GuestLoopbackError::NothingListens(_) => {}
                failure => return Err(failure),
            },
        }
    }
    Err(GuestLoopbackError::NothingListens(guest_port))
}

/// A daemon client over an environment's admitted daemon access.
pub async fn connect_daemon_access(
    access: v1::DaemonAccess,
) -> Result<DaemonSessionClient, GuestLoopbackError> {
    let capability = zeroize::Zeroizing::new(access.generation_capability);
    let target = HybridVsockTarget::new(PathBuf::from(access.hybrid_socket), access.guest_port)
        .map_err(|_| GuestLoopbackError::DaemonUnreachable)?;
    let channel = target
        .connect_channel()
        .await
        .map_err(|_| GuestLoopbackError::DaemonUnreachable)?;
    let credential = DaemonAuthToken::new(capability.as_str())
        .map_err(|_| GuestLoopbackError::DaemonUnreachable)?;
    Ok(DaemonSessionClient::from_channel(channel, credential))
}

/// Whether something in the environment accepts a connection on
/// `guest_port`'s loopback now. The one probe connection closes at once.
pub async fn probe_guest_loopback(
    access: v1::DaemonAccess,
    guest_port: u16,
) -> Result<(), GuestLoopbackError> {
    let client = connect_daemon_access(access).await?;
    open_guest_loopback(&client, guest_port).await.map(drop)
}

fn failure(error: DaemonClientError, guest_port: u16) -> GuestLoopbackError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            Code::Unimplemented => GuestLoopbackError::Refused(
                "this local VM's runtime predates port forwarding; stop and start it to use it"
                    .into(),
            ),
            Code::PermissionDenied | Code::InvalidArgument => {
                GuestLoopbackError::Refused(status.message().to_owned())
            }
            _ => GuestLoopbackError::NothingListens(guest_port),
        },
        _ => GuestLoopbackError::DaemonUnreachable,
    }
}

#[cfg(test)]
pub(crate) mod tests;
