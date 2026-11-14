//! Port forwarding through the daemon's `ForwardTcp` (#3025), for an SSH
//! server outside the workload's network namespace, such as a local VM's
//! supervisor on the host. The daemon connects inside the namespace, as the
//! workload user, and refuses every target but its loopback.

use std::net::SocketAddr;

use async_trait::async_trait;
use codewire_daemon::client::SessionClientError;
use tokio::io::DuplexStream;
use tonic::Code;

use super::{DaemonClientError, DaemonSessionClient};
use crate::ssh::{ForwardDialError, ForwardDialer, ForwardIo, ForwardTarget};

impl DaemonSessionClient {
    /// One connection to `target` inside the workload's network namespace,
    /// once the daemon has made it. Writing end of stream half-closes it, and
    /// the target's end of stream reads as end of stream. The stream adapter
    /// is the daemon client's, shared with orchestration's preview proxy.
    pub async fn forward_tcp(&self, target: SocketAddr) -> Result<DuplexStream, DaemonClientError> {
        self.credential_client()
            .forward_tcp(target)
            .await
            .map_err(|error| match error {
                SessionClientError::Status(status) => self.refused(status),
                SessionClientError::RequestClosed => DaemonClientError::RequestClosed,
                _ => DaemonClientError::InvalidFrame("forward"),
            })
    }
}

/// Dials a forward's target through the environment's daemon.
pub struct DaemonForwardDialer {
    client: DaemonSessionClient,
}

impl DaemonForwardDialer {
    /// Forward through `client`'s daemon, which must offer
    /// `forward.workload_loopback.v1`.
    pub fn new(client: DaemonSessionClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ForwardDialer for DaemonForwardDialer {
    async fn dial(&self, target: &ForwardTarget) -> Result<Box<dyn ForwardIo>, ForwardDialError> {
        let mut failures = Vec::new();
        for addr in target.addrs() {
            match self.client.forward_tcp(*addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(DaemonClientError::Status(status))
                    if matches!(
                        status.code(),
                        Code::PermissionDenied | Code::InvalidArgument | Code::Unimplemented
                    ) =>
                {
                    return Err(ForwardDialError::Prohibited(status.message().to_owned()));
                }
                // The daemon's message already names the address and why.
                Err(DaemonClientError::Status(status)) => {
                    failures.push(status.message().to_owned());
                }
                Err(error) => failures.push(format!(
                    "the environment's daemon did not forward to {addr}: {error}"
                )),
            }
        }
        Err(ForwardDialError::ConnectFailed(failures.join("; ")))
    }
}
