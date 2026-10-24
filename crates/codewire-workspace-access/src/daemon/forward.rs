//! Port forwarding through the daemon's `ForwardTcp` (#3025), for an SSH
//! server outside the workload's network namespace, such as a local VM's
//! supervisor on the host. The daemon connects inside the namespace, as the
//! workload user, and refuses every target but its loopback.

use std::net::SocketAddr;

use async_trait::async_trait;
use codewire_daemon_proto::daemon::v1;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code, Request, Streaming};

use super::{DaemonClientError, DaemonSessionClient};
use crate::ssh::{ForwardDialError, ForwardDialer, ForwardIo, ForwardTarget};

/// Bytes buffered between a forward's SSH channel and its daemon stream.
const FORWARD_PIPE_BYTES: usize = 64 * 1024;
/// Most bytes sent to the daemon per `data` message.
const FORWARD_CHUNK: usize = 32 * 1024;
/// `data` messages queued toward the daemon before reading the channel waits.
const FORWARD_QUEUE: usize = 8;

type Payload = v1::forward_tcp_message::Payload;

fn message(payload: Payload) -> v1::ForwardTcpMessage {
    v1::ForwardTcpMessage {
        payload: Some(payload),
    }
}

impl DaemonSessionClient {
    /// One connection to `target` inside the workload's network namespace,
    /// once the daemon has made it. Writing end of stream half-closes it, and
    /// the target's end of stream reads as end of stream.
    pub async fn forward_tcp(&self, target: SocketAddr) -> Result<DuplexStream, DaemonClientError> {
        let (input, requests) = mpsc::channel(FORWARD_QUEUE);
        input
            .send(message(Payload::Open(v1::ForwardTcpOpen {
                address: target.ip().to_string(),
                port: target.port().into(),
            })))
            .await
            .map_err(|_| DaemonClientError::RequestClosed)?;
        let mut request = Request::new(ReceiverStream::new(requests));
        self.authorize(&mut request);
        let mut output = self
            .inner
            .clone()
            .forward_tcp(request)
            .await
            .map_err(|status| self.refused(status))?
            .into_inner();
        match output.message().await? {
            Some(v1::ForwardTcpMessage {
                payload: Some(Payload::Opened(())),
            }) => {}
            _ => return Err(DaemonClientError::InvalidFrame("forward")),
        }
        let (local, remote) = tokio::io::duplex(FORWARD_PIPE_BYTES);
        tokio::spawn(pump(remote, input, output));
        Ok(local)
    }
}

/// Copy between the local pipe and the daemon stream until both directions
/// end, or either fails, which drops both and so ends the forward.
async fn pump(
    remote: DuplexStream,
    input: mpsc::Sender<v1::ForwardTcpMessage>,
    mut output: Streaming<v1::ForwardTcpMessage>,
) {
    let (mut from_channel, mut to_channel) = tokio::io::split(remote);
    let to_daemon = async {
        let mut buffer = vec![0; FORWARD_CHUNK];
        loop {
            let read = from_channel.read(&mut buffer).await?;
            let payload = if read == 0 {
                Payload::End(())
            } else {
                Payload::Data(buffer[..read].to_vec())
            };
            input
                .send(message(payload))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
            if read == 0 {
                return Ok::<_, std::io::Error>(());
            }
        }
    };
    let from_daemon = async {
        loop {
            match output.message().await {
                Ok(Some(v1::ForwardTcpMessage {
                    payload: Some(Payload::Data(bytes)),
                })) => to_channel.write_all(&bytes).await?,
                Ok(Some(v1::ForwardTcpMessage {
                    payload: Some(Payload::End(())),
                })) => {
                    to_channel.shutdown().await?;
                    return Ok(());
                }
                Ok(_) | Err(_) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
                }
            }
        }
    };
    let _ = tokio::try_join!(to_daemon, from_daemon);
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
