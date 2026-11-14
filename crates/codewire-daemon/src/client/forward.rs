//! One TCP connection through the daemon's `ForwardTcp` (#3025). The daemon
//! connects inside the workload's network namespace, as the workload user,
//! and refuses every target but its loopback. Workspace access forwards SSH
//! channels this way, a local VM's host ports reach the guest's loopback
//! (#4347), and orchestration's preview proxy reaches the app (#4357).

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use super::{SessionClient, SessionClientError, v1};

/// Bytes buffered between the caller's end and the daemon stream.
const FORWARD_PIPE_BYTES: usize = 64 * 1024;
/// Most bytes sent to the daemon per `data` message.
const FORWARD_CHUNK: usize = 32 * 1024;
/// `data` messages queued toward the daemon before reading the caller waits.
const FORWARD_QUEUE: usize = 8;

type Payload = v1::forward_tcp_message::Payload;

fn message(payload: Payload) -> v1::ForwardTcpMessage {
    v1::ForwardTcpMessage {
        payload: Some(payload),
    }
}

impl SessionClient {
    /// One connection to `target` inside the workload's network namespace,
    /// once the daemon has made it. Writing end of stream half-closes it, and
    /// the target's end of stream reads as end of stream. The daemon's
    /// refusal, or a target nobody listens on, is a [`SessionClientError::Status`].
    pub async fn forward_tcp(
        &self,
        target: SocketAddr,
    ) -> Result<DuplexStream, SessionClientError> {
        let (input, requests) = mpsc::channel(FORWARD_QUEUE);
        input
            .send(message(Payload::Open(v1::ForwardTcpOpen {
                address: target.ip().to_string(),
                port: target.port().into(),
            })))
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        let mut output = self
            .inner
            .clone()
            .forward_tcp(self.authorized(ReceiverStream::new(requests)))
            .await?
            .into_inner();
        match output.message().await? {
            Some(v1::ForwardTcpMessage {
                payload: Some(Payload::Opened(())),
            }) => {}
            _ => return Err(SessionClientError::InvalidForwardFrame),
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
    let (mut from_caller, mut to_caller) = tokio::io::split(remote);
    let to_daemon = async {
        let mut buffer = vec![0; FORWARD_CHUNK];
        loop {
            let read = from_caller.read(&mut buffer).await?;
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
                })) => to_caller.write_all(&bytes).await?,
                Ok(Some(v1::ForwardTcpMessage {
                    payload: Some(Payload::End(())),
                })) => {
                    to_caller.shutdown().await?;
                    return Ok(());
                }
                Ok(_) | Err(_) => {
                    return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
                }
            }
        }
    };
    // Either direction failing ends the forward; its error has nowhere to go.
    let _ = tokio::try_join!(to_daemon, from_daemon);
}
