//! One TCP connection through the daemon's `ForwardTcp` (#3025), or one
//! Unix-socket connection through its `ForwardUnix` (#5608). The daemon
//! connects inside the workload's network namespace, as the workload user,
//! and refuses every target but its loopback. Workspace access forwards SSH
//! channels this way, a local VM's host ports reach the guest's loopback
//! (#4347), and orchestration's preview proxy reaches the app (#4357).

use std::net::SocketAddr;

use std::pin::Pin;
use std::task::{Context, Poll};

use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};

use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::Streaming;

use super::{SessionClient, SessionClientError, v1};

/// Bytes buffered between the caller's end and the daemon stream.
const FORWARD_PIPE_BYTES: usize = 64 * 1024;
/// Most bytes sent to the daemon per `data` message.
const FORWARD_CHUNK: usize = 32 * 1024;
/// `data` messages queued toward the daemon before reading the caller waits.
const FORWARD_QUEUE: usize = 8;
/// Once a forward's caller has gone, how long its last writes and the
/// daemon's finishing of them have, together; and how long a daemon whose
/// client went away still writes what it received to the target. A dropped
/// forward is ended within twice this.
pub const FORWARD_DROP_DRAIN: Duration = Duration::from_secs(5);

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
    ) -> Result<ForwardStream, SessionClientError> {
        let open = Payload::Open(v1::ForwardTcpOpen {
            address: target.ip().to_string(),
            port: target.port().into(),
        });
        self.forward(open, false).await
    }

    /// One connection to the Unix socket at `path` in the workload, made as
    /// the workload user, through the daemon's `ForwardUnix` (#5608); as
    /// [`Self::forward_tcp`] otherwise.
    pub async fn forward_unix(&self, path: &str) -> Result<ForwardStream, SessionClientError> {
        let open = Payload::UnixOpen(v1::ForwardUnixOpen {
            path: path.to_owned(),
        });
        self.forward(open, true).await
    }

    async fn forward(
        &self,
        open: Payload,
        unix: bool,
    ) -> Result<ForwardStream, SessionClientError> {
        let (input, requests) = mpsc::channel(FORWARD_QUEUE);
        input
            .send(message(open))
            .await
            .map_err(|_| SessionClientError::RequestClosed)?;
        let requests = self.authorized(ReceiverStream::new(requests));
        let mut client = self.inner.clone();
        let mut output = if unix {
            client.forward_unix(requests).await?
        } else {
            client.forward_tcp(requests).await?
        }
        .into_inner();
        match output.message().await? {
            Some(v1::ForwardTcpMessage {
                payload: Some(Payload::Opened(())),
            }) => {}
            _ => return Err(SessionClientError::InvalidForwardFrame),
        }
        let (local, remote) = tokio::io::duplex(FORWARD_PIPE_BYTES);
        let gone = Gone::default();
        tokio::spawn(pump(remote, input, output, gone.clone()));
        Ok(ForwardStream {
            stream: local,
            gone,
        })
    }
}

/// One forward's local end. Shutting down writing is a half-close, as on a
/// TCP stream, and the forward goes on in the other direction. Dropping it
/// ends the forward promptly: what was written before still reaches the
/// daemon, with the end of the caller's side, and then the pump waits at
/// most [`FORWARD_DROP_DRAIN`] for the daemon to finish before it drops the
/// RPC, so a target that neither writes nor closes cannot keep the forward,
/// or a local VM's helper, alive (#5608).
#[derive(Debug)]
pub struct ForwardStream {
    stream: DuplexStream,
    gone: Gone,
}

impl Drop for ForwardStream {
    fn drop(&mut self) {
        self.gone.mark();
    }
}

/// When a forward's caller went, shared by its stream and its pump, so the
/// pump's waits after that share one deadline.
#[derive(Debug, Clone, Default)]
struct Gone {
    token: CancellationToken,
    at: Arc<OnceLock<Instant>>,
}

impl Gone {
    fn mark(&self) {
        // Already set means the caller went earlier; its first time stands.
        let _ = self.at.set(Instant::now());
        self.token.cancel();
    }

    /// [`FORWARD_DROP_DRAIN`] after the caller went, once it has.
    async fn deadline(&self) -> Instant {
        self.token.cancelled().await;
        // `mark` sets the time before it cancels.
        self.at.get().copied().unwrap_or_else(Instant::now) + FORWARD_DROP_DRAIN
    }
}

impl AsyncRead for ForwardStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for ForwardStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, data)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

/// Copy between the local pipe and the daemon stream until both directions
/// end, then wait for the daemon to end the RPC, which it does once it has
/// written everything to the target.
///
/// Each direction runs to its own end: the caller's side to its end of
/// stream, sent as `end`, which still comes after a drop since the pipe
/// keeps what was written; the daemon's side to the daemon's `end`, or the
/// caller going, after which nobody reads it. Once the caller is gone, what
/// is left is bounded by [`FORWARD_DROP_DRAIN`].
async fn pump(
    remote: DuplexStream,
    input: mpsc::Sender<v1::ForwardTcpMessage>,
    mut output: Streaming<v1::ForwardTcpMessage>,
    gone: Gone,
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
    let from_daemon = async {
        tokio::select! {
            ended = from_daemon => ended,
            // Nobody reads the daemon's side once the caller is gone.
            () = gone.token.cancelled() => Ok(()),
        }
    };
    // A direction failing ends only itself: the caller's writes still reach
    // the daemon when the target's answer can no longer be delivered.
    let (sent, _) = tokio::join!(bounded_once_gone(&gone, to_daemon), from_daemon);
    if sent.is_ok() {
        // The daemon ends the RPC once it has written the caller's side to
        // the target. Dropping it sooner would cut that off; a target that
        // never lets it finish is left after the bound.
        let wait = async { tokio::time::sleep_until(gone.deadline().await).await };
        tokio::select! {
            () = async { while let Ok(Some(_)) = output.message().await {} } => {}
            () = wait => {}
        }
    }
}

/// `work` to its end while the caller is there, and until the caller's
/// deadline once it has gone.
async fn bounded_once_gone<T>(
    gone: &Gone,
    work: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    let mut work = std::pin::pin!(work);
    tokio::select! {
        ended = &mut work => return ended,
        () = gone.token.cancelled() => {}
    }
    tokio::time::timeout_at(gone.deadline().await, work)
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
}
