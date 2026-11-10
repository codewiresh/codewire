//! Durable session attachment over an environment's tailnet (#3827): the
//! client half of the daemon's `session@codewire.sh` SSH subsystem.
//!
//! An [`EnvironmentTailnet`] joins the environment's tailnet once and holds
//! one SSH connection to its daemon, verified against the host key the
//! platform recorded, for every attachment and reattachment that follows.
//! WireGuard starts on DERP and moves to direct UDP under the open
//! connection once disco proves a path; [`EnvironmentTailnet::path`] says
//! which path is in use and, when it is not direct UDP, why.
//!
//! An attachment is the same [`EnvironmentSessionAttachment`] the API path
//! returns, carrying the same messages, so a caller keeps one attach loop
//! and reconnects from its output offset on either transport.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use codewire_tailnet::conn::{Conn, PeerTransport};
use codewire_tailnet::node::Node;
use connectrpc::{ConnectError, ErrorCode};
use russh::keys::PublicKey;
use russh::{ChannelMsg, client};

use crate::session_wire::{FrameDecoder, SESSION_SUBSYSTEM, encode_frame};
use crate::tailnet::dial_tailnet_ssh;
use crate::{
    AttachSessionOpen, AttachSessionRequest, AttachSessionResponse, ClientError, CodewireClient,
    EnvironmentSessionAttachment, EnvironmentSessionAttachmentInput, GetEnvironmentHostKeyRequest,
    attach_session_request,
};

/// The user the daemon's SSH server expects; the tailnet authenticated the
/// client before the connection arrived.
const SSH_USER: &str = "codewire";
/// Matches the daemon's server keepalive.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 3;
/// A connection that hears nothing for this long is dead, and the caller
/// reconnects. Keepalives alone cannot say so: a network cut can fill the
/// tailnet's bounded TCP buffers and stall russh's writer and keepalive timer
/// until the stack's 120 s idle timeout (#3861). A live connection hears the
/// daemon's keepalive or a reply to its own at least every
/// [`KEEPALIVE_INTERVAL`].
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(45);

/// How long the end of a connection waits for its stream to shut down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// The stream under an SSH connection, with its shutdown bounded by
/// [`SHUTDOWN_GRACE`]. russh shuts its stream down whenever the connection
/// ends, including after giving it up as dead, and keeps the connection's
/// channels open until that completes. The tailnet's TCP completes a
/// shutdown only once the peer acknowledges the pending data, so after a
/// network cut every attachment waited for the network to return or for the
/// stack's 120 s idle timeout (#3861). Past the grace the stream is dropped,
/// which resets the connection.
struct BoundedShutdown<S> {
    inner: S,
    deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BoundedShutdown<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BoundedShutdown<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let std::task::Poll::Ready(result) =
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        {
            return std::task::Poll::Ready(result);
        }
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(SHUTDOWN_GRACE)));
        deadline.as_mut().poll(cx).map(Ok)
    }
}

/// Which tailnet path carries the connection now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailnetPath {
    DirectUdp,
    PeerRelay,
    Derp,
}

impl TailnetPath {
    pub fn label(self) -> &'static str {
        match self {
            Self::DirectUdp => "direct UDP",
            Self::PeerRelay => "relay",
            Self::Derp => "DERP",
        }
    }
}

/// The path in use and, unless it is direct UDP, why not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailnetPathReport {
    pub path: TailnetPath,
    pub reason: Option<String>,
}

/// An SSH connection to an environment's daemon over any stream, verified
/// against the host key the platform recorded. [`EnvironmentTailnet`] runs
/// it over the tailnet; a native client may bring its own stream.
pub struct EnvironmentSsh {
    ssh: client::Handle<RecordedHostKey>,
}

impl EnvironmentSsh {
    /// Open the SSH connection over `stream`, refusing any host key other
    /// than `recorded_host_key`, one OpenSSH public key line.
    pub async fn connect<S>(stream: S, recorded_host_key: &str) -> anyhow::Result<Self>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let expected = PublicKey::from_openssh(recorded_host_key)
            .context("the recorded SSH host key is not an OpenSSH public key")?;
        let config = Arc::new(client::Config {
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX,
            inactivity_timeout: Some(INACTIVITY_TIMEOUT),
            ..Default::default()
        });
        let stream = BoundedShutdown {
            inner: stream,
            deadline: None,
        };
        let mut ssh = client::connect_stream(config, stream, RecordedHostKey { expected })
            .await
            .map_err(|error| anyhow!(error).context("SSH handshake with the environment"))?;
        let authenticated = ssh
            .authenticate_none(SSH_USER)
            .await
            .map(|result| matches!(result, client::AuthResult::Success));
        if !matches!(authenticated, Ok(true)) {
            return Err(anyhow!(
                "the environment's SSH server refused the connection"
            ));
        }
        Ok(Self { ssh })
    }

    /// Whether the connection has ended; a caller then connects again.
    pub fn is_closed(&self) -> bool {
        self.ssh.is_closed()
    }

    /// Attach to a durable session at `open.output_offset`. The attachment
    /// ends with a retryable error if the connection drops, and with the
    /// daemon's reason if it refuses.
    pub async fn attach(
        &self,
        open: AttachSessionOpen,
    ) -> Result<EnvironmentSessionAttachment, ClientError> {
        attach_over(&self.ssh, open).await
    }

    /// Open an interactive login shell on a terminal of `columns` x `rows`,
    /// as `ssh` does: the shell belongs to this connection and ends with it
    /// (plain `cw shell`, owner 2026-11-01 on #3827).
    pub async fn open_shell(
        &self,
        term: &str,
        columns: u32,
        rows: u32,
    ) -> anyhow::Result<InteractiveShell> {
        let channel = self
            .ssh
            .channel_open_session()
            .await
            .context("open an SSH session channel")?;
        let (mut read, write) = channel.split();
        write
            .request_pty(true, term, columns, rows, 0, 0, &[])
            .await
            .context("request a terminal")?;
        write.request_shell(true).await.context("request a shell")?;
        // One reply for the terminal and one for the shell, in order.
        for request in ["terminal", "shell"] {
            loop {
                match read.wait().await {
                    Some(ChannelMsg::Success) => break,
                    Some(ChannelMsg::Failure) => {
                        return Err(anyhow!("the environment refused the {request} request"));
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                        return Err(anyhow!(
                            "the environment refused the {request} request: {}",
                            String::from_utf8_lossy(&data).trim()
                        ));
                    }
                    Some(_) => {}
                    None => return Err(anyhow!("the SSH connection closed")),
                }
            }
        }
        Ok(InteractiveShell {
            input: ShellInput { write },
            output: ShellOutput { read },
        })
    }
}

/// An interactive shell on the environment, in two halves so input and
/// output run independently.
pub struct InteractiveShell {
    pub input: ShellInput,
    pub output: ShellOutput,
}

pub struct ShellInput {
    write: russh::ChannelWriteHalf<client::Msg>,
}

impl ShellInput {
    pub async fn write(&self, data: &[u8]) -> anyhow::Result<()> {
        self.write
            .data_bytes(data.to_vec())
            .await
            .context("the SSH connection closed")
    }

    pub async fn resize(&self, columns: u32, rows: u32) -> anyhow::Result<()> {
        self.write
            .window_change(columns, rows, 0, 0)
            .await
            .context("the SSH connection closed")
    }

    /// No more input; the shell sees end of file.
    pub async fn close(&self) -> anyhow::Result<()> {
        self.write.eof().await.context("the SSH connection closed")
    }
}

/// What the shell sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The shell exited with this status; the channel closes next.
    Exit(u32),
}

pub struct ShellOutput {
    read: russh::ChannelReadHalf,
}

impl ShellOutput {
    /// The next output or exit status; `None` once the channel closed, which
    /// without an exit status means the connection dropped.
    pub async fn next(&mut self) -> Option<ShellEvent> {
        loop {
            match self.read.wait().await? {
                ChannelMsg::Data { data } => return Some(ShellEvent::Stdout(data.to_vec())),
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    return Some(ShellEvent::Stderr(data.to_vec()));
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    return Some(ShellEvent::Exit(exit_status));
                }
                ChannelMsg::Close => return None,
                _ => {}
            }
        }
    }
}

/// One environment's tailnet and the SSH connection to its daemon.
pub struct EnvironmentTailnet {
    ssh: EnvironmentSsh,
    conn: Arc<Conn>,
    peer: Node,
    derp_forced: bool,
    coordinator: tokio::task::JoinHandle<()>,
}

impl Drop for EnvironmentTailnet {
    fn drop(&mut self) {
        self.coordinator.abort();
    }
}

impl EnvironmentTailnet {
    /// Join `environment_id`'s tailnet and open an SSH connection to its
    /// daemon, refusing a host key other than the one the platform recorded.
    pub async fn connect(
        client: &CodewireClient,
        org_id: &str,
        environment_id: &str,
    ) -> anyhow::Result<Self> {
        let recorded = client
            .get_environment_host_key(GetEnvironmentHostKeyRequest {
                org_id: org_id.into(),
                environment_id: environment_id.into(),
                ..Default::default()
            })
            .await
            .context("read the environment's recorded SSH host key")?;
        let dialed = dial_tailnet_ssh(client, org_id, environment_id).await?;
        let coordinator = dialed.coordinator_task;
        let ssh = match EnvironmentSsh::connect(dialed.stream, &recorded.public_key_openssh).await {
            Ok(ssh) => ssh,
            Err(error) => {
                coordinator.abort();
                return Err(error);
            }
        };
        Ok(Self {
            ssh,
            conn: dialed.conn,
            peer: dialed.peer,
            derp_forced: std::env::var_os("CW_DERP_ONLY").is_some(),
            coordinator,
        })
    }

    /// Whether the connection has ended, or the coordinator refused this
    /// client (its access was revoked); a caller then connects again, and is
    /// told why if it may not.
    pub fn is_closed(&self) -> bool {
        self.ssh.is_closed() || self.coordinator.is_finished()
    }

    /// Open an interactive shell over this environment's tailnet; see
    /// [`EnvironmentSsh::open_shell`].
    pub async fn open_shell(
        &self,
        term: &str,
        columns: u32,
        rows: u32,
    ) -> anyhow::Result<InteractiveShell> {
        self.ssh.open_shell(term, columns, rows).await
    }

    /// Attach to a durable session over this environment's tailnet.
    pub async fn attach(
        &self,
        open: AttachSessionOpen,
    ) -> Result<EnvironmentSessionAttachment, ClientError> {
        self.ssh.attach(open).await
    }

    /// Wait up to `limit` for direct UDP, so a first report of the path is
    /// not the DERP every connection starts on. Returns the path then.
    pub async fn wait_for_direct(&self, limit: Duration) -> anyhow::Result<TailnetPathReport> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let report = self.path()?;
            if report.path == TailnetPath::DirectUdp
                || self.derp_forced
                || tokio::time::Instant::now() >= deadline
            {
                return Ok(report);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The path carrying the connection now.
    pub fn path(&self) -> anyhow::Result<TailnetPathReport> {
        let probe = self.conn.probe_peer_path(&self.peer)?;
        let path = match probe.transport {
            PeerTransport::DirectUdp => TailnetPath::DirectUdp,
            PeerTransport::PeerRelay => TailnetPath::PeerRelay,
            PeerTransport::DerpRelay | PeerTransport::Unknown => TailnetPath::Derp,
        };
        let reason = (path != TailnetPath::DirectUdp)
            .then(|| not_direct_reason(self.derp_forced, &self.peer));
        Ok(TailnetPathReport { path, reason })
    }
}

async fn attach_over(
    ssh: &client::Handle<RecordedHostKey>,
    open: AttachSessionOpen,
) -> Result<EnvironmentSessionAttachment, ClientError> {
    let lost = || {
        ClientError::from(ConnectError::unavailable(
            "the tailnet SSH connection was lost",
        ))
    };
    let mut channel = ssh.channel_open_session().await.map_err(|_| lost())?;
    channel
        .request_subsystem(true, SESSION_SUBSYSTEM)
        .await
        .map_err(|_| lost())?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure) => {
                return Err(ClientError::new(
                    ErrorCode::Unimplemented,
                    "the environment's daemon does not serve session attachment over SSH",
                ));
            }
            Some(_) => {}
            None => return Err(lost()),
        }
    }
    let open = AttachSessionRequest {
        input: Some(attach_session_request::Input::Open(Box::new(open))),
        ..Default::default()
    };
    let frame = encode_frame(&open)
        .map_err(|error| ClientError::new(ErrorCode::InvalidArgument, error.to_string()))?;
    channel.data(&frame[..]).await.map_err(|_| lost())?;

    let (input_tx, input_rx) = tokio::sync::mpsc::channel(32);
    let (output_tx, output_rx) = tokio::sync::mpsc::channel(32);
    let (terminal_error_tx, terminal_error_rx) = tokio::sync::watch::channel(None);
    let driver = tokio::spawn(drive_attachment(
        channel,
        input_rx,
        output_tx,
        terminal_error_tx,
    ));
    Ok(EnvironmentSessionAttachment {
        input: EnvironmentSessionAttachmentInput {
            input: input_tx,
            terminal_error: terminal_error_rx,
        },
        output: output_rx,
        first: None,
        driver,
    })
}

/// Why the connection is not on direct UDP, from what the environment
/// published: forced DERP, no direct endpoint, or endpoints that did not
/// answer from this network.
fn not_direct_reason(derp_forced: bool, peer: &Node) -> String {
    if derp_forced {
        "DERP was forced (CW_DERP_ONLY)".into()
    } else if peer.endpoints.is_empty() {
        "the environment published no direct UDP endpoint".into()
    } else {
        "the environment's direct UDP endpoint did not answer from this network (UDP may be blocked)"
            .into()
    }
}

async fn drive_attachment(
    mut channel: russh::Channel<client::Msg>,
    mut input: tokio::sync::mpsc::Receiver<AttachSessionRequest>,
    output: tokio::sync::mpsc::Sender<Result<AttachSessionResponse, ClientError>>,
    terminal_error: tokio::sync::watch::Sender<Option<ClientError>>,
) {
    let mut frames = FrameDecoder::default();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    let mut input_open = true;
    let ended = 'attached: loop {
        loop {
            match frames.next_message::<AttachSessionResponse>() {
                Ok(Some(response)) => {
                    if output.send(Ok(response)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    break 'attached Some(ClientError::new(ErrorCode::Internal, error.to_string()));
                }
            }
        }
        tokio::select! {
            request = input.recv(), if input_open => match request {
                Some(request) => {
                    let frame = match encode_frame(&request) {
                        Ok(frame) => frame,
                        Err(error) => break Some(ClientError::new(ErrorCode::InvalidArgument, error.to_string())),
                    };
                    if channel.data(&frame[..]).await.is_err() {
                        break Some(ClientError::from(ConnectError::unavailable("the tailnet SSH connection was lost")));
                    }
                }
                None => {
                    input_open = false;
                    let _ = channel.eof().await;
                }
            },
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) => frames.push(&data),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                Some(ChannelMsg::Close) | None => break match exit_status {
                    // The attachment ended normally: detached, or the
                    // session finished and its last status was sent.
                    Some(0) => None,
                    Some(_) => Some(ClientError::new(
                        ErrorCode::FailedPrecondition,
                        String::from_utf8_lossy(&stderr).trim().to_owned(),
                    )),
                    // No exit status: the connection dropped under it.
                    None => Some(ClientError::from(ConnectError::unavailable(
                        "the tailnet SSH connection was lost",
                    ))),
                },
                Some(_) => {}
            },
        }
    };
    if let Some(error) = ended {
        let _ = terminal_error.send(Some(error.clone()));
        let _ = output.send(Err(error)).await;
    }
}

/// Accepts only the host key the platform recorded for the environment.
struct RecordedHostKey {
    expected: PublicKey,
}

impl client::Handler for RecordedHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.key_data() == self.expected.key_data()
            }
            russh::keys::PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

#[cfg(test)]
#[path = "tailnet_ssh_flush_tests.rs"]
mod flush_tests;

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context as TaskContext, Poll};

    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::server;
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    use super::*;

    /// A server that admits the `none` user, as the daemon's does once the
    /// tailnet has authenticated the client, and keeps the channels it opens.
    #[derive(Default)]
    struct Admit {
        channels: Vec<russh::Channel<server::Msg>>,
    }

    impl server::Handler for Admit {
        type Error = russh::Error;

        async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
            Ok(server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<server::Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            self.channels.push(channel);
            reply.accept().await;
            Ok(())
        }
    }

    /// The client's end of the connection, which can go silent the way the
    /// tailnet's TCP does in a network cut: writes are taken but go nowhere,
    /// a flush waits for an acknowledgement that never comes, and nothing is
    /// read.
    struct Cuttable {
        inner: DuplexStream,
        cut: Arc<AtomicBool>,
    }

    impl AsyncRead for Cuttable {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.cut.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Cuttable {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.cut.load(Ordering::SeqCst) {
                return Poll::Ready(Ok(buf.len()));
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.cut.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            // The tailnet's TCP shuts down only once its data is acknowledged.
            if self.cut.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    // A network cut that sends no reset (#3861): the connection is given up
    // within the inactivity timeout, not the tailnet TCP's 120 s idle
    // timeout, so `cw shell` reconnects while typed keys can still reach the
    // shell.
    #[tokio::test]
    async fn a_silent_cut_is_noticed_within_the_inactivity_timeout() {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let host_key = key.public_key().to_openssh().unwrap();
        let config = Arc::new(server::Config {
            keys: vec![key],
            ..Default::default()
        });
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let running = server::run_stream(config, server_end, Admit::default()).await?;
            running.await
        });
        let cut = Arc::new(AtomicBool::new(false));
        let ssh = EnvironmentSsh::connect(
            Cuttable {
                inner: client_end,
                cut: cut.clone(),
            },
            &host_key,
        )
        .await
        .expect("the connection opens");
        // What an attachment rides on: it ends only when the channel does.
        let mut channel = ssh
            .ssh
            .channel_open_session()
            .await
            .expect("a channel opens");

        cut.store(true, Ordering::SeqCst);
        // Typed during the cut: its flush never completes.
        channel
            .data(&b"typed"[..])
            .await
            .expect("the write is queued");
        // Only the deadlines are under test, and everything here is in
        // memory: the idle runtime advances straight to each timer.
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let ended = tokio::time::timeout(Duration::from_secs(600), async {
            while channel.wait().await.is_some() {}
        })
        .await;
        assert!(
            ended.is_ok(),
            "the channel of a silent connection never ended"
        );
        assert!(
            started.elapsed() <= INACTIVITY_TIMEOUT + SHUTDOWN_GRACE + Duration::from_secs(1),
            "the channel ended after {:?}",
            started.elapsed()
        );
        assert!(ssh.is_closed());
        server.abort();
    }
}
