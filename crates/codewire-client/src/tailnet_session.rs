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
/// Matches the daemon's server keepalive: a silent connection is noticed
/// within about 45 s, and the caller reconnects.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_MAX: usize = 3;

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
            ..Default::default()
        });
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
