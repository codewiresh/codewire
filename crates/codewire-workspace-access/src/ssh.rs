use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet, Pty, server};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use crate::daemon::{
    DaemonClient, DaemonClientError, DaemonSessionOutput, ExecDaemonSessionInput, ExecSessionInput,
    PtyDaemonSessionInput, PtySessionInput, PtyStart, SessionStart,
};
use crate::scp::{ScpProtocolRunner, is_scp_command};
use crate::sftp::DaemonSftpRunner;

mod forward;
#[cfg(all(test, target_os = "linux"))]
#[path = "ssh/stock_credentials.rs"]
mod stock_credentials;

use forward::Forwarding;
pub use forward::{
    FORWARD_CLOSE_GRACE, FORWARD_DIAL_TIMEOUT, ForwardDialError, ForwardDialer, ForwardIo,
    ForwardRefusal, ForwardTarget, MAX_FORWARDS_PER_CONNECTION, PlatformListeners,
    WorkloadLoopbackDialer,
};

/// How often the server asks a silent client whether it is still there, and
/// how many unanswered asks end the connection. A client that vanished
/// without closing its connection is noticed within about a minute, and its
/// sessions end with it.
pub const WORKSPACE_SSH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const WORKSPACE_SSH_KEEPALIVE_MAX: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSessionRequest {
    pub command: Vec<String>,
    pub working_dir: String,
    pub env: Vec<String>,
    pub pty: Option<SshPtyRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPtyRequest {
    pub term: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSessionStart {
    Exec(SessionStart),
    Pty(PtyStart),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSessionInput {
    Stdin(Vec<u8>),
    CloseStdin,
    Resize { width: i32, height: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshSessionOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    Error(String),
}

/// One process session's place: the SSH connection that started it and its
/// channel there. russh numbers channels per connection from the same
/// start, so a channel id alone names a session on every connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshSessionKey {
    pub connection: u64,
    pub channel: ChannelId,
}

#[derive(Clone)]
pub struct SshChannelOutput {
    channel: ChannelId,
    handle: server::Handle,
}

impl SshChannelOutput {
    pub fn new(channel: ChannelId, handle: server::Handle) -> Self {
        Self { channel, handle }
    }

    pub async fn send(&self, output: SshSessionOutput) -> Result<(), SshSessionRunnerError> {
        send_ssh_session_output(&self.handle, self.channel, output).await
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct SshSessionRunnerError(pub String);

#[async_trait]
pub trait SshSessionRunner: Send + Sync + 'static {
    /// Start the process of one exec or shell request. The returned session
    /// owns the process: its connection's input pump holds it, and dropping
    /// it ends the process.
    async fn start_session(
        &self,
        key: SshSessionKey,
        start: DaemonSessionStart,
        output: SshChannelOutput,
    ) -> Result<Box<dyn SshSession>, SshSessionRunnerError>;
}

/// A running process session, owned by its SSH channel. Dropping it ends the
/// process: the daemon signals the process group of a command that is still
/// running.
#[async_trait]
pub trait SshSession: Send + 'static {
    /// Deliver one piece of input in order. This waits while the process is
    /// not reading its stdin, and that wait is the backpressure that pauses
    /// the SSH connection.
    async fn send(&mut self, input: SshSessionInput) -> Result<(), SshSessionRunnerError>;
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct SftpSubsystemRunnerError(pub String);

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ScpProtocolRunnerError(pub String);

#[async_trait]
pub trait SftpSubsystemRunner: Send + Sync + 'static {
    async fn start_sftp(
        &self,
        channel: Channel<server::Msg>,
    ) -> Result<(), SftpSubsystemRunnerError>;
}

#[async_trait]
pub trait ScpProtocolRunnerBridge: Send + Sync + 'static {
    async fn start_scp_bridge(
        &self,
        command: Vec<String>,
        channel: Channel<server::Msg>,
    ) -> Result<(), ScpProtocolRunnerError>;
}

#[async_trait]
impl<T> ScpProtocolRunnerBridge for T
where
    T: ScpProtocolRunner,
{
    async fn start_scp_bridge(
        &self,
        command: Vec<String>,
        channel: Channel<server::Msg>,
    ) -> Result<(), ScpProtocolRunnerError> {
        self.start_scp(command, channel)
            .await
            .map_err(|err| ScpProtocolRunnerError(err.to_string()))
    }
}

#[async_trait]
impl<C> SftpSubsystemRunner for DaemonSftpRunner<C>
where
    C: DaemonClient + Clone + Send + Sync + 'static,
{
    async fn start_sftp(
        &self,
        channel: Channel<server::Msg>,
    ) -> Result<(), SftpSubsystemRunnerError> {
        self.run(channel.into_stream()).await;
        Ok(())
    }
}

pub struct DaemonBackedSshRunner<C> {
    client: C,
}

impl<C> DaemonBackedSshRunner<C>
where
    C: DaemonClient,
{
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<C> SshSessionRunner for DaemonBackedSshRunner<C>
where
    C: DaemonClient + 'static,
{
    async fn start_session(
        &self,
        key: SshSessionKey,
        start: DaemonSessionStart,
        output: SshChannelOutput,
    ) -> Result<Box<dyn SshSession>, SshSessionRunnerError> {
        match start {
            DaemonSessionStart::Exec(start) => {
                let mut session = self
                    .client
                    .exec_session(start)
                    .await
                    .map_err(SshSessionRunnerError::from)?;
                let input = session.input_handle();
                // Aborting this task drops the daemon session's response
                // stream, which the daemon takes as the client leaving.
                let output = AbortOnDropHandle::new(tokio::spawn(async move {
                    if let Ok(code) = forward_daemon_outputs(
                        &mut session,
                        &output,
                        "workspace exec session ended without an exit status",
                    )
                    .await
                    {
                        log_session_exit(key, code);
                    }
                }));
                Ok(Box::new(DaemonExecSshSession {
                    input,
                    _output: output,
                }))
            }
            DaemonSessionStart::Pty(start) => {
                let mut session = self
                    .client
                    .pty_session(start)
                    .await
                    .map_err(SshSessionRunnerError::from)?;
                let input = session.input_handle();
                let output = AbortOnDropHandle::new(tokio::spawn(async move {
                    if let Ok(code) = forward_daemon_outputs(
                        &mut session,
                        &output,
                        "workspace PTY session ended without an exit status",
                    )
                    .await
                    {
                        log_session_exit(key, code);
                    }
                }));
                Ok(Box::new(DaemonPtySshSession {
                    input,
                    _output: output,
                }))
            }
        }
    }
}

/// A daemon exec session held by its SSH channel. Dropping it closes both of
/// the daemon session's streams.
struct DaemonExecSshSession {
    input: ExecDaemonSessionInput,
    _output: AbortOnDropHandle<()>,
}

#[async_trait]
impl SshSession for DaemonExecSshSession {
    async fn send(&mut self, input: SshSessionInput) -> Result<(), SshSessionRunnerError> {
        let input = match input {
            SshSessionInput::Stdin(data) => ExecSessionInput::Stdin(data),
            SshSessionInput::CloseStdin => ExecSessionInput::CloseStdin,
            SshSessionInput::Resize { .. } => return Ok(()),
        };
        self.input
            .send_input(input)
            .await
            .map_err(SshSessionRunnerError::from)
    }
}

/// A daemon PTY session held by its SSH channel. Dropping it closes both of
/// the daemon session's streams.
struct DaemonPtySshSession {
    input: PtyDaemonSessionInput,
    _output: AbortOnDropHandle<()>,
}

#[async_trait]
impl SshSession for DaemonPtySshSession {
    async fn send(&mut self, input: SshSessionInput) -> Result<(), SshSessionRunnerError> {
        let input = match input {
            SshSessionInput::Stdin(data) => PtySessionInput::Stdin(data),
            SshSessionInput::CloseStdin => PtySessionInput::CloseStdin,
            SshSessionInput::Resize { width, height } => PtySessionInput::Resize { width, height },
        };
        self.input
            .send_input(input)
            .await
            .map_err(SshSessionRunnerError::from)
    }
}

impl From<DaemonClientError> for SshSessionRunnerError {
    fn from(value: DaemonClientError) -> Self {
        Self(value.to_string())
    }
}

/// Daemon output a session has read and its SSH channel has not taken yet.
const MAX_PENDING_SSH_OUTPUT: usize = 1024 * 1024;
/// Most output handed to the SSH channel in one write.
const MAX_COALESCED_SSH_OUTPUT: usize = 32 * 1024;

/// A daemon session's output stream.
#[async_trait]
trait DaemonOutputStream: Send {
    async fn next_output(&mut self) -> Result<Option<DaemonSessionOutput>, DaemonClientError>;
}

#[async_trait]
impl DaemonOutputStream for crate::daemon::ExecDaemonSession {
    async fn next_output(&mut self) -> Result<Option<DaemonSessionOutput>, DaemonClientError> {
        crate::daemon::ExecDaemonSession::next_output(self).await
    }
}

#[async_trait]
impl DaemonOutputStream for crate::daemon::PtyDaemonSession {
    async fn next_output(&mut self) -> Result<Option<DaemonSessionOutput>, DaemonClientError> {
        crate::daemon::PtyDaemonSession::next_output(self).await
    }
}

/// Where a session's output goes: its SSH channel.
#[async_trait]
trait SshOutputSink: Send + Sync {
    async fn send(&self, output: SshSessionOutput) -> Result<(), SshSessionRunnerError>;
}

#[async_trait]
impl SshOutputSink for SshChannelOutput {
    async fn send(&self, output: SshSessionOutput) -> Result<(), SshSessionRunnerError> {
        SshChannelOutput::send(self, output).await
    }
}

/// Output read from the daemon and not yet sent to the channel, in order.
/// Consecutive stdout, and consecutive stderr, is joined into one write.
#[derive(Default)]
struct PendingSshOutput {
    outputs: std::collections::VecDeque<SshSessionOutput>,
    bytes: usize,
}

impl PendingSshOutput {
    fn push(&mut self, output: SshSessionOutput) {
        let len = ssh_output_len(&output);
        self.bytes = self.bytes.saturating_add(len);
        match (self.outputs.back_mut(), output) {
            (Some(SshSessionOutput::Stdout(held)), SshSessionOutput::Stdout(data))
            | (Some(SshSessionOutput::Stderr(held)), SshSessionOutput::Stderr(data))
                if held.len() + data.len() <= MAX_COALESCED_SSH_OUTPUT =>
            {
                held.extend_from_slice(&data);
            }
            (_, output) => self.outputs.push_back(output),
        }
    }

    fn pop(&mut self) -> Option<SshSessionOutput> {
        let output = self.outputs.pop_front()?;
        self.bytes = self.bytes.saturating_sub(ssh_output_len(&output));
        Some(output)
    }
}

fn ssh_output_len(output: &SshSessionOutput) -> usize {
    match output {
        SshSessionOutput::Stdout(data) | SshSessionOutput::Stderr(data) => data.len(),
        SshSessionOutput::Error(error) => error.len(),
        SshSessionOutput::Exit(_) => 0,
    }
}

/// Forward a daemon session's output to its SSH channel, in order, ending
/// with its exit status, which it returns. A stream that fails or ends
/// without one ends the channel with an error message and exit status 1, and
/// is returned as the error.
///
/// The daemon stream is read as output arrives, into at most
/// [`MAX_PENDING_SSH_OUTPUT`] bytes, while the channel takes it. The channel
/// can wait: russh serves its handle from the connection's one session task,
/// which also delivers the client's input and waits while a channel's input
/// queue is full. Output left unread meanwhile would sit in HTTP/2 as small
/// DATA frames, which the daemon connection's flood guard counts until it
/// ends the connection and every session on it (#2822).
async fn forward_daemon_outputs<D, O>(
    session: &mut D,
    output: &O,
    ended_without_exit: &str,
) -> Result<i32, SshSessionRunnerError>
where
    D: DaemonOutputStream,
    O: SshOutputSink,
{
    let pending = std::sync::Mutex::new(PendingSshOutput::default());
    let queued = tokio::sync::Notify::new();
    let room = tokio::sync::Notify::new();
    let push = |output| {
        pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(output);
        queued.notify_one();
    };
    // Reads the daemon stream to its end: its exit status, or a failure
    // that becomes an error message and exit status 1.
    let read = async {
        loop {
            loop {
                let more = room.notified();
                if pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .bytes
                    < MAX_PENDING_SSH_OUTPUT
                {
                    break;
                }
                more.await;
            }
            match session.next_output().await {
                Ok(Some(daemon_output)) => {
                    let ssh_output = ssh_output_from_daemon(daemon_output);
                    let exit = matches!(ssh_output, SshSessionOutput::Exit(_));
                    push(ssh_output);
                    if exit {
                        return Ok(());
                    }
                }
                Ok(None) => {
                    let error = SshSessionRunnerError(ended_without_exit.into());
                    push(SshSessionOutput::Error(error.to_string()));
                    push(SshSessionOutput::Exit(1));
                    return Err(error);
                }
                Err(err) => {
                    push(SshSessionOutput::Error(format!(
                        "workspace session failed: {err}"
                    )));
                    push(SshSessionOutput::Exit(1));
                    return Err(SshSessionRunnerError::from(err));
                }
            }
        }
    };
    // Sends what was read, in order, through the exit status.
    let write = async {
        loop {
            let next = loop {
                let more = queued.notified();
                let next = pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pop();
                match next {
                    Some(next) => break next,
                    None => more.await,
                }
            };
            room.notify_one();
            let exit = match next {
                SshSessionOutput::Exit(code) => Some(code),
                _ => None,
            };
            output.send(next).await?;
            if let Some(code) = exit {
                return Ok::<_, SshSessionRunnerError>(code);
            }
        }
    };
    tokio::pin!(read, write);
    let mut stream = None;
    let code = loop {
        tokio::select! {
            sent = &mut write => break sent?,
            result = &mut read, if stream.is_none() => stream = Some(result),
        }
    };
    match stream {
        Some(Err(error)) => Err(error),
        _ => Ok(code),
    }
}

fn log_session_exit(key: SshSessionKey, code: i32) {
    tracing::info!(
        connection = key.connection,
        channel = %key.channel,
        exit_code = code,
        "workspace SSH session exited"
    );
}

fn ssh_output_from_daemon(output: DaemonSessionOutput) -> SshSessionOutput {
    match output {
        DaemonSessionOutput::Stdout(data) => SshSessionOutput::Stdout(data),
        DaemonSessionOutput::Stderr(data) => SshSessionOutput::Stderr(data),
        DaemonSessionOutput::Exit(code) => SshSessionOutput::Exit(code),
        DaemonSessionOutput::Error(error) => SshSessionOutput::Error(error),
    }
}

pub async fn send_ssh_session_output(
    handle: &server::Handle,
    channel: ChannelId,
    output: SshSessionOutput,
) -> Result<(), SshSessionRunnerError> {
    match output {
        SshSessionOutput::Stdout(data) => {
            if !data.is_empty() {
                handle
                    .data(channel, data)
                    .await
                    .map_err(|_| SshSessionRunnerError("send SSH stdout failed".into()))?;
            }
            Ok(())
        }
        SshSessionOutput::Stderr(data) => {
            if !data.is_empty() {
                handle
                    .extended_data(channel, 1, data)
                    .await
                    .map_err(|_| SshSessionRunnerError("send SSH stderr failed".into()))?;
            }
            Ok(())
        }
        SshSessionOutput::Error(error) => {
            let mut message = error.into_bytes();
            if !message.ends_with(b"\n") {
                message.push(b'\n');
            }
            handle
                .extended_data(channel, 1, message)
                .await
                .map_err(|_| SshSessionRunnerError("send SSH error failed".into()))
        }
        SshSessionOutput::Exit(code) => {
            handle
                .exit_status_request(channel, exit_code_to_u32(code))
                .await
                .map_err(|_| SshSessionRunnerError("send SSH exit status failed".into()))?;
            handle
                .eof(channel)
                .await
                .map_err(|_| SshSessionRunnerError("send SSH EOF failed".into()))?;
            handle
                .close(channel)
                .await
                .map_err(|_| SshSessionRunnerError("close SSH channel failed".into()))
        }
    }
}

fn exit_code_to_u32(code: i32) -> u32 {
    u32::try_from(code).unwrap_or(1)
}

/// Deliver a process channel's input to its session, in the order the client
/// sent it, until the channel or its connection ends; then end the session.
///
/// russh queues every message for a channel (a bounded queue) before it hands
/// the message to the handler, and waits when that queue is full. This pump
/// reads the queue only as fast as the process takes its input, so a process
/// that is not reading its stdin pauses the connection's reads: bounded
/// backpressure down to TCP, with no data buffered beyond the queue.
///
/// Stdin already queued behind the message the pump takes travels with it,
/// as one message of up to [`MAX_COALESCED_STDIN`] bytes. A burst of small
/// writes, such as keystrokes or a paste, then reaches the daemon in a few
/// large HTTP/2 DATA frames rather than many small ones, which the daemon
/// connection's flood guard would count against it (#2822).
async fn pump_session_input(
    key: SshSessionKey,
    mut channel: Channel<server::Msg>,
    mut session: Box<dyn SshSession>,
    ended: CancellationToken,
) {
    // A process that closed its stdin, or whose input stream ended, still
    // runs; the rest of its input is read and dropped so the channel never
    // stalls the connection.
    let mut accepting = true;
    // A message taken while coalescing that did not join the Stdin before
    // it; it is the next one handled, so input keeps its order.
    let mut held = None;
    let reason = loop {
        let step = match held.take() {
            Some(step) => step,
            None => channel_step(channel.wait().await),
        };
        let mut input = match step {
            ChannelStep::Input(input) => input,
            ChannelStep::Skip => continue,
            ChannelStep::End(reason) => break reason,
        };
        if !accepting {
            continue;
        }
        if let SshSessionInput::Stdin(data) = &mut input {
            held = coalesce_queued_stdin(&mut channel, data);
        }
        // Input the client sent before closing is still delivered while the
        // process takes it; only a wait on a process that is not reading
        // ends early, when the channel or connection ends.
        tokio::select! {
            biased;
            sent = session.send(input) => {
                if sent.is_err() {
                    accepting = false;
                }
            }
            () = ended.cancelled() => break "the channel or connection ended while input waited",
        }
    };
    drop(session);
    tracing::info!(
        connection = key.connection,
        channel = %key.channel,
        reason,
        "workspace SSH session ended"
    );
}

/// Most Stdin the input pump hands its session in one message.
const MAX_COALESCED_STDIN: usize = 32 * 1024;

/// What one channel message is to its process session.
enum ChannelStep {
    Input(SshSessionInput),
    Skip,
    End(&'static str),
}

fn channel_step(message: Option<ChannelMsg>) -> ChannelStep {
    match message {
        Some(ChannelMsg::Data { data }) => {
            ChannelStep::Input(SshSessionInput::Stdin(data.to_vec()))
        }
        Some(ChannelMsg::Eof) => ChannelStep::Input(SshSessionInput::CloseStdin),
        Some(ChannelMsg::WindowChange {
            col_width,
            row_height,
            ..
        }) => ChannelStep::Input(SshSessionInput::Resize {
            width: pty_dimension_to_i32(col_width),
            height: pty_dimension_to_i32(row_height),
        }),
        Some(ChannelMsg::Close) => ChannelStep::End("the client closed the channel"),
        None => ChannelStep::End("the connection ended"),
        Some(_) => ChannelStep::Skip,
    }
}

/// Append the Stdin already queued on `channel` to `data`, without waiting,
/// up to [`MAX_COALESCED_STDIN`] bytes. Coalescing stops at the first
/// message that is not Stdin, or that would not fit, and returns it to be
/// handled next: Stdin never passes a resize or end of input.
fn coalesce_queued_stdin(
    channel: &mut Channel<server::Msg>,
    data: &mut Vec<u8>,
) -> Option<ChannelStep> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    while data.len() < MAX_COALESCED_STDIN {
        // Channel::wait is a queue receive: dropping it unfinished loses
        // nothing.
        let message = match std::pin::pin!(channel.wait()).poll(&mut context) {
            std::task::Poll::Ready(message) => message,
            std::task::Poll::Pending => return None,
        };
        match channel_step(message) {
            ChannelStep::Input(SshSessionInput::Stdin(more))
                if data.len() + more.len() <= MAX_COALESCED_STDIN =>
            {
                data.extend_from_slice(&more);
            }
            ChannelStep::Skip => {}
            step => return Some(step),
        }
    }
    None
}

#[derive(Debug, Error)]
pub enum WorkspaceSshError {
    #[error(transparent)]
    Russh(#[from] russh::Error),
    #[error("unknown SSH channel {0}")]
    UnknownChannel(ChannelId),
    #[error("invalid SSH exec command: {0}")]
    InvalidExecCommand(String),
    #[error("SSH session runner failed: {0}")]
    Runner(#[from] SshSessionRunnerError),
    #[error("SFTP subsystem runner failed: {0}")]
    Sftp(#[from] SftpSubsystemRunnerError),
    #[error("SCP protocol runner failed: {0}")]
    Scp(#[from] ScpProtocolRunnerError),
}

#[derive(Clone)]
pub struct WorkspaceSshServer<R> {
    runner: Arc<R>,
    sftp: Option<Arc<dyn SftpSubsystemRunner>>,
    scp: Option<Arc<dyn ScpProtocolRunnerBridge>>,
    exec_shell: Option<String>,
}

impl<R> WorkspaceSshServer<R>
where
    R: SshSessionRunner,
{
    pub fn new(runner: Arc<R>) -> Self {
        Self {
            runner,
            sftp: None,
            scp: None,
            exec_shell: None,
        }
    }

    pub fn with_sftp(runner: Arc<R>, sftp: Arc<dyn SftpSubsystemRunner>) -> Self {
        Self {
            runner,
            sftp: Some(sftp),
            scp: None,
            exec_shell: None,
        }
    }

    pub fn with_file_protocols(
        runner: Arc<R>,
        sftp: Arc<dyn SftpSubsystemRunner>,
        scp: Arc<dyn ScpProtocolRunnerBridge>,
    ) -> Self {
        Self {
            runner,
            sftp: Some(sftp),
            scp: Some(scp),
            exec_shell: None,
        }
    }

    /// Run each exec request's command line as `<shell> -c <command>`; see
    /// [`WorkspaceSshHandler::with_exec_shell`].
    pub fn with_exec_shell(mut self, shell: impl Into<String>) -> Self {
        self.exec_shell = Some(shell.into());
        self
    }
}

impl<R> server::Server for WorkspaceSshServer<R>
where
    R: SshSessionRunner,
{
    type Handler = WorkspaceSshHandler<R>;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        let handler = WorkspaceSshHandler::with_file_protocols(
            self.runner.clone(),
            self.sftp.clone(),
            self.scp.clone(),
        );
        match &self.exec_shell {
            Some(shell) => handler.with_exec_shell(shell.clone()),
            None => handler,
        }
    }
}

/// Connection ids for logs and session keys; unique within the process.
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// One SSH connection's handler. It owns the connection's sessions: they end
/// when their channel closes or when the connection ends, for any reason,
/// because russh drops the handler then.
pub struct WorkspaceSshHandler<R> {
    runner: Arc<R>,
    sftp: Option<Arc<dyn SftpSubsystemRunner>>,
    scp: Option<Arc<dyn ScpProtocolRunnerBridge>>,
    exec_shell: Option<String>,
    /// Local port forwarding; without it every `direct-tcpip` channel is
    /// refused.
    forwarding: Option<Forwarding>,
    connection: u64,
    /// Cancelled when the connection ends; each process channel and forward
    /// holds a child token.
    ended: CancellationToken,
    channels: HashMap<ChannelId, SshChannelState>,
}

impl<R> WorkspaceSshHandler<R>
where
    R: SshSessionRunner,
{
    pub fn new(runner: Arc<R>) -> Self {
        Self::with_file_protocols(runner, None, None)
    }

    pub fn with_sftp(runner: Arc<R>, sftp: Option<Arc<dyn SftpSubsystemRunner>>) -> Self {
        Self::with_file_protocols(runner, sftp, None)
    }

    pub fn with_file_protocols(
        runner: Arc<R>,
        sftp: Option<Arc<dyn SftpSubsystemRunner>>,
        scp: Option<Arc<dyn ScpProtocolRunnerBridge>>,
    ) -> Self {
        Self {
            runner,
            sftp,
            scp,
            exec_shell: None,
            forwarding: None,
            connection: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
            ended: CancellationToken::new(),
            channels: HashMap::new(),
        }
    }

    /// Run each exec request's command line as `<shell> -c <command>`, as
    /// sshd runs it through the user's login shell, so pipes, `&&`, globs
    /// and variables work. Without a shell the line is split into words and
    /// run directly. SCP requests are recognized before either.
    pub fn with_exec_shell(mut self, shell: impl Into<String>) -> Self {
        self.exec_shell = Some(shell.into());
        self
    }

    /// Serve `direct-tcpip` channels (`ssh -L`, `ssh -W`, `ssh -D`, VS Code
    /// Remote-SSH) through `dialer`, which must reach the workload's own
    /// network namespace, refusing the `platform` listeners there
    /// (`codewire_daemon_proto::platform_listeners`). Without a dialer every
    /// forward is refused with a reason.
    pub fn with_port_forwarding(
        mut self,
        dialer: Arc<dyn ForwardDialer>,
        platform: Arc<PlatformListeners>,
    ) -> Self {
        self.forwarding = Some(Forwarding::new(dialer, platform));
        self
    }

    #[cfg(test)]
    fn with_forwarding(mut self, forwarding: Forwarding) -> Self {
        self.forwarding = Some(forwarding);
        self
    }

    /// This connection's id in session keys and logs.
    pub fn connection_id(&self) -> u64 {
        self.connection
    }

    /// Take an opened channel that no request has started yet.
    fn take_pending(&mut self, channel: ChannelId) -> Option<PendingChannel> {
        match self.channels.remove(&channel) {
            Some(SshChannelState::Pending(pending)) => Some(pending),
            Some(other) => {
                self.channels.insert(channel, other);
                None
            }
            None => None,
        }
    }

    fn pending_mut(&mut self, channel: ChannelId) -> Option<&mut PendingChannel> {
        match self.channels.get_mut(&channel) {
            Some(SshChannelState::Pending(pending)) => Some(pending),
            _ => None,
        }
    }

    async fn start_channel_session(
        &mut self,
        channel: ChannelId,
        command: Vec<String>,
        session: &mut server::Session,
    ) -> Result<(), WorkspaceSshError> {
        let Some(pending) = self.take_pending(channel) else {
            session.channel_failure(channel)?;
            return Err(WorkspaceSshError::UnknownChannel(channel));
        };

        let pty = pending.pty.is_some();
        let start = build_daemon_session_start(SshSessionRequest {
            command,
            working_dir: String::new(),
            env: pending.env,
            pty: pending.pty,
        });
        let key = SshSessionKey {
            connection: self.connection,
            channel,
        };
        let output = SshChannelOutput::new(channel, session.handle());
        let process = match self.runner.start_session(key, start, output).await {
            Ok(process) => process,
            Err(err) => {
                session.channel_failure(channel)?;
                return Err(WorkspaceSshError::Runner(err));
            }
        };
        tracing::info!(
            connection = key.connection,
            channel = %key.channel,
            pty,
            "workspace SSH session started"
        );
        let ended = self.ended.child_token();
        tokio::spawn(pump_session_input(
            key,
            pending.channel,
            process,
            ended.clone(),
        ));
        self.channels
            .insert(channel, SshChannelState::Process { ended });
        session.channel_success(channel)?;
        Ok(())
    }
}

impl<R> Drop for WorkspaceSshHandler<R> {
    fn drop(&mut self) {
        // russh drops the handler when the connection ends, however it ends:
        // closed, reset, idle, or keepalive timeout. End every session.
        self.ended.cancel();
    }
}

enum SshChannelState {
    /// Opened, and collecting its environment and terminal until a request
    /// starts it. russh queues the channel's messages, including any early
    /// input, until its process takes the channel.
    Pending(PendingChannel),
    /// Runs a process. Its input pump owns the channel and the session.
    Process { ended: CancellationToken },
    /// Served by SFTP or SCP, which read the channel themselves.
    FileProtocol { sftp: bool },
    /// A forward, dialing or open. Its task owns the channel; `stop` ends it
    /// when the client closes the channel, and is cancelled once it ends.
    Forward { stop: CancellationToken },
}

struct PendingChannel {
    channel: Channel<server::Msg>,
    env: Vec<String>,
    pty: Option<SshPtyRequest>,
}

pub fn workspace_ssh_server_config() -> server::Config {
    let mut config = server::Config::default();
    apply_workspace_ssh_policy(&mut config);
    config
}

pub fn apply_workspace_ssh_policy(config: &mut server::Config) {
    config.methods = workspace_ssh_auth_methods();
    config.keepalive_interval = Some(WORKSPACE_SSH_KEEPALIVE_INTERVAL);
    config.keepalive_max = WORKSPACE_SSH_KEEPALIVE_MAX;
}

pub fn workspace_ssh_auth_methods() -> MethodSet {
    MethodSet::from(&[MethodKind::None][..])
}

pub fn build_daemon_session_start(request: SshSessionRequest) -> DaemonSessionStart {
    match request.pty {
        Some(pty) => DaemonSessionStart::Pty(PtyStart {
            command: request.command,
            working_dir: request.working_dir,
            env: without_term_env(request.env),
            term: pty.term,
            width: pty_dimension_to_i32(pty.width),
            height: pty_dimension_to_i32(pty.height),
        }),
        None => DaemonSessionStart::Exec(SessionStart {
            command: request.command,
            working_dir: request.working_dir,
            env: request.env,
        }),
    }
}

pub fn parse_exec_command(command: &[u8]) -> Result<Vec<String>, WorkspaceSshError> {
    let command = std::str::from_utf8(command)
        .map_err(|err| WorkspaceSshError::InvalidExecCommand(err.to_string()))?;
    shell_words::split(command)
        .map_err(|err| WorkspaceSshError::InvalidExecCommand(err.to_string()))
}

pub fn allow_reverse_port_forward(_host: &str, _port: u32) -> bool {
    false
}

fn without_term_env(env: Vec<String>) -> Vec<String> {
    env.into_iter()
        .filter(|entry| !entry.starts_with("TERM="))
        .collect()
}

fn pty_dimension_to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl<R> server::Handler for WorkspaceSshHandler<R>
where
    R: SshSessionRunner,
{
    type Error = WorkspaceSshError;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(
            channel.id(),
            SshChannelState::Pending(PendingChannel {
                channel,
                env: Vec::new(),
                pty: None,
            }),
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let key = SshSessionKey {
            connection: self.connection,
            channel: channel.id(),
        };
        let Some(forwarding) = &self.forwarding else {
            forward::refuse_unavailable(key, reply).await;
            return Ok(());
        };
        // Forget forwards that ended without the client closing them.
        self.channels.retain(
            |_, state| !matches!(state, SshChannelState::Forward { stop } if stop.is_cancelled()),
        );
        if let Some(stop) = forwarding
            .open(
                key,
                channel,
                host_to_connect,
                port_to_connect,
                reply,
                &self.ended,
            )
            .await
        {
            self.channels
                .insert(key.channel, SshChannelState::Forward { stop });
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(pending) = self.pending_mut(channel) else {
            session.channel_failure(channel)?;
            return Err(WorkspaceSshError::UnknownChannel(channel));
        };
        pending.pty = Some(SshPtyRequest {
            term: term.into(),
            width: col_width,
            height: row_height,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(pending) = self.pending_mut(channel) else {
            session.channel_failure(channel)?;
            return Err(WorkspaceSshError::UnknownChannel(channel));
        };
        pending
            .env
            .push(format!("{variable_name}={variable_value}"));
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.start_channel_session(channel, Vec::new(), session)
            .await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let command = match parse_exec_command(data) {
            Ok(command) => command,
            Err(err) => {
                session.channel_failure(channel)?;
                return Err(err);
            }
        };
        if is_scp_command(&command) {
            let Some(scp) = self.scp.clone() else {
                session.channel_failure(channel)?;
                return Ok(());
            };
            let Some(pending) = self.take_pending(channel) else {
                session.channel_failure(channel)?;
                return Err(WorkspaceSshError::UnknownChannel(channel));
            };
            self.channels
                .insert(channel, SshChannelState::FileProtocol { sftp: false });
            session.channel_success(channel)?;
            tokio::spawn(async move {
                let _ = scp.start_scp_bridge(command, pending.channel).await;
            });
            return Ok(());
        }
        let command = match &self.exec_shell {
            // `parse_exec_command` accepted the line as UTF-8.
            Some(shell) => vec![
                shell.clone(),
                "-c".into(),
                String::from_utf8_lossy(data).into_owned(),
            ],
            None => command,
        };
        self.start_channel_session(channel, command, session).await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let Some(sftp) = self.sftp.clone() else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let Some(pending) = self.take_pending(channel) else {
            session.channel_failure(channel)?;
            return Err(WorkspaceSshError::UnknownChannel(channel));
        };
        self.channels
            .insert(channel, SshChannelState::FileProtocol { sftp: true });
        session.channel_success(channel)?;
        tokio::spawn(async move {
            let _ = sftp.start_sftp(pending.channel).await;
        });
        Ok(())
    }

    // Channel data needs no handler: russh queues it on the channel, where
    // the process's input pump, SFTP or SCP reads it in order.

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        // An SFTP client sends EOF once it is done, which is when sshd's
        // sftp-server exits 0. OpenSSH reports a subsystem channel closed
        // without an exit status as status -1, and scp then fails. A process
        // channel's EOF reaches its pump in order, after its input.
        if let Some(SshChannelState::FileProtocol { sftp }) = self.channels.get_mut(&channel)
            && std::mem::take(sftp)
        {
            session.exit_status_request(channel, 0)?;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        // The pump or forward also reads the close in order; this ends one
        // that is waiting on a process or target that is not reading.
        if let Some(SshChannelState::Process { ended } | SshChannelState::Forward { stop: ended }) =
            self.channels.remove(&channel)
        {
            ended.cancel();
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        match self.channels.get_mut(&channel) {
            // Not started: the process starts at this size.
            Some(SshChannelState::Pending(pending)) => {
                if let Some(pty) = pending.pty.as_mut() {
                    pty.width = col_width;
                    pty.height = row_height;
                }
            }
            // Started: the resize reaches the pump in order, after earlier
            // input.
            Some(SshChannelState::Process { .. }) => {}
            Some(SshChannelState::FileProtocol { .. } | SshChannelState::Forward { .. }) | None => {
                session.channel_failure(channel)?;
                return Err(WorkspaceSshError::UnknownChannel(channel));
            }
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        _address: &str,
        _port: u32,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::DaemonSessionClient;
    use crate::host_key;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use codewire_daemon_proto::codewire::bridge::v1 as bridge_v1;
    use codewire_daemon_proto::daemon::v1;
    use codewire_daemon_proto::daemon::v1::daemon_service_server::{
        DaemonService, DaemonServiceServer,
    };
    use codewire_tailnet::conn::{
        Conn as TailnetConn, Options as TailnetOptions, PeerTransport, Transport, WgDatagram,
    };
    use codewire_tailnet::derp::NodePublic as DerpPublic;
    use codewire_tailnet::direct_udp::{self, Options as DirectUdpOptions};
    use codewire_tailnet::disco::DiscoPrivate;
    use codewire_tailnet::node::{AddrPort, DiscoPublic, Node, NodePublic, Prefix};
    use codewire_tailnet::udp_relay;
    use russh::{ChannelMsg, MethodKind, client, kex};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tokio::net::TcpListener;
    use tokio::sync::{Mutex, mpsc};
    use tokio::time::{Duration, sleep, timeout};
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};
    use uuid::Uuid;

    const TAILNET_GATEWAY_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x101);
    const TAILNET_CLIENT_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x102);

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RunnerEvent {
        Start {
            channel: ChannelId,
            start: DaemonSessionStart,
        },
        Input {
            channel: ChannelId,
            input: SshSessionInput,
        },
        Ended {
            channel: ChannelId,
        },
    }

    type RecordedEvents = Arc<std::sync::Mutex<Vec<(u64, RunnerEvent)>>>;

    /// Records each session's start, input and end with its connection.
    /// With a gate, each input waits for one permit first: a process that
    /// reads its stdin only when the test lets it.
    #[derive(Default)]
    struct RecordingRunner {
        events: RecordedEvents,
        gate: Option<Arc<tokio::sync::Semaphore>>,
    }

    impl RecordingRunner {
        fn gated(gate: Arc<tokio::sync::Semaphore>) -> Self {
            Self {
                events: Default::default(),
                gate: Some(gate),
            }
        }
    }

    struct RecordingSession {
        key: SshSessionKey,
        events: RecordedEvents,
        gate: Option<Arc<tokio::sync::Semaphore>>,
    }

    #[async_trait]
    impl SshSessionRunner for RecordingRunner {
        async fn start_session(
            &self,
            key: SshSessionKey,
            start: DaemonSessionStart,
            _output: SshChannelOutput,
        ) -> Result<Box<dyn SshSession>, SshSessionRunnerError> {
            self.events.lock().unwrap().push((
                key.connection,
                RunnerEvent::Start {
                    channel: key.channel,
                    start,
                },
            ));
            Ok(Box::new(RecordingSession {
                key,
                events: self.events.clone(),
                gate: self.gate.clone(),
            }))
        }
    }

    #[async_trait]
    impl SshSession for RecordingSession {
        async fn send(&mut self, input: SshSessionInput) -> Result<(), SshSessionRunnerError> {
            if let Some(gate) = &self.gate {
                gate.acquire().await.unwrap().forget();
            }
            self.events.lock().unwrap().push((
                self.key.connection,
                RunnerEvent::Input {
                    channel: self.key.channel,
                    input,
                },
            ));
            Ok(())
        }
    }

    impl Drop for RecordingSession {
        fn drop(&mut self) {
            self.events.lock().unwrap().push((
                self.key.connection,
                RunnerEvent::Ended {
                    channel: self.key.channel,
                },
            ));
        }
    }

    struct CompletingRunner;

    struct NoInput;

    #[async_trait]
    impl SshSession for NoInput {
        async fn send(&mut self, _input: SshSessionInput) -> Result<(), SshSessionRunnerError> {
            Ok(())
        }
    }

    #[async_trait]
    impl SshSessionRunner for CompletingRunner {
        async fn start_session(
            &self,
            _key: SshSessionKey,
            _start: DaemonSessionStart,
            output: SshChannelOutput,
        ) -> Result<Box<dyn SshSession>, SshSessionRunnerError> {
            output
                .send(SshSessionOutput::Stdout(b"openssh-ok\n".to_vec()))
                .await?;
            output.send(SshSessionOutput::Exit(0)).await?;
            Ok(Box::new(NoInput))
        }
    }

    #[derive(Default)]
    struct RecordingSftpRunner {
        channels: Mutex<Vec<ChannelId>>,
    }

    impl RecordingSftpRunner {
        async fn wait_for_channels(&self, count: usize) -> Vec<ChannelId> {
            timeout(Duration::from_secs(2), async {
                loop {
                    let channels = self.channels.lock().await.clone();
                    if channels.len() >= count {
                        return channels;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("SFTP subsystem channels")
        }
    }

    #[async_trait]
    impl SftpSubsystemRunner for RecordingSftpRunner {
        async fn start_sftp(
            &self,
            channel: Channel<server::Msg>,
        ) -> Result<(), SftpSubsystemRunnerError> {
            self.channels.lock().await.push(channel.id());
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingScpRunner {
        calls: Mutex<Vec<(ChannelId, Vec<String>)>>,
    }

    impl RecordingScpRunner {
        async fn wait_for_calls(&self, count: usize) -> Vec<(ChannelId, Vec<String>)> {
            timeout(Duration::from_secs(2), async {
                loop {
                    let calls = self.calls.lock().await.clone();
                    if calls.len() >= count {
                        return calls;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("SCP protocol calls")
        }
    }

    #[async_trait]
    impl ScpProtocolRunnerBridge for RecordingScpRunner {
        async fn start_scp_bridge(
            &self,
            command: Vec<String>,
            channel: Channel<server::Msg>,
        ) -> Result<(), ScpProtocolRunnerError> {
            self.calls.lock().await.push((channel.id(), command));
            channel
                .exit_status(0)
                .await
                .map_err(|err| ScpProtocolRunnerError(err.to_string()))?;
            channel
                .eof()
                .await
                .map_err(|err| ScpProtocolRunnerError(err.to_string()))?;
            channel
                .close()
                .await
                .map_err(|err| ScpProtocolRunnerError(err.to_string()))?;
            Ok(())
        }
    }

    struct AcceptAllKeys;

    impl client::Handler for AcceptAllKeys {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    async fn spawn_test_gateway() -> (
        Arc<RecordingRunner>,
        SocketAddr,
        tokio::task::JoinHandle<()>,
    ) {
        let runner = Arc::new(RecordingRunner::default());
        let (addr, task) = spawn_test_gateway_with_runner(runner.clone()).await;
        (runner, addr, task)
    }

    async fn spawn_test_gateway_with_runner<R>(
        runner: Arc<R>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        R: SshSessionRunner,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = workspace_ssh_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(config, stream, WorkspaceSshHandler::new(runner))
                .await
                .unwrap();
            let _ = session.await;
        });
        (addr, task)
    }

    async fn spawn_test_gateway_with_runner_and_sftp<R>(
        runner: Arc<R>,
        sftp: Arc<dyn SftpSubsystemRunner>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        R: SshSessionRunner,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = workspace_ssh_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                config,
                stream,
                WorkspaceSshHandler::with_sftp(runner, Some(sftp)),
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        (addr, task)
    }

    async fn spawn_test_gateway_with_file_protocols<R>(
        runner: Arc<R>,
        sftp: Arc<dyn SftpSubsystemRunner>,
        scp: Arc<dyn ScpProtocolRunnerBridge>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        R: SshSessionRunner,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = workspace_ssh_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                config,
                stream,
                WorkspaceSshHandler::with_file_protocols(runner, Some(sftp), Some(scp)),
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        (addr, task)
    }

    fn test_host_key() -> russh::keys::PrivateKey {
        host_key::generate_ed25519_key()
    }

    fn test_client_config() -> Arc<client::Config> {
        Arc::new(client::Config::default())
    }

    async fn authenticated_client(addr: SocketAddr) -> client::Handle<AcceptAllKeys> {
        let mut handle = client::connect(test_client_config(), addr, AcceptAllKeys)
            .await
            .unwrap();
        let authenticated = handle
            .authenticate_none("codewire")
            .await
            .map(|result| matches!(result, client::AuthResult::Success))
            .unwrap_or(false);
        assert!(authenticated, "none-auth should be accepted");
        handle
    }

    async fn runner_events(runner: &RecordingRunner) -> Vec<RunnerEvent> {
        runner
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|(_, event)| event.clone())
            .collect()
    }

    async fn wait_for_runner_events(runner: &RecordingRunner, count: usize) -> Vec<RunnerEvent> {
        for _ in 0..50 {
            let events = runner_events(runner).await;
            if events.len() >= count {
                return events;
            }
            sleep(Duration::from_millis(10)).await;
        }
        runner_events(runner).await
    }

    async fn stop_client_and_server(
        client: client::Handle<AcceptAllKeys>,
        task: tokio::task::JoinHandle<()>,
    ) {
        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    async fn collect_ssh_channel_output(
        channel: &mut russh::Channel<client::Msg>,
    ) -> (Vec<u8>, Vec<u8>, Option<u32>) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        timeout(Duration::from_secs(2), async {
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("SSH channel output");
        (stdout, stderr, exit)
    }

    fn derp_public_from_node(node: NodePublic) -> DerpPublic {
        DerpPublic::from_raw(*node.as_bytes())
    }

    fn fallback_pair(a_node: NodePublic, b_node: NodePublic) -> (Transport, Transport) {
        let (a_out_tx, mut a_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (b_out_tx, mut b_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<WgDatagram>();

        tokio::spawn(async move {
            while let Some(dg) = a_out_rx.recv().await {
                let _ = b_in_tx.send(WgDatagram {
                    peer: derp_public_from_node(a_node),
                    data: dg.data,
                });
            }
        });
        tokio::spawn(async move {
            while let Some(dg) = b_out_rx.recv().await {
                let _ = a_in_tx.send(WgDatagram {
                    peer: derp_public_from_node(b_node),
                    data: dg.data,
                });
            }
        });

        (
            Transport {
                to_transport: a_out_tx,
                from_transport: a_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
            Transport {
                to_transport: b_out_tx,
                from_transport: b_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
        )
    }

    fn tailnet_node(
        node_key: NodePublic,
        disco_key: DiscoPublic,
        endpoints: Vec<SocketAddr>,
        ip: Ipv6Addr,
    ) -> Node {
        Node {
            id: Uuid::new_v4(),
            as_of: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            key: node_key,
            disco_key,
            preferred_derp: 1,
            derp_latency: None,
            endpoints: endpoints.into_iter().map(AddrPort).collect(),
            addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
        }
    }

    fn tailnet_options(secret: &StaticSecret, disco: DiscoPrivate, ip: Ipv6Addr) -> TailnetOptions {
        TailnetOptions {
            id: Uuid::new_v4(),
            addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
            endpoints: Vec::new(),
            private_key: Some(secret.clone()),
            disco_private: Some(disco),
        }
    }

    async fn wait_for_peer_relay(handle: &direct_udp::Handle, peer: &NodePublic, label: &str) {
        for _ in 0..1000 {
            if handle.path_for_peer(peer).transport == PeerTransport::PeerRelay {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("UDP peer relay endpoint was not bound for {label}");
    }

    async fn wait_for_peer_known(handle: &direct_udp::Handle, peer: &NodePublic, label: &str) {
        for _ in 0..1000 {
            if handle.path_for_peer(peer).transport != PeerTransport::Unknown {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("UDP peer was not registered for {label}");
    }

    async fn peer_relay_tailnet_pair() -> (
        TailnetConn,
        TailnetConn,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), udp_relay::Error>>,
    ) {
        let gateway_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let client_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let gateway_node = NodePublic::from_raw(PublicKey::from(&gateway_secret).to_bytes());
        let client_node = NodePublic::from_raw(PublicKey::from(&client_secret).to_bytes());
        let gateway_disco = DiscoPrivate::generate(&mut rand::rngs::OsRng);
        let client_disco = DiscoPrivate::generate(&mut rand::rngs::OsRng);
        let (gateway_fallback, client_fallback) = fallback_pair(gateway_node, client_node);

        let relay_key = DiscoPrivate::generate(&mut rand::rngs::OsRng);
        let relay = udp_relay::SocketServer::bind(
            relay_key,
            udp_relay::SocketOptions::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .with_expire_interval(Duration::from_millis(50)),
        )
        .await
        .unwrap();
        let relay_endpoint = relay
            .handle()
            .allocate_endpoint(gateway_disco.public(), client_disco.public())
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_task = tokio::spawn(relay.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let (gateway_transport, gateway_handle) = direct_udp::wrap_transport(
            gateway_fallback,
            DirectUdpOptions::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                gateway_node,
                gateway_disco.clone(),
            ),
        )
        .await
        .unwrap();
        let (client_transport, client_handle) = direct_udp::wrap_transport(
            client_fallback,
            DirectUdpOptions::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                client_node,
                client_disco.clone(),
            ),
        )
        .await
        .unwrap();

        let gateway = TailnetConn::new(
            tailnet_options(&gateway_secret, gateway_disco.clone(), TAILNET_GATEWAY_IP),
            gateway_transport,
        )
        .unwrap();
        let client = TailnetConn::new(
            tailnet_options(&client_secret, client_disco.clone(), TAILNET_CLIENT_IP),
            client_transport,
        )
        .unwrap();

        let gateway_peer = tailnet_node(
            gateway_node,
            gateway_disco.public(),
            Vec::new(),
            TAILNET_GATEWAY_IP,
        );
        let client_peer = tailnet_node(
            client_node,
            client_disco.public(),
            Vec::new(),
            TAILNET_CLIENT_IP,
        );
        gateway
            .update_peers(std::slice::from_ref(&client_peer))
            .unwrap();
        client
            .update_peers(std::slice::from_ref(&gateway_peer))
            .unwrap();

        wait_for_peer_known(&gateway_handle, &client_node, "gateway").await;
        wait_for_peer_known(&client_handle, &gateway_node, "client").await;
        gateway_handle
            .request_peer_relay(client_node, relay_endpoint)
            .unwrap();
        wait_for_peer_relay(&gateway_handle, &client_node, "gateway").await;
        wait_for_peer_relay(&client_handle, &gateway_node, "client").await;
        assert_eq!(
            gateway.probe_peer_path(&client_peer).unwrap().transport,
            PeerTransport::PeerRelay
        );
        assert_eq!(
            client.probe_peer_path(&gateway_peer).unwrap().transport,
            PeerTransport::PeerRelay
        );

        (gateway, client, shutdown_tx, relay_task)
    }

    #[test]
    fn workspace_ssh_server_config_keeps_no_client_auth_admission() {
        let config = workspace_ssh_server_config();
        assert_eq!(&*config.methods, &[MethodKind::None]);
    }

    /// OpenSSH 10 warns on every connection that does not negotiate a
    /// post-quantum key exchange, so the server offers ML-KEM first.
    #[test]
    fn workspace_ssh_server_config_prefers_post_quantum_kex() {
        let config = workspace_ssh_server_config();
        assert_eq!(config.preferred.kex[0], kex::MLKEM768X25519_SHA256);
    }

    #[test]
    fn exec_session_request_maps_to_daemon_start() {
        let start = build_daemon_session_start(SshSessionRequest {
            command: vec!["/bin/sh".into(), "-lc".into(), "echo ok".into()],
            working_dir: String::new(),
            env: vec!["A=B".into()],
            pty: None,
        });

        assert_eq!(
            start,
            DaemonSessionStart::Exec(SessionStart {
                command: vec!["/bin/sh".into(), "-lc".into(), "echo ok".into()],
                working_dir: String::new(),
                env: vec!["A=B".into()],
            })
        );
    }

    #[test]
    fn exec_command_uses_shellword_splitting_like_go_gateway() {
        assert_eq!(
            parse_exec_command(br#"printf 'hello world' "and goodbye""#).unwrap(),
            ["printf", "hello world", "and goodbye"]
        );
    }

    #[test]
    fn pty_session_request_maps_term_and_window_to_daemon_start() {
        let start = build_daemon_session_start(SshSessionRequest {
            command: vec!["bash".into()],
            working_dir: String::new(),
            env: vec!["A=B".into(), "TERM=ignored".into()],
            pty: Some(SshPtyRequest {
                term: "xterm-256color".into(),
                width: 120,
                height: 40,
            }),
        });

        assert_eq!(
            start,
            DaemonSessionStart::Pty(PtyStart {
                command: vec!["bash".into()],
                working_dir: String::new(),
                env: vec!["A=B".into()],
                term: "xterm-256color".into(),
                width: 120,
                height: 40,
            })
        );
    }

    #[test]
    fn pty_window_dimensions_saturate_to_daemon_i32() {
        let start = build_daemon_session_start(SshSessionRequest {
            command: Vec::new(),
            working_dir: String::new(),
            env: Vec::new(),
            pty: Some(SshPtyRequest {
                term: "xterm".into(),
                width: u32::MAX,
                height: u32::MAX,
            }),
        });

        assert_eq!(
            start,
            DaemonSessionStart::Pty(PtyStart {
                command: Vec::new(),
                working_dir: String::new(),
                env: Vec::new(),
                term: "xterm".into(),
                width: i32::MAX,
                height: i32::MAX,
            })
        );
    }

    #[test]
    fn reverse_port_forward_policy_is_denied() {
        assert!(!allow_reverse_port_forward("127.0.0.1", 8080));
        assert!(!allow_reverse_port_forward("", 8080));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn russh_handler_routes_exec_over_peer_relay_tailnet() {
        let (gateway, tailnet_client, relay_shutdown, relay_task) = peer_relay_tailnet_pair().await;
        let runner = Arc::new(RecordingRunner::default());
        let mut listener = gateway.listen("tcp", ":22").await.unwrap();
        let mut config = workspace_ssh_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let server_runner = runner.clone();
        let server_task = tokio::spawn(async move {
            let stream = timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("tailnet SSH accept did not hang")
                .expect("tailnet SSH listener accepts a stream");
            let session =
                server::run_stream(config, stream, WorkspaceSshHandler::new(server_runner))
                    .await
                    .expect("SSH server accepts tailnet stream");
            let _ = session.await;
        });

        let dst = SocketAddr::new(IpAddr::V6(TAILNET_GATEWAY_IP), 22);
        let stream = timeout(
            Duration::from_secs(10),
            tailnet_client.dial_context_tcp(dst),
        )
        .await
        .expect("tailnet client dial did not hang")
        .expect("tailnet client dials gateway");
        let mut client = timeout(
            Duration::from_secs(10),
            client::connect_stream(test_client_config(), stream, AcceptAllKeys),
        )
        .await
        .expect("SSH client connect over peer relay did not hang")
        .expect("SSH client connects over peer relay");
        let authenticated = timeout(
            Duration::from_secs(10),
            client.authenticate_none("codewire"),
        )
        .await
        .expect("SSH none-auth over peer relay did not hang")
        .map(|result| matches!(result, client::AuthResult::Success))
        .unwrap_or(false);
        assert!(authenticated, "none-auth should be accepted");
        let channel = timeout(Duration::from_secs(10), client.channel_open_session())
            .await
            .expect("SSH channel open over peer relay did not hang")
            .expect("SSH channel opens over peer relay");

        timeout(
            Duration::from_secs(10),
            channel.exec(true, br#"printf 'hello over peer relay'"#.to_vec()),
        )
        .await
        .expect("SSH exec over peer relay did not hang")
        .expect("SSH exec over peer relay");
        timeout(Duration::from_secs(10), channel.eof())
            .await
            .expect("SSH eof over peer relay did not hang")
            .expect("SSH eof over peer relay");

        let events = wait_for_runner_events(&runner, 2).await;
        assert_eq!(
            &events[..2],
            [
                RunnerEvent::Start {
                    channel: channel.id(),
                    start: DaemonSessionStart::Exec(SessionStart {
                        command: vec!["printf".into(), "hello over peer relay".into()],
                        working_dir: String::new(),
                        env: Vec::new(),
                    }),
                },
                RunnerEvent::Input {
                    channel: channel.id(),
                    input: SshSessionInput::CloseStdin,
                },
            ]
        );

        let _ = client
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        let _ = relay_shutdown.send(());
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    #[ignore = "diagnostic: shells out to the host OpenSSH client"]
    async fn openssh_client_completes_exec_against_gateway_tcp() {
        let runner = Arc::new(CompletingRunner);
        let (addr, server_task) = spawn_test_gateway_with_runner(runner).await;
        let output = timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("ssh")
                .arg("-F")
                .arg("/dev/null")
                .arg("-o")
                .arg("BatchMode=yes")
                .arg("-o")
                .arg("PreferredAuthentications=none")
                .arg("-o")
                .arg("PubkeyAuthentication=no")
                .arg("-o")
                .arg("PasswordAuthentication=no")
                .arg("-o")
                .arg("KbdInteractiveAuthentication=no")
                .arg("-o")
                .arg("StrictHostKeyChecking=no")
                .arg("-o")
                .arg("UserKnownHostsFile=/dev/null")
                .arg("-p")
                .arg(addr.port().to_string())
                .arg("codewire@127.0.0.1")
                .arg("printf ignored")
                .output(),
        )
        .await
        .expect("OpenSSH command did not hang")
        .expect("spawn OpenSSH command");
        assert!(
            output.status.success(),
            "ssh failed: status={:?}\nstdout={}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), "openssh-ok\n");
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic: shells out to the host OpenSSH client"]
    async fn openssh_client_completes_exec_over_rust_peer_relay_bridge() {
        let (gateway, tailnet_client, relay_shutdown, relay_task) = peer_relay_tailnet_pair().await;
        let runner = Arc::new(CompletingRunner);
        let mut listener = gateway.listen("tcp", ":22").await.unwrap();
        let mut config = workspace_ssh_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let server_task = tokio::spawn(async move {
            let stream = timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("tailnet SSH accept did not hang")
                .expect("tailnet SSH listener accepts a stream");
            let session = server::run_stream(config, stream, WorkspaceSshHandler::new(runner))
                .await
                .expect("SSH server accepts tailnet stream");
            let _ = session.await;
        });

        let bridge = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bridge_addr = bridge.local_addr().unwrap();
        let bridge_task = tokio::spawn(async move {
            let (mut local, _) = bridge.accept().await.unwrap();
            let dst = SocketAddr::new(IpAddr::V6(TAILNET_GATEWAY_IP), 22);
            let mut remote = timeout(
                Duration::from_secs(10),
                tailnet_client.dial_context_tcp(dst),
            )
            .await
            .expect("tailnet client dial did not hang")
            .expect("tailnet client dials gateway");
            let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
        });

        let output = timeout(
            Duration::from_secs(10),
            tokio::process::Command::new("ssh")
                .arg("-F")
                .arg("/dev/null")
                .arg("-o")
                .arg("BatchMode=yes")
                .arg("-o")
                .arg("PreferredAuthentications=none")
                .arg("-o")
                .arg("PubkeyAuthentication=no")
                .arg("-o")
                .arg("PasswordAuthentication=no")
                .arg("-o")
                .arg("KbdInteractiveAuthentication=no")
                .arg("-o")
                .arg("StrictHostKeyChecking=no")
                .arg("-o")
                .arg("UserKnownHostsFile=/dev/null")
                .arg("-p")
                .arg(bridge_addr.port().to_string())
                .arg("codewire@127.0.0.1")
                .arg("printf ignored")
                .output(),
        )
        .await
        .expect("OpenSSH command did not hang")
        .expect("spawn OpenSSH command");
        assert!(
            output.status.success(),
            "ssh failed: status={:?}\nstdout={}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), "openssh-ok\n");

        timeout(Duration::from_secs(2), bridge_task)
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        let _ = relay_shutdown.send(());
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn russh_handler_rejects_nonlocal_direct_tcpip_channels() {
        let (runner, addr, server_task) = spawn_test_gateway().await;
        let client = authenticated_client(addr).await;
        let result = timeout(
            Duration::from_secs(5),
            client.channel_open_direct_tcpip("198.51.100.1", 443, "127.0.0.1", 12345),
        )
        .await
        .expect("direct-tcpip rejection did not hang");
        assert!(matches!(
            result,
            Err(russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::AdministrativelyProhibited
            ))
        ));
        assert!(runner_events(&runner).await.is_empty());
        stop_client_and_server(client, server_task).await;
    }

    #[tokio::test]
    async fn russh_handler_routes_exec_requests_to_runner() {
        let (runner, addr, server_task) = spawn_test_gateway().await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();

        channel.set_env(true, "A", "B").await.unwrap();
        channel
            .exec(true, br#"printf 'hello world'"#.to_vec())
            .await
            .unwrap();
        channel.eof().await.unwrap();

        let events = wait_for_runner_events(&runner, 2).await;
        assert_eq!(
            &events[..2],
            [
                RunnerEvent::Start {
                    channel: channel.id(),
                    start: DaemonSessionStart::Exec(SessionStart {
                        command: vec!["printf".into(), "hello world".into()],
                        working_dir: String::new(),
                        env: vec!["A=B".into()],
                    }),
                },
                RunnerEvent::Input {
                    channel: channel.id(),
                    input: SshSessionInput::CloseStdin,
                },
            ]
        );

        stop_client_and_server(client, server_task).await;
    }

    #[tokio::test]
    async fn russh_handler_routes_pty_shell_requests_to_runner() {
        let (runner, addr, server_task) = spawn_test_gateway().await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();

        channel
            .request_pty(true, "xterm-256color", 120, 40, 0, 0, &[])
            .await
            .unwrap();
        channel.set_env(true, "TERM", "ignored").await.unwrap();
        channel.set_env(true, "A", "B").await.unwrap();
        channel.request_shell(true).await.unwrap();
        channel.window_change(100, 32, 0, 0).await.unwrap();

        let events = wait_for_runner_events(&runner, 2).await;
        assert_eq!(
            &events[..2],
            [
                RunnerEvent::Start {
                    channel: channel.id(),
                    start: DaemonSessionStart::Pty(PtyStart {
                        command: Vec::new(),
                        working_dir: String::new(),
                        env: vec!["A=B".into()],
                        term: "xterm-256color".into(),
                        width: 120,
                        height: 40,
                    }),
                },
                RunnerEvent::Input {
                    channel: channel.id(),
                    input: SshSessionInput::Resize {
                        width: 100,
                        height: 32,
                    },
                },
            ]
        );

        stop_client_and_server(client, server_task).await;
    }

    /// A gateway serving `connections` connections with `config`, each through
    /// its own handler on the shared `runner`.
    async fn spawn_test_gateway_with_config<R>(
        runner: Arc<R>,
        config: server::Config,
        connections: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>)
    where
        R: SshSessionRunner,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = config;
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let mut served = Vec::new();
            for _ in 0..connections {
                let (stream, _) = listener.accept().await.unwrap();
                let config = config.clone();
                let runner = runner.clone();
                served.push(tokio::spawn(async move {
                    let session =
                        server::run_stream(config, stream, WorkspaceSshHandler::new(runner))
                            .await
                            .unwrap();
                    let _ = session.await;
                }));
            }
            for connection in served {
                let _ = connection.await;
            }
        });
        (addr, task)
    }

    /// A TCP relay in front of `target` for one connection. Freezing it stops
    /// both directions but keeps both sockets open: a client that went
    /// silent without closing its connection. Aborting it closes both.
    async fn spawn_relay(
        target: SocketAddr,
    ) -> (
        SocketAddr,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frozen, frozen_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = tokio::net::TcpStream::connect(target).await.unwrap();
            let (client_rx, client_tx) = client.into_split();
            let (server_rx, server_tx) = server.into_split();
            let up = relay_half(client_rx, server_tx, frozen_rx.clone());
            let down = relay_half(server_rx, client_tx, frozen_rx);
            let _ = tokio::join!(up, down);
        });
        (addr, frozen, task)
    }

    async fn relay_half(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        mut frozen: tokio::sync::watch::Receiver<bool>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let read = tokio::select! {
                _ = frozen.wait_for(|frozen| *frozen) => None,
                read = from.read(&mut buffer) => Some(read),
            };
            match read {
                // Frozen: hold both halves open and silent.
                None => std::future::pending::<()>().await,
                Some(Ok(0) | Err(_)) => return,
                Some(Ok(read)) => {
                    if to.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    async fn authenticated_client_over(
        stream: tokio::net::TcpStream,
    ) -> client::Handle<AcceptAllKeys> {
        let mut handle = client::connect_stream(test_client_config(), stream, AcceptAllKeys)
            .await
            .unwrap();
        let authenticated = handle
            .authenticate_none("codewire")
            .await
            .map(|result| matches!(result, client::AuthResult::Success))
            .unwrap_or(false);
        assert!(authenticated, "none-auth should be accepted");
        handle
    }

    fn recorded(runner: &RecordingRunner) -> Vec<(u64, RunnerEvent)> {
        runner.events.lock().unwrap().clone()
    }

    async fn wait_for_recorded<F>(
        runner: &RecordingRunner,
        what: &str,
        done: F,
    ) -> Vec<(u64, RunnerEvent)>
    where
        F: Fn(&[(u64, RunnerEvent)]) -> bool,
    {
        timeout(Duration::from_secs(10), async {
            loop {
                let events = recorded(runner);
                if done(&events) {
                    return events;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("runner did not see {what}: {:?}", recorded(runner).len()))
    }

    fn stdin_of(events: &[(u64, RunnerEvent)], connection: u64) -> Vec<u8> {
        events
            .iter()
            .filter(|(owner, _)| *owner == connection)
            .filter_map(|(_, event)| match event {
                RunnerEvent::Input {
                    input: SshSessionInput::Stdin(data),
                    ..
                } => Some(data.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    fn count_inputs(events: &[(u64, RunnerEvent)]) -> usize {
        events
            .iter()
            .filter(|(_, event)| matches!(event, RunnerEvent::Input { .. }))
            .count()
    }

    fn ended(events: &[(u64, RunnerEvent)], channel: ChannelId) -> bool {
        events
            .iter()
            .any(|(_, event)| *event == RunnerEvent::Ended { channel })
    }

    /// russh queues 100 messages per channel before it stops reading the
    /// connection; the exec session's input must keep flowing past that.
    #[tokio::test]
    async fn russh_handler_delivers_exec_input_beyond_the_channel_queue() {
        let (runner, addr, server_task) = spawn_test_gateway().await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();
        channel.exec(true, b"cat".to_vec()).await.unwrap();
        let mut sent = Vec::new();
        for index in 0..300 {
            let line = format!("line {index}\n").into_bytes();
            sent.extend_from_slice(&line);
            timeout(Duration::from_secs(5), channel.data_bytes(line))
                .await
                .expect("input message accepted")
                .unwrap();
        }
        channel.eof().await.unwrap();

        let events = wait_for_recorded(&runner, "300 inputs and EOF", |events| {
            events.iter().any(|(_, event)| {
                matches!(
                    event,
                    RunnerEvent::Input {
                        input: SshSessionInput::CloseStdin,
                        ..
                    }
                )
            })
        })
        .await;
        let connection = events[0].0;
        assert_eq!(stdin_of(&events, connection), sent);
        // Queued stdin may travel together; EOF still comes last.
        assert!(count_inputs(&events) <= 301);
        assert!(matches!(
            events.last(),
            Some((
                _,
                RunnerEvent::Input {
                    input: SshSessionInput::CloseStdin,
                    ..
                }
            ))
        ));

        stop_client_and_server(client, server_task).await;
    }

    /// The same for an interactive terminal: every keystroke and resize.
    #[tokio::test]
    async fn russh_handler_delivers_pty_keystrokes_beyond_the_channel_queue() {
        let (runner, addr, server_task) = spawn_test_gateway().await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        let mut expected = Vec::new();
        for index in 0..300u32 {
            let key = vec![b'a' + (index % 26) as u8];
            expected.push(SshSessionInput::Stdin(key.clone()));
            timeout(Duration::from_secs(5), channel.data_bytes(key))
                .await
                .expect("keystroke accepted")
                .unwrap();
            if index % 6 == 0 {
                let width = 80 + index;
                expected.push(SshSessionInput::Resize {
                    width: i32::try_from(width).unwrap(),
                    height: 24,
                });
                channel.window_change(width, 24, 0, 0).await.unwrap();
            }
        }

        let resizes = expected
            .iter()
            .filter(|input| matches!(input, SshSessionInput::Resize { .. }))
            .count();
        let events = wait_for_recorded(&runner, "every keystroke and resize", |events| {
            inputs_of(events)
                .iter()
                .filter(|input| matches!(input, SshSessionInput::Resize { .. }))
                .count()
                == resizes
                && events
                    .first()
                    .is_some_and(|(connection, _)| stdin_of(events, *connection).len() == 300)
        })
        .await;
        assert_eq!(joined(&inputs_of(&events)), joined(&expected));

        stop_client_and_server(client, server_task).await;
    }

    /// A daemon session's output stream with every output ready at once,
    /// counting the outputs read.
    struct ReadyDaemonOutputs {
        outputs: std::vec::IntoIter<DaemonSessionOutput>,
        read: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl DaemonOutputStream for ReadyDaemonOutputs {
        async fn next_output(&mut self) -> Result<Option<DaemonSessionOutput>, DaemonClientError> {
            let next = self.outputs.next();
            if next.is_some() {
                self.read.fetch_add(1, Ordering::SeqCst);
            }
            Ok(next)
        }
    }

    /// An SSH channel that takes output only while its gate has permits.
    struct GatedSink {
        gate: Arc<tokio::sync::Semaphore>,
        sent: std::sync::Mutex<Vec<SshSessionOutput>>,
    }

    #[async_trait]
    impl SshOutputSink for GatedSink {
        async fn send(&self, output: SshSessionOutput) -> Result<(), SshSessionRunnerError> {
            self.gate.acquire().await.unwrap().forget();
            self.sent.lock().unwrap().push(output);
            Ok(())
        }
    }

    /// Run the output forwarder over `outputs` into a channel that takes
    /// nothing yet; returns the forwarder, the read count and the channel.
    fn forward_into_waiting_channel(
        outputs: Vec<DaemonSessionOutput>,
    ) -> (
        tokio::task::JoinHandle<Result<i32, SshSessionRunnerError>>,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<GatedSink>,
    ) {
        let read = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sink = Arc::new(GatedSink {
            gate: Arc::new(tokio::sync::Semaphore::new(0)),
            sent: Default::default(),
        });
        let mut session = ReadyDaemonOutputs {
            outputs: outputs.into_iter(),
            read: read.clone(),
        };
        let forward = tokio::spawn({
            let sink = sink.clone();
            async move { forward_daemon_outputs(&mut session, &*sink, "ended").await }
        });
        (forward, read, sink)
    }

    async fn settle(read: &std::sync::atomic::AtomicUsize) -> usize {
        let mut last = usize::MAX;
        loop {
            sleep(Duration::from_millis(50)).await;
            let now = read.load(Ordering::SeqCst);
            if now == last {
                return now;
            }
            last = now;
        }
    }

    /// Daemon output keeps being read while the SSH channel takes none of
    /// it, so more than a thousand small output frames never wait unread in
    /// HTTP/2, whose flood guard would end the daemon connection (#2822). The
    /// channel then gets every byte once, in order, in a few joined writes,
    /// and the exit status last.
    #[tokio::test]
    async fn daemon_output_is_read_while_the_ssh_channel_waits() {
        const FRAMES: usize = 1500;
        let mut outputs: Vec<_> = (0..FRAMES)
            .map(|index| DaemonSessionOutput::Stdout(vec![(index % 251) as u8]))
            .collect();
        outputs.push(DaemonSessionOutput::Exit(0));
        let (forward, read, sink) = forward_into_waiting_channel(outputs);
        assert_eq!(settle(&read).await, FRAMES + 1);
        assert!(sink.sent.lock().unwrap().is_empty());

        sink.gate
            .add_permits(tokio::sync::Semaphore::MAX_PERMITS / 2);
        let code = timeout(Duration::from_secs(5), forward)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(code, 0);
        let sent = sink.sent.lock().unwrap();
        let stdout: Vec<u8> = sent
            .iter()
            .filter_map(|output| match output {
                SshSessionOutput::Stdout(data) => Some(data.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        assert_eq!(
            stdout,
            (0..FRAMES)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>()
        );
        assert_eq!(sent.last(), Some(&SshSessionOutput::Exit(0)));
        assert!(sent.len() <= 3, "{} channel writes", sent.len());
    }

    /// The pending output is bounded: at the bound the forwarder stops
    /// reading until the channel takes output, and a stream that ends without
    /// an exit status still ends the channel with an error and status 1.
    #[tokio::test]
    async fn pending_daemon_output_is_bounded() {
        const CHUNK: usize = 64 * 1024;
        const CHUNKS: usize = 20;
        let outputs = (0..CHUNKS)
            .map(|index| DaemonSessionOutput::Stdout(vec![index as u8; CHUNK]))
            .collect();
        let (forward, read, sink) = forward_into_waiting_channel(outputs);
        // The writer holds one chunk; the queue holds the bound.
        assert_eq!(settle(&read).await, MAX_PENDING_SSH_OUTPUT / CHUNK + 1);

        sink.gate
            .add_permits(tokio::sync::Semaphore::MAX_PERMITS / 2);
        let error = timeout(Duration::from_secs(5), forward)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.to_string(), "ended");
        assert_eq!(read.load(Ordering::SeqCst), CHUNKS);
        let sent = sink.sent.lock().unwrap();
        let stdout: Vec<u8> = sent
            .iter()
            .filter_map(|output| match output {
                SshSessionOutput::Stdout(data) => Some(data.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        assert_eq!(
            stdout,
            (0..CHUNKS)
                .flat_map(|index| vec![index as u8; CHUNK])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            &sent[sent.len() - 2..],
            [
                SshSessionOutput::Error("ended".into()),
                SshSessionOutput::Exit(1)
            ]
        );
    }

    fn inputs_of(events: &[(u64, RunnerEvent)]) -> Vec<SshSessionInput> {
        events
            .iter()
            .filter_map(|(_, event)| match event {
                RunnerEvent::Input { input, .. } => Some(input.clone()),
                _ => None,
            })
            .collect()
    }

    /// `inputs` with each run of consecutive Stdin joined, as the pump may
    /// join it: what a process sees, in order.
    fn joined(inputs: &[SshSessionInput]) -> Vec<SshSessionInput> {
        let mut joined: Vec<SshSessionInput> = Vec::new();
        for input in inputs {
            match (joined.last_mut(), input) {
                (Some(SshSessionInput::Stdin(held)), SshSessionInput::Stdin(data)) => {
                    held.extend_from_slice(data);
                }
                _ => joined.push(input.clone()),
            }
        }
        joined
    }

    /// Keystrokes queued while the session is not taking input travel
    /// together, in fewer, larger messages: a burst reaches the daemon as a
    /// few HTTP/2 DATA frames rather than one per keystroke, which the
    /// connection's flood guard would count against it (#2822). Stdin never
    /// passes a resize or EOF, and no message exceeds the coalescing limit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn russh_handler_coalesces_backlogged_keystrokes_in_order() {
        const KEYS: u32 = 1200;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runner = Arc::new(RecordingRunner::gated(gate.clone()));
        let (addr, server_task) =
            spawn_test_gateway_with_config(runner.clone(), workspace_ssh_server_config(), 1).await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        let mut expected = Vec::new();
        for index in 0..KEYS {
            let key = vec![b'a' + (index % 26) as u8];
            expected.push(SshSessionInput::Stdin(key.clone()));
            timeout(Duration::from_secs(5), channel.data_bytes(key))
                .await
                .expect("keystroke accepted")
                .unwrap();
            if index % 100 == 99 {
                let width = 80 + index;
                expected.push(SshSessionInput::Resize {
                    width: i32::try_from(width).unwrap(),
                    height: 24,
                });
                channel.window_change(width, 24, 0, 0).await.unwrap();
            }
        }
        expected.push(SshSessionInput::CloseStdin);
        channel.eof().await.unwrap();

        gate.add_permits(tokio::sync::Semaphore::MAX_PERMITS / 2);
        let events = wait_for_recorded(&runner, "every keystroke, resize and EOF", |events| {
            events.iter().any(|(_, event)| {
                matches!(
                    event,
                    RunnerEvent::Input {
                        input: SshSessionInput::CloseStdin,
                        ..
                    }
                )
            })
        })
        .await;
        let inputs = inputs_of(&events);
        assert_eq!(joined(&inputs), joined(&expected));
        let longest = inputs
            .iter()
            .filter_map(|input| match input {
                SshSessionInput::Stdin(data) => Some(data.len()),
                _ => None,
            })
            .max()
            .unwrap();
        assert!(
            (50..=MAX_COALESCED_STDIN).contains(&longest),
            "queued keystrokes were not coalesced: the longest input was {longest} bytes"
        );
        assert!(inputs.len() < expected.len());

        stop_client_and_server(client, server_task).await;
    }

    /// A process that is not reading its stdin pauses the connection: the
    /// client cannot send more than russh's bounded queue and window, and
    /// nothing is lost or reordered once the process reads again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn russh_handler_backpressures_input_to_a_process_that_is_not_reading() {
        const MESSAGES: usize = 400;
        const MESSAGE: usize = 32 * 1024;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runner = Arc::new(RecordingRunner::gated(gate.clone()));
        let (addr, server_task) =
            spawn_test_gateway_with_config(runner.clone(), workspace_ssh_server_config(), 1).await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();
        channel.exec(true, b"cat > upload".to_vec()).await.unwrap();
        let payload: Vec<u8> = (0..MESSAGES * MESSAGE)
            .map(|index| (index % 251) as u8)
            .collect();
        let (reader, writer) = channel.split();
        let sender = {
            let payload = payload.clone();
            tokio::spawn(async move {
                writer.data(&payload[..]).await.unwrap();
                writer.eof().await.unwrap();
                writer
            })
        };

        sleep(Duration::from_secs(1)).await;
        assert!(
            !sender.is_finished(),
            "the client sent {} MiB to a process that read nothing",
            MESSAGES * MESSAGE / (1024 * 1024)
        );
        assert_eq!(count_inputs(&recorded(&runner)), 0);

        gate.add_permits(tokio::sync::Semaphore::MAX_PERMITS / 2);
        let writer = timeout(Duration::from_secs(20), sender)
            .await
            .expect("the client finished once the process read")
            .unwrap();
        let events = wait_for_recorded(&runner, "the whole upload and EOF", |events| {
            events.iter().any(|(_, event)| {
                matches!(
                    event,
                    RunnerEvent::Input {
                        input: SshSessionInput::CloseStdin,
                        ..
                    }
                )
            })
        })
        .await;
        assert_eq!(stdin_of(&events, events[0].0), payload);

        drop((reader, writer));
        stop_client_and_server(client, server_task).await;
    }

    /// A session ends when its channel closes, and the connection keeps
    /// serving other channels.
    #[tokio::test]
    async fn russh_handler_ends_a_session_when_its_channel_closes() {
        let (runner, addr, server_task) = spawn_test_gateway().await;
        let client = authenticated_client(addr).await;
        let first = client.channel_open_session().await.unwrap();
        first.exec(true, b"sleep 600".to_vec()).await.unwrap();
        first.close().await.unwrap();
        wait_for_recorded(&runner, "the closed channel's session end", |events| {
            ended(events, first.id())
        })
        .await;

        let second = client.channel_open_session().await.unwrap();
        second.exec(true, b"true".to_vec()).await.unwrap();
        second.data_bytes(b"still served".to_vec()).await.unwrap();
        let events = wait_for_recorded(&runner, "the second channel's input", |events| {
            count_inputs(events) == 1
        })
        .await;
        assert!(!ended(&events, second.id()));

        stop_client_and_server(client, server_task).await;
    }

    /// A connection that closes, even while its process is not reading,
    /// ends every session it started.
    #[tokio::test]
    async fn russh_handler_ends_sessions_when_the_connection_closes() {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let runner = Arc::new(RecordingRunner::gated(gate));
        let (addr, server_task) =
            spawn_test_gateway_with_config(runner.clone(), workspace_ssh_server_config(), 1).await;
        let (relay, _frozen, relay_task) = spawn_relay(addr).await;
        let client =
            authenticated_client_over(tokio::net::TcpStream::connect(relay).await.unwrap()).await;
        let channel = client.channel_open_session().await.unwrap();
        channel.exec(true, b"cat > f".to_vec()).await.unwrap();
        // The pump now waits on a process that reads nothing.
        channel.data_bytes(b"unread".to_vec()).await.unwrap();
        wait_for_recorded(&runner, "the session start", |events| !events.is_empty()).await;

        relay_task.abort();
        wait_for_recorded(&runner, "the session end", |events| {
            ended(events, channel.id())
        })
        .await;
        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the server connection ended")
            .unwrap();
    }

    /// A client that goes silent without closing its connection is noticed
    /// by keepalive, and its sessions end.
    #[tokio::test]
    async fn russh_handler_ends_sessions_of_a_client_that_went_silent() {
        let runner = Arc::new(RecordingRunner::default());
        let mut config = workspace_ssh_server_config();
        config.keepalive_interval = Some(Duration::from_millis(200));
        config.keepalive_max = 2;
        let (addr, server_task) = spawn_test_gateway_with_config(runner.clone(), config, 1).await;
        let (relay, frozen, _relay_task) = spawn_relay(addr).await;
        let client =
            authenticated_client_over(tokio::net::TcpStream::connect(relay).await.unwrap()).await;
        let channel = client.channel_open_session().await.unwrap();
        channel.exec(true, b"sleep 600".to_vec()).await.unwrap();
        wait_for_recorded(&runner, "the session start", |events| !events.is_empty()).await;

        frozen.send(true).unwrap();
        wait_for_recorded(&runner, "the silent client's session end", |events| {
            ended(events, channel.id())
        })
        .await;
        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the server gave up on the silent client")
            .unwrap();
    }

    /// russh numbers channels per connection, so two connections' first
    /// channels share an id. Each connection's input reaches only its own
    /// session, and closing one leaves the other running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn russh_handler_keeps_concurrent_connections_sessions_apart() {
        let runner = Arc::new(RecordingRunner::default());
        let (addr, server_task) =
            spawn_test_gateway_with_config(runner.clone(), workspace_ssh_server_config(), 2).await;
        let first = authenticated_client(addr).await;
        let second = authenticated_client(addr).await;
        let a = first.channel_open_session().await.unwrap();
        a.exec(true, b"cat > a".to_vec()).await.unwrap();
        wait_for_recorded(&runner, "the first start", |events| events.len() == 1).await;
        let b = second.channel_open_session().await.unwrap();
        b.exec(true, b"cat > b".to_vec()).await.unwrap();
        let starts = wait_for_recorded(&runner, "both starts", |events| events.len() == 2).await;
        let (a_connection, b_connection) = (starts[0].0, starts[1].0);
        assert_ne!(a_connection, b_connection);
        let channels: Vec<_> = starts
            .iter()
            .map(|(_, event)| match event {
                RunnerEvent::Start { channel, .. } => *channel,
                other => panic!("expected a start, got {other:?}"),
            })
            .collect();
        assert_eq!(channels[0], channels[1], "both first channels share an id");

        for round in 0..50 {
            a.data_bytes(format!("a{round};").into_bytes())
                .await
                .unwrap();
            b.data_bytes(format!("b{round};").into_bytes())
                .await
                .unwrap();
        }
        a.close().await.unwrap();
        wait_for_recorded(&runner, "the first session end", |events| {
            events.iter().any(|(owner, event)| {
                *owner == a_connection && matches!(event, RunnerEvent::Ended { .. })
            })
        })
        .await;
        b.data_bytes(b"after".to_vec()).await.unwrap();
        b.eof().await.unwrap();
        let events = wait_for_recorded(&runner, "the second session's EOF", |events| {
            events.iter().any(|(owner, event)| {
                *owner == b_connection
                    && matches!(
                        event,
                        RunnerEvent::Input {
                            input: SshSessionInput::CloseStdin,
                            ..
                        }
                    )
            })
        })
        .await;
        let expected = |prefix: &str| -> Vec<u8> {
            (0..50)
                .map(|round| format!("{prefix}{round};"))
                .collect::<String>()
                .into_bytes()
        };
        assert_eq!(stdin_of(&events, a_connection), expected("a"));
        let mut b_expected = expected("b");
        b_expected.extend_from_slice(b"after");
        assert_eq!(stdin_of(&events, b_connection), b_expected);
        assert!(
            !events.iter().any(|(owner, event)| {
                *owner == b_connection && matches!(event, RunnerEvent::Ended { .. })
            }),
            "closing the first connection's channel ended the second's session"
        );

        let _ = first
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        let _ = second
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        timeout(Duration::from_secs(5), server_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn workspace_ssh_server_config_notices_a_silent_client_within_a_minute() {
        let config = workspace_ssh_server_config();
        assert_eq!(
            config.keepalive_interval,
            Some(WORKSPACE_SSH_KEEPALIVE_INTERVAL)
        );
        assert_eq!(config.keepalive_max, WORKSPACE_SSH_KEEPALIVE_MAX);
        let unanswered = u32::try_from(WORKSPACE_SSH_KEEPALIVE_MAX + 1).unwrap();
        assert!(WORKSPACE_SSH_KEEPALIVE_INTERVAL * unanswered <= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn russh_handler_accepts_sftp_subsystem_without_starting_process_session() {
        let runner = Arc::new(RecordingRunner::default());
        let sftp = Arc::new(RecordingSftpRunner::default());
        let (addr, server_task) =
            spawn_test_gateway_with_runner_and_sftp(runner.clone(), sftp.clone()).await;
        let client = authenticated_client(addr).await;
        let channel = client.channel_open_session().await.unwrap();

        channel.request_subsystem(true, "sftp").await.unwrap();

        assert_eq!(sftp.wait_for_channels(1).await, [channel.id()]);
        assert_eq!(runner_events(&runner).await, []);

        stop_client_and_server(client, server_task).await;
    }

    #[tokio::test]
    async fn russh_handler_routes_scp_exec_to_scp_runner() {
        let runner = Arc::new(RecordingRunner::default());
        let sftp = Arc::new(RecordingSftpRunner::default());
        let scp = Arc::new(RecordingScpRunner::default());
        let (addr, server_task) =
            spawn_test_gateway_with_file_protocols(runner.clone(), sftp, scp.clone()).await;
        let client = authenticated_client(addr).await;
        let mut channel = client.channel_open_session().await.unwrap();

        channel
            .exec(true, br#"scp -t /workspace/scp.txt"#.to_vec())
            .await
            .unwrap();

        let (_, _, exit) = collect_ssh_channel_output(&mut channel).await;
        assert_eq!(exit, Some(0));
        assert_eq!(
            scp.wait_for_calls(1).await,
            [(
                channel.id(),
                vec!["scp".into(), "-t".into(), "/workspace/scp.txt".into()]
            )]
        );
        assert_eq!(runner_events(&runner).await, []);

        stop_client_and_server(client, server_task).await;
    }

    #[tokio::test]
    async fn daemon_backed_runner_bridges_exec_output_to_ssh_channel() {
        let daemon = RecordingTonicDaemon::default();
        let daemon_addr = spawn_recording_tonic_daemon(daemon.clone()).await;
        let daemon_client = DaemonSessionClient::connect_endpoint(
            format!("http://{daemon_addr}"),
            codewire_daemon_proto::DaemonAuthToken::new("gateway-ssh-test-token").unwrap(),
        )
        .await
        .unwrap();
        let runner = Arc::new(DaemonBackedSshRunner::new(daemon_client));
        let (addr, server_task) = spawn_test_gateway_with_runner(runner).await;
        let client = authenticated_client(addr).await;
        let mut channel = client.channel_open_session().await.unwrap();

        channel
            .exec(true, br#"printf 'hello world'"#.to_vec())
            .await
            .unwrap();
        channel.data_bytes(b"stdin".to_vec()).await.unwrap();
        channel.eof().await.unwrap();

        let (stdout, stderr, exit) = collect_ssh_channel_output(&mut channel).await;
        assert_eq!(stdout, b"exec-out");
        assert_eq!(stderr, b"exec-err");
        assert_eq!(exit, Some(7));

        let frames = daemon.wait_for_exec_frames(3).await;
        let Some(v1::exec_message::Payload::Start(start)) = frames[0].payload.clone() else {
            panic!("missing exec start frame");
        };
        assert_eq!(start.command, ["printf", "hello world"]);
        assert_eq!(
            frames[1].payload,
            Some(v1::exec_message::Payload::Stdin(b"stdin".to_vec()))
        );
        assert_eq!(
            frames[2].payload,
            Some(v1::exec_message::Payload::CloseStdin(()))
        );

        stop_client_and_server(client, server_task).await;
    }

    #[tokio::test]
    async fn daemon_backed_runner_bridges_pty_output_to_ssh_channel() {
        let daemon = RecordingTonicDaemon::default();
        let daemon_addr = spawn_recording_tonic_daemon(daemon.clone()).await;
        let daemon_client = DaemonSessionClient::connect_endpoint(
            format!("http://{daemon_addr}"),
            codewire_daemon_proto::DaemonAuthToken::new("gateway-ssh-test-token").unwrap(),
        )
        .await
        .unwrap();
        let runner = Arc::new(DaemonBackedSshRunner::new(daemon_client));
        let (addr, server_task) = spawn_test_gateway_with_runner(runner).await;
        let client = authenticated_client(addr).await;
        let mut channel = client.channel_open_session().await.unwrap();

        channel
            .request_pty(true, "xterm-256color", 120, 40, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel.data_bytes(b"stdin".to_vec()).await.unwrap();
        channel.window_change(80, 24, 0, 0).await.unwrap();
        channel.eof().await.unwrap();

        let (stdout, stderr, exit) = collect_ssh_channel_output(&mut channel).await;
        assert_eq!(stdout, b"pty-out");
        assert_eq!(stderr, b"pty-err");
        assert_eq!(exit, Some(0));

        let frames = daemon.wait_for_pty_frames(4).await;
        let Some(v1::pty_message::Payload::Start(start)) = frames[0].payload.clone() else {
            panic!("missing pty start frame");
        };
        assert_eq!(start.command, Vec::<String>::new());
        assert_eq!(start.term, "xterm-256color");
        assert_eq!(start.width, 120);
        assert_eq!(start.height, 40);
        assert_eq!(
            frames[1].payload,
            Some(v1::pty_message::Payload::Stdin(b"stdin".to_vec()))
        );
        assert_eq!(
            frames[2].payload,
            Some(v1::pty_message::Payload::Resize(v1::ResizeRequest {
                width: 80,
                height: 24,
            }))
        );
        assert_eq!(
            frames[3].payload,
            Some(v1::pty_message::Payload::CloseStdin(()))
        );

        stop_client_and_server(client, server_task).await;
    }

    #[derive(Clone, Default)]
    struct RecordingTonicDaemon {
        exec_frames: Arc<Mutex<Vec<v1::ExecMessage>>>,
        pty_frames: Arc<Mutex<Vec<v1::PtyMessage>>>,
    }

    impl RecordingTonicDaemon {
        async fn wait_for_exec_frames(&self, count: usize) -> Vec<v1::ExecMessage> {
            timeout(Duration::from_secs(2), async {
                loop {
                    let frames = self.exec_frames.lock().await.clone();
                    if frames.len() >= count {
                        return frames;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("exec daemon frames")
        }

        async fn wait_for_pty_frames(&self, count: usize) -> Vec<v1::PtyMessage> {
            timeout(Duration::from_secs(2), async {
                loop {
                    let frames = self.pty_frames.lock().await.clone();
                    if frames.len() >= count {
                        return frames;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("pty daemon frames")
        }
    }

    async fn spawn_recording_tonic_daemon(daemon: RecordingTonicDaemon) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        tokio::spawn(async move {
            Server::builder()
                .add_service(DaemonServiceServer::new(daemon))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        addr
    }

    #[tonic::async_trait]
    impl DaemonService for RecordingTonicDaemon {
        async fn poweroff_guest(
            &self,
            _request: Request<v1::PoweroffGuestRequest>,
        ) -> Result<Response<v1::PoweroffGuestResponse>, Status> {
            Err(Status::unimplemented("fixture unused lifecycle RPC"))
        }

        async fn set_app_ports(
            &self,
            _request: Request<v1::SetAppPortsRequest>,
        ) -> Result<Response<v1::SetAppPortsResponse>, Status> {
            Err(Status::unimplemented("fixture unused app ports RPC"))
        }

        type ExecSessionStream = ReceiverStream<Result<v1::ExecMessage, Status>>;
        type PtySessionStream = ReceiverStream<Result<v1::PtyMessage, Status>>;
        type AttachSessionStream = ReceiverStream<Result<v1::SessionAttachMessage, Status>>;
        type CredentialBridgeStream =
            ReceiverStream<Result<bridge_v1::CredentialBridgeGuestMessage, Status>>;

        async fn get_capabilities(
            &self,
            _request: Request<v1::GetCapabilitiesRequest>,
        ) -> Result<Response<v1::GetCapabilitiesResponse>, Status> {
            Err(Status::unimplemented("get capabilities"))
        }

        async fn get_health(
            &self,
            _request: Request<v1::GetHealthRequest>,
        ) -> Result<Response<v1::GetHealthResponse>, Status> {
            Err(Status::unimplemented("get health"))
        }

        async fn credential_bridge(
            &self,
            _request: Request<tonic::Streaming<bridge_v1::CredentialBridgeHostMessage>>,
        ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
            Err(Status::unimplemented("credential bridge"))
        }

        async fn launch_session(
            &self,
            _request: Request<v1::LaunchSessionRequest>,
        ) -> Result<Response<v1::LaunchSessionResponse>, Status> {
            Err(Status::unimplemented("launch session"))
        }

        async fn list_sessions(
            &self,
            _request: Request<v1::ListSessionsRequest>,
        ) -> Result<Response<v1::ListSessionsResponse>, Status> {
            Err(Status::unimplemented("list sessions"))
        }

        async fn get_session(
            &self,
            _request: Request<v1::GetSessionRequest>,
        ) -> Result<Response<v1::GetSessionResponse>, Status> {
            Err(Status::unimplemented("get session"))
        }

        async fn stop_session(
            &self,
            _request: Request<v1::StopSessionRequest>,
        ) -> Result<Response<v1::StopSessionResponse>, Status> {
            Err(Status::unimplemented("stop session"))
        }

        async fn restart_session(
            &self,
            _request: Request<v1::RestartSessionRequest>,
        ) -> Result<Response<v1::RestartSessionResponse>, Status> {
            Err(Status::unimplemented("restart session"))
        }

        async fn send_session_input(
            &self,
            _request: Request<v1::SendSessionInputRequest>,
        ) -> Result<Response<v1::SendSessionInputResponse>, Status> {
            Err(Status::unimplemented(
                "fixture unused acknowledged input RPC",
            ))
        }

        async fn read_session_output(
            &self,
            _request: Request<v1::ReadSessionOutputRequest>,
        ) -> Result<Response<v1::ReadSessionOutputResponse>, Status> {
            Err(Status::unimplemented("read session output"))
        }

        async fn attach_session(
            &self,
            _request: Request<tonic::Streaming<v1::SessionAttachMessage>>,
        ) -> Result<Response<Self::AttachSessionStream>, Status> {
            Err(Status::unimplemented("attach session"))
        }

        async fn exec_session(
            &self,
            request: Request<tonic::Streaming<v1::ExecMessage>>,
        ) -> Result<Response<Self::ExecSessionStream>, Status> {
            let mut inbound = request.into_inner();
            let start = inbound
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("exec start message is required"))?;
            self.exec_frames.lock().await.push(start);

            let frames = self.exec_frames.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(message)) = inbound.message().await {
                    let close_stdin = matches!(
                        &message.payload,
                        Some(v1::exec_message::Payload::CloseStdin(()))
                    );
                    frames.lock().await.push(message);
                    if close_stdin {
                        break;
                    }
                }
                let _ = tx
                    .send(Ok(v1::ExecMessage {
                        payload: Some(v1::exec_message::Payload::Stdout(b"exec-out".to_vec())),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(v1::ExecMessage {
                        payload: Some(v1::exec_message::Payload::Stderr(b"exec-err".to_vec())),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(v1::ExecMessage {
                        payload: Some(v1::exec_message::Payload::Exit(v1::ExitStatus { code: 7 })),
                    }))
                    .await;
            });

            Ok(Response::new(ReceiverStream::new(rx)))
        }

        async fn pty_session(
            &self,
            request: Request<tonic::Streaming<v1::PtyMessage>>,
        ) -> Result<Response<Self::PtySessionStream>, Status> {
            let mut inbound = request.into_inner();
            let start = inbound
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("pty start message is required"))?;
            self.pty_frames.lock().await.push(start);

            let frames = self.pty_frames.clone();
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok(Some(message)) = inbound.message().await {
                    let close_stdin = matches!(
                        &message.payload,
                        Some(v1::pty_message::Payload::CloseStdin(()))
                    );
                    frames.lock().await.push(message);
                    if close_stdin {
                        break;
                    }
                }
                let _ = tx
                    .send(Ok(v1::PtyMessage {
                        payload: Some(v1::pty_message::Payload::Stdout(b"pty-out".to_vec())),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(v1::PtyMessage {
                        payload: Some(v1::pty_message::Payload::Stderr(b"pty-err".to_vec())),
                    }))
                    .await;
                let _ = tx
                    .send(Ok(v1::PtyMessage {
                        payload: Some(v1::pty_message::Payload::Exit(v1::ExitStatus { code: 0 })),
                    }))
                    .await;
            });

            Ok(Response::new(ReceiverStream::new(rx)))
        }

        async fn list(
            &self,
            _request: Request<v1::ListRequest>,
        ) -> Result<Response<v1::ListResponse>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn stat(
            &self,
            _request: Request<v1::StatRequest>,
        ) -> Result<Response<v1::StatResponse>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn open_file(
            &self,
            _request: Request<v1::OpenFileRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn read(
            &self,
            _request: Request<v1::ReadRequest>,
        ) -> Result<Response<v1::ReadResponse>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn write(
            &self,
            _request: Request<v1::WriteRequest>,
        ) -> Result<Response<v1::WriteResponse>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn mkdir(
            &self,
            _request: Request<v1::MkdirRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn remove(
            &self,
            _request: Request<v1::RemoveRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn rename(
            &self,
            _request: Request<v1::RenameRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn set_stat(
            &self,
            _request: Request<v1::SetStatRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }

        async fn readlink(
            &self,
            _request: Request<v1::ReadlinkRequest>,
        ) -> Result<Response<v1::ReadlinkResponse>, Status> {
            Err(Status::unimplemented("not used by SSH bridge tests"))
        }
    }
}
