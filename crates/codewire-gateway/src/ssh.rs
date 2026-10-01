use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty, kex, server};
use thiserror::Error;

use crate::daemon::{
    DaemonClient, DaemonClientError, DaemonSessionOutput, ExecDaemonSessionInput, ExecSessionInput,
    PtyDaemonSessionInput, PtySessionInput, PtyStart, SessionStart,
};
use crate::scp::{ScpProtocolRunner, is_scp_command};
use crate::sftp::DaemonSftpRunner;

#[cfg(all(test, target_os = "linux"))]
#[path = "ssh/stock_credentials.rs"]
mod stock_credentials;

const GATEWAY_KEX_ORDER: &[kex::Name] = &[
    kex::CURVE25519,
    kex::ECDH_SHA2_NISTP256,
    kex::ECDH_SHA2_NISTP384,
    kex::ECDH_SHA2_NISTP521,
    kex::DH_G14_SHA256,
];

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
    async fn start_session(
        &self,
        channel: ChannelId,
        start: DaemonSessionStart,
        output: SshChannelOutput,
    ) -> Result<(), SshSessionRunnerError>;

    async fn session_input(
        &self,
        channel: ChannelId,
        input: SshSessionInput,
    ) -> Result<(), SshSessionRunnerError>;

    async fn close_session(&self, channel: ChannelId) -> Result<(), SshSessionRunnerError>;
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
    sessions: tokio::sync::Mutex<HashMap<ChannelId, DaemonRunningSession>>,
}

enum DaemonRunningSession {
    Exec(ExecDaemonSessionInput),
    Pty(PtyDaemonSessionInput),
}

impl<C> DaemonBackedSshRunner<C>
where
    C: DaemonClient,
{
    pub fn new(client: C) -> Self {
        Self {
            client,
            sessions: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<C> SshSessionRunner for DaemonBackedSshRunner<C>
where
    C: DaemonClient + 'static,
{
    async fn start_session(
        &self,
        channel: ChannelId,
        start: DaemonSessionStart,
        output: SshChannelOutput,
    ) -> Result<(), SshSessionRunnerError> {
        match start {
            DaemonSessionStart::Exec(start) => {
                let mut session = self
                    .client
                    .exec_session(start)
                    .await
                    .map_err(SshSessionRunnerError::from)?;
                let input = session.input_handle();
                tokio::spawn(async move {
                    let _ = forward_exec_daemon_outputs(&mut session, output).await;
                });
                self.sessions
                    .lock()
                    .await
                    .insert(channel, DaemonRunningSession::Exec(input));
            }
            DaemonSessionStart::Pty(start) => {
                let mut session = self
                    .client
                    .pty_session(start)
                    .await
                    .map_err(SshSessionRunnerError::from)?;
                let input = session.input_handle();
                tokio::spawn(async move {
                    let _ = forward_pty_daemon_outputs(&mut session, output).await;
                });
                self.sessions
                    .lock()
                    .await
                    .insert(channel, DaemonRunningSession::Pty(input));
            }
        }
        Ok(())
    }

    async fn session_input(
        &self,
        channel: ChannelId,
        input: SshSessionInput,
    ) -> Result<(), SshSessionRunnerError> {
        let session = self.sessions.lock().await.get(&channel).cloned();
        match (session, input) {
            (Some(DaemonRunningSession::Exec(session)), SshSessionInput::Stdin(data)) => session
                .send_input(ExecSessionInput::Stdin(data))
                .await
                .map_err(SshSessionRunnerError::from),
            (Some(DaemonRunningSession::Exec(session)), SshSessionInput::CloseStdin) => session
                .send_input(ExecSessionInput::CloseStdin)
                .await
                .map_err(SshSessionRunnerError::from),
            (Some(DaemonRunningSession::Exec(_)), SshSessionInput::Resize { .. }) => Ok(()),
            (Some(DaemonRunningSession::Pty(session)), SshSessionInput::Stdin(data)) => session
                .send_input(PtySessionInput::Stdin(data))
                .await
                .map_err(SshSessionRunnerError::from),
            (Some(DaemonRunningSession::Pty(session)), SshSessionInput::CloseStdin) => session
                .send_input(PtySessionInput::CloseStdin)
                .await
                .map_err(SshSessionRunnerError::from),
            (
                Some(DaemonRunningSession::Pty(session)),
                SshSessionInput::Resize { width, height },
            ) => session
                .send_input(PtySessionInput::Resize { width, height })
                .await
                .map_err(SshSessionRunnerError::from),
            (None, _) => Err(SshSessionRunnerError(format!(
                "unknown SSH channel {channel}"
            ))),
        }
    }

    async fn close_session(&self, channel: ChannelId) -> Result<(), SshSessionRunnerError> {
        self.sessions.lock().await.remove(&channel);
        Ok(())
    }
}

impl Clone for DaemonRunningSession {
    fn clone(&self) -> Self {
        match self {
            Self::Exec(session) => Self::Exec(session.clone()),
            Self::Pty(session) => Self::Pty(session.clone()),
        }
    }
}

impl From<DaemonClientError> for SshSessionRunnerError {
    fn from(value: DaemonClientError) -> Self {
        Self(value.to_string())
    }
}

async fn forward_exec_daemon_outputs(
    session: &mut crate::daemon::ExecDaemonSession,
    output: SshChannelOutput,
) -> Result<(), SshSessionRunnerError> {
    loop {
        match session.next_output().await {
            Ok(Some(daemon_output)) => {
                let ssh_output = ssh_output_from_daemon(daemon_output);
                let is_exit = matches!(ssh_output, SshSessionOutput::Exit(_));
                output.send(ssh_output).await?;
                if is_exit {
                    return Ok(());
                }
            }
            Ok(None) => {
                let error = SshSessionRunnerError(
                    "workspace exec session ended without an exit status".into(),
                );
                output
                    .send(SshSessionOutput::Error(error.to_string()))
                    .await?;
                output.send(SshSessionOutput::Exit(1)).await?;
                return Err(error);
            }
            Err(err) => {
                output
                    .send(SshSessionOutput::Error(format!(
                        "workspace session failed: {err}"
                    )))
                    .await?;
                output.send(SshSessionOutput::Exit(1)).await?;
                return Err(SshSessionRunnerError::from(err));
            }
        }
    }
}

async fn forward_pty_daemon_outputs(
    session: &mut crate::daemon::PtyDaemonSession,
    output: SshChannelOutput,
) -> Result<(), SshSessionRunnerError> {
    loop {
        match session.next_output().await {
            Ok(Some(daemon_output)) => {
                let ssh_output = ssh_output_from_daemon(daemon_output);
                let is_exit = matches!(ssh_output, SshSessionOutput::Exit(_));
                output.send(ssh_output).await?;
                if is_exit {
                    return Ok(());
                }
            }
            Ok(None) => {
                let error = SshSessionRunnerError(
                    "workspace PTY session ended without an exit status".into(),
                );
                output
                    .send(SshSessionOutput::Error(error.to_string()))
                    .await?;
                output.send(SshSessionOutput::Exit(1)).await?;
                return Err(error);
            }
            Err(err) => {
                output
                    .send(SshSessionOutput::Error(format!(
                        "workspace session failed: {err}"
                    )))
                    .await?;
                output.send(SshSessionOutput::Exit(1)).await?;
                return Err(SshSessionRunnerError::from(err));
            }
        }
    }
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

#[derive(Debug, Error)]
pub enum GatewaySshError {
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
pub struct GatewaySshServer<R> {
    runner: Arc<R>,
    sftp: Option<Arc<dyn SftpSubsystemRunner>>,
    scp: Option<Arc<dyn ScpProtocolRunnerBridge>>,
}

impl<R> GatewaySshServer<R>
where
    R: SshSessionRunner,
{
    pub fn new(runner: Arc<R>) -> Self {
        Self {
            runner,
            sftp: None,
            scp: None,
        }
    }

    pub fn with_sftp(runner: Arc<R>, sftp: Arc<dyn SftpSubsystemRunner>) -> Self {
        Self {
            runner,
            sftp: Some(sftp),
            scp: None,
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
        }
    }
}

impl<R> server::Server for GatewaySshServer<R>
where
    R: SshSessionRunner,
{
    type Handler = GatewaySshHandler<R>;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        GatewaySshHandler::with_file_protocols(
            self.runner.clone(),
            self.sftp.clone(),
            self.scp.clone(),
        )
    }
}

pub struct GatewaySshHandler<R> {
    runner: Arc<R>,
    sftp: Option<Arc<dyn SftpSubsystemRunner>>,
    scp: Option<Arc<dyn ScpProtocolRunnerBridge>>,
    channels: HashMap<ChannelId, SshChannelState>,
    file_protocol_channels: HashSet<ChannelId>,
}

impl<R> GatewaySshHandler<R>
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
            channels: HashMap::new(),
            file_protocol_channels: HashSet::new(),
        }
    }

    async fn start_channel_session(
        &mut self,
        channel: ChannelId,
        command: Vec<String>,
        session: &mut server::Session,
    ) -> Result<(), GatewaySshError> {
        let Some(state) = self.channels.get(&channel) else {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::UnknownChannel(channel));
        };

        let start = build_daemon_session_start(SshSessionRequest {
            command,
            working_dir: String::new(),
            env: state.env.clone(),
            pty: state.pty.clone(),
        });
        let output = SshChannelOutput::new(channel, session.handle());
        if let Err(err) = self.runner.start_session(channel, start, output).await {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::Runner(err));
        }
        if let Some(state) = self.channels.get_mut(&channel) {
            state.started = true;
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn send_input(
        &self,
        channel: ChannelId,
        input: SshSessionInput,
    ) -> Result<(), GatewaySshError> {
        self.runner.session_input(channel, input).await?;
        Ok(())
    }
}

struct SshChannelState {
    channel: Option<Channel<server::Msg>>,
    env: Vec<String>,
    pty: Option<SshPtyRequest>,
    started: bool,
}

impl SshChannelState {
    fn new(channel: Channel<server::Msg>) -> Self {
        Self {
            channel: Some(channel),
            env: Vec::new(),
            pty: None,
            started: false,
        }
    }
}

pub fn gateway_server_config() -> server::Config {
    let mut config = server::Config::default();
    apply_gateway_server_policy(&mut config);
    config
}

pub fn apply_gateway_server_policy(config: &mut server::Config) {
    config.methods = gateway_auth_methods();
    config.preferred = gateway_preferred_algorithms();
}

pub fn gateway_auth_methods() -> MethodSet {
    MethodSet::from(&[MethodKind::None][..])
}

pub fn gateway_preferred_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(GATEWAY_KEX_ORDER),
        ..Preferred::DEFAULT
    }
}

pub fn gateway_kex_names() -> Vec<String> {
    GATEWAY_KEX_ORDER
        .iter()
        .map(|name| name.as_ref().to_string())
        .collect()
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

pub fn parse_exec_command(command: &[u8]) -> Result<Vec<String>, GatewaySshError> {
    let command = std::str::from_utf8(command)
        .map_err(|err| GatewaySshError::InvalidExecCommand(err.to_string()))?;
    shell_words::split(command).map_err(|err| GatewaySshError::InvalidExecCommand(err.to_string()))
}

pub fn allow_local_port_forward(host: &str, port: u32) -> bool {
    port != 0 && is_pod_local_forward_host(host)
}

pub fn allow_reverse_port_forward(_host: &str, _port: u32) -> bool {
    false
}

pub fn is_pod_local_forward_host(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    match host.as_str() {
        "" | "localhost" | "127.0.0.1" | "0.0.0.0" | "::1" | "::" => return true,
        _ => {}
    }

    host.parse::<IpAddr>()
        .map(|addr| addr.is_loopback() || addr.is_unspecified())
        .unwrap_or(false)
}

fn without_term_env(env: Vec<String>) -> Vec<String> {
    env.into_iter()
        .filter(|entry| !entry.starts_with("TERM="))
        .collect()
}

fn pty_dimension_to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl<R> server::Handler for GatewaySshHandler<R>
where
    R: SshSessionRunner,
{
    type Error = GatewaySshError;

    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels
            .insert(channel.id(), SshChannelState::new(channel));
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if allow_local_port_forward(host_to_connect, port_to_connect) {
            reply.accept().await;
        } else {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
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
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::UnknownChannel(channel));
        };
        state.pty = Some(SshPtyRequest {
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
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::UnknownChannel(channel));
        };
        state.env.push(format!("{variable_name}={variable_value}"));
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
            let Some(mut state) = self.channels.remove(&channel) else {
                session.channel_failure(channel)?;
                return Err(GatewaySshError::UnknownChannel(channel));
            };
            let Some(ssh_channel) = state.channel.take() else {
                session.channel_failure(channel)?;
                return Err(GatewaySshError::UnknownChannel(channel));
            };
            self.file_protocol_channels.insert(channel);
            session.channel_success(channel)?;
            tokio::spawn(async move {
                let _ = scp.start_scp_bridge(command, ssh_channel).await;
            });
            return Ok(());
        }
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
        let Some(mut state) = self.channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::UnknownChannel(channel));
        };
        let Some(ssh_channel) = state.channel.take() else {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::UnknownChannel(channel));
        };
        self.file_protocol_channels.insert(channel);
        session.channel_success(channel)?;
        tokio::spawn(async move {
            let _ = sftp.start_sftp(ssh_channel).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.file_protocol_channels.contains(&channel) {
            return Ok(());
        }
        self.send_input(channel, SshSessionInput::Stdin(data.to_vec()))
            .await
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.file_protocol_channels.contains(&channel) {
            return Ok(());
        }
        self.send_input(channel, SshSessionInput::CloseStdin).await
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.file_protocol_channels.remove(&channel) {
            return Ok(());
        }
        let state = self.channels.remove(&channel);
        if state.map(|state| state.started).unwrap_or(false) {
            self.runner.close_session(channel).await?;
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
        let resize = SshSessionInput::Resize {
            width: pty_dimension_to_i32(col_width),
            height: pty_dimension_to_i32(row_height),
        };
        let Some(state) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Err(GatewaySshError::UnknownChannel(channel));
        };
        if let Some(pty) = state.pty.as_mut() {
            pty.width = col_width;
            pty.height = row_height;
        }
        if state.started {
            self.send_input(channel, resize).await?;
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
    use codewire_gateway_proto::codewire::bridge::v1 as bridge_v1;
    use codewire_gateway_proto::daemon::v1;
    use codewire_gateway_proto::daemon::v1::daemon_service_server::{
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
        Close {
            channel: ChannelId,
        },
    }

    #[derive(Default)]
    struct RecordingRunner {
        events: Mutex<Vec<RunnerEvent>>,
    }

    #[async_trait]
    impl SshSessionRunner for RecordingRunner {
        async fn start_session(
            &self,
            channel: ChannelId,
            start: DaemonSessionStart,
            _output: SshChannelOutput,
        ) -> Result<(), SshSessionRunnerError> {
            self.events
                .lock()
                .await
                .push(RunnerEvent::Start { channel, start });
            Ok(())
        }

        async fn session_input(
            &self,
            channel: ChannelId,
            input: SshSessionInput,
        ) -> Result<(), SshSessionRunnerError> {
            self.events
                .lock()
                .await
                .push(RunnerEvent::Input { channel, input });
            Ok(())
        }

        async fn close_session(&self, channel: ChannelId) -> Result<(), SshSessionRunnerError> {
            self.events
                .lock()
                .await
                .push(RunnerEvent::Close { channel });
            Ok(())
        }
    }

    struct CompletingRunner;

    #[async_trait]
    impl SshSessionRunner for CompletingRunner {
        async fn start_session(
            &self,
            _channel: ChannelId,
            _start: DaemonSessionStart,
            output: SshChannelOutput,
        ) -> Result<(), SshSessionRunnerError> {
            output
                .send(SshSessionOutput::Stdout(b"openssh-ok\n".to_vec()))
                .await?;
            output.send(SshSessionOutput::Exit(0)).await?;
            Ok(())
        }

        async fn session_input(
            &self,
            _channel: ChannelId,
            _input: SshSessionInput,
        ) -> Result<(), SshSessionRunnerError> {
            Ok(())
        }

        async fn close_session(&self, _channel: ChannelId) -> Result<(), SshSessionRunnerError> {
            Ok(())
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
        let mut config = gateway_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(config, stream, GatewaySshHandler::new(runner))
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
        let mut config = gateway_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                config,
                stream,
                GatewaySshHandler::with_sftp(runner, Some(sftp)),
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
        let mut config = gateway_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let session = server::run_stream(
                config,
                stream,
                GatewaySshHandler::with_file_protocols(runner, Some(sftp), Some(scp)),
            )
            .await
            .unwrap();
            let _ = session.await;
        });
        (addr, task)
    }

    fn test_host_key() -> russh::keys::PrivateKey {
        let dir = std::env::temp_dir().join(format!(
            "codewire-gateway-russh-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("host_ed25519");
        let key = host_key::load_or_create(&path).unwrap().key;
        let _ = std::fs::remove_dir_all(dir);
        key
    }

    fn test_client_config() -> Arc<client::Config> {
        let mut config = client::Config::default();
        config.preferred.kex =
            Cow::Borrowed(&[kex::CURVE25519, kex::ECDH_SHA2_NISTP256, kex::DH_G14_SHA256]);
        Arc::new(config)
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
        runner.events.lock().await.clone()
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
    fn gateway_server_config_keeps_no_client_auth_admission() {
        let config = gateway_server_config();
        assert_eq!(&*config.methods, &[MethodKind::None]);
    }

    #[test]
    fn gateway_server_config_excludes_mlkem_until_tailnet_supports_it() {
        let config = gateway_server_config();
        assert!(config.preferred.kex.contains(&kex::CURVE25519));
        assert!(!config.preferred.kex.contains(&kex::MLKEM768X25519_SHA256));
        assert_eq!(
            gateway_kex_names(),
            [
                "curve25519-sha256",
                "ecdh-sha2-nistp256",
                "ecdh-sha2-nistp384",
                "ecdh-sha2-nistp521",
                "diffie-hellman-group14-sha256",
            ]
        );
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
    fn local_port_forward_policy_allows_only_pod_local_targets() {
        for host in [
            "",
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "::",
        ] {
            assert!(
                allow_local_port_forward(host, 8080),
                "{host:?} should be allowed"
            );
        }

        for host in ["10.0.0.1", "8.8.8.8", "codewire.dev"] {
            assert!(
                !allow_local_port_forward(host, 8080),
                "{host:?} should be denied"
            );
        }

        assert!(!allow_local_port_forward("127.0.0.1", 0));
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
        let mut config = gateway_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let server_runner = runner.clone();
        let server_task = tokio::spawn(async move {
            let stream = timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("tailnet SSH accept did not hang")
                .expect("tailnet SSH listener accepts a stream");
            let session = server::run_stream(config, stream, GatewaySshHandler::new(server_runner))
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
        let mut config = gateway_server_config();
        config.keys.push(test_host_key());
        let config = Arc::new(config);
        let server_task = tokio::spawn(async move {
            let stream = timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("tailnet SSH accept did not hang")
                .expect("tailnet SSH listener accepts a stream");
            let session = server::run_stream(config, stream, GatewaySshHandler::new(runner))
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
            codewire_gateway_proto::DaemonAuthToken::new("gateway-ssh-test-token").unwrap(),
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
            codewire_gateway_proto::DaemonAuthToken::new("gateway-ssh-test-token").unwrap(),
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
