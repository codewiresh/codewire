//! Typed host client for the private guest daemon protocol.
//!
//! Callers own transport discovery and authorization. This client owns daemon
//! token attachment, capability negotiation, and private stream framing; it
//! never exposes the token through the public Codewire API.

use std::time::Duration;

pub use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::{
    DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITY_EXEC, DAEMON_CAPABILITY_PTY,
    DAEMON_PROTOCOL_VERSION,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};

#[derive(Debug, thiserror::Error)]
pub enum DaemonClientError {
    #[error("daemon endpoint is invalid")]
    InvalidEndpoint,
    #[error("daemon credential is invalid")]
    InvalidCredential,
    #[error("connect to environment daemon failed")]
    Connect,
    #[error("environment daemon RPC: {0}")]
    Status(#[from] tonic::Status),
    #[error("environment daemon request stream is closed")]
    RequestClosed,
    #[error("environment daemon returned no {0}")]
    MissingResponse(&'static str),
    #[error("environment daemon is not ready ({state:?}): {message}")]
    NotReady {
        state: v1::DaemonState,
        message: String,
    },
    #[error(
        "environment daemon protocol range {minimum_protocol_version}..={protocol_version} is incompatible"
    )]
    IncompatibleProtocol {
        protocol_version: u32,
        minimum_protocol_version: u32,
    },
    #[error("environment daemon does not support required capability {capability}")]
    MissingCapability { capability: String },
    #[error("environment daemon returned an invalid {0} frame")]
    InvalidFrame(&'static str),
    #[error("environment command failed: {0}")]
    Remote(String),
}

#[derive(Clone)]
pub struct DaemonClient {
    inner: v1::daemon_service_client::DaemonServiceClient<Channel>,
    auth_token: MetadataValue<tonic::metadata::Ascii>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonRunStart {
    pub command: Vec<String>,
    pub working_dir: String,
    pub env: Vec<String>,
    pub allocate_tty: bool,
    pub term: String,
    pub columns: i32,
    pub rows: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonRunInput {
    Stdin(Vec<u8>),
    Resize { columns: i32, rows: i32 },
    CloseStdin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonRunOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
}

pub enum DaemonRunSession {
    Exec {
        input: mpsc::Sender<v1::ExecMessage>,
        output: Streaming<v1::ExecMessage>,
    },
    Pty {
        input: mpsc::Sender<v1::PtyMessage>,
        output: Streaming<v1::PtyMessage>,
    },
}

impl DaemonClient {
    pub fn from_channel(
        channel: Channel,
        daemon_token: impl AsRef<str>,
    ) -> Result<Self, DaemonClientError> {
        let auth_token = Self::parse_auth_token(daemon_token)?;
        Ok(Self {
            inner: v1::daemon_service_client::DaemonServiceClient::new(channel),
            auth_token,
        })
    }

    pub async fn connect(
        endpoint: impl AsRef<str>,
        daemon_token: impl AsRef<str>,
    ) -> Result<Self, DaemonClientError> {
        let endpoint = endpoint.as_ref().trim();
        let channel = Endpoint::from_shared(endpoint.to_string())
            .map_err(|_| DaemonClientError::InvalidEndpoint)?
            .connect_timeout(Duration::from_secs(3))
            .connect()
            .await
            .map_err(|_| DaemonClientError::Connect)?;
        Self::from_channel(channel, daemon_token)
    }

    pub async fn require_ready(
        &self,
        required_capabilities: &[&str],
    ) -> Result<v1::GetCapabilitiesResponse, DaemonClientError> {
        let response = self.get_capabilities(required_capabilities).await?;
        let state =
            v1::DaemonState::try_from(response.state).unwrap_or(v1::DaemonState::Unspecified);
        if state != v1::DaemonState::Ready {
            return Err(DaemonClientError::NotReady {
                state,
                message: response.message,
            });
        }
        if response.minimum_protocol_version > DAEMON_PROTOCOL_VERSION
            || response.protocol_version < DAEMON_PROTOCOL_VERSION
        {
            return Err(DaemonClientError::IncompatibleProtocol {
                protocol_version: response.protocol_version,
                minimum_protocol_version: response.minimum_protocol_version,
            });
        }
        for capability in required_capabilities {
            if !response
                .capabilities
                .iter()
                .any(|value| value == capability)
            {
                return Err(DaemonClientError::MissingCapability {
                    capability: (*capability).to_string(),
                });
            }
        }
        Ok(response)
    }

    pub async fn get_capabilities(
        &self,
        required_capabilities: &[&str],
    ) -> Result<v1::GetCapabilitiesResponse, DaemonClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .get_capabilities(
                self.authorized(v1::GetCapabilitiesRequest {
                    protocol_version: DAEMON_PROTOCOL_VERSION,
                    required_capabilities: required_capabilities
                        .iter()
                        .map(|capability| (*capability).to_string())
                        .collect(),
                }),
            )
            .await?
            .into_inner())
    }

    pub async fn start_run(
        &self,
        start: DaemonRunStart,
    ) -> Result<DaemonRunSession, DaemonClientError> {
        let required = if start.allocate_tty {
            DAEMON_CAPABILITY_PTY
        } else {
            DAEMON_CAPABILITY_EXEC
        };
        self.require_ready(&[required]).await?;
        let mut client = self.inner.clone();
        if start.allocate_tty {
            let (input, rx) = mpsc::channel(32);
            input
                .send(v1::PtyMessage {
                    payload: Some(v1::pty_message::Payload::Start(v1::PtyStartRequest {
                        command: start.command,
                        working_dir: start.working_dir,
                        env: start.env,
                        term: start.term,
                        width: start.columns,
                        height: start.rows,
                    })),
                })
                .await
                .map_err(|_| DaemonClientError::RequestClosed)?;
            let output = client
                .pty_session(self.authorized(ReceiverStream::new(rx)))
                .await?
                .into_inner();
            Ok(DaemonRunSession::Pty { input, output })
        } else {
            let (input, rx) = mpsc::channel(32);
            input
                .send(v1::ExecMessage {
                    payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                        command: start.command,
                        working_dir: start.working_dir,
                        env: start.env,
                    })),
                })
                .await
                .map_err(|_| DaemonClientError::RequestClosed)?;
            let output = client
                .exec_session(self.authorized(ReceiverStream::new(rx)))
                .await?
                .into_inner();
            Ok(DaemonRunSession::Exec { input, output })
        }
    }

    pub async fn list_files(
        &self,
        path: impl Into<String>,
    ) -> Result<Vec<v1::FileMetadata>, DaemonClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .list(self.authorized(v1::ListRequest { path: path.into() }))
            .await?
            .into_inner()
            .entries)
    }

    pub async fn stat_file(
        &self,
        path: impl Into<String>,
        follow: bool,
    ) -> Result<v1::FileMetadata, DaemonClientError> {
        let mut client = self.inner.clone();
        client
            .stat(self.authorized(v1::StatRequest {
                path: path.into(),
                follow,
            }))
            .await?
            .into_inner()
            .entry
            .ok_or(DaemonClientError::MissingResponse("file metadata"))
    }

    pub async fn open_file(&self, request: v1::OpenFileRequest) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        client.open_file(self.authorized(request)).await?;
        Ok(())
    }

    pub async fn read_file(&self, request: v1::ReadRequest) -> Result<Vec<u8>, DaemonClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .read(self.authorized(request))
            .await?
            .into_inner()
            .data)
    }

    pub async fn write_file(&self, request: v1::WriteRequest) -> Result<i64, DaemonClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .write(self.authorized(request))
            .await?
            .into_inner()
            .bytes_written)
    }

    pub async fn mkdir(&self, request: v1::MkdirRequest) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        client.mkdir(self.authorized(request)).await?;
        Ok(())
    }

    pub async fn remove(&self, request: v1::RemoveRequest) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        client.remove(self.authorized(request)).await?;
        Ok(())
    }

    pub async fn rename(&self, request: v1::RenameRequest) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        client.rename(self.authorized(request)).await?;
        Ok(())
    }

    pub async fn set_stat(&self, request: v1::SetStatRequest) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        client.set_stat(self.authorized(request)).await?;
        Ok(())
    }

    pub async fn readlink(&self, path: impl Into<String>) -> Result<String, DaemonClientError> {
        let mut client = self.inner.clone();
        Ok(client
            .readlink(self.authorized(v1::ReadlinkRequest { path: path.into() }))
            .await?
            .into_inner()
            .target)
    }

    fn parse_auth_token(
        daemon_token: impl AsRef<str>,
    ) -> Result<MetadataValue<tonic::metadata::Ascii>, DaemonClientError> {
        let daemon_token = daemon_token.as_ref().trim();
        if daemon_token.is_empty() {
            return Err(DaemonClientError::InvalidCredential);
        }
        let mut auth_token = MetadataValue::try_from(daemon_token)
            .map_err(|_| DaemonClientError::InvalidCredential)?;
        auth_token.set_sensitive(true);
        Ok(auth_token)
    }

    fn authorized<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, self.auth_token.clone());
        request
    }
}

impl DaemonRunSession {
    pub async fn send_input(&self, input: DaemonRunInput) -> Result<(), DaemonClientError> {
        match self {
            Self::Exec { input: tx, .. } => {
                let payload = match input {
                    DaemonRunInput::Stdin(data) => v1::exec_message::Payload::Stdin(data),
                    DaemonRunInput::CloseStdin => v1::exec_message::Payload::CloseStdin(()),
                    DaemonRunInput::Resize { .. } => return Ok(()),
                };
                tx.send(v1::ExecMessage {
                    payload: Some(payload),
                })
                .await
                .map_err(|_| DaemonClientError::RequestClosed)
            }
            Self::Pty { input: tx, .. } => {
                let payload = match input {
                    DaemonRunInput::Stdin(data) => v1::pty_message::Payload::Stdin(data),
                    DaemonRunInput::Resize { columns, rows } => {
                        v1::pty_message::Payload::Resize(v1::ResizeRequest {
                            width: columns,
                            height: rows,
                        })
                    }
                    DaemonRunInput::CloseStdin => v1::pty_message::Payload::CloseStdin(()),
                };
                tx.send(v1::PtyMessage {
                    payload: Some(payload),
                })
                .await
                .map_err(|_| DaemonClientError::RequestClosed)
            }
        }
    }

    pub async fn next_output(&mut self) -> Result<Option<DaemonRunOutput>, DaemonClientError> {
        match self {
            Self::Exec { output, .. } => {
                let Some(message) = output.message().await? else {
                    return Ok(None);
                };
                match message.payload {
                    Some(v1::exec_message::Payload::Stdout(data)) => {
                        Ok(Some(DaemonRunOutput::Stdout(data)))
                    }
                    Some(v1::exec_message::Payload::Stderr(data)) => {
                        Ok(Some(DaemonRunOutput::Stderr(data)))
                    }
                    Some(v1::exec_message::Payload::Exit(exit)) => {
                        Ok(Some(DaemonRunOutput::Exit(exit.code)))
                    }
                    Some(v1::exec_message::Payload::Error(error)) => {
                        Err(DaemonClientError::Remote(error))
                    }
                    _ => Err(DaemonClientError::InvalidFrame("exec output")),
                }
            }
            Self::Pty { output, .. } => {
                let Some(message) = output.message().await? else {
                    return Ok(None);
                };
                match message.payload {
                    Some(v1::pty_message::Payload::Stdout(data)) => {
                        Ok(Some(DaemonRunOutput::Stdout(data)))
                    }
                    Some(v1::pty_message::Payload::Stderr(data)) => {
                        Ok(Some(DaemonRunOutput::Stderr(data)))
                    }
                    Some(v1::pty_message::Payload::Exit(exit)) => {
                        Ok(Some(DaemonRunOutput::Exit(exit.code)))
                    }
                    Some(v1::pty_message::Payload::Error(error)) => {
                        Err(DaemonClientError::Remote(error))
                    }
                    _ => Err(DaemonClientError::InvalidFrame("PTY output")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use codewire_gateway_proto::{DAEMON_CAPABILITY_EXEC, DAEMON_CAPABILITY_FILES};

    use super::*;
    use crate::test_support::DaemonHarness;

    #[tokio::test]
    async fn typed_client_preserves_exec_frames_and_file_operations() {
        let harness = DaemonHarness::spawn().await;
        let client = harness.client().await;
        client
            .require_ready(&[DAEMON_CAPABILITY_EXEC, DAEMON_CAPABILITY_FILES])
            .await
            .expect("daemon capabilities");
        let file_path = harness.workspace_root().join("client.bin");
        let file_path = file_path.to_string_lossy().into_owned();
        let workspace = harness.workspace_root().to_string_lossy().into_owned();

        client
            .open_file(v1::OpenFileRequest {
                path: file_path.clone(),
                options: Some(v1::FileOpenOptions {
                    write: true,
                    create: true,
                    truncate: true,
                    exclusive: true,
                    ..Default::default()
                }),
                perm: 0o600,
            })
            .await
            .expect("open file");
        assert_eq!(
            client
                .write_file(v1::WriteRequest {
                    path: file_path.clone(),
                    offset: 0,
                    data: vec![0xff, 0x00, b'x'],
                })
                .await
                .expect("write file"),
            3
        );
        assert_eq!(
            client
                .read_file(v1::ReadRequest {
                    path: file_path.clone(),
                    offset: 0,
                    length: 3,
                })
                .await
                .expect("read file"),
            vec![0xff, 0x00, b'x']
        );
        assert_eq!(
            client
                .stat_file(&file_path, false)
                .await
                .expect("stat file")
                .size,
            3
        );
        assert!(
            client
                .list_files(&workspace)
                .await
                .expect("list workspace")
                .iter()
                .any(|entry| entry.name == "client.bin")
        );

        let mut session = client
            .start_run(DaemonRunStart {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "read line; printf 'out:%s' \"$line\"; printf '\\377err' >&2; exit 17".into(),
                ],
                working_dir: harness.workspace_root().to_string_lossy().into_owned(),
                env: Vec::new(),
                allocate_tty: false,
                term: String::new(),
                columns: 0,
                rows: 0,
            })
            .await
            .expect("start exec");
        session
            .send_input(DaemonRunInput::Stdin(b"pipe\n".to_vec()))
            .await
            .expect("send stdin");
        session
            .send_input(DaemonRunInput::CloseStdin)
            .await
            .expect("close stdin");

        let (stdout, stderr, exit) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                match session.next_output().await.expect("exec output") {
                    Some(DaemonRunOutput::Stdout(data)) => stdout.extend(data),
                    Some(DaemonRunOutput::Stderr(data)) => stderr.extend(data),
                    Some(DaemonRunOutput::Exit(code)) => break (stdout, stderr, code),
                    None => panic!("exec ended without an exit frame"),
                }
            }
        })
        .await
        .expect("exec deadline");
        assert_eq!(stdout, b"out:pipe");
        assert_eq!(stderr, b"\xfferr");
        assert_eq!(exit, 17);

        drop(session);
        let mut session = client
            .start_run(DaemonRunStart {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "read ready; stty size; printf '%s' \"$TERM\"; exit 23".into(),
                ],
                working_dir: workspace,
                env: Vec::new(),
                allocate_tty: true,
                term: "xterm-256color".into(),
                columns: 80,
                rows: 24,
            })
            .await
            .expect("start PTY");
        session
            .send_input(DaemonRunInput::Resize {
                columns: 111,
                rows: 37,
            })
            .await
            .expect("resize PTY");
        session
            .send_input(DaemonRunInput::Stdin(b"go\n".to_vec()))
            .await
            .expect("release PTY command");

        let (output, exit) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut output = Vec::new();
            loop {
                match session.next_output().await.expect("PTY output") {
                    Some(DaemonRunOutput::Stdout(data)) => output.extend(data),
                    Some(DaemonRunOutput::Stderr(data)) => {
                        panic!("unexpected PTY stderr: {data:?}")
                    }
                    Some(DaemonRunOutput::Exit(code)) => break (output, code),
                    None => panic!("PTY ended without an exit frame"),
                }
            }
        })
        .await
        .expect("PTY deadline");
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("37 111"), "PTY output = {output:?}");
        assert!(output.contains("xterm-256color"), "PTY output = {output:?}");
        assert_eq!(exit, 23);

        drop(session);
        drop(client);
        harness.shutdown().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dropping_output_after_stdin_half_close_cancels_the_remote_process() {
        let harness = DaemonHarness::spawn().await;
        let client = harness.client().await;
        let mut session = client
            .start_run(DaemonRunStart {
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf '%s\\n' $$; exec sleep 30".into(),
                ],
                working_dir: harness.workspace_root().to_string_lossy().into_owned(),
                env: Vec::new(),
                allocate_tty: false,
                term: String::new(),
                columns: 0,
                rows: 0,
            })
            .await
            .expect("start cancellable exec");
        session
            .send_input(DaemonRunInput::CloseStdin)
            .await
            .expect("half-close cancellable exec");

        let pid = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stdout = Vec::new();
            loop {
                match session.next_output().await.expect("cancellable output") {
                    Some(DaemonRunOutput::Stdout(data)) => {
                        stdout.extend(data);
                        if stdout.contains(&b'\n') {
                            return String::from_utf8(stdout)
                                .expect("ASCII process id")
                                .trim()
                                .parse::<u32>()
                                .expect("numeric process id");
                        }
                    }
                    Some(DaemonRunOutput::Stderr(data)) => {
                        panic!("unexpected cancellable stderr: {data:?}")
                    }
                    Some(DaemonRunOutput::Exit(code)) => {
                        panic!("cancellable process exited early with {code}")
                    }
                    None => panic!("cancellable stream ended before process id"),
                }
            }
        })
        .await
        .expect("cancellable process id deadline");
        let process = std::path::PathBuf::from(format!("/proc/{pid}"));
        assert!(process.exists(), "remote process was never observable");

        drop(session);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while process.exists() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !process.exists(),
            "remote process survived client cancellation"
        );

        drop(client);
        harness.shutdown().await;
    }
}
