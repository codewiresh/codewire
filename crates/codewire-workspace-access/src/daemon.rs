use async_trait::async_trait;
use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::{DAEMON_AUTH_TOKEN_HEADER, DaemonAuthToken};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Channel;

mod forward;
pub use forward::DaemonForwardDialer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStart {
    pub command: Vec<String>,
    pub working_dir: String,
    pub env: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyStart {
    pub command: Vec<String>,
    pub working_dir: String,
    pub env: Vec<String>,
    pub term: String,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOpenOptions {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub create: bool,
    pub truncate: bool,
    pub exclusive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSetStatRequest {
    pub path: String,
    pub size: Option<i64>,
    pub mode: Option<u32>,
    pub access_time: Option<prost_types::Timestamp>,
    pub mod_time: Option<prost_types::Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecSessionInput {
    Stdin(Vec<u8>),
    CloseStdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtySessionInput {
    Stdin(Vec<u8>),
    Resize { width: i32, height: i32 },
    CloseStdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonSessionOutput {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(i32),
    Error(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonClientError {
    #[error("invalid daemon endpoint {endpoint}: {source}")]
    InvalidEndpoint {
        endpoint: String,
        source: http::uri::InvalidUri,
    },
    #[error("connect daemon {endpoint}: {source}")]
    Connect {
        endpoint: String,
        source: tonic::transport::Error,
    },
    #[error("daemon session stream failed: {0}")]
    Status(#[from] tonic::Status),
    #[error("daemon session request stream is closed")]
    RequestClosed,
    #[error("daemon {0} session ended before an exit frame")]
    UnexpectedEof(&'static str),
    #[error("daemon returned an invalid {0} frame")]
    InvalidFrame(&'static str),
    #[error("{0}")]
    Unsupported(&'static str),
}

#[async_trait]
pub trait DaemonClient: Send + Sync {
    async fn exec_session(
        &self,
        start: SessionStart,
    ) -> Result<ExecDaemonSession, DaemonClientError>;
    async fn pty_session(&self, start: PtyStart) -> Result<PtyDaemonSession, DaemonClientError>;
    async fn list(&self, path: &str) -> Result<Vec<v1::FileMetadata>, DaemonClientError>;
    async fn stat(
        &self,
        path: &str,
        follow: bool,
    ) -> Result<Option<v1::FileMetadata>, DaemonClientError>;
    async fn open_file(
        &self,
        path: &str,
        options: FileOpenOptions,
        perm: u32,
    ) -> Result<(), DaemonClientError>;
    async fn read_at(
        &self,
        path: &str,
        offset: i64,
        length: i64,
    ) -> Result<Vec<u8>, DaemonClientError>;
    async fn write_at(
        &self,
        path: &str,
        offset: i64,
        data: Vec<u8>,
    ) -> Result<i64, DaemonClientError>;
    async fn mkdir(&self, path: &str, perm: u32) -> Result<(), DaemonClientError>;
    async fn remove(&self, path: &str, dir: bool) -> Result<(), DaemonClientError>;
    async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), DaemonClientError>;
    async fn set_stat(&self, request: FileSetStatRequest) -> Result<(), DaemonClientError>;
    async fn readlink(&self, path: &str) -> Result<String, DaemonClientError>;
}

/// Workspace access's client for its daemon. Each call presents the bound
/// Pod's daemon credential.
#[derive(Clone)]
pub struct DaemonSessionClient {
    inner: v1::daemon_service_client::DaemonServiceClient<Channel>,
    channel: Channel,
    credential: DaemonAuthToken,
}

pub struct ExecDaemonSession {
    input: mpsc::Sender<v1::ExecMessage>,
    output: tonic::Streaming<v1::ExecMessage>,
}

pub struct PtyDaemonSession {
    input: mpsc::Sender<v1::PtyMessage>,
    output: tonic::Streaming<v1::PtyMessage>,
}

#[derive(Clone)]
pub struct ExecDaemonSessionInput {
    input: mpsc::Sender<v1::ExecMessage>,
}

#[derive(Clone)]
pub struct PtyDaemonSessionInput {
    input: mpsc::Sender<v1::PtyMessage>,
}

impl DaemonSessionClient {
    pub async fn connect_endpoint(
        endpoint: String,
        credential: DaemonAuthToken,
    ) -> Result<Self, DaemonClientError> {
        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|source| DaemonClientError::InvalidEndpoint {
                endpoint: endpoint.clone(),
                source,
            })?
            .connect()
            .await
            .map_err(|source| DaemonClientError::Connect {
                endpoint: endpoint.clone(),
                source,
            })?;
        Ok(Self {
            inner: v1::daemon_service_client::DaemonServiceClient::new(channel.clone()),
            channel,
            credential,
        })
    }

    /// A client of this process's own daemon over its in-process transport
    /// (#2460): workspace access served by the daemon itself. No network
    /// connection is made; per-RPC authorization still presents
    /// `credential`.
    pub async fn connect_local(
        connector: codewire_daemon::local_transport::LocalDaemonConnector,
        credential: DaemonAuthToken,
    ) -> Result<Self, DaemonClientError> {
        const LOCAL_ENDPOINT: &str = "http://codewire-daemon.local";
        let channel = tonic::transport::Endpoint::from_static(LOCAL_ENDPOINT)
            .connect_with_connector(tower::service_fn(move |_| {
                let connector = connector.clone();
                async move { connector.connect().await.map(hyper_util::rt::TokioIo::new) }
            }))
            .await
            .map_err(|source| DaemonClientError::Connect {
                endpoint: LOCAL_ENDPOINT.to_owned(),
                source,
            })?;
        Ok(Self::from_channel(channel, credential))
    }

    /// A client over an already connected daemon channel: a local VM's
    /// supervisor reaches its guest daemon over hybrid vsock (#3025).
    pub fn from_channel(channel: Channel, credential: DaemonAuthToken) -> Self {
        Self {
            inner: v1::daemon_service_client::DaemonServiceClient::new(channel.clone()),
            channel,
            credential,
        }
    }

    /// A credential-bridge client presenting this client's credential.
    pub fn credential_client(&self) -> codewire_daemon::client::SessionClient {
        codewire_daemon::client::SessionClient::from_channel(
            self.channel.clone(),
            self.credential.expose_secret(),
        )
        .expect("DaemonAuthToken guarantees valid ASCII metadata")
    }

    /// The daemon's capabilities and default shell, for this client's
    /// protocol.
    pub async fn capabilities(&self) -> Result<v1::GetCapabilitiesResponse, DaemonClientError> {
        let mut request = Request::new(v1::GetCapabilitiesRequest {
            protocol_version: codewire_daemon::client::DAEMON_PROTOCOL_VERSION,
            ..Default::default()
        });
        self.authorize(&mut request);
        Ok(self
            .inner
            .clone()
            .get_capabilities(request)
            .await
            .map_err(|status| self.refused(status))?
            .into_inner())
    }

    fn authorize<T>(&self, request: &mut Request<T>) {
        let mut value = MetadataValue::<Ascii>::try_from(self.credential.expose_secret())
            .expect("DaemonAuthToken guarantees valid ASCII metadata");
        value.set_sensitive(true);
        request
            .metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, value);
    }

    fn refused(&self, status: tonic::Status) -> DaemonClientError {
        DaemonClientError::Status(status)
    }
}

#[async_trait]
impl DaemonClient for DaemonSessionClient {
    async fn exec_session(
        &self,
        start: SessionStart,
    ) -> Result<ExecDaemonSession, DaemonClientError> {
        let (input, rx) = mpsc::channel(32);
        input
            .send(exec_start_message(start))
            .await
            .map_err(|_| DaemonClientError::RequestClosed)?;

        let mut client = self.inner.clone();
        let mut request = Request::new(ReceiverStream::new(rx));
        self.authorize(&mut request);
        let output = client
            .exec_session(request)
            .await
            .map_err(|status| self.refused(status))?
            .into_inner();
        Ok(ExecDaemonSession { input, output })
    }

    async fn pty_session(&self, start: PtyStart) -> Result<PtyDaemonSession, DaemonClientError> {
        let (input, rx) = mpsc::channel(32);
        input
            .send(pty_start_message(start))
            .await
            .map_err(|_| DaemonClientError::RequestClosed)?;

        let mut client = self.inner.clone();
        let mut request = Request::new(ReceiverStream::new(rx));
        self.authorize(&mut request);
        let output = client
            .pty_session(request)
            .await
            .map_err(|status| self.refused(status))?
            .into_inner();
        Ok(PtyDaemonSession { input, output })
    }

    async fn list(&self, path: &str) -> Result<Vec<v1::FileMetadata>, DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::ListRequest { path: path.into() });
        self.authorize(&mut request);
        let response = client
            .list(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(response.into_inner().entries)
    }

    async fn stat(
        &self,
        path: &str,
        follow: bool,
    ) -> Result<Option<v1::FileMetadata>, DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::StatRequest {
            path: path.into(),
            follow,
        });
        self.authorize(&mut request);
        let response = match client.stat(request).await {
            Ok(response) => response,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Ok(None);
            }
            Err(status) => return Err(self.refused(status)),
        };
        Ok(response.into_inner().entry)
    }

    async fn open_file(
        &self,
        path: &str,
        options: FileOpenOptions,
        perm: u32,
    ) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::OpenFileRequest {
            path: path.into(),
            options: Some(file_open_options(options)),
            perm,
        });
        self.authorize(&mut request);
        client
            .open_file(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(())
    }

    async fn read_at(
        &self,
        path: &str,
        offset: i64,
        length: i64,
    ) -> Result<Vec<u8>, DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::ReadRequest {
            path: path.into(),
            offset,
            length,
        });
        self.authorize(&mut request);
        let response = client
            .read(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(response.into_inner().data)
    }

    async fn write_at(
        &self,
        path: &str,
        offset: i64,
        data: Vec<u8>,
    ) -> Result<i64, DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::WriteRequest {
            path: path.into(),
            offset,
            data,
        });
        self.authorize(&mut request);
        let response = client
            .write(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(response.into_inner().bytes_written)
    }

    async fn mkdir(&self, path: &str, perm: u32) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::MkdirRequest {
            path: path.into(),
            perm,
        });
        self.authorize(&mut request);
        client
            .mkdir(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(())
    }

    async fn remove(&self, path: &str, dir: bool) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::RemoveRequest {
            path: path.into(),
            dir,
        });
        self.authorize(&mut request);
        client
            .remove(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(())
    }

    async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::RenameRequest {
            old_path: old_path.into(),
            new_path: new_path.into(),
        });
        self.authorize(&mut request);
        client
            .rename(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(())
    }

    async fn set_stat(&self, request: FileSetStatRequest) -> Result<(), DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(file_set_stat_request(request));
        self.authorize(&mut request);
        client
            .set_stat(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(())
    }

    async fn readlink(&self, path: &str) -> Result<String, DaemonClientError> {
        let mut client = self.inner.clone();
        let mut request = Request::new(v1::ReadlinkRequest { path: path.into() });
        self.authorize(&mut request);
        let response = client
            .readlink(request)
            .await
            .map_err(|status| self.refused(status))?;
        Ok(response.into_inner().target)
    }
}

impl ExecDaemonSession {
    pub fn input_handle(&self) -> ExecDaemonSessionInput {
        ExecDaemonSessionInput {
            input: self.input.clone(),
        }
    }

    pub async fn send_input(&self, input: ExecSessionInput) -> Result<(), DaemonClientError> {
        self.input_handle().send_input(input).await
    }

    pub async fn next_output(&mut self) -> Result<Option<DaemonSessionOutput>, DaemonClientError> {
        let message = self
            .output
            .message()
            .await?
            .ok_or(DaemonClientError::UnexpectedEof("exec"))?;
        exec_output_from_message(message).map(Some)
    }
}

impl PtyDaemonSession {
    pub fn input_handle(&self) -> PtyDaemonSessionInput {
        PtyDaemonSessionInput {
            input: self.input.clone(),
        }
    }

    pub async fn send_input(&self, input: PtySessionInput) -> Result<(), DaemonClientError> {
        self.input_handle().send_input(input).await
    }

    pub async fn next_output(&mut self) -> Result<Option<DaemonSessionOutput>, DaemonClientError> {
        let message = self
            .output
            .message()
            .await?
            .ok_or(DaemonClientError::UnexpectedEof("PTY"))?;
        pty_output_from_message(message).map(Some)
    }
}

impl ExecDaemonSessionInput {
    pub async fn send_input(&self, input: ExecSessionInput) -> Result<(), DaemonClientError> {
        self.input
            .send(exec_input_message(input))
            .await
            .map_err(|_| DaemonClientError::RequestClosed)
    }
}

impl PtyDaemonSessionInput {
    pub async fn send_input(&self, input: PtySessionInput) -> Result<(), DaemonClientError> {
        self.input
            .send(pty_input_message(input))
            .await
            .map_err(|_| DaemonClientError::RequestClosed)
    }
}

pub fn exec_start_message(start: SessionStart) -> v1::ExecMessage {
    v1::ExecMessage {
        payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
            command: start.command,
            working_dir: start.working_dir,
            env: start.env,
        })),
    }
}

pub fn pty_start_message(start: PtyStart) -> v1::PtyMessage {
    v1::PtyMessage {
        payload: Some(v1::pty_message::Payload::Start(v1::PtyStartRequest {
            command: start.command,
            working_dir: start.working_dir,
            env: start.env,
            term: start.term,
            width: start.width,
            height: start.height,
        })),
    }
}

pub fn exec_input_message(input: ExecSessionInput) -> v1::ExecMessage {
    match input {
        ExecSessionInput::Stdin(data) => v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::Stdin(data)),
        },
        ExecSessionInput::CloseStdin => v1::ExecMessage {
            payload: Some(v1::exec_message::Payload::CloseStdin(())),
        },
    }
}

pub fn pty_input_message(input: PtySessionInput) -> v1::PtyMessage {
    match input {
        PtySessionInput::Stdin(data) => v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Stdin(data)),
        },
        PtySessionInput::Resize { width, height } => v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::Resize(v1::ResizeRequest {
                width,
                height,
            })),
        },
        PtySessionInput::CloseStdin => v1::PtyMessage {
            payload: Some(v1::pty_message::Payload::CloseStdin(())),
        },
    }
}

pub fn exec_output_from_message(
    message: v1::ExecMessage,
) -> Result<DaemonSessionOutput, DaemonClientError> {
    match message.payload {
        Some(v1::exec_message::Payload::Stdout(data)) => Ok(DaemonSessionOutput::Stdout(data)),
        Some(v1::exec_message::Payload::Stderr(data)) => Ok(DaemonSessionOutput::Stderr(data)),
        Some(v1::exec_message::Payload::Exit(exit)) => Ok(DaemonSessionOutput::Exit(exit.code)),
        Some(v1::exec_message::Payload::Error(error)) => Ok(DaemonSessionOutput::Error(error)),
        Some(
            v1::exec_message::Payload::Start(_)
            | v1::exec_message::Payload::Stdin(_)
            | v1::exec_message::Payload::CloseStdin(()),
        )
        | None => Err(DaemonClientError::InvalidFrame("exec session output")),
    }
}

pub fn pty_output_from_message(
    message: v1::PtyMessage,
) -> Result<DaemonSessionOutput, DaemonClientError> {
    match message.payload {
        Some(v1::pty_message::Payload::Stdout(data)) => Ok(DaemonSessionOutput::Stdout(data)),
        Some(v1::pty_message::Payload::Stderr(data)) => Ok(DaemonSessionOutput::Stderr(data)),
        Some(v1::pty_message::Payload::Exit(exit)) => Ok(DaemonSessionOutput::Exit(exit.code)),
        Some(v1::pty_message::Payload::Error(error)) => Ok(DaemonSessionOutput::Error(error)),
        Some(
            v1::pty_message::Payload::Start(_)
            | v1::pty_message::Payload::Stdin(_)
            | v1::pty_message::Payload::Resize(_)
            | v1::pty_message::Payload::CloseStdin(()),
        )
        | None => Err(DaemonClientError::InvalidFrame("PTY session output")),
    }
}

pub fn file_open_options(options: FileOpenOptions) -> v1::FileOpenOptions {
    v1::FileOpenOptions {
        read: options.read,
        write: options.write,
        append: options.append,
        create: options.create,
        truncate: options.truncate,
        exclusive: options.exclusive,
    }
}

pub fn file_set_stat_request(request: FileSetStatRequest) -> v1::SetStatRequest {
    v1::SetStatRequest {
        path: request.path,
        size: request.size,
        mode: request.mode,
        access_time: request.access_time,
        mod_time: request.mod_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_daemon_proto::DaemonAuthToken;
    use codewire_daemon_proto::codewire::bridge::v1 as bridge_v1;
    use codewire_daemon_proto::daemon::v1::daemon_service_server::{
        DaemonService, DaemonServiceServer,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio::time::{Duration, sleep, timeout};
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    #[test]
    fn exec_start_maps_to_daemon_proto() {
        let msg = exec_start_message(SessionStart {
            command: vec!["/bin/sh".into(), "-lc".into(), "echo hi".into()],
            working_dir: "/workspace".into(),
            env: vec!["A=B".into()],
        });

        let Some(v1::exec_message::Payload::Start(start)) = msg.payload else {
            panic!("missing exec start payload");
        };
        assert_eq!(start.command, ["/bin/sh", "-lc", "echo hi"]);
        assert_eq!(start.working_dir, "/workspace");
        assert_eq!(start.env, ["A=B"]);
    }

    #[test]
    fn pty_start_maps_to_daemon_proto() {
        let msg = pty_start_message(PtyStart {
            command: vec!["bash".into()],
            working_dir: "/home/codewire".into(),
            env: vec!["TERM=xterm-256color".into()],
            term: "xterm-256color".into(),
            width: 120,
            height: 40,
        });

        let Some(v1::pty_message::Payload::Start(start)) = msg.payload else {
            panic!("missing pty start payload");
        };
        assert_eq!(start.command, ["bash"]);
        assert_eq!(start.working_dir, "/home/codewire");
        assert_eq!(start.env, ["TERM=xterm-256color"]);
        assert_eq!(start.term, "xterm-256color");
        assert_eq!(start.width, 120);
        assert_eq!(start.height, 40);
    }

    #[test]
    fn exec_input_maps_to_daemon_proto() {
        let msg = exec_input_message(ExecSessionInput::Stdin(b"hello".to_vec()));
        assert_eq!(
            msg.payload,
            Some(v1::exec_message::Payload::Stdin(b"hello".to_vec()))
        );

        let msg = exec_input_message(ExecSessionInput::CloseStdin);
        assert_eq!(msg.payload, Some(v1::exec_message::Payload::CloseStdin(())));
    }

    #[test]
    fn pty_input_maps_to_daemon_proto() {
        let msg = pty_input_message(PtySessionInput::Stdin(b"hello".to_vec()));
        assert_eq!(
            msg.payload,
            Some(v1::pty_message::Payload::Stdin(b"hello".to_vec()))
        );

        let msg = pty_input_message(PtySessionInput::Resize {
            width: 120,
            height: 40,
        });
        assert_eq!(
            msg.payload,
            Some(v1::pty_message::Payload::Resize(v1::ResizeRequest {
                width: 120,
                height: 40,
            }))
        );

        let msg = pty_input_message(PtySessionInput::CloseStdin);
        assert_eq!(msg.payload, Some(v1::pty_message::Payload::CloseStdin(())));
    }

    #[test]
    fn exec_output_maps_from_daemon_proto() {
        assert_eq!(
            exec_output_from_message(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Stdout(b"out".to_vec())),
            })
            .expect("valid exec stdout"),
            DaemonSessionOutput::Stdout(b"out".to_vec())
        );
        assert_eq!(
            exec_output_from_message(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Stderr(b"err".to_vec())),
            })
            .expect("valid exec stderr"),
            DaemonSessionOutput::Stderr(b"err".to_vec())
        );
        assert_eq!(
            exec_output_from_message(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Exit(v1::ExitStatus { code: 7 })),
            })
            .expect("valid exec exit"),
            DaemonSessionOutput::Exit(7)
        );
        assert_eq!(
            exec_output_from_message(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Error("boom".into())),
            })
            .expect("valid exec error"),
            DaemonSessionOutput::Error("boom".into())
        );
        assert!(matches!(
            exec_output_from_message(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::CloseStdin(())),
            }),
            Err(DaemonClientError::InvalidFrame("exec session output"))
        ));
    }

    #[test]
    fn pty_output_maps_from_daemon_proto() {
        assert_eq!(
            pty_output_from_message(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Stdout(b"out".to_vec())),
            })
            .expect("valid PTY stdout"),
            DaemonSessionOutput::Stdout(b"out".to_vec())
        );
        assert_eq!(
            pty_output_from_message(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Stderr(b"err".to_vec())),
            })
            .expect("valid PTY stderr"),
            DaemonSessionOutput::Stderr(b"err".to_vec())
        );
        assert_eq!(
            pty_output_from_message(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Exit(v1::ExitStatus { code: 7 })),
            })
            .expect("valid PTY exit"),
            DaemonSessionOutput::Exit(7)
        );
        assert_eq!(
            pty_output_from_message(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Error("boom".into())),
            })
            .expect("valid PTY error"),
            DaemonSessionOutput::Error("boom".into())
        );
        assert!(matches!(
            pty_output_from_message(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Resize(v1::ResizeRequest {
                    width: 80,
                    height: 24,
                })),
            }),
            Err(DaemonClientError::InvalidFrame("PTY session output"))
        ));
    }

    #[test]
    fn file_open_options_maps_to_daemon_proto() {
        let options = file_open_options(FileOpenOptions {
            read: true,
            write: true,
            append: false,
            create: true,
            truncate: true,
            exclusive: false,
        });
        assert!(options.read);
        assert!(options.write);
        assert!(!options.append);
        assert!(options.create);
        assert!(options.truncate);
        assert!(!options.exclusive);
    }

    #[test]
    fn file_set_stat_maps_to_daemon_proto() {
        let request = file_set_stat_request(FileSetStatRequest {
            path: "/workspace/file".into(),
            size: Some(123),
            mode: Some(0o644),
            access_time: Some(prost_types::Timestamp {
                seconds: 10,
                nanos: 20,
            }),
            mod_time: Some(prost_types::Timestamp {
                seconds: 30,
                nanos: 40,
            }),
        });

        assert_eq!(request.path, "/workspace/file");
        assert_eq!(request.size, Some(123));
        assert_eq!(request.mode, Some(0o644));
        assert_eq!(
            request.access_time,
            Some(prost_types::Timestamp {
                seconds: 10,
                nanos: 20,
            })
        );
        assert_eq!(
            request.mod_time,
            Some(prost_types::Timestamp {
                seconds: 30,
                nanos: 40,
            })
        );
    }

    #[tokio::test]
    async fn grpc_file_rpcs_round_trip_daemon_requests() {
        let daemon = RecordingDaemon::default();
        let addr = spawn_recording_daemon(daemon.clone()).await;
        let client = DaemonSessionClient::connect_endpoint(
            format!("http://{addr}"),
            DaemonAuthToken::new("gateway-daemon-test-token").unwrap(),
        )
        .await
        .unwrap();

        let entries = client.list("/workspace").await.unwrap();
        assert_eq!(entries[0].name, "file.txt");

        let stat = client
            .stat("/workspace/file.txt", true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stat.path, "/workspace/file.txt");
        assert!(
            client
                .stat("/workspace/missing", false)
                .await
                .unwrap()
                .is_none()
        );

        client
            .open_file(
                "/workspace/file.txt",
                FileOpenOptions {
                    read: true,
                    write: true,
                    append: false,
                    create: true,
                    truncate: false,
                    exclusive: false,
                },
                0o644,
            )
            .await
            .unwrap();
        assert_eq!(
            client.read_at("/workspace/file.txt", 4, 8).await.unwrap(),
            b"read-data"
        );
        assert_eq!(
            client
                .write_at("/workspace/file.txt", 12, b"write-data".to_vec())
                .await
                .unwrap(),
            10
        );
        client.mkdir("/workspace/dir", 0o755).await.unwrap();
        client.remove("/workspace/dir", true).await.unwrap();
        client
            .rename("/workspace/old", "/workspace/new")
            .await
            .unwrap();
        client
            .set_stat(FileSetStatRequest {
                path: "/workspace/file.txt".into(),
                size: Some(42),
                mode: Some(0o600),
                access_time: Some(prost_types::Timestamp {
                    seconds: 100,
                    nanos: 200,
                }),
                mod_time: Some(prost_types::Timestamp {
                    seconds: 300,
                    nanos: 400,
                }),
            })
            .await
            .unwrap();
        assert_eq!(
            client.readlink("/workspace/link").await.unwrap(),
            "/workspace/target"
        );

        let requests = daemon.file_requests.lock().await.clone();
        assert_eq!(
            requests.list,
            [v1::ListRequest {
                path: "/workspace".into()
            }]
        );
        assert_eq!(
            requests.stat,
            [
                v1::StatRequest {
                    path: "/workspace/file.txt".into(),
                    follow: true,
                },
                v1::StatRequest {
                    path: "/workspace/missing".into(),
                    follow: false,
                },
            ]
        );
        assert_eq!(
            requests.open_file,
            [v1::OpenFileRequest {
                path: "/workspace/file.txt".into(),
                options: Some(v1::FileOpenOptions {
                    read: true,
                    write: true,
                    append: false,
                    create: true,
                    truncate: false,
                    exclusive: false,
                }),
                perm: 0o644,
            }]
        );
        assert_eq!(
            requests.read,
            [v1::ReadRequest {
                path: "/workspace/file.txt".into(),
                offset: 4,
                length: 8,
            }]
        );
        assert_eq!(
            requests.write,
            [v1::WriteRequest {
                path: "/workspace/file.txt".into(),
                offset: 12,
                data: b"write-data".to_vec(),
            }]
        );
        assert_eq!(
            requests.mkdir,
            [v1::MkdirRequest {
                path: "/workspace/dir".into(),
                perm: 0o755,
            }]
        );
        assert_eq!(
            requests.remove,
            [v1::RemoveRequest {
                path: "/workspace/dir".into(),
                dir: true,
            }]
        );
        assert_eq!(
            requests.rename,
            [v1::RenameRequest {
                old_path: "/workspace/old".into(),
                new_path: "/workspace/new".into(),
            }]
        );
        assert_eq!(
            requests.set_stat,
            [v1::SetStatRequest {
                path: "/workspace/file.txt".into(),
                size: Some(42),
                mode: Some(0o600),
                access_time: Some(prost_types::Timestamp {
                    seconds: 100,
                    nanos: 200,
                }),
                mod_time: Some(prost_types::Timestamp {
                    seconds: 300,
                    nanos: 400,
                }),
            }]
        );
        assert_eq!(
            requests.readlink,
            [v1::ReadlinkRequest {
                path: "/workspace/link".into(),
            }]
        );
    }

    #[tokio::test]
    async fn grpc_exec_session_round_trips_daemon_frames() {
        let daemon = RecordingDaemon::default();
        let addr = spawn_recording_daemon(daemon.clone()).await;
        let client = DaemonSessionClient::connect_endpoint(
            format!("http://{addr}"),
            DaemonAuthToken::new("gateway-daemon-test-token").unwrap(),
        )
        .await
        .unwrap();

        let mut session = client
            .exec_session(SessionStart {
                command: vec!["/bin/sh".into(), "-lc".into(), "echo hi".into()],
                working_dir: "/workspace".into(),
                env: vec!["A=B".into()],
            })
            .await
            .unwrap();
        session
            .send_input(ExecSessionInput::Stdin(b"stdin".to_vec()))
            .await
            .unwrap();
        session
            .send_input(ExecSessionInput::CloseStdin)
            .await
            .unwrap();

        assert_eq!(
            session.next_output().await.unwrap(),
            Some(DaemonSessionOutput::Stdout(b"exec-out".to_vec()))
        );
        assert_eq!(
            session.next_output().await.unwrap(),
            Some(DaemonSessionOutput::Exit(0))
        );

        let frames = daemon.wait_for_exec_frames(3).await;
        let Some(v1::exec_message::Payload::Start(start)) = frames[0].payload.clone() else {
            panic!("missing exec start frame");
        };
        assert_eq!(start.command, ["/bin/sh", "-lc", "echo hi"]);
        assert_eq!(start.working_dir, "/workspace");
        assert_eq!(start.env, ["A=B"]);
        assert_eq!(
            frames[1].payload,
            Some(v1::exec_message::Payload::Stdin(b"stdin".to_vec()))
        );
        assert_eq!(
            frames[2].payload,
            Some(v1::exec_message::Payload::CloseStdin(()))
        );
    }

    #[tokio::test]
    async fn grpc_pty_session_round_trips_daemon_frames() {
        let daemon = RecordingDaemon::default();
        let addr = spawn_recording_daemon(daemon.clone()).await;
        let client = DaemonSessionClient::connect_endpoint(
            format!("http://{addr}"),
            DaemonAuthToken::new("gateway-daemon-test-token").unwrap(),
        )
        .await
        .unwrap();

        let mut session = client
            .pty_session(PtyStart {
                command: vec!["bash".into()],
                working_dir: "/workspace".into(),
                env: vec!["A=B".into()],
                term: "xterm-256color".into(),
                width: 120,
                height: 40,
            })
            .await
            .unwrap();
        session
            .send_input(PtySessionInput::Stdin(b"stdin".to_vec()))
            .await
            .unwrap();
        session
            .send_input(PtySessionInput::Resize {
                width: 80,
                height: 24,
            })
            .await
            .unwrap();
        session
            .send_input(PtySessionInput::CloseStdin)
            .await
            .unwrap();

        assert_eq!(
            session.next_output().await.unwrap(),
            Some(DaemonSessionOutput::Stdout(b"pty-out".to_vec()))
        );
        assert_eq!(
            session.next_output().await.unwrap(),
            Some(DaemonSessionOutput::Exit(0))
        );

        let frames = daemon.wait_for_pty_frames(4).await;
        let Some(v1::pty_message::Payload::Start(start)) = frames[0].payload.clone() else {
            panic!("missing pty start frame");
        };
        assert_eq!(start.command, ["bash"]);
        assert_eq!(start.working_dir, "/workspace");
        assert_eq!(start.env, ["A=B"]);
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
    }

    /// A runtime with one worker, which [`stall`] can hold up.
    fn one_worker_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    /// Hold up every task on a one-worker runtime, its HTTP/2 connection
    /// included, until the returned sender is dropped: as a busy host delays
    /// one side of a session while the other keeps sending.
    fn stall(runtime: &tokio::runtime::Runtime) -> std::sync::mpsc::Sender<()> {
        let (stalled, held) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel::<()>();
        runtime.spawn(async move {
            let _ = stalled.send(());
            // Blocks the only worker on purpose.
            let _ = resumed.recv();
        });
        held.recv().unwrap();
        resume
    }

    /// Small terminal frames: one byte each, as a shell echoes keystrokes.
    const SMALL_FRAMES: usize = 400;

    fn small_frame(index: usize) -> Vec<u8> {
        vec![b'a' + (index % 26) as u8]
    }

    fn pty_start() -> PtyStart {
        PtyStart {
            command: vec!["sh".into()],
            working_dir: String::new(),
            env: Vec::new(),
            term: String::new(),
            width: 80,
            height: 24,
        }
    }

    /// Output the client has not read yet, a byte per frame, waits for it
    /// while the client's side is held up: the connection is kept and every
    /// byte arrives in order (#3688). Unread small DATA frames count against
    /// HTTP/2's flood guard, which once allowed only about a hundred.
    #[test]
    fn small_output_frames_queued_behind_a_busy_client_keep_the_session() {
        let server = one_worker_runtime();
        let client = one_worker_runtime();
        let daemon = RecordingDaemon {
            hold_pty_output: true,
            ..Default::default()
        };
        let addr = server.block_on(spawn_recording_daemon(daemon.clone()));
        let mut session = client.block_on(async {
            DaemonSessionClient::connect_endpoint(
                format!("http://{addr}"),
                DaemonAuthToken::new("gateway-daemon-test-token").unwrap(),
            )
            .await
            .unwrap()
            .pty_session(pty_start())
            .await
            .unwrap()
        });
        let output = server.block_on(daemon.held_pty_output());

        let held = stall(&client);
        server.block_on(async {
            let messages = (0..SMALL_FRAMES)
                .map(|index| v1::pty_message::Payload::Stdout(small_frame(index)))
                .chain([v1::pty_message::Payload::Exit(v1::ExitStatus { code: 0 })]);
            for payload in messages {
                output
                    .send(Ok(v1::PtyMessage {
                        payload: Some(payload),
                    }))
                    .await
                    .unwrap();
                // Each message leaves as its own DATA frame once the
                // server has taken it.
                while output.capacity() < output.max_capacity() {
                    sleep(Duration::from_millis(1)).await;
                }
            }
            sleep(Duration::from_millis(200)).await;
        });
        drop(held);

        // The reader shares the client's one worker with its connection, as
        // a busy client's tasks wait their turn.
        let reader = client.spawn(async move {
            timeout(Duration::from_secs(20), async {
                let mut stdout = Vec::new();
                loop {
                    match session.next_output().await {
                        Ok(Some(DaemonSessionOutput::Stdout(data))) => stdout.extend(data),
                        Ok(Some(DaemonSessionOutput::Exit(code))) => return (stdout, Ok(code)),
                        other => return (stdout, Err(format!("{other:?}"))),
                    }
                }
            })
            .await
            .expect("the session ended")
        });
        let (stdout, exit) = client.block_on(reader).unwrap();
        let expected: Vec<u8> = (0..SMALL_FRAMES).flat_map(small_frame).collect();
        assert_eq!(
            exit,
            Ok(0),
            "after {} of {} bytes",
            stdout.len(),
            expected.len()
        );
        assert!(stdout == expected, "the output arrived changed");
    }

    /// Input the daemon has not read yet, a byte per frame as keystrokes are
    /// typed, waits for it while the daemon's side is held up: the
    /// connection is kept and every byte arrives in order (#3688).
    #[test]
    fn small_input_frames_queued_behind_a_busy_daemon_keep_the_session() {
        let server = one_worker_runtime();
        let client = one_worker_runtime();
        let daemon = RecordingDaemon {
            hold_pty_output: true,
            ..Default::default()
        };
        let addr = server.block_on(spawn_recording_daemon(daemon.clone()));
        let session = client.block_on(async {
            DaemonSessionClient::connect_endpoint(
                format!("http://{addr}"),
                DaemonAuthToken::new("gateway-daemon-test-token").unwrap(),
            )
            .await
            .unwrap()
            .pty_session(pty_start())
            .await
            .unwrap()
        });
        let _output = server.block_on(daemon.held_pty_output());
        server.block_on(daemon.wait_for_pty_frames(1));

        let held = stall(&server);
        client.block_on(async {
            for index in 0..SMALL_FRAMES {
                session
                    .send_input(PtySessionInput::Stdin(small_frame(index)))
                    .await
                    .unwrap();
                // Typed one at a time, each leaves as its own DATA frame.
                sleep(Duration::from_millis(1)).await;
            }
            sleep(Duration::from_millis(200)).await;
        });
        drop(held);

        let frames = server.block_on(daemon.wait_for_pty_frames(1 + SMALL_FRAMES));
        let stdin: Vec<u8> = frames[1..]
            .iter()
            .flat_map(|frame| match &frame.payload {
                Some(v1::pty_message::Payload::Stdin(data)) => data.clone(),
                other => panic!("unexpected input frame {other:?}"),
            })
            .collect();
        let expected: Vec<u8> = (0..SMALL_FRAMES).flat_map(small_frame).collect();
        assert!(stdin == expected, "the input arrived changed");
    }

    #[tokio::test]
    async fn grpc_sessions_reject_eof_without_an_exit_frame() {
        let daemon = RecordingDaemon {
            close_exec_before_exit: true,
            close_pty_before_exit: true,
            ..Default::default()
        };
        let addr = spawn_recording_daemon(daemon).await;
        let client = DaemonSessionClient::connect_endpoint(
            format!("http://{addr}"),
            DaemonAuthToken::new("gateway-daemon-test-token").unwrap(),
        )
        .await
        .unwrap();

        let mut exec = client
            .exec_session(SessionStart {
                command: vec!["true".into()],
                working_dir: String::new(),
                env: Vec::new(),
            })
            .await
            .unwrap();
        assert!(matches!(
            exec.next_output().await,
            Ok(Some(DaemonSessionOutput::Stdout(_)))
        ));
        assert!(matches!(
            exec.next_output().await,
            Err(DaemonClientError::UnexpectedEof("exec"))
        ));

        let mut pty = client
            .pty_session(PtyStart {
                command: vec!["sh".into()],
                working_dir: String::new(),
                env: Vec::new(),
                term: String::new(),
                width: 0,
                height: 0,
            })
            .await
            .unwrap();
        assert!(matches!(
            pty.next_output().await,
            Ok(Some(DaemonSessionOutput::Stdout(_)))
        ));
        assert!(matches!(
            pty.next_output().await,
            Err(DaemonClientError::UnexpectedEof("PTY"))
        ));
    }

    #[derive(Clone, Default)]
    struct RecordingDaemon {
        exec_frames: Arc<Mutex<Vec<v1::ExecMessage>>>,
        pty_frames: Arc<Mutex<Vec<v1::PtyMessage>>>,
        file_requests: Arc<Mutex<RecordingFileRequests>>,
        close_exec_before_exit: bool,
        close_pty_before_exit: bool,
        /// Hand the PTY session's output to the test instead of answering
        /// at once.
        hold_pty_output: bool,
        held_pty_output: Arc<std::sync::Mutex<Option<PtyOutputSender>>>,
    }

    type PtyOutputSender = tokio::sync::mpsc::Sender<Result<v1::PtyMessage, Status>>;

    #[derive(Clone, Default)]
    struct RecordingFileRequests {
        list: Vec<v1::ListRequest>,
        stat: Vec<v1::StatRequest>,
        open_file: Vec<v1::OpenFileRequest>,
        read: Vec<v1::ReadRequest>,
        write: Vec<v1::WriteRequest>,
        mkdir: Vec<v1::MkdirRequest>,
        remove: Vec<v1::RemoveRequest>,
        rename: Vec<v1::RenameRequest>,
        set_stat: Vec<v1::SetStatRequest>,
        readlink: Vec<v1::ReadlinkRequest>,
    }

    impl RecordingDaemon {
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
            .expect("exec frames")
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
            .expect("pty frames")
        }

        /// The output of the PTY session a `hold_pty_output` daemon opened.
        async fn held_pty_output(&self) -> PtyOutputSender {
            timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(output) = self.held_pty_output.lock().unwrap().clone() {
                        return output;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("held pty output")
        }
    }

    async fn spawn_recording_daemon(daemon: RecordingDaemon) -> SocketAddr {
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
    impl DaemonService for RecordingDaemon {
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
        type ForwardTcpStream = ReceiverStream<Result<v1::ForwardTcpMessage, Status>>;
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
            tokio::spawn(async move {
                while let Ok(Some(message)) = inbound.message().await {
                    frames.lock().await.push(message);
                }
            });

            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tx.send(Ok(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Stdout(b"exec-out".to_vec())),
            }))
            .await
            .unwrap();
            if !self.close_exec_before_exit {
                tx.send(Ok(v1::ExecMessage {
                    payload: Some(v1::exec_message::Payload::Exit(v1::ExitStatus { code: 0 })),
                }))
                .await
                .unwrap();
            }
            Ok(Response::new(ReceiverStream::new(rx)))
        }

        async fn forward_tcp(
            &self,
            _request: Request<tonic::Streaming<v1::ForwardTcpMessage>>,
        ) -> Result<Response<Self::ForwardTcpStream>, Status> {
            Err(Status::unimplemented("forward tcp"))
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
            tokio::spawn(async move {
                while let Ok(Some(message)) = inbound.message().await {
                    frames.lock().await.push(message);
                }
            });

            let (tx, rx) = tokio::sync::mpsc::channel(4);
            if self.hold_pty_output {
                *self.held_pty_output.lock().unwrap() = Some(tx);
                return Ok(Response::new(ReceiverStream::new(rx)));
            }
            tx.send(Ok(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Stdout(b"pty-out".to_vec())),
            }))
            .await
            .unwrap();
            if !self.close_pty_before_exit {
                tx.send(Ok(v1::PtyMessage {
                    payload: Some(v1::pty_message::Payload::Exit(v1::ExitStatus { code: 0 })),
                }))
                .await
                .unwrap();
            }
            Ok(Response::new(ReceiverStream::new(rx)))
        }

        async fn list(
            &self,
            request: Request<v1::ListRequest>,
        ) -> Result<Response<v1::ListResponse>, Status> {
            self.file_requests
                .lock()
                .await
                .list
                .push(request.into_inner());
            Ok(Response::new(v1::ListResponse {
                entries: vec![v1::FileMetadata {
                    name: "file.txt".into(),
                    path: "/workspace/file.txt".into(),
                    size: 9,
                    mode: 0o100644,
                    mod_time: Some(prost_types::Timestamp {
                        seconds: 1,
                        nanos: 0,
                    }),
                    link_target: String::new(),
                }],
            }))
        }

        async fn stat(
            &self,
            request: Request<v1::StatRequest>,
        ) -> Result<Response<v1::StatResponse>, Status> {
            let request = request.into_inner();
            if request.path == "/workspace/missing" {
                self.file_requests.lock().await.stat.push(request);
                return Err(Status::not_found("missing"));
            }
            self.file_requests.lock().await.stat.push(request);
            Ok(Response::new(v1::StatResponse {
                entry: Some(v1::FileMetadata {
                    name: "file.txt".into(),
                    path: "/workspace/file.txt".into(),
                    size: 9,
                    mode: 0o100644,
                    mod_time: None,
                    link_target: String::new(),
                }),
            }))
        }

        async fn open_file(
            &self,
            request: Request<v1::OpenFileRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            self.file_requests
                .lock()
                .await
                .open_file
                .push(request.into_inner());
            Ok(Response::new(v1::OperationStatus {
                status: "ok".into(),
            }))
        }

        async fn read(
            &self,
            request: Request<v1::ReadRequest>,
        ) -> Result<Response<v1::ReadResponse>, Status> {
            self.file_requests
                .lock()
                .await
                .read
                .push(request.into_inner());
            Ok(Response::new(v1::ReadResponse {
                data: b"read-data".to_vec(),
            }))
        }

        async fn write(
            &self,
            request: Request<v1::WriteRequest>,
        ) -> Result<Response<v1::WriteResponse>, Status> {
            let request = request.into_inner();
            let bytes_written = request.data.len() as i64;
            self.file_requests.lock().await.write.push(request);
            Ok(Response::new(v1::WriteResponse { bytes_written }))
        }

        async fn mkdir(
            &self,
            request: Request<v1::MkdirRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            self.file_requests
                .lock()
                .await
                .mkdir
                .push(request.into_inner());
            Ok(Response::new(v1::OperationStatus {
                status: "ok".into(),
            }))
        }

        async fn remove(
            &self,
            request: Request<v1::RemoveRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            self.file_requests
                .lock()
                .await
                .remove
                .push(request.into_inner());
            Ok(Response::new(v1::OperationStatus {
                status: "ok".into(),
            }))
        }

        async fn rename(
            &self,
            request: Request<v1::RenameRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            self.file_requests
                .lock()
                .await
                .rename
                .push(request.into_inner());
            Ok(Response::new(v1::OperationStatus {
                status: "ok".into(),
            }))
        }

        async fn set_stat(
            &self,
            request: Request<v1::SetStatRequest>,
        ) -> Result<Response<v1::OperationStatus>, Status> {
            self.file_requests
                .lock()
                .await
                .set_stat
                .push(request.into_inner());
            Ok(Response::new(v1::OperationStatus {
                status: "ok".into(),
            }))
        }

        async fn readlink(
            &self,
            request: Request<v1::ReadlinkRequest>,
        ) -> Result<Response<v1::ReadlinkResponse>, Status> {
            self.file_requests
                .lock()
                .await
                .readlink
                .push(request.into_inner());
            Ok(Response::new(v1::ReadlinkResponse {
                target: "/workspace/target".into(),
            }))
        }
    }
}
