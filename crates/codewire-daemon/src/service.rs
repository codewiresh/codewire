use std::collections::BTreeSet;
use std::time::Duration;

use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::daemon::v1::daemon_service_server::DaemonService;
use codewire_gateway_proto::{
    DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITIES, DAEMON_CAPABILITY_CREDENTIAL_BRIDGE,
    DAEMON_MINIMUM_PROTOCOL_VERSION, DAEMON_PROTOCOL_VERSION,
};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::credential_bridge::CredentialBridge;
use crate::durable_session::{SessionEngine, status_from_session_error};
use crate::{Config, files, session};

const ATTACH_SESSION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct DaemonServiceImpl {
    config: Config,
    runtime_state: DaemonRuntimeState,
    session_engine: SessionEngine,
    credential_bridge: CredentialBridge,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DaemonRuntimeState {
    state: v1::DaemonState,
    message: String,
    diagnostics: Vec<v1::HealthDiagnostic>,
}

impl DaemonRuntimeState {
    pub fn new(
        state: v1::DaemonState,
        message: impl Into<String>,
        diagnostics: Vec<v1::HealthDiagnostic>,
    ) -> Self {
        Self {
            state,
            message: message.into(),
            diagnostics,
        }
    }

    pub fn ready() -> Self {
        Self::new(v1::DaemonState::Ready, "daemon ready", Vec::new())
    }
}

impl DaemonServiceImpl {
    pub fn new(config: Config) -> Self {
        Self::with_runtime_state(config, DaemonRuntimeState::ready())
    }

    pub fn with_runtime_state(config: Config, runtime_state: DaemonRuntimeState) -> Self {
        Self {
            session_engine: SessionEngine::new(&config),
            credential_bridge: CredentialBridge::new(config.credential_bridge.clone()),
            config,
            runtime_state,
        }
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let expected = self.config.auth_token.expose_secret();
        let Some(actual) = request
            .metadata()
            .get(DAEMON_AUTH_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
        else {
            return Err(Status::unauthenticated("missing daemon auth token"));
        };
        if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(Status::unauthenticated("invalid daemon auth token"));
        }
        Ok(())
    }

    pub(crate) fn credential_bridge(&self) -> CredentialBridge {
        self.credential_bridge.clone()
    }
}

#[tonic::async_trait]
impl DaemonService for DaemonServiceImpl {
    type ExecSessionStream = ReceiverStream<Result<v1::ExecMessage, Status>>;
    type PtySessionStream = ReceiverStream<Result<v1::PtyMessage, Status>>;
    type AttachSessionStream = ReceiverStream<Result<v1::SessionAttachMessage, Status>>;
    type CredentialBridgeStream = ReceiverStream<Result<v1::CredentialBridgeGuestMessage, Status>>;

    async fn get_capabilities(
        &self,
        request: Request<v1::GetCapabilitiesRequest>,
    ) -> Result<Response<v1::GetCapabilitiesResponse>, Status> {
        self.authorize(&request)?;
        Ok(Response::new(self.capabilities(request.into_inner())))
    }

    async fn get_health(
        &self,
        request: Request<v1::GetHealthRequest>,
    ) -> Result<Response<v1::GetHealthResponse>, Status> {
        self.authorize(&request)?;
        Ok(Response::new(v1::GetHealthResponse {
            state: self.runtime_state.state as i32,
            message: self.runtime_state.message.clone(),
            diagnostics: self.runtime_state.diagnostics.clone(),
        }))
    }

    async fn credential_bridge(
        &self,
        request: Request<Streaming<v1::CredentialBridgeHostMessage>>,
    ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
        self.authorize(&request)?;
        let connection = self.credential_bridge.connect(request.into_inner()).await?;
        Ok(Response::new(connection.output))
    }

    async fn launch_session(
        &self,
        request: Request<v1::LaunchSessionRequest>,
    ) -> Result<Response<v1::LaunchSessionResponse>, Status> {
        self.authorize(&request)?;
        let session = self
            .session_engine
            .launch(request.into_inner())
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(v1::LaunchSessionResponse {
            session: Some(session),
        }))
    }

    async fn list_sessions(
        &self,
        request: Request<v1::ListSessionsRequest>,
    ) -> Result<Response<v1::ListSessionsResponse>, Status> {
        self.authorize(&request)?;
        let sessions = self
            .session_engine
            .list()
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(v1::ListSessionsResponse { sessions }))
    }

    async fn get_session(
        &self,
        request: Request<v1::GetSessionRequest>,
    ) -> Result<Response<v1::GetSessionResponse>, Status> {
        self.authorize(&request)?;
        let session = self
            .session_engine
            .get(&request.into_inner().session_id)
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(v1::GetSessionResponse {
            session: Some(session),
        }))
    }

    async fn stop_session(
        &self,
        request: Request<v1::StopSessionRequest>,
    ) -> Result<Response<v1::StopSessionResponse>, Status> {
        self.authorize(&request)?;
        let session = self
            .session_engine
            .stop(&request.into_inner().session_id)
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(v1::StopSessionResponse {
            session: Some(session),
        }))
    }

    async fn restart_session(
        &self,
        request: Request<v1::RestartSessionRequest>,
    ) -> Result<Response<v1::RestartSessionResponse>, Status> {
        self.authorize(&request)?;
        let session = self
            .session_engine
            .restart(&request.into_inner().session_id)
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(v1::RestartSessionResponse {
            session: Some(session),
        }))
    }

    async fn read_session_output(
        &self,
        request: Request<v1::ReadSessionOutputRequest>,
    ) -> Result<Response<v1::ReadSessionOutputResponse>, Status> {
        self.authorize(&request)?;
        let output = self
            .session_engine
            .read_output(request.into_inner())
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(output))
    }

    async fn attach_session(
        &self,
        request: Request<Streaming<v1::SessionAttachMessage>>,
    ) -> Result<Response<Self::AttachSessionStream>, Status> {
        self.authorize(&request)?;
        let mut stream = request.into_inner();
        let attach = match stream
            .message()
            .await
            .map_err(|error| {
                Status::invalid_argument(format!("read attach start message: {error}"))
            })?
            .and_then(|message| message.payload)
        {
            Some(v1::session_attach_message::Payload::Attach(attach)) => attach,
            _ => return Err(Status::invalid_argument("attach start message is required")),
        };
        self.session_engine
            .get(&attach.session_id)
            .await
            .map_err(status_from_session_error)?;
        self.session_engine
            .read_output(v1::ReadSessionOutputRequest {
                session_id: attach.session_id.clone(),
                offset: attach.output_offset,
                limit: 1,
            })
            .await
            .map_err(status_from_session_error)?;

        let (tx, rx) = mpsc::channel(32);
        let engine = self.session_engine.clone();
        tokio::spawn(async move {
            run_attach_session(engine, stream, attach, tx).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn exec_session(
        &self,
        request: Request<Streaming<v1::ExecMessage>>,
    ) -> Result<Response<Self::ExecSessionStream>, Status> {
        self.authorize(&request)?;
        let mut stream = request.into_inner();
        let start = match stream
            .message()
            .await
            .map_err(|err| Status::invalid_argument(format!("read exec start message: {err}")))?
            .and_then(|msg| msg.payload)
        {
            Some(v1::exec_message::Payload::Start(start)) => start,
            _ => return Err(Status::invalid_argument("exec start message is required")),
        };

        Ok(Response::new(session::exec_session(
            self.config.clone(),
            stream,
            start,
        )))
    }

    async fn pty_session(
        &self,
        request: Request<Streaming<v1::PtyMessage>>,
    ) -> Result<Response<Self::PtySessionStream>, Status> {
        self.authorize(&request)?;
        let mut stream = request.into_inner();
        let start = match stream
            .message()
            .await
            .map_err(|err| Status::invalid_argument(format!("read pty start message: {err}")))?
            .and_then(|msg| msg.payload)
        {
            Some(v1::pty_message::Payload::Start(start)) => start,
            _ => return Err(Status::invalid_argument("pty start message is required")),
        };

        Ok(Response::new(session::pty_session(
            self.config.clone(),
            stream,
            start,
        )))
    }

    async fn list(
        &self,
        request: Request<v1::ListRequest>,
    ) -> Result<Response<v1::ListResponse>, Status> {
        self.authorize(&request)?;
        let entries = files::list(&self.config, &request.into_inner().path)
            .map_err(status_from_file_error)?;
        Ok(Response::new(v1::ListResponse { entries }))
    }

    async fn stat(
        &self,
        request: Request<v1::StatRequest>,
    ) -> Result<Response<v1::StatResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let entry = files::stat(&self.config, &request.path, request.follow)
            .map_err(status_from_file_error)?;
        Ok(Response::new(v1::StatResponse { entry: Some(entry) }))
    }

    async fn open_file(
        &self,
        request: Request<v1::OpenFileRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        files::open_file(
            &self.config,
            &request.path,
            request.options.as_ref(),
            request.perm,
        )
        .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn read(
        &self,
        request: Request<v1::ReadRequest>,
    ) -> Result<Response<v1::ReadResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let data = files::read(&self.config, &request.path, request.offset, request.length)
            .map_err(status_from_file_error)?;
        Ok(Response::new(v1::ReadResponse { data }))
    }

    async fn write(
        &self,
        request: Request<v1::WriteRequest>,
    ) -> Result<Response<v1::WriteResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let bytes_written =
            files::write(&self.config, &request.path, request.offset, &request.data)
                .map_err(status_from_file_error)?;
        Ok(Response::new(v1::WriteResponse { bytes_written }))
    }

    async fn mkdir(
        &self,
        request: Request<v1::MkdirRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        files::mkdir(&self.config, &request.path, request.perm).map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn remove(
        &self,
        request: Request<v1::RemoveRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        let _ = request.dir;
        files::remove(&self.config, &request.path).map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn rename(
        &self,
        request: Request<v1::RenameRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        files::rename(&self.config, &request.old_path, &request.new_path)
            .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn set_stat(
        &self,
        request: Request<v1::SetStatRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        validate_timestamp(request.access_time.as_ref())?;
        validate_timestamp(request.mod_time.as_ref())?;
        files::set_stat(&self.config, &request).map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn readlink(
        &self,
        request: Request<v1::ReadlinkRequest>,
    ) -> Result<Response<v1::ReadlinkResponse>, Status> {
        self.authorize(&request)?;
        let target = files::readlink(&self.config, &request.into_inner().path)
            .map_err(status_from_file_error)?;
        Ok(Response::new(v1::ReadlinkResponse { target }))
    }
}

async fn run_attach_session(
    engine: SessionEngine,
    mut incoming: Streaming<v1::SessionAttachMessage>,
    attach: v1::AttachSessionRequest,
    tx: mpsc::Sender<Result<v1::SessionAttachMessage, Status>>,
) {
    let session_id = attach.session_id;
    let mut cursor = attach.output_offset;
    let mut last_status = None;
    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + ATTACH_SESSION_HEARTBEAT_INTERVAL,
        ATTACH_SESSION_HEARTBEAT_INTERVAL,
    );
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let output = match engine
            .read_output(v1::ReadSessionOutputRequest {
                session_id: session_id.clone(),
                offset: cursor,
                limit: 0,
            })
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let _ = tx.send(Err(status_from_session_error(error))).await;
                return;
            }
        };
        for chunk in output.chunks {
            if tx
                .send(Ok(v1::SessionAttachMessage {
                    payload: Some(v1::session_attach_message::Payload::Output(chunk)),
                }))
                .await
                .is_err()
            {
                return;
            }
        }
        cursor = output.next_offset;

        let record = match engine.get(&session_id).await {
            Ok(record) => record,
            Err(error) => {
                let _ = tx.send(Err(status_from_session_error(error))).await;
                return;
            }
        };
        if cursor < record.output_end_offset {
            continue;
        }
        let status = session_status(&record, None);
        if last_status.as_ref() != Some(&status) {
            if tx
                .send(Ok(v1::SessionAttachMessage {
                    payload: Some(v1::session_attach_message::Payload::Status(status.clone())),
                }))
                .await
                .is_err()
            {
                return;
            }
            last_status = Some(status);
            heartbeat.reset();
        }
        if !is_attached_session_live(record.state) {
            return;
        }

        tokio::select! {
            message = incoming.message() => {
                match message {
                    Ok(Some(message)) => match message.payload {
                        Some(v1::session_attach_message::Payload::Input(input)) => {
                            if let Err(error) = engine.input(&session_id, input.data).await {
                                let _ = tx.send(Err(status_from_session_error(error))).await;
                                return;
                            }
                        }
                        Some(v1::session_attach_message::Payload::Resize(resize)) => {
                            match engine.resize(&session_id, resize.width, resize.height).await {
                                Ok(record) => {
                                    let status = session_status(&record, None);
                                    if tx
                                        .send(Ok(v1::SessionAttachMessage {
                                            payload: Some(
                                                v1::session_attach_message::Payload::Status(
                                                    status.clone(),
                                                ),
                                            ),
                                        }))
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                    last_status = Some(status);
                                }
                                Err(error) => {
                                    let _ = tx.send(Err(status_from_session_error(error))).await;
                                    return;
                                }
                            }
                        }
                        Some(v1::session_attach_message::Payload::Detach(detach)) => {
                            if detach.session_id != session_id {
                                let _ = tx
                                    .send(Err(Status::invalid_argument(
                                        "detach session identifier does not match attached session",
                                    )))
                                    .await;
                                return;
                            }
                            match engine.get(&session_id).await {
                                Ok(record) => {
                                    let status = session_status(
                                        &record,
                                        Some("client detached; session remains running"),
                                    );
                                    let _ = tx
                                        .send(Ok(v1::SessionAttachMessage {
                                            payload: Some(
                                                v1::session_attach_message::Payload::Status(status),
                                            ),
                                        }))
                                        .await;
                                }
                                Err(error) => {
                                    let _ = tx.send(Err(status_from_session_error(error))).await;
                                }
                            }
                            return;
                        }
                        Some(v1::session_attach_message::Payload::Attach(_)) => {
                            let _ = tx
                                .send(Err(Status::invalid_argument(
                                    "attach stream already has a session",
                                )))
                                .await;
                            return;
                        }
                        Some(v1::session_attach_message::Payload::Output(_))
                        | Some(v1::session_attach_message::Payload::Status(_))
                        | None => {
                            let _ = tx
                                .send(Err(Status::invalid_argument(
                                    "attach stream contains a server-only or empty message",
                                )))
                                .await;
                            return;
                        }
                    },
                    Ok(None) | Err(_) => return,
                }
            }
            _ = heartbeat.tick() => {
                let status = session_status(&record, None);
                if tx
                    .send(Ok(v1::SessionAttachMessage {
                        payload: Some(v1::session_attach_message::Payload::Status(
                            status.clone(),
                        )),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                last_status = Some(status);
            }
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
}

fn session_status(record: &v1::SessionRecord, message: Option<&str>) -> v1::SessionStatus {
    v1::SessionStatus {
        session_id: record.session_id.clone(),
        state: record.state,
        exit_code: record.exit_code,
        output_end_offset: record.output_end_offset,
        message: message.unwrap_or(&record.status_message).into(),
    }
}

fn is_attached_session_live(state: i32) -> bool {
    matches!(
        v1::SessionLifecycleState::try_from(state),
        Ok(v1::SessionLifecycleState::Starting
            | v1::SessionLifecycleState::Running
            | v1::SessionLifecycleState::Stopping)
    )
}

impl DaemonServiceImpl {
    fn capabilities(&self, request: v1::GetCapabilitiesRequest) -> v1::GetCapabilitiesResponse {
        let supported = DAEMON_CAPABILITIES
            .iter()
            .copied()
            .chain(
                self.credential_bridge
                    .is_enabled()
                    .then_some(DAEMON_CAPABILITY_CREDENTIAL_BRIDGE),
            )
            .map(str::to_owned)
            .collect::<Vec<_>>();

        let (state, message) = if request.protocol_version > DAEMON_PROTOCOL_VERSION {
            (
                v1::DaemonState::UpgradeRequired,
                format!(
                    "daemon protocol {DAEMON_PROTOCOL_VERSION} does not support requested protocol {}; upgrade the environment daemon",
                    request.protocol_version
                ),
            )
        } else if request.protocol_version != 0
            && request.protocol_version < DAEMON_MINIMUM_PROTOCOL_VERSION
        {
            (
                v1::DaemonState::UpgradeRequired,
                format!(
                    "client protocol {} is older than minimum protocol {DAEMON_MINIMUM_PROTOCOL_VERSION}; upgrade cw",
                    request.protocol_version
                ),
            )
        } else {
            let supported_set = supported
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let missing = request
                .required_capabilities
                .iter()
                .filter(|capability| !supported_set.contains(capability.as_str()))
                .cloned()
                .collect::<BTreeSet<_>>();
            if missing.is_empty() {
                (self.runtime_state.state, self.runtime_state.message.clone())
            } else {
                (
                    v1::DaemonState::Unsupported,
                    format!(
                        "daemon does not support required capabilities: {}",
                        missing.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                )
            }
        };

        v1::GetCapabilitiesResponse {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            minimum_protocol_version: DAEMON_MINIMUM_PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            capabilities: supported,
            state: state as i32,
            message,
        }
    }
}

fn ok_status() -> v1::OperationStatus {
    v1::OperationStatus {
        status: "ok".into(),
    }
}

pub fn status_from_file_error(err: files::FileError) -> Status {
    match err {
        files::FileError::PathOutsideWorkspace
        | files::FileError::InvalidPath
        | files::FileError::NotRegularFile
        | files::FileError::NotSymlink
        | files::FileError::InvalidOffset
        | files::FileError::InvalidLength
        | files::FileError::InvalidSize
        | files::FileError::IsDirectory => Status::invalid_argument(err.to_string()),
        files::FileError::TraversalDenied => Status::permission_denied(err.to_string()),
        files::FileError::UntrustedRoot => Status::failed_precondition(err.to_string()),
        files::FileError::Io(err) => match err.kind() {
            std::io::ErrorKind::NotFound => Status::not_found(err.to_string()),
            std::io::ErrorKind::PermissionDenied => Status::permission_denied(err.to_string()),
            std::io::ErrorKind::AlreadyExists => Status::already_exists(err.to_string()),
            std::io::ErrorKind::InvalidInput => Status::invalid_argument(err.to_string()),
            _ => Status::internal(err.to_string()),
        },
    }
}

fn validate_timestamp(timestamp: Option<&prost_types::Timestamp>) -> Result<(), Status> {
    if let Some(timestamp) = timestamp
        && (timestamp.nanos < 0 || timestamp.nanos >= 1_000_000_000)
    {
        return Err(Status::invalid_argument("invalid timestamp nanos"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_gateway_proto::daemon::v1::daemon_service_client::DaemonServiceClient;
    use codewire_gateway_proto::{DAEMON_AUTH_TOKEN_HEADER, DaemonAuthToken};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{Duration, sleep};
    use tokio_stream::{
        iter,
        wrappers::{ReceiverStream, TcpListenerStream},
    };
    use tonic::metadata::{Ascii, MetadataValue};
    use tonic::service::Interceptor;
    use tonic::service::interceptor::InterceptedService;
    use tonic::transport::Channel;

    const TEST_AUTH_TOKEN: &str = "daemon-service-test-token";

    #[derive(Clone)]
    struct TestAuthInterceptor {
        token: MetadataValue<Ascii>,
    }

    impl Interceptor for TestAuthInterceptor {
        fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
            request
                .metadata_mut()
                .insert(DAEMON_AUTH_TOKEN_HEADER, self.token.clone());
            Ok(request)
        }
    }

    type TestClient = DaemonServiceClient<InterceptedService<Channel, TestAuthInterceptor>>;

    async fn authenticated_client(addr: SocketAddr) -> TestClient {
        let channel = Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .expect("connect daemon");
        DaemonServiceClient::with_interceptor(
            channel,
            TestAuthInterceptor {
                token: TEST_AUTH_TOKEN.parse().unwrap(),
            },
        )
    }

    #[tokio::test]
    async fn exec_session_streams_stdout_stderr_and_exit() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;

        let request = iter([
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                    command: vec![
                        "sh".into(),
                        "-c".into(),
                        "printf hello; printf world >&2; exit 7".into(),
                    ],
                    ..Default::default()
                })),
            },
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::CloseStdin(())),
            },
        ]);
        let mut stream = client
            .exec_session(request)
            .await
            .expect("exec session")
            .into_inner();

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit = None;
        while let Some(message) = stream.message().await.expect("exec message") {
            match message.payload {
                Some(v1::exec_message::Payload::Stdout(data)) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(v1::exec_message::Payload::Stderr(data)) => {
                    stderr.push_str(&String::from_utf8_lossy(&data));
                }
                Some(v1::exec_message::Payload::Exit(status)) => {
                    exit = Some(status.code);
                    break;
                }
                Some(v1::exec_message::Payload::Error(error)) => panic!("exec error: {error}"),
                _ => {}
            }
        }

        assert_eq!(stdout, "hello");
        assert_eq!(stderr, "world");
        assert_eq!(exit, Some(7));
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn exec_session_forwards_stdin_and_close() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;

        let request = iter([
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                    command: vec!["sh".into(), "-c".into(), "cat".into()],
                    ..Default::default()
                })),
            },
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Stdin(b"stdin-ok".to_vec())),
            },
            v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::CloseStdin(())),
            },
        ]);
        let mut stream = client
            .exec_session(request)
            .await
            .expect("exec session")
            .into_inner();

        let mut stdout = String::new();
        while let Some(message) = stream.message().await.expect("exec message") {
            match message.payload {
                Some(v1::exec_message::Payload::Stdout(data)) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(v1::exec_message::Payload::Exit(_)) => break,
                Some(v1::exec_message::Payload::Error(error)) => panic!("exec error: {error}"),
                _ => {}
            }
        }

        assert_eq!(stdout, "stdin-ok");
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn pty_session_uses_requested_term() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;

        let request = iter([
            v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Start(v1::PtyStartRequest {
                    command: vec!["sh".into(), "-lc".into(), "printf \"$TERM\"".into()],
                    term: "xterm-256color".into(),
                    width: 120,
                    height: 40,
                    ..Default::default()
                })),
            },
            v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Resize(v1::ResizeRequest {
                    width: 100,
                    height: 30,
                })),
            },
            v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::CloseStdin(())),
            },
        ]);
        let mut stream = client
            .pty_session(request)
            .await
            .expect("pty session")
            .into_inner();

        let mut stdout = String::new();
        while let Some(message) = stream.message().await.expect("pty message") {
            match message.payload {
                Some(v1::pty_message::Payload::Stdout(data)) => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                Some(v1::pty_message::Payload::Exit(_)) => break,
                Some(v1::pty_message::Payload::Error(error)) => panic!("pty error: {error}"),
                _ => {}
            }
        }

        assert!(stdout.contains("xterm-256color"), "stdout = {stdout:?}");
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn exec_transport_loss_terminates_remote_process() {
        let (temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;
        let workspace = temp.path().join("workspace");
        let pid_file = workspace.join("exec.pid");
        let (input, rx) = mpsc::channel(4);
        input
            .send(v1::ExecMessage {
                payload: Some(v1::exec_message::Payload::Start(v1::ExecStartRequest {
                    command: vec![
                        "sh".into(),
                        "-c".into(),
                        "echo $$ > exec.pid; exec sleep 300".into(),
                    ],
                    working_dir: workspace.to_string_lossy().into_owned(),
                    ..Default::default()
                })),
            })
            .await
            .expect("send exec start");
        let output = client
            .exec_session(ReceiverStream::new(rx))
            .await
            .expect("exec session")
            .into_inner();
        let pid = wait_for_pid(&pid_file).await;

        drop(input);
        drop(output);
        wait_for_process_exit(pid).await;
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn pty_transport_loss_terminates_remote_process() {
        let (temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;
        let workspace = temp.path().join("workspace");
        let pid_file = workspace.join("pty.pid");
        let (input, rx) = mpsc::channel(4);
        input
            .send(v1::PtyMessage {
                payload: Some(v1::pty_message::Payload::Start(v1::PtyStartRequest {
                    command: vec![
                        "sh".into(),
                        "-c".into(),
                        "echo $$ > pty.pid; exec sleep 300".into(),
                    ],
                    working_dir: workspace.to_string_lossy().into_owned(),
                    term: "xterm-256color".into(),
                    width: 80,
                    height: 24,
                    ..Default::default()
                })),
            })
            .await
            .expect("send PTY start");
        let output = client
            .pty_session(ReceiverStream::new(rx))
            .await
            .expect("PTY session")
            .into_inner();
        let pid = wait_for_pid(&pid_file).await;

        drop(input);
        drop(output);
        wait_for_process_exit(pid).await;
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn file_rpcs_cover_lifecycle_and_path_rejection() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;

        client
            .open_file(v1::OpenFileRequest {
                path: "hello.txt".into(),
                options: Some(v1::FileOpenOptions {
                    write: true,
                    create: true,
                    truncate: true,
                    ..Default::default()
                }),
                perm: 0o644,
            })
            .await
            .expect("open");
        let written = client
            .write(v1::WriteRequest {
                path: "hello.txt".into(),
                offset: 0,
                data: b"hello world".to_vec(),
            })
            .await
            .expect("write")
            .into_inner();
        assert_eq!(written.bytes_written, 11);

        let read = client
            .read(v1::ReadRequest {
                path: "hello.txt".into(),
                offset: 6,
                length: 5,
            })
            .await
            .expect("read")
            .into_inner();
        assert_eq!(read.data, b"world");

        let stat = client
            .stat(v1::StatRequest {
                path: "hello.txt".into(),
                follow: false,
            })
            .await
            .expect("stat")
            .into_inner()
            .entry
            .expect("entry");
        assert_eq!(stat.size, 11);
        assert_eq!(stat.mode & 0o777, 0o644);

        let list = client
            .list(v1::ListRequest { path: "".into() })
            .await
            .expect("list")
            .into_inner();
        assert_eq!(list.entries.len(), 1);
        assert_eq!(list.entries[0].name, "hello.txt");

        client
            .rename(v1::RenameRequest {
                old_path: "hello.txt".into(),
                new_path: "renamed.txt".into(),
            })
            .await
            .expect("rename");
        client
            .remove(v1::RemoveRequest {
                path: "renamed.txt".into(),
                dir: false,
            })
            .await
            .expect("remove");

        let err = client
            .stat(v1::StatRequest {
                path: "/etc/passwd".into(),
                follow: false,
            })
            .await
            .expect_err("outside path rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn typed_health_returns_ready() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let response = authenticated_client(addr)
            .await
            .get_health(v1::GetHealthRequest {})
            .await
            .expect("typed health request")
            .into_inner();
        assert_eq!(response.state, v1::DaemonState::Ready as i32);
        shutdown.send(()).ok();
    }

    #[tokio::test]
    async fn typed_service_enforces_auth_token() {
        let (_temp, addr, shutdown) = spawn_daemon_with_auth("daemon-secret").await;
        let mut client = DaemonServiceClient::connect(format!("http://{addr}"))
            .await
            .expect("connect daemon");

        let err = client
            .get_capabilities(v1::GetCapabilitiesRequest::default())
            .await
            .expect_err("missing discovery token rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "missing daemon auth token");

        let err = client
            .list_sessions(v1::ListSessionsRequest {})
            .await
            .expect_err("missing durable-session token rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "missing daemon auth token");

        let err = client
            .list(v1::ListRequest { path: "".into() })
            .await
            .expect_err("missing token rejected");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "missing daemon auth token");

        for token in [
            "Xaemon-secret",
            "daemon-Xecret",
            "daemon-secreX",
            "short",
            "daemon-secret-extra",
        ] {
            let mut wrong = tonic::Request::new(v1::ListRequest { path: "".into() });
            wrong
                .metadata_mut()
                .insert(DAEMON_AUTH_TOKEN_HEADER, token.parse().unwrap());
            let err = client
                .list(wrong)
                .await
                .expect_err("mismatched token rejected");
            assert_eq!(
                err.code(),
                tonic::Code::Unauthenticated,
                "token = {token:?}"
            );
            assert_eq!(err.message(), "invalid daemon auth token");
        }

        let mut good = tonic::Request::new(v1::ListRequest { path: "".into() });
        good.metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, "daemon-secret".parse().unwrap());
        client.list(good).await.expect("valid token accepted");

        let mut good = tonic::Request::new(v1::GetCapabilitiesRequest::default());
        good.metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, "daemon-secret".parse().unwrap());
        client
            .get_capabilities(good)
            .await
            .expect("valid discovery token accepted");

        let mut good = tonic::Request::new(v1::ListSessionsRequest {});
        good.metadata_mut()
            .insert(DAEMON_AUTH_TOKEN_HEADER, "daemon-secret".parse().unwrap());
        client
            .list_sessions(good)
            .await
            .expect("valid durable-session token accepted");
        shutdown.send(()).ok();
    }

    async fn spawn_daemon() -> (tempfile::TempDir, SocketAddr, oneshot::Sender<()>) {
        spawn_daemon_with_auth(TEST_AUTH_TOKEN).await
    }

    async fn spawn_daemon_with_auth(
        auth_token: &str,
    ) -> (tempfile::TempDir, SocketAddr, oneshot::Sender<()>) {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        std::fs::create_dir_all(&workspace_root).expect("workspace");
        std::fs::create_dir_all(&home_root).expect("home");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let addr = listener.local_addr().expect("addr");
        let config = Config {
            listen_addr: addr.to_string(),
            workspace_root,
            home_root,
            auth_token: DaemonAuthToken::new(auth_token).expect("valid daemon test token"),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
        };
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = crate::server::serve_grpc_with_incoming(
                config,
                TcpListenerStream::new(listener),
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await;
        });
        (temp, addr, shutdown_tx)
    }

    async fn wait_for_pid(path: &std::path::Path) -> u32 {
        for _ in 0..100 {
            if let Ok(raw) = std::fs::read_to_string(path)
                && let Ok(pid) = raw.trim().parse()
            {
                return pid;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("process pid was not written to {}", path.display());
    }

    async fn wait_for_process_exit(pid: u32) {
        let proc_path = std::path::PathBuf::from(format!("/proc/{pid}"));
        for _ in 0..100 {
            if !proc_path.exists() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("remote process {pid} survived transport loss");
    }
}
