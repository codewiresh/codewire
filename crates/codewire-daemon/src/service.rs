use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use codewire_gateway_proto::codewire::bridge::v1 as bridge_v1;
use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::daemon::v1::daemon_service_server::DaemonService;
use codewire_gateway_proto::{
    DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITIES, DAEMON_CAPABILITY_CREDENTIAL_BRIDGE,
    DAEMON_MINIMUM_PROTOCOL_VERSION, DAEMON_PROTOCOL_VERSION,
};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::credential_bridge::CredentialBridge;
use crate::durable_session::{SessionEngine, status_from_session_error};
use crate::{Config, files, session};

const ATTACH_SESSION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const ATTACH_SESSION_READ_BYTES: u64 = 32 * 1024;
const ATTACH_SESSION_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const ATTACH_SESSION_FINAL_SEND_TIMEOUT: Duration = Duration::from_millis(100);

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
        let credential_bridge = CredentialBridge::new(config.credential_bridge.clone());
        Self {
            session_engine: SessionEngine::new(&config, credential_bridge.clone()),
            credential_bridge,
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
    type CredentialBridgeStream = codewire_credential_bridge::CredentialBridgeOutput;

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

    async fn poweroff_guest(
        &self,
        request: Request<v1::PoweroffGuestRequest>,
    ) -> Result<Response<v1::PoweroffGuestResponse>, Status> {
        self.authorize(&request)?;
        crate::lifecycle::poweroff_guest(&self.config).await?;
        Ok(Response::new(v1::PoweroffGuestResponse {}))
    }

    async fn credential_bridge(
        &self,
        request: Request<Streaming<bridge_v1::CredentialBridgeHostMessage>>,
    ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
        self.authorize(&request)?;
        let connection = self.credential_bridge.connect(request.into_inner()).await?;
        let mut response = Response::new(connection.output);
        if let Some(value) = connection.workspace_authorization {
            // This existing private capability-authenticated daemon transport
            // is plaintext inside the cluster. Sensitive metadata is redaction,
            // not encryption; the gateway-to-broker leg separately uses TLS.
            response.metadata_mut().insert_bin(
                crate::credential_bridge::WORKSPACE_AUTHORIZATION,
                value.into_metadata(),
            );
        }
        Ok(response)
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
                allow_history_gap: true,
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
            self.credential_bridge.clone(),
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
            self.credential_bridge.clone(),
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

type AttachRead = Pin<
    Box<
        dyn Future<Output = Result<(v1::ReadSessionOutputResponse, v1::SessionRecord), Status>>
            + Send,
    >,
>;

fn read_attach_batch(engine: SessionEngine, session_id: String, cursor: u64) -> AttachRead {
    Box::pin(async move {
        let output = engine
            .read_output(v1::ReadSessionOutputRequest {
                session_id: session_id.clone(),
                offset: cursor,
                limit: ATTACH_SESSION_READ_BYTES,
                allow_history_gap: true,
            })
            .await
            .map_err(status_from_session_error)?;
        let record = engine
            .get(&session_id)
            .await
            .map_err(status_from_session_error)?;
        Ok((output, record))
    })
}

async fn finish_attach(
    tx: &mpsc::Sender<Result<v1::SessionAttachMessage, Status>>,
    message: Result<v1::SessionAttachMessage, Status>,
) {
    // A reader that has stopped accepting output cannot prevent detach or an
    // invalid stream from releasing this attachment. The durable process is
    // never stopped here; its retained output remains available for replay.
    let _ = tokio::time::timeout(ATTACH_SESSION_FINAL_SEND_TIMEOUT, tx.send(message)).await;
}

async fn attach_control<T>(
    tx: &mpsc::Sender<Result<v1::SessionAttachMessage, Status>>,
    operation: impl Future<Output = Result<T, crate::durable_session::SessionError>>,
) -> Result<T, Status> {
    tokio::select! {
        () = tx.closed() => Err(Status::cancelled("attachment closed")),
        result = tokio::time::timeout(ATTACH_SESSION_CONTROL_TIMEOUT, operation) => {
            result.map_err(|_| Status::deadline_exceeded("session control timed out"))?
                .map_err(status_from_session_error)
        }
    }
}

async fn run_attach_session<S>(
    engine: SessionEngine,
    mut incoming: S,
    attach: v1::AttachSessionRequest,
    tx: mpsc::Sender<Result<v1::SessionAttachMessage, Status>>,
) where
    S: Stream<Item = Result<v1::SessionAttachMessage, Status>> + Unpin,
{
    let session_id = attach.session_id;
    let mut cursor = attach.output_offset;
    let mut last_status = None;
    let mut record: Option<v1::SessionRecord> = None;
    let mut chunks: VecDeque<v1::SessionOutputChunk> = VecDeque::new();
    let mut pending_status = None;
    let mut pending_gap: Option<v1::SessionOutputGap> = None;
    let mut terminal_status: Option<v1::SessionStatus> = None;
    let mut read = None;
    let mut refresh_due = true;
    let mut refresh = tokio::time::interval(Duration::from_millis(10));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + ATTACH_SESSION_HEARTBEAT_INTERVAL,
        ATTACH_SESSION_HEARTBEAT_INTERVAL,
    );
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let terminal_ready = terminal_status.as_ref().is_some_and(|status| {
            pending_gap.is_none() && chunks.is_empty() && cursor >= status.output_end_offset
        });
        if read.is_none()
            && chunks.is_empty()
            && pending_gap.is_none()
            && pending_status.is_none()
            && refresh_due
            && !terminal_ready
        {
            read = Some(read_attach_batch(
                engine.clone(),
                session_id.clone(),
                cursor,
            ));
            refresh_due = false;
        }

        // One owner retains the pending batch while capacity is unavailable.
        // Every iteration still polls input and disconnect, even when output
        // never catches up with a continuous producer. No detached writer can
        // reorder chunks or advance the replay cursor ahead of an enqueue.
        tokio::select! {
            () = tx.closed() => return,
            message = incoming.next() => {
                match message {
                    Some(Ok(message)) => match message.payload {
                        Some(v1::session_attach_message::Payload::Input(input)) => {
                            if let Err(error) = attach_control(&tx, engine.input(&session_id, input.data)).await {
                                finish_attach(&tx, Err(error)).await;
                                return;
                            }
                        }
                        Some(v1::session_attach_message::Payload::Resize(resize)) => {
                            match attach_control(&tx, engine.resize(&session_id, resize.width, resize.height)).await {
                                Ok(updated) => {
                                    // Apply first, then coalesce the informational
                                    // acknowledgement. Output capacity never holds
                                    // up another input or detach request.
                                    // Discard any read-only refresh begun before
                                    // this resize. Its cursor never advanced, so
                                    // replay is safe and it cannot replace this
                                    // acknowledged state with an older clone.
                                    read = None;
                                    refresh_due = true;
                                    if is_attached_session_live(updated.state) {
                                        terminal_status = None;
                                        pending_status = Some(session_status(&updated, None));
                                    } else {
                                        pending_status = None;
                                        terminal_status = Some(session_status(&updated, None));
                                    }
                                    record = Some(updated);
                                }
                                Err(error) => {
                                    finish_attach(&tx, Err(error)).await;
                                    return;
                                }
                            }
                        }
                        Some(v1::session_attach_message::Payload::Detach(detach)) => {
                            if detach.session_id != session_id {
                                finish_attach(&tx, Err(Status::invalid_argument(
                                        "detach session identifier does not match attached session",
                                    ))).await;
                                return;
                            }
                            match attach_control(&tx, engine.get(&session_id)).await {
                                Ok(record) => {
                                    // Never announce terminal completion before
                                    // pending output, even on explicit detach.
                                    if is_attached_session_live(record.state) || cursor >= record.output_end_offset {
                                        let status = session_status(
                                            &record,
                                            Some("client detached; session remains running"),
                                        );
                                        finish_attach(&tx, Ok(v1::SessionAttachMessage {
                                            payload: Some(v1::session_attach_message::Payload::Status(status)),
                                        })).await;
                                    }
                                }
                                Err(error) => {
                                    finish_attach(&tx, Err(error)).await;
                                }
                            }
                            return;
                        }
                        Some(v1::session_attach_message::Payload::Attach(_)) => {
                            finish_attach(&tx, Err(Status::invalid_argument(
                                    "attach stream already has a session",
                                ))).await;
                            return;
                        }
                        Some(v1::session_attach_message::Payload::Output(_))
                        | Some(v1::session_attach_message::Payload::Status(_))
                        | Some(v1::session_attach_message::Payload::HistoryGap(_))
                        | None => {
                            finish_attach(&tx, Err(Status::invalid_argument(
                                    "attach stream contains a server-only or empty message",
                                ))).await;
                            return;
                        }
                    },
                    None | Some(Err(_)) => return,
                }
            }
            permit = tx.reserve(), if pending_gap.is_some() || !chunks.is_empty() || pending_status.is_some() || terminal_ready => {
                let Ok(permit) = permit else { return };
                if let Some(gap) = pending_gap.take() {
                    cursor = gap.retained_start_offset;
                    permit.send(Ok(v1::SessionAttachMessage {
                        payload: Some(v1::session_attach_message::Payload::HistoryGap(gap)),
                    }));
                } else if let Some(chunk) = chunks.pop_front() {
                    let next_offset = chunk.next_offset;
                    permit.send(Ok(v1::SessionAttachMessage {
                        payload: Some(v1::session_attach_message::Payload::Output(chunk)),
                    }));
                    cursor = next_offset;
                } else if terminal_ready {
                    permit.send(Ok(v1::SessionAttachMessage {
                        payload: Some(v1::session_attach_message::Payload::Status(
                            terminal_status.take().expect("terminal status is ready"),
                        )),
                    }));
                    return;
                } else if let Some(status) = pending_status.take() {
                    permit.send(Ok(v1::SessionAttachMessage {
                        payload: Some(v1::session_attach_message::Payload::Status(status.clone())),
                    }));
                    last_status = Some(status);
                    heartbeat.reset();
                }
            }
            result = async { read.as_mut().expect("pending read").await }, if read.is_some() => {
                read = None;
                let (output, updated) = match result {
                    Ok(result) => result,
                    Err(error) => {
                        finish_attach(&tx, Err(error)).await;
                        return;
                    }
                };
                refresh_due = output.next_offset < updated.output_end_offset;
                if output.history_gap {
                    pending_gap = Some(v1::SessionOutputGap {
                        requested_offset: cursor,
                        retained_start_offset: output.retained_start_offset,
                    });
                }
                chunks = output.chunks.into();
                let status = session_status(&updated, None);
                if !is_attached_session_live(updated.state) {
                    terminal_status = Some(status);
                    pending_status = None;
                } else {
                    // Restart retains a session ID. A fresh live record can
                    // supersede a terminal observation while replay is pending.
                    terminal_status = None;
                    if !refresh_due && pending_status.is_none() && last_status.as_ref() != Some(&status) {
                        pending_status = Some(status);
                    }
                }
                record = Some(updated);
            }
            _ = heartbeat.tick() => {
                if pending_status.is_none() && terminal_status.is_none()
                    && let Some(record) = &record
                {
                    pending_status = Some(session_status(record, None));
                }
            }
            _ = refresh.tick(), if pending_gap.is_none() && chunks.is_empty() && read.is_none() && pending_status.is_none() && !terminal_ready => refresh_due = true,
        }
    }
}

fn session_status(record: &v1::SessionRecord, message: Option<&str>) -> v1::SessionStatus {
    v1::SessionStatus {
        session_id: record.session_id.clone(),
        state: record.state,
        exit_code: record.exit_code,
        output_end_offset: record.output_end_offset,
        output_start_offset: record.output_start_offset,
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
    async fn guest_poweroff_requires_auth_and_is_not_available_on_a_native_host_daemon() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let mut unauthorized = DaemonServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        assert_eq!(
            unauthorized
                .poweroff_guest(v1::PoweroffGuestRequest {})
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let mut authorized = authenticated_client(addr).await;
        assert_eq!(
            authorized
                .poweroff_guest(v1::PoweroffGuestRequest {})
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        shutdown.send(()).unwrap();
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

    fn attach_engine() -> (tempfile::TempDir, SessionEngine) {
        let temp = tempfile::tempdir().expect("attach engine root");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        std::fs::create_dir_all(&workspace_root).unwrap();
        std::fs::create_dir_all(&home_root).unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root,
            home_root,
            auth_token: DaemonAuthToken::new(TEST_AUTH_TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
        };
        (
            temp,
            SessionEngine::new(&config, CredentialBridge::new(None)),
        )
    }

    #[tokio::test]
    async fn attach_saturated_reader_keeps_input_resize_and_detach_responsive() {
        saturated_attach_controls(2 * 1024 * 1024, false).await;
    }

    #[tokio::test]
    async fn attach_saturated_gap_replay_keeps_controls_responsive() {
        saturated_attach_controls(9 * 1024 * 1024, true).await;
    }

    async fn saturated_attach_controls(output_bytes: u64, expect_gap: bool) {
        let (temp, engine) = attach_engine();
        let session = engine.launch(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(),
                format!("stty -echo; head -c {output_bytes} /dev/zero; IFS= read -r line; printf '%s' \"$line\" > attach-input; stty size > attach-size; exec sleep 30")],
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            ..Default::default()
        }).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while engine
                .get(&session.session_id)
                .await
                .unwrap()
                .output_end_offset
                < output_bytes
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("bounded producer persisted its output");
        let (input, incoming) = mpsc::channel(8);
        let (output, mut unread) = mpsc::channel(32);
        let capacity = output.clone();
        let owner = tokio::spawn(run_attach_session(
            engine.clone(),
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session.session_id.clone(),
                output_offset: 0,
            },
            output,
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while capacity.capacity() != 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all 32 response slots are saturated");
        input
            .send(Ok(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Resize(
                    v1::ResizeRequest {
                        width: 132,
                        height: 43,
                    },
                )),
            }))
            .await
            .unwrap();
        input
            .send(Ok(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Input(
                    v1::SessionInput {
                        data: b"fair-input\n".to_vec(),
                    },
                )),
            }))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let input = std::fs::read_to_string(temp.path().join("home/attach-input"));
                let size = std::fs::read_to_string(temp.path().join("home/attach-size"));
                if input.as_deref().is_ok_and(|input| input == "fair-input")
                    && size.as_deref().is_ok_and(|size| size.trim() == "43 132")
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("resize and input complete without reading response frames");
        assert_eq!(capacity.capacity(), 0);
        input
            .send(Ok(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Detach(
                    v1::DetachSessionRequest {
                        session_id: session.session_id.clone(),
                    },
                )),
            }))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .expect("detach does not wait for the saturated reader")
            .unwrap();
        assert_eq!(
            engine.get(&session.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Running as i32
        );
        let first = unread.recv().await.unwrap().unwrap().payload.unwrap();
        let replay_start = if expect_gap {
            let v1::session_attach_message::Payload::HistoryGap(gap) = first else {
                panic!("retained replay must begin with a history gap");
            };
            assert_eq!(gap.requested_offset, 0);
            assert!(gap.retained_start_offset > 0);
            gap.retained_start_offset
        } else {
            let v1::session_attach_message::Payload::Output(chunk) = first else {
                panic!("complete replay must begin with output");
            };
            assert_eq!(chunk.offset, 0);
            chunk.next_offset
        };
        let mut cursor = replay_start;
        while let Ok(message) = unread.try_recv() {
            if let Some(v1::session_attach_message::Payload::Output(chunk)) =
                message.unwrap().payload
            {
                assert_eq!(chunk.offset, cursor);
                assert_eq!(chunk.next_offset, cursor + chunk.data.len() as u64);
                cursor = chunk.next_offset;
            }
        }
        assert!(cursor > replay_start);
        engine.stop(&session.session_id).await.unwrap();
    }

    #[tokio::test]
    async fn attach_reports_later_retention_gap_after_already_queued_output() {
        let (_temp, engine) = attach_engine();
        let session = engine.launch(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(),
                "stty -echo; head -c 262144 /dev/zero; IFS= read -r line; head -c 9437184 /dev/zero; exec sleep 30".into()],
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            ..Default::default()
        }).await.unwrap();
        let (input, incoming) = mpsc::channel(8);
        let (output, mut receiver) = mpsc::channel(1);
        let capacity = output.clone();
        let owner = tokio::spawn(run_attach_session(
            engine.clone(),
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session.session_id.clone(),
                output_offset: 0,
            },
            output,
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while capacity.capacity() != 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("initial replay saturated");
        input
            .send(Ok(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Input(
                    v1::SessionInput {
                        data: b"produce\n".to_vec(),
                    },
                )),
            }))
            .await
            .unwrap();
        let end = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let record = engine.get(&session.session_id).await.unwrap();
                if record.output_end_offset == 262144 + 9437184 && record.output_start_offset > 0 {
                    break record.output_end_offset;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("producer compacted while attachment was blocked");
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut cursor = 0;
            let mut gap_seen = false;
            while cursor < end {
                match receiver.recv().await.unwrap().unwrap().payload.unwrap() {
                    v1::session_attach_message::Payload::Output(chunk) => {
                        assert_eq!(chunk.offset, cursor);
                        assert!(chunk.data.iter().all(|byte| *byte == 0));
                        cursor += chunk.data.len() as u64;
                        assert_eq!(chunk.next_offset, cursor);
                    }
                    v1::session_attach_message::Payload::HistoryGap(gap) => {
                        assert!(cursor > 0, "older queued output must precede the gap");
                        assert!(!gap_seen);
                        assert_eq!(gap.requested_offset, cursor);
                        assert!(gap.retained_start_offset > cursor);
                        cursor = gap.retained_start_offset;
                        gap_seen = true;
                    }
                    v1::session_attach_message::Payload::Status(status) => {
                        assert!(is_attached_session_live(status.state));
                    }
                    other => panic!("unexpected server frame {other:?}"),
                }
            }
            assert!(gap_seen);
            assert_eq!(cursor, end);
        })
        .await
        .expect("gap-aware ordered replay finishes");
        drop(receiver);
        tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .expect("closed reader releases attachment")
            .unwrap();
        assert_eq!(
            engine.get(&session.session_id).await.unwrap().state,
            v1::SessionLifecycleState::Running as i32
        );
        engine.stop(&session.session_id).await.unwrap();
    }

    #[tokio::test]
    async fn attach_pending_output_is_contiguous_before_terminal_status() {
        let (_temp, engine) = attach_engine();
        let session = engine
            .launch(v1::LaunchSessionRequest {
                command: vec!["sh".into(), "-c".into(), "head -c 262144 /dev/zero".into()],
                ..Default::default()
            })
            .await
            .unwrap();
        let (_input, incoming) = mpsc::channel(8);
        let (output, mut receiver) = mpsc::channel(1);
        let owner = tokio::spawn(run_attach_session(
            engine,
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session.session_id,
                output_offset: 0,
            },
            output,
        ));
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut cursor = 0;
            let mut terminal_seen = false;
            while let Some(message) = receiver.recv().await {
                match message.unwrap().payload.unwrap() {
                    v1::session_attach_message::Payload::Output(chunk) => {
                        assert!(!terminal_seen);
                        assert_eq!(chunk.offset, cursor);
                        assert!(chunk.data.iter().all(|byte| *byte == 0));
                        cursor += chunk.data.len() as u64;
                        assert_eq!(chunk.next_offset, cursor);
                    }
                    v1::session_attach_message::Payload::Status(status) => {
                        if !is_attached_session_live(status.state) {
                            assert_eq!(status.state, v1::SessionLifecycleState::Exited as i32);
                            assert_eq!(status.output_end_offset, cursor);
                            terminal_seen = true;
                        }
                    }
                    other => panic!("unexpected server frame {other:?}"),
                }
                tokio::task::yield_now().await;
            }
            assert!(terminal_seen);
            assert_eq!(cursor, 262144);
        })
        .await
        .expect("bounded ordered replay");
        owner.await.unwrap();
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
            managed_credential_clients: Default::default(),
            launch_projection: None,
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
