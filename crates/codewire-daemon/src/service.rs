use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use codewire_daemon_proto::codewire::bridge::v1 as bridge_v1;
use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::daemon::v1::daemon_service_server::DaemonService;
use codewire_daemon_proto::{
    DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITIES, DAEMON_CAPABILITY_CREDENTIAL_BRIDGE,
    DAEMON_MINIMUM_PROTOCOL_VERSION, DAEMON_PROTOCOL_VERSION,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

use crate::app_ports::AppPortsSender;
use crate::credential_bridge::CredentialBridge;
use crate::durable_session::{SessionEngine, status_from_session_error};
use crate::{Config, files, session};

const ATTACH_SESSION_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const ATTACH_SESSION_READ_BYTES: u64 = 32 * 1024;
const ATTACH_SESSION_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const ATTACH_SESSION_FINAL_SEND_TIMEOUT: Duration = Duration::from_millis(100);
/// Attach input read from the client and not yet applied. An attachment reads
/// its input as it arrives, up to this bound, while it applies earlier input:
/// keystroke-sized frames left unread in HTTP/2 count against the
/// connection's small DATA frame flood guard, which ends the connection and
/// every attachment on it (#2822). At the bound it stops reading, and flow
/// control pauses the client.
const MAX_PENDING_ATTACH_INPUT_BYTES: usize = 1024 * 1024;
/// Largest input write that consecutive Input frames are joined into.
const MAX_COALESCED_ATTACH_INPUT: usize = 32 * 1024;
/// What a held message other than input counts against the bound.
const ATTACH_CONTROL_COST: usize = 64;

#[derive(Clone)]
pub struct DaemonServiceImpl {
    config: Config,
    runtime_state: DaemonRuntimeState,
    session_engine: SessionEngine,
    credential_bridge: CredentialBridge,
    /// A bound daemon's exposed application ports; `None` where the daemon
    /// serves no tailnet (environment-token mode, local placements).
    app_ports: Option<AppPortsSender>,
    workload_sockets: crate::forward::WorkloadSockets,
    /// The token every RPC must present. It starts as `config.auth_token`;
    /// only a local guest daemon rotates it (`auth_rotation`).
    auth: crate::auth_rotation::DaemonAuth,
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

    /// [`Self::ready`], also reporting what a bound daemon wrote before it
    /// served (#3684). The diagnostic never changes the daemon's state: a
    /// failed write falls back to setup's own.
    #[cfg(unix)]
    pub fn ready_with_defaults(
        outcome: Option<crate::workspace_defaults::DefaultsOutcome>,
    ) -> Self {
        Self::new(
            v1::DaemonState::Ready,
            "daemon ready",
            outcome.map(|outcome| outcome.0).into_iter().collect(),
        )
    }
}

impl DaemonServiceImpl {
    pub(crate) fn session_engine(&self) -> SessionEngine {
        self.session_engine.clone()
    }

    pub fn new(config: Config) -> Self {
        Self::with_runtime_state(config, DaemonRuntimeState::ready())
    }

    pub fn with_runtime_state(config: Config, runtime_state: DaemonRuntimeState) -> Self {
        let credential_bridge = CredentialBridge::new(config.credential_bridge.clone());
        Self {
            session_engine: SessionEngine::new(&config, credential_bridge.clone()),
            auth: crate::auth_rotation::DaemonAuth::new(config.auth_token.clone()),
            credential_bridge,
            config,
            runtime_state,
            app_ports: None,
            workload_sockets: crate::forward::WorkloadSockets::default(),
        }
    }

    fn require_guest(&self) -> Result<(), Status> {
        if self.config.host.is_some() {
            return Err(Status::permission_denied(
                "trusted host daemon permits durable-session RPCs only",
            ));
        }
        Ok(())
    }

    /// Accept `SetAppPorts`, publishing each set to `app_ports`.
    pub fn with_app_ports(mut self, app_ports: AppPortsSender) -> Self {
        self.app_ports = Some(app_ports);
        self
    }

    /// The same service whose session engine has `bounds` for its host
    /// sessions; see [`SessionEngine::with_host_bounds`]. It replaces an
    /// engine that has not started, so it is called before serving.
    pub(crate) fn with_host_bounds(mut self, bounds: crate::durable_session::HostBounds) -> Self {
        self.session_engine =
            SessionEngine::with_host_bounds(&self.config, self.credential_bridge.clone(), bounds);
        self
    }

    fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
        self.auth.authorize(
            request
                .metadata()
                .get(DAEMON_AUTH_TOKEN_HEADER)
                .and_then(|value| value.to_str().ok()),
        )?;
        self.config
            .validate_host()
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(())
    }

    pub(crate) fn credential_bridge(&self) -> CredentialBridge {
        self.credential_bridge.clone()
    }

    pub(crate) fn auth(&self) -> crate::auth_rotation::DaemonAuth {
        self.auth.clone()
    }
}

#[tonic::async_trait]
impl DaemonService for DaemonServiceImpl {
    type ExecSessionStream = ReceiverStream<Result<v1::ExecMessage, Status>>;
    type PtySessionStream = ReceiverStream<Result<v1::PtyMessage, Status>>;
    type ForwardTcpStream = ReceiverStream<Result<v1::ForwardTcpMessage, Status>>;
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
        let mut diagnostics = self.runtime_state.diagnostics.clone();
        diagnostics.extend(self.session_engine.store_diagnostic());
        Ok(Response::new(v1::GetHealthResponse {
            state: self.runtime_state.state as i32,
            message: self.runtime_state.message.clone(),
            diagnostics,
        }))
    }

    async fn poweroff_guest(
        &self,
        request: Request<v1::PoweroffGuestRequest>,
    ) -> Result<Response<v1::PoweroffGuestResponse>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        crate::lifecycle::poweroff_guest(&self.config).await?;
        Ok(Response::new(v1::PoweroffGuestResponse {}))
    }

    async fn set_app_ports(
        &self,
        request: Request<v1::SetAppPortsRequest>,
    ) -> Result<Response<v1::SetAppPortsResponse>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let Some(app_ports) = &self.app_ports else {
            return Err(Status::failed_precondition(
                "this daemon serves no application ports",
            ));
        };
        let ports = crate::app_ports::app_ports(&request.into_inner().ports)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        tracing::info!(app_port_count = ports.len(), "application ports replaced");
        app_ports.send_replace(ports);
        Ok(Response::new(v1::SetAppPortsResponse {}))
    }

    async fn credential_bridge(
        &self,
        request: Request<Streaming<bridge_v1::CredentialBridgeHostMessage>>,
    ) -> Result<Response<Self::CredentialBridgeStream>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let connection = self.credential_bridge.connect(request.into_inner()).await?;
        let mut response = Response::new(connection.output);
        if let Some(value) = connection.workspace_authorization {
            // This existing private capability-authenticated daemon transport
            // is plaintext inside the cluster. Sensitive metadata is redaction,
            // not encryption; the relay-to-broker leg separately uses TLS.
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
        let request = request.into_inner();
        let session = match request.expected_launch_generation {
            Some(generation) => {
                self.session_engine
                    .restart_with_generation(&request.session_id, Some(generation))
                    .await
            }
            None => self.session_engine.restart(&request.session_id).await,
        }
        .map_err(status_from_session_error)?;
        Ok(Response::new(v1::RestartSessionResponse {
            session: Some(session),
        }))
    }

    async fn send_session_input(
        &self,
        request: Request<v1::SendSessionInputRequest>,
    ) -> Result<Response<v1::SendSessionInputResponse>, Status> {
        self.authorize(&request)?;
        let request = request.into_inner();
        self.session_engine
            .send_input(&request.session_id, request.data)
            .await
            .map_err(status_from_session_error)?;
        Ok(Response::new(v1::SendSessionInputResponse {}))
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
        self.require_guest()?;
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

    async fn forward_tcp(
        &self,
        request: Request<Streaming<v1::ForwardTcpMessage>>,
    ) -> Result<Response<Self::ForwardTcpStream>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let mut inbound = request.into_inner();
        let open = match inbound
            .message()
            .await
            .map_err(|err| Status::invalid_argument(format!("read forward open message: {err}")))?
            .and_then(|msg| msg.payload)
        {
            Some(v1::forward_tcp_message::Payload::Open(open)) => open,
            _ => return Err(Status::invalid_argument("forward open message is required")),
        };
        let target = crate::forward::admit(&open, self.config.tcp_port())?;
        let stream = self.workload_sockets.connect(&self.config, target).await?;
        Ok(Response::new(crate::forward::serve(stream, inbound)))
    }

    async fn pty_session(
        &self,
        request: Request<Streaming<v1::PtyMessage>>,
    ) -> Result<Response<Self::PtySessionStream>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
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
        self.require_guest()?;
        let path = request.into_inner().path;
        let entries = files::as_workload_user(&self.config, || files::list(&self.config, &path))
            .map_err(status_from_file_error)?;
        Ok(Response::new(v1::ListResponse { entries }))
    }

    async fn stat(
        &self,
        request: Request<v1::StatRequest>,
    ) -> Result<Response<v1::StatResponse>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        let entry = files::as_workload_user(&self.config, || {
            files::stat(&self.config, &request.path, request.follow)
        })
        .map_err(status_from_file_error)?;
        Ok(Response::new(v1::StatResponse { entry: Some(entry) }))
    }

    async fn open_file(
        &self,
        request: Request<v1::OpenFileRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        files::as_workload_user(&self.config, || {
            files::open_file(
                &self.config,
                &request.path,
                request.options.as_ref(),
                request.perm,
            )
        })
        .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn read(
        &self,
        request: Request<v1::ReadRequest>,
    ) -> Result<Response<v1::ReadResponse>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        let data = files::as_workload_user(&self.config, || {
            files::read(&self.config, &request.path, request.offset, request.length)
        })
        .map_err(status_from_file_error)?;
        Ok(Response::new(v1::ReadResponse { data }))
    }

    async fn write(
        &self,
        request: Request<v1::WriteRequest>,
    ) -> Result<Response<v1::WriteResponse>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        let bytes_written = files::as_workload_user(&self.config, || {
            files::write(&self.config, &request.path, request.offset, &request.data)
        })
        .map_err(status_from_file_error)?;
        Ok(Response::new(v1::WriteResponse { bytes_written }))
    }

    async fn mkdir(
        &self,
        request: Request<v1::MkdirRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        files::as_workload_user(&self.config, || {
            files::mkdir(&self.config, &request.path, request.perm)
        })
        .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn remove(
        &self,
        request: Request<v1::RemoveRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        let _ = request.dir;
        files::as_workload_user(&self.config, || files::remove(&self.config, &request.path))
            .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn rename(
        &self,
        request: Request<v1::RenameRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        files::as_workload_user(&self.config, || {
            files::rename(&self.config, &request.old_path, &request.new_path)
        })
        .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn set_stat(
        &self,
        request: Request<v1::SetStatRequest>,
    ) -> Result<Response<v1::OperationStatus>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let request = request.into_inner();
        validate_timestamp(request.access_time.as_ref())?;
        validate_timestamp(request.mod_time.as_ref())?;
        files::as_workload_user(&self.config, || files::set_stat(&self.config, &request))
            .map_err(status_from_file_error)?;
        Ok(Response::new(ok_status()))
    }

    async fn readlink(
        &self,
        request: Request<v1::ReadlinkRequest>,
    ) -> Result<Response<v1::ReadlinkResponse>, Status> {
        self.authorize(&request)?;
        self.require_guest()?;
        let path = request.into_inner().path;
        let target = files::as_workload_user(&self.config, || files::readlink(&self.config, &path))
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

/// Join a read's contiguous chunks of one stream, up to the read size, so
/// output read in one batch leaves as one message, not one small DATA frame
/// per terminal write.
fn merge_output_chunks(chunks: Vec<v1::SessionOutputChunk>) -> VecDeque<v1::SessionOutputChunk> {
    let mut merged: VecDeque<v1::SessionOutputChunk> = VecDeque::with_capacity(chunks.len());
    for chunk in chunks {
        if let Some(last) = merged.back_mut()
            && last.stream == chunk.stream
            && last.next_offset == chunk.offset
            && last.data.len() + chunk.data.len() <= ATTACH_SESSION_READ_BYTES as usize
        {
            last.data.extend_from_slice(&chunk.data);
            last.next_offset = chunk.next_offset;
            continue;
        }
        merged.push_back(chunk);
    }
    merged
}

/// Attach input read ahead of its application, in order; `None` is the end,
/// or failure, of the client's stream. Consecutive Input joins into one write;
/// a resize, detach or anything else keeps its place.
#[derive(Default)]
struct AttachInputQueue {
    messages: VecDeque<Option<v1::SessionAttachMessage>>,
    bytes: usize,
}

fn attach_input_cost(message: &Option<v1::SessionAttachMessage>) -> usize {
    match message {
        Some(v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Input(input)),
        }) => input.data.len(),
        _ => ATTACH_CONTROL_COST,
    }
}

impl AttachInputQueue {
    fn push(&mut self, message: Option<v1::SessionAttachMessage>) {
        self.bytes = self.bytes.saturating_add(attach_input_cost(&message));
        if let (
            Some(Some(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Input(held)),
            })),
            Some(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Input(input)),
            }),
        ) = (self.messages.back_mut(), &message)
            && held.data.len() + input.data.len() <= MAX_COALESCED_ATTACH_INPUT
        {
            held.data.extend_from_slice(&input.data);
            return;
        }
        self.messages.push_back(message);
    }

    fn pop(&mut self) -> Option<Option<v1::SessionAttachMessage>> {
        let message = self.messages.pop_front()?;
        self.bytes = self.bytes.saturating_sub(attach_input_cost(&message));
        Some(message)
    }
}

/// The input half of an attachment: a reader takes the client's frames as
/// they arrive, and the attachment applies them in order.
#[derive(Default)]
struct AttachInput {
    queue: std::sync::Mutex<AttachInputQueue>,
    queued: tokio::sync::Notify,
    room: tokio::sync::Notify,
}

impl AttachInput {
    fn lock(&self) -> std::sync::MutexGuard<'_, AttachInputQueue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn read<S>(&self, mut incoming: S)
    where
        S: Stream<Item = Result<v1::SessionAttachMessage, Status>> + Unpin,
    {
        loop {
            loop {
                let room = self.room.notified();
                if self.lock().bytes < MAX_PENDING_ATTACH_INPUT_BYTES {
                    break;
                }
                room.await;
            }
            let message = match incoming.next().await {
                Some(Ok(message)) => Some(message),
                None | Some(Err(_)) => None,
            };
            let ended = message.is_none();
            self.lock().push(message);
            self.queued.notify_one();
            if ended {
                return;
            }
        }
    }

    /// The next message to apply; `None` once the client's stream ended.
    async fn next(&self) -> Option<v1::SessionAttachMessage> {
        loop {
            let queued = self.queued.notified();
            let next = self.lock().pop();
            if let Some(next) = next {
                self.room.notify_one();
                return next;
            }
            queued.await;
        }
    }
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
    incoming: S,
    attach: v1::AttachSessionRequest,
    tx: mpsc::Sender<Result<v1::SessionAttachMessage, Status>>,
) where
    S: Stream<Item = Result<v1::SessionAttachMessage, Status>> + Send + Unpin + 'static,
{
    // Every client attachment, over the API or the SSH server's session
    // subsystem, is counted here while it runs: a session launched with
    // `end_after_detached_seconds` ends only after that long with none.
    let _attached = engine.attached(&attach.session_id);
    // Input is read by its own task, so applying one input never leaves the
    // next unread. It ends with the attachment.
    let input = std::sync::Arc::new(AttachInput::default());
    let _reader = tokio_util::task::AbortOnDropHandle::new(tokio::spawn({
        let input = input.clone();
        async move { input.read(incoming).await }
    }));
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
    // New output wakes the attachment at once; the interval stays as the
    // fallback and still notices state changes. Without this a keystroke's
    // echo waited for the next tick, about 10 ms (#3827). A session whose
    // handle is replaced ends the watch, and the interval alone remains.
    let mut output_grew = engine.watch_output(&session_id).ok();
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
            message = input.next() => {
                match message {
                    Some(message) => match message.payload {
                        Some(v1::session_attach_message::Payload::Input(input)) => {
                            if let Err(error) = attach_control(&tx, engine.input(&session_id, input.data)).await {
                                finish_attach(&tx, Err(error)).await;
                                return;
                            }
                        }
                        Some(v1::session_attach_message::Payload::Resize(resize)) => {
                            // Resize and detach wait for the session's metadata
                            // lock. A pending read set aside by this loop may
                            // hold that lock, or be next in line for it, and
                            // cannot finish while the loop waits here, so the
                            // control would wait out its deadline and end the
                            // attachment (#2484). Discard the read first: it
                            // is read-only and its cursor never advanced, so
                            // replay is safe and it cannot replace this
                            // control's state with an older clone.
                            read = None;
                            match attach_control(&tx, engine.resize(&session_id, resize.width, resize.height)).await {
                                Ok(updated) => {
                                    // Apply first, then coalesce the informational
                                    // acknowledgement. Output capacity never holds
                                    // up another input or detach request.
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
                            // As for resize: never wait on the lock behind this
                            // loop's own pending read.
                            drop(read.take());
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
                    None => return,
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
                chunks = merge_output_chunks(output.chunks);
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
            grew = async { output_grew.as_mut().expect("watched").changed().await }, if output_grew.is_some() && pending_gap.is_none() && chunks.is_empty() && read.is_none() && pending_status.is_none() && !terminal_ready => {
                match grew {
                    Ok(()) => refresh_due = true,
                    Err(_) => output_grew = None,
                }
            }
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
        let selected = if self.config.host.is_some() {
            codewire_daemon_proto::HOST_DAEMON_CAPABILITIES
        } else {
            DAEMON_CAPABILITIES
        };
        let supported = selected
            .iter()
            .copied()
            .chain(
                self.credential_bridge
                    .is_enabled()
                    .then_some(DAEMON_CAPABILITY_CREDENTIAL_BRIDGE),
            )
            .map(str::to_owned)
            .collect::<Vec<_>>();
        #[cfg(target_os = "linux")]
        let supported = if crate::platform_managed::Service::available(&self.config) {
            let mut supported = supported;
            supported.push(codewire_daemon_proto::platform_managed::CAPABILITY.into());
            supported
        } else {
            supported
        };

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
            default_shell: crate::env::default_shell_for(&self.config),
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
        files::FileError::UntrustedRoot | files::FileError::MountUnavailable => {
            Status::failed_precondition(err.to_string())
        }
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
mod unattended_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_daemon_proto::daemon::v1::daemon_service_client::DaemonServiceClient;
    use codewire_daemon_proto::{DAEMON_AUTH_TOKEN_HEADER, DaemonAuthToken};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{Duration, sleep};
    use tokio_stream::{
        iter,
        wrappers::{ReceiverStream, TcpListenerStream},
    };
    use tonic::metadata::{Ascii, MetadataValue};

    /// Bounds writing a test transcript through the real append path, so a
    /// hang fails instead of stalling the run. Each 32 KiB frame is synced to
    /// disk, so a 9 MiB transcript is hundreds of syncs, and a contended CI
    /// disk can take seconds for them all (main CI, 2026-11-11: 30 s ran out
    /// before any attach control was tested). It is never the expected
    /// duration; what these tests time is the controls after it.
    const TRANSCRIPT_HANG: Duration = Duration::from_secs(300);
    use tonic::service::Interceptor;
    use tonic::service::interceptor::InterceptedService;
    use tonic::transport::Channel;

    const TEST_AUTH_TOKEN: &str = "daemon-service-test-token";

    #[derive(Clone)]
    pub(super) struct TestAuthInterceptor {
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

    pub(super) type TestClient =
        DaemonServiceClient<InterceptedService<Channel, TestAuthInterceptor>>;

    pub(super) async fn authenticated_client(addr: SocketAddr) -> TestClient {
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

    async fn client_with_token(addr: SocketAddr, token: &str) -> TestClient {
        let channel = Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .expect("connect daemon");
        DaemonServiceClient::with_interceptor(
            channel,
            TestAuthInterceptor {
                token: token.parse().unwrap(),
            },
        )
    }

    #[tokio::test]
    async fn rotation_refuses_the_old_token_ends_its_streams_and_keeps_sessions() {
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
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new("synthetic-before").unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        let (rotation, requests) = crate::auth_rotation::rotation_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(crate::server::serve_rotating_grpc_for_tests(
            config,
            requests,
            TcpListenerStream::new(listener),
            async {
                let _ = shutdown_rx.await;
            },
        ));

        let mut old = client_with_token(addr, "synthetic-before").await;
        let session = old
            .launch_session(v1::LaunchSessionRequest {
                command: vec!["sh".into(), "-c".into(), "exec sleep 30".into()],
                name: "ticker".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_inner()
            .session
            .unwrap();
        let (attach_input, input) = mpsc::channel(4);
        attach_input
            .send(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Attach(
                    v1::AttachSessionRequest {
                        session_id: session.session_id.clone(),
                        output_offset: 0,
                    },
                )),
            })
            .await
            .unwrap();
        let mut attached = old
            .attach_session(ReceiverStream::new(input))
            .await
            .unwrap()
            .into_inner();

        let epoch = rotation
            .rotate(crate::auth_rotation::RotatedIdentity {
                token: DaemonAuthToken::new("synthetic-after").unwrap(),
                environment_id: uuid::Uuid::new_v4(),
                environment_generation: 2,
            })
            .await
            .unwrap();
        assert_eq!(epoch, 1);

        // The stream admitted with the old token ends.
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            while let Ok(Some(_)) = attached.message().await {}
        })
        .await;
        assert!(ended.is_ok(), "the old epoch's attach stream did not end");

        // The old token is refused on a new connection, too.
        let mut stale = client_with_token(addr, "synthetic-before").await;
        assert_eq!(
            stale
                .list_sessions(v1::ListSessionsRequest {})
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        // The session kept running and is reachable with the new token.
        let mut new = client_with_token(addr, "synthetic-after").await;
        let sessions = new
            .list_sessions(v1::ListSessionsRequest {})
            .await
            .unwrap()
            .into_inner()
            .sessions;
        let kept = sessions
            .iter()
            .find(|record| record.session_id == session.session_id)
            .expect("the session survives the rotation");
        assert_eq!(kept.state, session.state);
        new.stop_session(v1::StopSessionRequest {
            session_id: session.session_id.clone(),
        })
        .await
        .unwrap();
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
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
                // Not the 0o644 default, and kept whole by any umask that
                // leaves the owner's read and write (077 as well as 022).
                perm: 0o600,
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
        assert_eq!(stat.mode & 0o777, 0o600);

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
    async fn a_restart_the_daemon_never_admits_says_so_over_the_wire() {
        let (_temp, addr, shutdown) = spawn_daemon().await;
        let mut client = authenticated_client(addr).await;
        let missing = format!("session-{}", uuid::Uuid::new_v4());
        let refused = client
            .restart_session(v1::RestartSessionRequest {
                session_id: missing.clone(),
                expected_launch_generation: None,
            })
            .await
            .unwrap_err();
        // The code a client always saw, and the daemon's reason beside it.
        assert_eq!(refused.code(), tonic::Code::NotFound);
        assert_eq!(
            crate::NeverRestarts::of(&refused),
            Some(crate::NeverRestarts::NoSession)
        );
        assert_eq!(
            crate::client::SessionClientError::from(refused).never_restarts(),
            Some(crate::NeverRestarts::NoSession)
        );
        // Another refusal with the same code carries none.
        let other = client
            .get_session(v1::GetSessionRequest {
                session_id: missing,
            })
            .await
            .unwrap_err();
        assert_eq!(other.code(), tonic::Code::NotFound);
        assert_eq!(
            crate::client::SessionClientError::from(other).never_restarts(),
            None
        );
        let _ = shutdown.send(());
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

    pub(super) async fn spawn_daemon() -> (tempfile::TempDir, SocketAddr, oneshot::Sender<()>) {
        spawn_daemon_with_auth(TEST_AUTH_TOKEN).await
    }

    pub(super) fn attach_engine() -> (tempfile::TempDir, SessionEngine) {
        let temp = tempfile::tempdir().expect("attach engine root");
        let workspace_root = temp.path().join("workspace");
        let home_root = temp.path().join("home");
        std::fs::create_dir_all(&workspace_root).unwrap();
        std::fs::create_dir_all(&home_root).unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root,
            home_root,
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new(TEST_AUTH_TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        (
            temp,
            SessionEngine::new(&config, CredentialBridge::new(None)),
        )
    }

    fn app_ports_request(token: Option<&str>, ports: Vec<i32>) -> Request<v1::SetAppPortsRequest> {
        let mut request = Request::new(v1::SetAppPortsRequest { ports });
        if let Some(token) = token {
            request
                .metadata_mut()
                .insert(DAEMON_AUTH_TOKEN_HEADER, token.parse().unwrap());
        }
        request
    }

    #[tokio::test]
    async fn the_defaults_report_reaches_health_and_never_changes_the_daemons_state() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().to_path_buf(),
            home_root: temp.path().to_path_buf(),
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new(TEST_AUTH_TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        let health = |outcome| {
            let service = DaemonServiceImpl::with_runtime_state(
                config.clone(),
                DaemonRuntimeState::ready_with_defaults(outcome),
            );
            async move {
                let mut request = Request::new(v1::GetHealthRequest {});
                request
                    .metadata_mut()
                    .insert(DAEMON_AUTH_TOKEN_HEADER, TEST_AUTH_TOKEN.parse().unwrap());
                service.get_health(request).await.unwrap().into_inner()
            }
        };
        let report = |healthy| v1::HealthDiagnostic {
            name: codewire_daemon_proto::WORKSPACE_DEFAULTS_DIAGNOSTIC.to_owned(),
            healthy,
            message: "synthetic".to_owned(),
        };
        // A write that failed leaves the daemon ready: setup writes them.
        for healthy in [true, false] {
            let response = health(Some(crate::workspace_defaults::DefaultsOutcome(report(
                healthy,
            ))))
            .await;
            assert_eq!(response.state, v1::DaemonState::Ready as i32);
            assert_eq!(response.diagnostics, [report(healthy)]);
        }
        // No defaults, as from an older server: nothing is reported.
        let response = health(None).await;
        assert_eq!(response.state, v1::DaemonState::Ready as i32);
        assert!(response.diagnostics.is_empty());
    }

    #[tokio::test]
    async fn a_refused_session_store_is_a_distinct_status_and_a_health_diagnostic_until_corrected()
    {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().to_path_buf(),
            home_root: temp.path().to_path_buf(),
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new(TEST_AUTH_TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        let store = temp.path().join(".codewire/daemon/sessions");
        std::fs::create_dir_all(store.parent().unwrap()).unwrap();
        std::fs::write(&store, b"not a directory").unwrap();
        let service = DaemonServiceImpl::new(config);
        fn request<T>(message: T) -> Request<T> {
            let mut request = Request::new(message);
            request
                .metadata_mut()
                .insert(DAEMON_AUTH_TOKEN_HEADER, TEST_AUTH_TOKEN.parse().unwrap());
            request
        }
        let health = |service: DaemonServiceImpl| async move {
            service
                .get_health(request(v1::GetHealthRequest {}))
                .await
                .unwrap()
                .into_inner()
                .diagnostics
        };
        // Nothing is reported before a request has met the store.
        assert!(health(service.clone()).await.is_empty());
        for _ in 0..2 {
            let refused = service
                .list_sessions(request(v1::ListSessionsRequest {}))
                .await
                .unwrap_err();
            assert_eq!(refused.code(), tonic::Code::DataLoss);
            assert!(
                refused
                    .message()
                    .starts_with("session store refused: create session store "),
                "{refused:?}"
            );
            let diagnostics = health(service.clone()).await;
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].name, "session-store");
            assert!(!diagnostics[0].healthy);
            assert!(
                diagnostics[0]
                    .message
                    .starts_with("refused: create session store "),
                "{diagnostics:?}"
            );
        }
        std::fs::remove_file(&store).unwrap();
        let listed = service
            .list_sessions(request(v1::ListSessionsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(listed.sessions.is_empty());
        assert!(health(service).await.is_empty());
    }

    #[tokio::test]
    async fn app_ports_are_replaced_only_by_an_authenticated_bound_caller() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().to_path_buf(),
            home_root: temp.path().to_path_buf(),
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new(TEST_AUTH_TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        // A daemon that serves no tailnet refuses the push.
        let unbound = DaemonServiceImpl::new(config.clone());
        let error = unbound
            .set_app_ports(app_ports_request(Some(TEST_AUTH_TOKEN), vec![3000]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let (app_ports, current) =
            tokio::sync::watch::channel(crate::app_ports::AppPorts::from([8080]));
        let bound = DaemonServiceImpl::new(config).with_app_ports(app_ports);
        for token in [None, Some("wrong-daemon-token")] {
            let error = bound
                .set_app_ports(app_ports_request(token, vec![3000]))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::Unauthenticated);
        }
        let error = bound
            .set_app_ports(app_ports_request(Some(TEST_AUTH_TOKEN), vec![3000, 0]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(*current.borrow(), crate::app_ports::AppPorts::from([8080]));

        bound
            .set_app_ports(app_ports_request(Some(TEST_AUTH_TOKEN), vec![5173, 3000]))
            .await
            .unwrap();
        assert_eq!(
            *current.borrow(),
            crate::app_ports::AppPorts::from([3000, 5173])
        );
        bound
            .set_app_ports(app_ports_request(Some(TEST_AUTH_TOKEN), Vec::new()))
            .await
            .unwrap();
        assert!(current.borrow().is_empty());
    }

    /// Wait until the fixture shell has disabled echo and said so. Its start
    /// under load is not what these tests measure, so this waits on that
    /// state rather than a clock; a shell that ends first fails.
    async fn wait_attach_fixture_ready(
        temp: &tempfile::TempDir,
        engine: &SessionEngine,
        session_id: &str,
    ) {
        while !std::fs::read_to_string(temp.path().join("home/attach-ready"))
            .as_deref()
            .is_ok_and(|value| value == "ready")
        {
            assert_attach_fixture_live(engine, session_id).await;
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn assert_attach_fixture_live(engine: &SessionEngine, session_id: &str) {
        assert!(
            is_attached_session_live(engine.get(session_id).await.unwrap().state),
            "the fixture shell ended before writing its evidence"
        );
    }

    /// A browser terminal types each key as its own small frame. While the
    /// terminal is not taking input, the attachment still reads every frame
    /// as it arrives, so none waits unread in HTTP/2, whose flood guard
    /// would end the connection (#2822); the process then receives every
    /// byte once, in order.
    #[tokio::test]
    async fn recorded_output_wakes_a_watching_attachment() {
        // #3827: an attachment learns of new output when it is recorded, not
        // on its next poll, so a keystroke's echo is not held for a tick.
        let (temp, engine) = attach_engine();
        let session = engine
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "printf ready > attach-ready; exec sleep 30".into(),
                ],
                pty: true,
                term: "xterm-256color".into(),
                width: 80,
                height: 24,
                ..Default::default()
            })
            .await
            .unwrap();
        wait_attach_fixture_ready(&temp, &engine, &session.session_id).await;
        let mut output = engine.watch_output(&session.session_id).unwrap();
        let before = *output.borrow_and_update();
        engine
            .append_test_output(&session.session_id, b"echo")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), output.changed())
            .await
            .expect("recorded output woke the watcher")
            .unwrap();
        assert!(*output.borrow_and_update() >= before + 4);
    }

    #[tokio::test]
    #[ignore = "manual measurement: run with --ignored --nocapture"]
    async fn attach_echo_latency_report() {
        // Manual measurement (#3827): the daemon's own share of a keystroke's
        // round trip. One byte goes into `cat` through an attachment and is
        // timed until its echo comes back out of the same attachment.
        const ROUNDS: usize = 200;
        let (temp, engine) = attach_engine();
        let session = engine
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    "stty raw -echo; printf ready > attach-ready; exec cat".into(),
                ],
                pty: true,
                term: "xterm-256color".into(),
                width: 80,
                height: 24,
                ..Default::default()
            })
            .await
            .unwrap();
        wait_attach_fixture_ready(&temp, &engine, &session.session_id).await;
        let (input, incoming) = mpsc::channel(8);
        let (output, mut received) = mpsc::channel(32);
        let _owner = tokio::spawn(run_attach_session(
            engine.clone(),
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session.session_id.clone(),
                output_offset: 0,
            },
            output,
        ));
        let mut samples = Vec::with_capacity(ROUNDS);
        for round in 0..ROUNDS {
            let byte = b'a' + (round % 26) as u8;
            let started = std::time::Instant::now();
            input
                .send(Ok(v1::SessionAttachMessage {
                    payload: Some(v1::session_attach_message::Payload::Input(
                        v1::SessionInput { data: vec![byte] },
                    )),
                }))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let message = received.recv().await.unwrap().unwrap();
                    if let Some(v1::session_attach_message::Payload::Output(chunk)) =
                        message.payload
                        && chunk.data.contains(&byte)
                    {
                        break;
                    }
                }
            })
            .await
            .expect("echo arrived");
            samples.push(started.elapsed());
        }
        samples.sort();
        let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q) as usize];
        eprintln!(
            "attach echo over {ROUNDS} rounds: min {:?} median {:?} p95 {:?} max {:?}",
            samples[0],
            at(0.5),
            at(0.95),
            samples[samples.len() - 1]
        );
    }

    #[tokio::test]
    async fn attach_reads_input_while_the_terminal_is_busy() {
        const FRAMES: usize = 2000;
        const FRAME: usize = 64;
        let expected: Vec<u8> = (0..FRAMES * FRAME)
            .map(|index| b'0' + (index % 10) as u8)
            .collect();
        let (temp, engine) = attach_engine();
        let session = engine
            .launch(v1::LaunchSessionRequest {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    format!(
                        "stty raw -echo; printf ready > attach-ready; \
                         while [ ! -e go ]; do sleep 0.05; done; \
                         head -c {} > attach-input; exec sleep 30",
                        expected.len()
                    ),
                ],
                pty: true,
                term: "xterm-256color".into(),
                width: 80,
                height: 24,
                ..Default::default()
            })
            .await
            .unwrap();
        wait_attach_fixture_ready(&temp, &engine, &session.session_id).await;
        let (input, incoming) = mpsc::channel(8);
        let (output, _unread) = mpsc::channel(32);
        let owner = tokio::spawn(run_attach_session(
            engine.clone(),
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session.session_id.clone(),
                output_offset: 0,
            },
            output,
        ));
        // More than the terminal holds, while its process reads nothing.
        tokio::time::timeout(Duration::from_secs(5), async {
            for frame in expected.chunks(FRAME) {
                input
                    .send(Ok(v1::SessionAttachMessage {
                        payload: Some(v1::session_attach_message::Payload::Input(
                            v1::SessionInput {
                                data: frame.to_vec(),
                            },
                        )),
                    }))
                    .await
                    .unwrap();
            }
        })
        .await
        .expect("the attachment stopped reading input while the terminal was busy");
        std::fs::write(temp.path().join("home/go"), b"").unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while std::fs::read(temp.path().join("home/attach-input"))
                .ok()
                .is_none_or(|written| written.len() < expected.len())
            {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the process received its input");
        assert_eq!(
            std::fs::read(temp.path().join("home/attach-input")).unwrap(),
            expected
        );
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
        tokio::time::timeout(Duration::from_secs(5), owner)
            .await
            .expect("detach ends the attachment")
            .unwrap();
    }

    #[test]
    fn attach_input_joins_consecutive_input_only_and_output_reads_merge() {
        use v1::session_attach_message::Payload;
        let input = |data: &[u8]| {
            Some(v1::SessionAttachMessage {
                payload: Some(Payload::Input(v1::SessionInput {
                    data: data.to_vec(),
                })),
            })
        };
        let resize = Some(v1::SessionAttachMessage {
            payload: Some(Payload::Resize(v1::ResizeRequest {
                width: 90,
                height: 30,
            })),
        });
        let mut queue = AttachInputQueue::default();
        for message in [
            input(b"a"),
            input(b"b"),
            resize.clone(),
            input(b"c"),
            input(&vec![b'd'; MAX_COALESCED_ATTACH_INPUT]),
            None,
        ] {
            queue.push(message);
        }
        assert_eq!(
            queue.bytes,
            3 + MAX_COALESCED_ATTACH_INPUT + 2 * ATTACH_CONTROL_COST
        );
        let order: Vec<_> = std::iter::from_fn(|| queue.pop()).collect();
        assert_eq!(
            order,
            [
                input(b"ab"),
                resize,
                input(b"c"),
                input(&vec![b'd'; MAX_COALESCED_ATTACH_INPUT]),
                None
            ]
        );
        assert_eq!(queue.bytes, 0);

        let chunk =
            |offset: u64, data: &[u8], stream: v1::SessionOutputStream| v1::SessionOutputChunk {
                offset,
                next_offset: offset + data.len() as u64,
                stream: stream.into(),
                data: data.to_vec(),
            };
        let pty = v1::SessionOutputStream::Pty;
        let merged = merge_output_chunks(vec![
            chunk(0, b"ab", pty),
            chunk(2, b"cd", pty),
            chunk(10, b"after a gap", pty),
            chunk(21, b"other", v1::SessionOutputStream::Stdout),
        ]);
        assert_eq!(
            merged,
            [
                chunk(0, b"abcd", pty),
                chunk(10, b"after a gap", pty),
                chunk(21, b"other", v1::SessionOutputStream::Stdout)
            ]
        );
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
                 // The shell outlives TRANSCRIPT_HANG; the test stops it.
                "stty -echo; printf ready > attach-ready; IFS= read -r line; printf '%s' \"$line\" > attach-input; stty size > attach-size; exec sleep 600".into()],
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            ..Default::default()
        }).await.unwrap();
        wait_attach_fixture_ready(&temp, &engine, &session.session_id).await;
        // Prepare the full production-sized transcript deterministically. This
        // is disk setup, not part of what the controls below prove.
        tokio::time::timeout(
            TRANSCRIPT_HANG,
            engine.append_test_output(&session.session_id, &vec![0; output_bytes as usize]),
        )
        .await
        .expect("bounded transcript preparation")
        .unwrap();
        assert_eq!(
            engine
                .get(&session.session_id)
                .await
                .unwrap()
                .output_end_offset,
            output_bytes
        );
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
        // The replay fills every response slot, and nothing reads them.
        while capacity.capacity() != 0 {
            assert!(
                !owner.is_finished(),
                "the attachment ended before it filled its response slots"
            );
            sleep(Duration::from_millis(10)).await;
        }
        // Nothing reads a response frame until the end, so an attachment
        // that waited for its reader, or for a lock behind it, would never
        // apply these controls; applying them at all proves it did not. The
        // proof is the controls' effects, not a clock: under load the shell
        // can take any time to run, and that is not what this measures
        // (#2442). A control that fails, or outlives the attachment's own
        // control deadline, ends the attachment, which fails here.
        for payload in [
            v1::session_attach_message::Payload::Resize(v1::ResizeRequest {
                width: 132,
                height: 43,
            }),
            v1::session_attach_message::Payload::Input(v1::SessionInput {
                data: b"fair-input\n".to_vec(),
            }),
        ] {
            input
                .send(Ok(v1::SessionAttachMessage {
                    payload: Some(payload),
                }))
                .await
                .unwrap();
        }
        // The shell reads the input line and then reports its terminal size,
        // so its evidence shows both reached it, in that order.
        let size = loop {
            if let Ok(size) = std::fs::read_to_string(temp.path().join("home/attach-size"))
                && size.ends_with('\n')
            {
                break size;
            }
            assert!(
                !owner.is_finished(),
                "the attachment ended before its controls reached the shell"
            );
            assert_attach_fixture_live(&engine, &session.session_id).await;
            sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(size.trim(), "43 132");
        assert_eq!(
            std::fs::read_to_string(temp.path().join("home/attach-input")).unwrap(),
            "fair-input"
        );
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
        // Still unread, so the attachment ends without waiting for its reader.
        owner.await.unwrap();
        assert_eq!(capacity.capacity(), 0);
        let record = engine.get(&session.session_id).await.unwrap();
        assert_eq!(record.state, v1::SessionLifecycleState::Running as i32);
        assert_eq!(record.status_message, "session resized to 132x43");
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
        let (temp, engine) = attach_engine();
        let session = engine.launch(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(),
                 // The shell outlives TRANSCRIPT_HANG; the test stops it.
                "stty -echo; printf ready > attach-ready; IFS= read -r line; printf '%s' \"$line\" > later-gap-input; exec sleep 600".into()],
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            ..Default::default()
        }).await.unwrap();
        wait_attach_fixture_ready(&temp, &engine, &session.session_id).await;
        tokio::time::timeout(
            TRANSCRIPT_HANG,
            engine.append_test_output(&session.session_id, &vec![0; 262144]),
        )
        .await
        .expect("initial transcript preparation")
        .unwrap();
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
        tokio::time::timeout(Duration::from_secs(3), async {
            while !std::fs::read_to_string(temp.path().join("home/later-gap-input"))
                .as_deref()
                .is_ok_and(|value| value == "produce")
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("input is consumed while replay is blocked");
        assert_eq!(capacity.capacity(), 0);
        tokio::time::timeout(
            TRANSCRIPT_HANG,
            engine.append_test_output(&session.session_id, &vec![0; 9437184]),
        )
        .await
        .expect("transcript compacted while attachment was blocked")
        .unwrap();
        let record = engine.get(&session.session_id).await.unwrap();
        assert_eq!(record.output_end_offset, 262144 + 9437184);
        assert!(record.output_start_offset > 0);
        let end = record.output_end_offset;
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

    /// Holds the session's metadata lock as output capture does across a
    /// chunk's write and fdatasync, long enough for the attachment's idle
    /// read (every 10 ms) to queue behind it; `release` lets it go.
    async fn hold_metadata_behind_attach_read(
        engine: &SessionEngine,
        session_id: &str,
    ) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
        let (held, acquired) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let holder = tokio::spawn({
            let engine = engine.clone();
            let session_id = session_id.to_owned();
            async move {
                engine
                    .hold_test_metadata_lock(&session_id, held, released)
                    .await
                    .unwrap();
            }
        });
        acquired.await.unwrap();
        sleep(Duration::from_millis(100)).await;
        (release, holder)
    }

    /// Closing one browser terminal tab refits the surviving one, so its
    /// attachment resizes the PTY while the shell redraws. Resize and detach
    /// wait for the session's metadata lock, which output capture holds
    /// across each chunk's write and fdatasync, and which the attachment's
    /// own pending read waits for as well. Once capture lets go, the control
    /// gets the lock: the attachment never leaves its own read holding it
    /// while the control waits, which stalled the terminal's input until the
    /// 5 s control deadline ended it (#2484).
    #[tokio::test]
    async fn attach_controls_never_wait_behind_their_own_pending_read() {
        let (temp, engine) = attach_engine();
        let session = engine.launch(v1::LaunchSessionRequest {
            command: vec!["sh".into(), "-c".into(),
                "stty -echo; printf ready > attach-ready; IFS= read -r line; printf '%s' \"$line\" > attach-input; stty size > attach-size; exec sleep 30".into()],
            pty: true,
            term: "xterm-256color".into(),
            width: 80,
            height: 24,
            ..Default::default()
        }).await.unwrap();
        wait_attach_fixture_ready(&temp, &engine, &session.session_id).await;
        let (input, incoming) = mpsc::channel(8);
        let (output, mut replies) = mpsc::channel(32);
        let owner = tokio::spawn(run_attach_session(
            engine.clone(),
            ReceiverStream::new(incoming),
            v1::AttachSessionRequest {
                session_id: session.session_id.clone(),
                output_offset: 0,
            },
            output,
        ));
        let control = |payload| {
            let input = input.clone();
            async move {
                input
                    .send(Ok(v1::SessionAttachMessage {
                        payload: Some(payload),
                    }))
                    .await
                    .unwrap();
            }
        };

        let (release, holder) =
            hold_metadata_behind_attach_read(&engine, &session.session_id).await;
        control(v1::session_attach_message::Payload::Resize(
            v1::ResizeRequest {
                width: 132,
                height: 43,
            },
        ))
        .await;
        control(v1::session_attach_message::Payload::Input(
            v1::SessionInput {
                data: b"after-resize\n".to_vec(),
            },
        ))
        .await;
        sleep(Duration::from_millis(100)).await;
        release.send(()).unwrap();
        holder.await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let input = std::fs::read_to_string(temp.path().join("home/attach-input"));
                let size = std::fs::read_to_string(temp.path().join("home/attach-size"));
                if input.as_deref().is_ok_and(|input| input == "after-resize")
                    && size.as_deref().is_ok_and(|size| size.trim() == "43 132")
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("resize and the input after it apply once capture releases the lock");

        let (release, holder) =
            hold_metadata_behind_attach_read(&engine, &session.session_id).await;
        control(v1::session_attach_message::Payload::Detach(
            v1::DetachSessionRequest {
                session_id: session.session_id.clone(),
            },
        ))
        .await;
        sleep(Duration::from_millis(100)).await;
        release.send(()).unwrap();
        holder.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .expect("detach completes once capture releases the lock")
            .unwrap();
        while let Ok(reply) = replies.try_recv() {
            let reply = reply.expect("the attachment never ends with a control deadline");
            if let Some(v1::session_attach_message::Payload::Status(status)) = reply.payload {
                assert!(is_attached_session_live(status.state));
            }
        }
        engine.stop(&session.session_id).await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn host_rpc_policy_advertises_only_session_capabilities_and_rejects_guest_effects() {
        use std::marker::PhantomData;
        struct Decoder<T>(PhantomData<T>);
        impl<T> tonic::codec::Decoder for Decoder<T> {
            type Item = T;
            type Error = Status;
            fn decode(
                &mut self,
                _buffer: &mut tonic::codec::DecodeBuf<'_>,
            ) -> Result<Option<T>, Status> {
                panic!("host guest-only RPC must reject before reading stream frames")
            }
        }
        fn stream<T: Send + 'static>() -> Streaming<T> {
            Streaming::new_request(Decoder(PhantomData), axum::body::Body::empty(), None, None)
        }
        fn authorized<T>(value: T) -> Request<T> {
            let mut request = Request::new(value);
            request
                .metadata_mut()
                .insert(DAEMON_AUTH_TOKEN_HEADER, TEST_AUTH_TOKEN.parse().unwrap());
            request
        }
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().join("workspace"),
            home_root: temp.path().join("home"),
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new(TEST_AUTH_TOKEN).unwrap(),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
            host: Some(crate::HostConfig {
                state_root: temp.path().join("state"),
            }),
            session_working_dir: None,
        };
        let (app_ports, current_ports) =
            tokio::sync::watch::channel(crate::app_ports::AppPorts::from([8080]));
        let service = DaemonServiceImpl::new(config).with_app_ports(app_ports);
        let capabilities = service
            .get_capabilities(authorized(v1::GetCapabilitiesRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            capabilities.capabilities,
            codewire_daemon_proto::HOST_DAEMON_CAPABILITIES
        );
        assert_eq!(
            service
                .set_app_ports(authorized(v1::SetAppPortsRequest { ports: vec![3000] }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            *current_ports.borrow(),
            crate::app_ports::AppPorts::from([8080])
        );
        assert_eq!(
            service
                .poweroff_guest(authorized(v1::PoweroffGuestRequest {}))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .exec_session(authorized(stream::<v1::ExecMessage>()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .pty_session(authorized(stream::<v1::PtyMessage>()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert!(
            matches!(DaemonService::credential_bridge(&service, authorized(stream::<bridge_v1::CredentialBridgeHostMessage>())).await,
            Err(error) if error.code() == tonic::Code::PermissionDenied)
        );
        assert_eq!(
            service
                .list(authorized(v1::ListRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .stat(authorized(v1::StatRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .open_file(authorized(v1::OpenFileRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .read(authorized(v1::ReadRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .write(authorized(v1::WriteRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .mkdir(authorized(v1::MkdirRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .remove(authorized(v1::RemoveRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .rename(authorized(v1::RenameRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .set_stat(authorized(v1::SetStatRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            service
                .readlink(authorized(v1::ReadlinkRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert!(!temp.path().join("home/.codewire").exists());
        assert!(
            service
                .list_sessions(authorized(v1::ListSessionsRequest {}))
                .await
                .unwrap()
                .into_inner()
                .sessions
                .is_empty()
        );
        assert!(temp.path().join("state/sessions").exists());
        service.session_engine.shutdown().await.unwrap();
    }

    async fn spawn_daemon_with_auth(
        auth_token: &str,
    ) -> (tempfile::TempDir, SocketAddr, oneshot::Sender<()>) {
        spawn_daemon_placement(auth_token, false).await
    }

    async fn spawn_daemon_placement(
        auth_token: &str,
        host: bool,
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
            mount_roots: Vec::new(),
            auth_token: DaemonAuthToken::new(auth_token).expect("valid daemon test token"),
            process_execution: crate::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: host.then(|| crate::HostConfig {
                state_root: temp.path().join("state"),
            }),
            launch_projection: None,
            session_working_dir: None,
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
