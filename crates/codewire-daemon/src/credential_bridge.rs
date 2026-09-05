use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::post;
use bytes::Bytes as WireBytes;
use codewire_gateway_proto::daemon::v1;
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADERS, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT,
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES, CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use tokio::net::{UnixListener, UnixStream, unix::SocketAddr};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::CredentialBridgeConfig;

const HOST_OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const FIRST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const HOST_OUTPUT_BUFFER: usize = 32;
const RESPONSE_BODY_BUFFER: usize = 16;

type GuestOutput = mpsc::Sender<Result<v1::CredentialBridgeGuestMessage, Status>>;
type ResponseBodyItem = Result<WireBytes, io::Error>;

#[derive(Clone)]
pub(crate) struct CredentialBridge {
    config: Option<CredentialBridgeConfig>,
    inner: Arc<Mutex<BridgeState>>,
}

struct BridgeState {
    next_epoch: u64,
    active: Option<ActiveHost>,
    pending: BTreeMap<String, PendingResponse>,
}

struct ActiveHost {
    epoch: u64,
    output: GuestOutput,
    cancel: oneshot::Sender<()>,
}

struct PendingResponse {
    epoch: u64,
    phase: ResponsePhase,
    received_bytes: usize,
    start: Option<oneshot::Sender<Result<ResponseStart, BridgeFailure>>>,
    body: mpsc::Sender<ResponseBodyItem>,
    completed: Arc<AtomicBool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResponsePhase {
    AwaitingStart,
    Streaming,
    Cancelled,
}

struct ResponseStart {
    status: StatusCode,
    headers: HeaderMap,
}

#[derive(Clone, Copy)]
enum BridgeFailure {
    Denied,
    Unavailable,
    Upstream,
    TooLarge,
}

pub(crate) struct CredentialBridgeConnection {
    pub output: ReceiverStream<Result<v1::CredentialBridgeGuestMessage, Status>>,
}

pub(crate) struct CredentialIngress {
    listener: CredentialIngressListener,
    bridge: CredentialBridge,
    socket: SocketGuard,
}

struct CredentialIngressListener {
    inner: UnixListener,
    uid: u32,
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

struct BridgeBodyStream {
    inner: ReceiverStream<ResponseBodyItem>,
    cancellation: PendingCancellation,
    completed: Arc<AtomicBool>,
    failure_emitted: bool,
}

struct PendingCancellation {
    bridge: CredentialBridge,
    request_id: Option<String>,
    epoch: u64,
}

impl CredentialBridge {
    pub(crate) fn new(config: Option<CredentialBridgeConfig>) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(BridgeState {
                next_epoch: 0,
                active: None,
                pending: BTreeMap::new(),
            })),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.config.is_some()
    }

    pub(crate) async fn connect(
        &self,
        mut input: Streaming<v1::CredentialBridgeHostMessage>,
    ) -> Result<CredentialBridgeConnection, Status> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("credential bridge is unavailable"))?;
        let first = tokio::time::timeout(HOST_OPEN_TIMEOUT, input.message())
            .await
            .map_err(|_| Status::deadline_exceeded("credential bridge open timed out"))??
            .ok_or_else(|| Status::invalid_argument("credential bridge open is missing"))?;
        let Some(v1::credential_bridge_host_message::Payload::Open(open)) = first.payload else {
            return Err(Status::invalid_argument(
                "credential bridge must begin with open",
            ));
        };
        if open.protocol_version != CREDENTIAL_BRIDGE_PROTOCOL_VERSION
            || open.environment_id != config.environment_id.to_string()
            || open.environment_generation != config.environment_generation
        {
            return Err(Status::failed_precondition(
                "credential bridge identity is invalid",
            ));
        }

        let (output_tx, output_rx) = mpsc::channel(HOST_OUTPUT_BUFFER);
        output_tx
            .try_send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::Ready(v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: config.environment_id.to_string(),
                    environment_generation: config.environment_generation,
                }),
            )))
            .map_err(|_| Status::resource_exhausted("credential bridge output is unavailable"))?;
        let (cancel_tx, cancel_rx) = oneshot::channel();

        let (epoch, replaced, stale) = {
            let mut state = self.inner.lock().await;
            state.next_epoch = state
                .next_epoch
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("credential bridge epoch exhausted"))?;
            let epoch = state.next_epoch;
            let replaced = state.active.replace(ActiveHost {
                epoch,
                output: output_tx.clone(),
                cancel: cancel_tx,
            });
            let stale = take_pending(&mut state, |_| true);
            (epoch, replaced, stale)
        };
        if let Some(replaced) = replaced {
            let _ = replaced.cancel.send(());
        }
        fail_pending(stale, BridgeFailure::Unavailable);

        let bridge = self.clone();
        tokio::spawn(async move {
            bridge
                .read_host_stream(epoch, input, output_tx, cancel_rx)
                .await;
        });
        Ok(CredentialBridgeConnection {
            output: ReceiverStream::new(output_rx),
        })
    }

    async fn read_host_stream(
        self,
        epoch: u64,
        mut input: Streaming<v1::CredentialBridgeHostMessage>,
        output: GuestOutput,
        mut cancel: oneshot::Receiver<()>,
    ) {
        let result = loop {
            tokio::select! {
                _ = &mut cancel => break Ok(()),
                message = input.message() => match message {
                    Ok(Some(message)) => {
                        if let Err(error) = self.apply_host_message(epoch, message).await {
                            break Err(error);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(_) => break Err(Status::unavailable("credential bridge host stream failed")),
                }
            }
        };
        if let Err(error) = result {
            let _ = output.try_send(Err(error));
        }
        self.detach(epoch).await;
    }

    async fn apply_host_message(
        &self,
        epoch: u64,
        message: v1::CredentialBridgeHostMessage,
    ) -> Result<(), Status> {
        use v1::credential_bridge_host_message::Payload;

        match message.payload {
            Some(Payload::ResponseStart(response)) => {
                let status = StatusCode::from_u16(
                    u16::try_from(response.status_code).map_err(|_| invalid_host_frame())?,
                )
                .map_err(|_| invalid_host_frame())?;
                if status.is_informational() {
                    return Err(invalid_host_frame());
                }
                let headers = headers_from_proto(&response.headers)?;
                let sender = {
                    let mut state = self.inner.lock().await;
                    require_active_epoch(&state, epoch)?;
                    let pending = state
                        .pending
                        .get_mut(&response.request_id)
                        .ok_or_else(invalid_host_frame)?;
                    if pending.epoch != epoch {
                        return Err(invalid_host_frame());
                    }
                    match pending.phase {
                        ResponsePhase::AwaitingStart => {
                            pending.phase = ResponsePhase::Streaming;
                            Some(pending.start.take().ok_or_else(invalid_host_frame)?)
                        }
                        ResponsePhase::Cancelled => None,
                        ResponsePhase::Streaming => return Err(invalid_host_frame()),
                    }
                };
                if let Some(sender) = sender {
                    sender
                        .send(Ok(ResponseStart { status, headers }))
                        .map_err(|_| {
                            Status::cancelled("credential bridge request was cancelled")
                        })?;
                }
                Ok(())
            }
            Some(Payload::ResponseBody(response)) => {
                if response.data.is_empty()
                    || response.data.len() > CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES
                {
                    return Err(invalid_host_frame());
                }
                let sender = {
                    let mut state = self.inner.lock().await;
                    require_active_epoch(&state, epoch)?;
                    let pending = state
                        .pending
                        .get_mut(&response.request_id)
                        .ok_or_else(invalid_host_frame)?;
                    if pending.epoch != epoch || pending.phase == ResponsePhase::AwaitingStart {
                        return Err(invalid_host_frame());
                    }
                    pending.received_bytes = pending
                        .received_bytes
                        .checked_add(response.data.len())
                        .filter(|bytes| *bytes <= CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES)
                        .ok_or_else(|| {
                            Status::resource_exhausted(
                                "credential bridge response exceeded its byte limit",
                            )
                        })?;
                    (pending.phase == ResponsePhase::Streaming).then(|| pending.body.clone())
                };
                if let Some(sender) = sender {
                    sender
                        .try_send(Ok(WireBytes::from(response.data)))
                        .map_err(|error| match error {
                            mpsc::error::TrySendError::Full(_) => Status::resource_exhausted(
                                "credential bridge response consumer is too slow",
                            ),
                            mpsc::error::TrySendError::Closed(_) => {
                                Status::cancelled("credential bridge request was cancelled")
                            }
                        })?;
                }
                Ok(())
            }
            Some(Payload::ResponseEnd(response)) => {
                let pending = {
                    let mut state = self.inner.lock().await;
                    require_active_epoch(&state, epoch)?;
                    let pending = state
                        .pending
                        .remove(&response.request_id)
                        .ok_or_else(invalid_host_frame)?;
                    if pending.epoch != epoch || pending.phase == ResponsePhase::AwaitingStart {
                        return Err(invalid_host_frame());
                    }
                    pending
                };
                pending.completed.store(true, Ordering::Release);
                drop(pending);
                Ok(())
            }
            Some(Payload::ResponseFailure(response)) => {
                let reason = match v1::CredentialBridgeFailureReason::try_from(response.reason) {
                    Ok(v1::CredentialBridgeFailureReason::Denied) => BridgeFailure::Denied,
                    Ok(v1::CredentialBridgeFailureReason::Unavailable) => {
                        BridgeFailure::Unavailable
                    }
                    Ok(v1::CredentialBridgeFailureReason::UpstreamFailed) => {
                        BridgeFailure::Upstream
                    }
                    Ok(v1::CredentialBridgeFailureReason::ResponseTooLarge) => {
                        BridgeFailure::TooLarge
                    }
                    _ => return Err(invalid_host_frame()),
                };
                let pending = {
                    let mut state = self.inner.lock().await;
                    require_active_epoch(&state, epoch)?;
                    let pending = state
                        .pending
                        .remove(&response.request_id)
                        .ok_or_else(invalid_host_frame)?;
                    if pending.epoch != epoch {
                        return Err(invalid_host_frame());
                    }
                    pending
                };
                fail_pending(vec![pending], reason);
                Ok(())
            }
            Some(Payload::Open(_)) | None => Err(invalid_host_frame()),
        }
    }

    async fn detach(&self, epoch: u64) {
        let stale = {
            let mut state = self.inner.lock().await;
            if state.active.as_ref().map(|active| active.epoch) != Some(epoch) {
                return;
            }
            state.active = None;
            take_pending(&mut state, |pending| pending.epoch == epoch)
        };
        fail_pending(stale, BridgeFailure::Unavailable);
    }

    async fn submit(
        &self,
        request: v1::CredentialBridgeRequest,
    ) -> Result<BridgeHttpResponse, BridgeFailure> {
        let request_id = request.request_id.clone();
        let (start_tx, start_rx) = oneshot::channel();
        let (body_tx, body_rx) = mpsc::channel(RESPONSE_BODY_BUFFER);
        let completed = Arc::new(AtomicBool::new(false));
        let (epoch, output) = {
            let mut state = self.inner.lock().await;
            let active = state.active.as_ref().ok_or(BridgeFailure::Unavailable)?;
            if state.pending.len() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                return Err(BridgeFailure::Unavailable);
            }
            if state.pending.contains_key(&request_id) {
                return Err(BridgeFailure::Unavailable);
            }
            let epoch = active.epoch;
            let output = active.output.clone();
            state.pending.insert(
                request_id.clone(),
                PendingResponse {
                    epoch,
                    phase: ResponsePhase::AwaitingStart,
                    received_bytes: 0,
                    start: Some(start_tx),
                    body: body_tx,
                    completed: Arc::clone(&completed),
                },
            );
            (epoch, output)
        };
        let mut cancellation = PendingCancellation::new(self.clone(), request_id.clone(), epoch);

        let send = output.send(Ok(guest_message(
            v1::credential_bridge_guest_message::Payload::Request(request),
        )));
        if !matches!(
            tokio::time::timeout(HOST_SEND_TIMEOUT, send).await,
            Ok(Ok(()))
        ) {
            self.detach(epoch).await;
            cancellation.disarm();
            return Err(BridgeFailure::Unavailable);
        }

        let start = match tokio::time::timeout(FIRST_RESPONSE_TIMEOUT, start_rx).await {
            Ok(Ok(Ok(start))) => start,
            Ok(Ok(Err(error))) => return Err(error),
            Ok(Err(_)) | Err(_) => {
                self.cancel(&request_id, epoch).await;
                cancellation.disarm();
                return Err(BridgeFailure::Unavailable);
            }
        };
        Ok(BridgeHttpResponse {
            start,
            body: BridgeBodyStream {
                inner: ReceiverStream::new(body_rx),
                cancellation,
                completed,
                failure_emitted: false,
            },
        })
    }

    async fn cancel(&self, request_id: &str, epoch: u64) {
        let output = {
            let mut state = self.inner.lock().await;
            let Some(pending) = state.pending.get_mut(request_id) else {
                return;
            };
            if pending.epoch != epoch || pending.phase == ResponsePhase::Cancelled {
                return;
            }
            pending.phase = ResponsePhase::Cancelled;
            drop(pending.start.take());
            state
                .active
                .as_ref()
                .filter(|active| active.epoch == epoch)
                .map(|active| active.output.clone())
        };
        if let Some(output) = output {
            let _ = output.try_send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::Cancel(v1::CredentialBridgeCancel {
                    request_id: request_id.to_owned(),
                }),
            )));
        }
    }

    pub(crate) fn prepare_ingress(&self) -> Result<Option<CredentialIngress>, io::Error> {
        let Some(config) = self.config.as_ref() else {
            return Ok(None);
        };
        validate_config(config)?;
        remove_stale_socket(&config.ingress_socket)?;
        let listener = UnixListener::bind(&config.ingress_socket)?;
        std::fs::set_permissions(
            &config.ingress_socket,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )?;
        chown_socket(
            &config.ingress_socket,
            config.ingress_uid,
            config.ingress_gid,
        )?;
        let metadata = std::fs::symlink_metadata(&config.ingress_socket)?;
        use std::os::unix::fs::MetadataExt as _;
        Ok(Some(CredentialIngress {
            listener: CredentialIngressListener {
                inner: listener,
                uid: config.ingress_uid,
            },
            bridge: self.clone(),
            socket: SocketGuard {
                path: config.ingress_socket.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        }))
    }
}

struct BridgeHttpResponse {
    start: ResponseStart,
    body: BridgeBodyStream,
}

impl CredentialIngress {
    pub(crate) async fn serve<F>(self, shutdown: F) -> Result<(), io::Error>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let bridge = self.bridge.clone();
        let router = Router::new()
            .route("/v1/responses", post(handle_responses))
            .with_state(bridge);
        let _socket = self.socket;
        axum::serve(self.listener, router)
            .with_graceful_shutdown(shutdown)
            .await
    }
}

async fn handle_responses(
    State(bridge): State<CredentialBridge>,
    request: Request<Body>,
) -> Response<Body> {
    match prepare_guest_request(request).await {
        Ok(request) => match bridge.submit(request).await {
            Ok(response) => {
                let mut built = Response::builder().status(response.start.status);
                if let Some(headers) = built.headers_mut() {
                    *headers = response.start.headers;
                }
                built
                    .body(Body::from_stream(response.body))
                    .unwrap_or_else(|_| fixed_response(StatusCode::BAD_GATEWAY))
            }
            Err(error) => fixed_response(error.status()),
        },
        Err(status) => fixed_response(status),
    }
}

async fn prepare_guest_request(
    request: Request<Body>,
) -> Result<v1::CredentialBridgeRequest, StatusCode> {
    if request.method() != Method::POST
        || request.uri().path() != "/v1/responses"
        || request.uri().query().is_some()
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let headers = headers_to_proto(request.headers()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body = to_bytes(request.into_body(), CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    Ok(v1::CredentialBridgeRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        method: Method::POST.as_str().to_owned(),
        path: "/responses".to_owned(),
        query: String::new(),
        headers,
        body: body.to_vec(),
    })
}

fn headers_to_proto(headers: &HeaderMap) -> Result<Vec<v1::CredentialHttpHeader>, ()> {
    if headers.len() > CREDENTIAL_BRIDGE_MAX_HEADERS {
        return Err(());
    }
    let mut total = 0_usize;
    let mut result = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if prohibited_framing_header(name) {
            continue;
        }
        total = total
            .checked_add(name.as_str().len())
            .and_then(|bytes| bytes.checked_add(value.as_bytes().len()))
            .ok_or(())?;
        if name.as_str().len() > CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES
            || value.as_bytes().len() > CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES
            || total > CREDENTIAL_BRIDGE_MAX_HEADER_BYTES
        {
            return Err(());
        }
        result.push(v1::CredentialHttpHeader {
            name: name.as_str().to_owned(),
            value: value.as_bytes().to_vec(),
        });
    }
    Ok(result)
}

fn headers_from_proto(headers: &[v1::CredentialHttpHeader]) -> Result<HeaderMap, Status> {
    if headers.len() > CREDENTIAL_BRIDGE_MAX_HEADERS {
        return Err(invalid_host_frame());
    }
    let mut total = 0_usize;
    let mut result = HeaderMap::new();
    for header in headers {
        if header.name.len() > CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES
            || header.value.len() > CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES
        {
            return Err(invalid_host_frame());
        }
        total = total
            .checked_add(header.name.len())
            .and_then(|bytes| bytes.checked_add(header.value.len()))
            .ok_or_else(invalid_host_frame)?;
        if total > CREDENTIAL_BRIDGE_MAX_HEADER_BYTES {
            return Err(invalid_host_frame());
        }
        let name =
            HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| invalid_host_frame())?;
        if name.as_str() != header.name || prohibited_framing_header(&name) {
            return Err(invalid_host_frame());
        }
        let value = HeaderValue::from_bytes(&header.value).map_err(|_| invalid_host_frame())?;
        result.append(name, value);
    }
    Ok(result)
}

fn prohibited_framing_header(name: &HeaderName) -> bool {
    *name == CONNECTION
        || *name == CONTENT_LENGTH
        || *name == TRANSFER_ENCODING
        || *name == UPGRADE
        || name.as_str() == "proxy-connection"
        || name.as_str() == "keep-alive"
        || name.as_str() == "trailer"
}

fn fixed_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from("credential route unavailable\n"))
        .expect("fixed credential response is valid")
}

fn guest_message(
    payload: v1::credential_bridge_guest_message::Payload,
) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(payload),
    }
}

fn invalid_host_frame() -> Status {
    Status::invalid_argument("credential bridge host frame is invalid")
}

fn require_active_epoch(state: &BridgeState, epoch: u64) -> Result<(), Status> {
    if state.active.as_ref().map(|active| active.epoch) == Some(epoch) {
        Ok(())
    } else {
        Err(Status::aborted("credential bridge was replaced"))
    }
}

fn take_pending(
    state: &mut BridgeState,
    predicate: impl Fn(&PendingResponse) -> bool,
) -> Vec<PendingResponse> {
    let keys = state
        .pending
        .iter()
        .filter_map(|(key, pending)| predicate(pending).then_some(key.clone()))
        .collect::<Vec<_>>();
    keys.into_iter()
        .filter_map(|key| state.pending.remove(&key))
        .collect()
}

fn fail_pending(pending: Vec<PendingResponse>, failure: BridgeFailure) {
    for mut pending in pending {
        if let Some(start) = pending.start.take() {
            let _ = start.send(Err(failure));
        } else {
            let _ = pending.body.try_send(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "credential bridge response failed",
            )));
        }
    }
}

impl BridgeFailure {
    fn status(self) -> StatusCode {
        match self {
            Self::Denied => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Upstream | Self::TooLarge => StatusCode::BAD_GATEWAY,
        }
    }
}

impl Stream for BridgeBodyStream {
    type Item = ResponseBodyItem;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Ready(Some(Err(error))) => {
                self.cancellation.disarm();
                self.failure_emitted = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.cancellation.disarm();
                if self.completed.load(Ordering::Acquire) || self.failure_emitted {
                    Poll::Ready(None)
                } else {
                    self.failure_emitted = true;
                    Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "credential bridge response ended without completion",
                    ))))
                }
            }
            other => other,
        }
    }
}

impl PendingCancellation {
    fn new(bridge: CredentialBridge, request_id: String, epoch: u64) -> Self {
        Self {
            bridge,
            request_id: Some(request_id),
            epoch,
        }
    }

    fn disarm(&mut self) {
        self.request_id = None;
    }
}

impl Drop for PendingCancellation {
    fn drop(&mut self) {
        if let Some(request_id) = self.request_id.take() {
            let bridge = self.bridge.clone();
            let epoch = self.epoch;
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    bridge.cancel(&request_id, epoch).await;
                });
            }
        }
    }
}

impl axum::serve::Listener for CredentialIngressListener {
    type Io = UnixStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, address)) => match stream.peer_cred() {
                    Ok(credential) if credential.uid() == self.uid => return (stream, address),
                    Ok(_) | Err(_) => continue,
                },
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn validate_config(config: &CredentialBridgeConfig) -> Result<(), io::Error> {
    if config.environment_id.is_nil()
        || config.environment_generation == 0
        || !config.ingress_socket.is_absolute()
        || config.ingress_socket.file_name().is_none()
        || config.ingress_socket.parent().is_none()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential bridge configuration is invalid",
        ));
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::FileTypeExt as _;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential bridge ingress path contains an unexpected object",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn chown_socket(path: &Path, uid: u32, gid: u32) -> Result<(), io::Error> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket path contains NUL"))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    use codewire_gateway_proto::DAEMON_CAPABILITY_CREDENTIAL_BRIDGE;
    use codewire_gateway_proto::daemon::v1::credential_bridge_guest_message::Payload as GuestPayload;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::oneshot;
    use tokio_stream::StreamExt as _;
    use tokio_stream::wrappers::TcpListenerStream;

    use super::*;
    use crate::client::{SessionClient, SessionClientError};
    use crate::execution::ProcessExecution;
    use crate::{Config, serve_grpc_with_incoming};

    const TEST_TOKEN: &str = "credential-bridge-test-generation-token";

    struct Harness {
        _temp: tempfile::TempDir,
        endpoint: String,
        socket: PathBuf,
        environment_id: uuid::Uuid,
        generation: u64,
        shutdown: Option<oneshot::Sender<()>>,
        server: tokio::task::JoinHandle<anyhow::Result<()>>,
    }

    impl Harness {
        async fn start() -> Self {
            let temp = tempfile::tempdir().expect("harness tempdir");
            let workspace_root = temp.path().join("workspace");
            let home_root = temp.path().join("home");
            let socket = temp.path().join("credential.sock");
            std::fs::create_dir_all(&workspace_root).expect("workspace root");
            std::fs::create_dir_all(&home_root).expect("home root");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("daemon listener");
            let endpoint = format!("http://{}", listener.local_addr().expect("daemon address"));
            let environment_id = uuid::Uuid::new_v4();
            let generation = 7;
            let config = Config {
                listen_addr: "injected:credential-bridge".to_owned(),
                workspace_root,
                home_root,
                auth_token: Some(TEST_TOKEN.to_owned()),
                process_execution: ProcessExecution::Native,
                credential_bridge: Some(CredentialBridgeConfig {
                    environment_id,
                    environment_generation: generation,
                    ingress_socket: socket.clone(),
                    ingress_uid: unsafe { libc::geteuid() },
                    ingress_gid: unsafe { libc::getegid() },
                }),
            };
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                serve_grpc_with_incoming(config, TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while !socket.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("credential ingress readiness");
            let metadata = std::fs::symlink_metadata(&socket).expect("credential socket");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            Self {
                _temp: temp,
                endpoint,
                socket,
                environment_id,
                generation,
                shutdown: Some(shutdown_tx),
                server,
            }
        }

        async fn client(&self, token: &str) -> SessionClient {
            SessionClient::connect(&self.endpoint, token)
                .await
                .expect("daemon client")
        }

        async fn stop(mut self) {
            self.shutdown.take().expect("shutdown sender").send(()).ok();
            self.server
                .await
                .expect("server task")
                .expect("server stop");
            assert!(!self.socket.exists());
        }
    }

    async fn raw_request(socket: PathBuf, body: &'static [u8]) -> Vec<u8> {
        let mut stream = UnixStream::connect(socket)
            .await
            .expect("credential ingress");
        let head = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("request head");
        stream.write_all(body).await.expect("request body");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("HTTP response");
        response
    }

    #[tokio::test]
    async fn authenticated_bridge_carries_only_bounded_guest_request_and_redacted_response() {
        let harness = Harness::start().await;

        let unavailable = raw_request(harness.socket.clone(), br#"{"model":"synthetic"}"#).await;
        assert!(
            unavailable.starts_with(b"HTTP/1.1 503 Service Unavailable"),
            "unexpected unavailable response: {}",
            String::from_utf8_lossy(&unavailable)
        );

        let client = harness.client(TEST_TOKEN).await;
        let capabilities = client
            .get_capabilities(&[DAEMON_CAPABILITY_CREDENTIAL_BRIDGE])
            .await
            .expect("credential bridge capability");
        assert!(
            capabilities
                .capabilities
                .iter()
                .any(|capability| capability == DAEMON_CAPABILITY_CREDENTIAL_BRIDGE)
        );
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("open credential bridge");
        let ready = bridge.receive().await.expect("ready frame").expect("ready");
        let Some(GuestPayload::Ready(ready)) = ready.payload else {
            panic!("first credential bridge frame was not ready");
        };
        assert_eq!(ready.environment_id, harness.environment_id.to_string());
        assert_eq!(ready.environment_generation, harness.generation);

        let request_task = tokio::spawn(raw_request(
            harness.socket.clone(),
            br#"{"model":"synthetic"}"#,
        ));
        let request = bridge
            .receive()
            .await
            .expect("request frame")
            .expect("request");
        let Some(GuestPayload::Request(request)) = request.payload else {
            panic!("credential bridge did not carry a request");
        };
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/responses");
        assert!(request.query.is_empty());
        assert_eq!(request.body, br#"{"model":"synthetic"}"#);
        assert!(
            request
                .headers
                .iter()
                .any(|header| header.name == "content-type" && header.value == b"application/json")
        );
        assert!(request.headers.iter().all(|header| {
            !matches!(
                header.name.as_str(),
                "content-length" | "connection" | "transfer-encoding"
            )
        }));

        bridge
            .send_response_start(v1::CredentialBridgeResponseStart {
                request_id: request.request_id.clone(),
                status_code: 200,
                headers: vec![v1::CredentialHttpHeader {
                    name: "content-type".to_owned(),
                    value: b"text/event-stream".to_vec(),
                }],
            })
            .await
            .expect("response start");
        for data in [b"data: synthetic".as_slice(), b" response\n\n".as_slice()] {
            bridge
                .send_response_body(v1::CredentialBridgeResponseBody {
                    request_id: request.request_id.clone(),
                    data: data.to_vec(),
                })
                .await
                .expect("response body");
        }
        bridge
            .send_response_end(v1::CredentialBridgeResponseEnd {
                request_id: request.request_id,
            })
            .await
            .expect("response end");

        let response = request_task.await.expect("request task");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(
            response
                .windows(b"content-type: text/event-stream".len())
                .any(|window| window == b"content-type: text/event-stream")
        );
        for chunk in [b"data: synthetic".as_slice(), b" response\n\n".as_slice()] {
            assert!(
                response.windows(chunk.len()).any(|window| window == chunk),
                "streamed response chunk was absent: {}",
                String::from_utf8_lossy(&response)
            );
        }

        drop(bridge);
        harness.stop().await;
    }

    #[tokio::test]
    async fn bridge_rejects_wrong_generation_identity_and_daemon_token() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let wrong_identity = match client
            .open_credential_bridge(uuid::Uuid::new_v4(), harness.generation)
            .await
        {
            Ok(_) => panic!("wrong environment must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            wrong_identity,
            SessionClientError::Status(status)
                if status.code() == tonic::Code::FailedPrecondition
        ));

        let wrong_token = harness.client("wrong-generation-token").await;
        let error = match wrong_token
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
        {
            Ok(_) => panic!("wrong token must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SessionClientError::Status(status) if status.code() == tonic::Code::Unauthenticated
        ));
        harness.stop().await;
    }

    #[tokio::test]
    async fn replacement_closes_stale_stream_and_fails_its_pending_request() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut first = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("first bridge");
        assert!(matches!(
            first.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let request_task = tokio::spawn(raw_request(harness.socket.clone(), b"{}"));
        assert!(matches!(
            first.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Request(_))
        ));

        let mut second = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("replacement bridge");
        assert!(matches!(
            second.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));
        let response = request_task.await.expect("pending request");
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));
        assert!(first.receive().await.unwrap().is_none());

        harness.stop().await;
    }

    #[tokio::test]
    async fn out_of_order_host_body_fails_closed_and_detaches_the_bridge() {
        let harness = Harness::start().await;
        let client = harness.client(TEST_TOKEN).await;
        let mut bridge = client
            .open_credential_bridge(harness.environment_id, harness.generation)
            .await
            .expect("bridge");
        assert!(matches!(
            bridge.receive().await.unwrap().unwrap().payload,
            Some(GuestPayload::Ready(_))
        ));

        let request_task = tokio::spawn(raw_request(harness.socket.clone(), b"{}"));
        let request = bridge
            .receive()
            .await
            .expect("request frame")
            .expect("request");
        let Some(GuestPayload::Request(request)) = request.payload else {
            panic!("credential bridge did not carry a request");
        };
        bridge
            .send_response_body(v1::CredentialBridgeResponseBody {
                request_id: request.request_id,
                data: b"body-before-start".to_vec(),
            })
            .await
            .expect("enqueue malformed host frame");

        assert!(matches!(
            bridge.receive().await,
            Err(SessionClientError::Status(status))
                if status.code() == tonic::Code::InvalidArgument
        ));
        let response = request_task.await.expect("pending request");
        assert!(response.starts_with(b"HTTP/1.1 503 Service Unavailable"));

        harness.stop().await;
    }

    #[tokio::test]
    async fn cancelled_guest_request_tolerates_late_host_frames_without_detaching_bridge() {
        let bridge = CredentialBridge::new(Some(CredentialBridgeConfig {
            environment_id: uuid::Uuid::new_v4(),
            environment_generation: 9,
            ingress_socket: PathBuf::from("/run/codewire/test-credential.sock"),
            ingress_uid: 1_000,
            ingress_gid: 1_000,
        }));
        let (output, mut requests) = mpsc::channel(HOST_OUTPUT_BUFFER);
        let (cancel, _cancelled) = oneshot::channel();
        let epoch = 1;
        {
            let mut state = bridge.inner.lock().await;
            state.next_epoch = epoch;
            state.active = Some(ActiveHost {
                epoch,
                output,
                cancel,
            });
        }

        let request_id = "cancelled-request".to_owned();
        let submitted = {
            let bridge = bridge.clone();
            let request_id = request_id.clone();
            tokio::spawn(async move {
                bridge
                    .submit(v1::CredentialBridgeRequest {
                        request_id,
                        method: "POST".to_owned(),
                        path: "/responses".to_owned(),
                        query: String::new(),
                        headers: Vec::new(),
                        body: b"{}".to_vec(),
                    })
                    .await
            })
        };
        assert!(matches!(
            requests.recv().await.unwrap().unwrap().payload,
            Some(GuestPayload::Request(_))
        ));
        submitted.abort();
        match submitted.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("cancelled submission completed"),
        }
        let cancelled = tokio::time::timeout(Duration::from_secs(1), requests.recv())
            .await
            .expect("cancel frame timeout")
            .expect("cancel frame")
            .expect("cancel frame status");
        assert!(matches!(
            cancelled.payload,
            Some(GuestPayload::Cancel(v1::CredentialBridgeCancel { request_id: id }))
                if id == request_id
        ));

        for payload in [
            v1::credential_bridge_host_message::Payload::ResponseStart(
                v1::CredentialBridgeResponseStart {
                    request_id: request_id.clone(),
                    status_code: 200,
                    headers: Vec::new(),
                },
            ),
            v1::credential_bridge_host_message::Payload::ResponseBody(
                v1::CredentialBridgeResponseBody {
                    request_id: request_id.clone(),
                    data: b"late".to_vec(),
                },
            ),
            v1::credential_bridge_host_message::Payload::ResponseEnd(
                v1::CredentialBridgeResponseEnd {
                    request_id: request_id.clone(),
                },
            ),
        ] {
            bridge
                .apply_host_message(
                    epoch,
                    v1::CredentialBridgeHostMessage {
                        payload: Some(payload),
                    },
                )
                .await
                .expect("late host frame after cancellation");
        }

        let second_id = "second-request".to_owned();
        let second = {
            let bridge = bridge.clone();
            let second_id = second_id.clone();
            tokio::spawn(async move {
                bridge
                    .submit(v1::CredentialBridgeRequest {
                        request_id: second_id,
                        method: "POST".to_owned(),
                        path: "/responses".to_owned(),
                        query: String::new(),
                        headers: Vec::new(),
                        body: b"{}".to_vec(),
                    })
                    .await
            })
        };
        assert!(matches!(
            requests.recv().await.unwrap().unwrap().payload,
            Some(GuestPayload::Request(_))
        ));
        bridge
            .apply_host_message(
                epoch,
                v1::CredentialBridgeHostMessage {
                    payload: Some(
                        v1::credential_bridge_host_message::Payload::ResponseFailure(
                            v1::CredentialBridgeResponseFailure {
                                request_id: second_id,
                                reason: v1::CredentialBridgeFailureReason::Denied as i32,
                            },
                        ),
                    ),
                },
            )
            .await
            .expect("second response failure");
        assert!(matches!(second.await.unwrap(), Err(BridgeFailure::Denied)));
        let state = bridge.inner.lock().await;
        assert_eq!(
            state.active.as_ref().map(|active| active.epoch),
            Some(epoch)
        );
        assert!(state.pending.is_empty());
    }

    #[tokio::test]
    async fn response_stream_requires_an_explicit_end_for_clean_eof() {
        let (body, receiver) = mpsc::channel(1);
        body.try_send(Ok(WireBytes::from_static(b"partial")))
            .expect("buffer partial body");
        drop(body);
        let completed = Arc::new(AtomicBool::new(false));
        let mut stream = BridgeBodyStream {
            inner: ReceiverStream::new(receiver),
            cancellation: PendingCancellation {
                bridge: CredentialBridge::new(None),
                request_id: None,
                epoch: 0,
            },
            completed: Arc::clone(&completed),
            failure_emitted: false,
        };

        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            WireBytes::from_static(b"partial")
        );
        assert_eq!(
            stream.next().await.unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(stream.next().await.is_none());

        let (body, receiver) = mpsc::channel(1);
        completed.store(true, Ordering::Release);
        drop(body);
        let mut stream = BridgeBodyStream {
            inner: ReceiverStream::new(receiver),
            cancellation: PendingCancellation {
                bridge: CredentialBridge::new(None),
                request_id: None,
                epoch: 0,
            },
            completed,
            failure_emitted: false,
        };
        assert!(stream.next().await.is_none());
    }
}
