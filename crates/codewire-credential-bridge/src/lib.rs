//! HTTP/credential-frame bridge shared by local and platform ingress, with
//! separate typed operations for launcher ciphertext, selected SSH signing and
//! the sealed Codex login (the one listed direct delivery exception).
//!
//! This crate does not authenticate peers, authorize credentials, bind listeners,
//! or access provider material. The consumer authenticates its transport and
//! activates a prepared connection only after that transport is admitted.
//! Request authentication headers must be consumed/removed by the ingress owner
//! before calling [`CredentialBridge::respond`]. Framing validation is not an
//! authorization or secret-redaction boundary.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, to_bytes};
#[cfg(test)]
use axum::http::Method;
use axum::http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING, UPGRADE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use bytes::Bytes as WireBytes;
use codewire_gateway_proto::codewire::bridge::v1;
use codewire_gateway_proto::{
    CREDENTIAL_BRIDGE_MAX_BODY_CHUNK_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADER_NAME_BYTES, CREDENTIAL_BRIDGE_MAX_HEADER_VALUE_BYTES,
    CREDENTIAL_BRIDGE_MAX_HEADERS, CREDENTIAL_BRIDGE_MAX_IN_FLIGHT,
    CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES, CREDENTIAL_BRIDGE_MAX_RESPONSE_BYTES,
    CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;
use uuid::Uuid;

mod http_ingress;
pub use http_ingress::{
    ClassifiedHttpRequest, MANAGED_GITHUB_GIT_PREFIX, MANAGED_OPENAI_API_PREFIX,
    classify_http_request,
};
mod codex_login;
pub use codex_login::{CODEX_LOGIN_REQUEST_LIFETIME, CodexLoginFailure};
use codex_login::{PendingCodexLogin, fail_codex_logins, take_codex_logins};
mod projection;
pub use projection::RelayedEnvironmentProjection;
use projection::{PendingProjection, fail_projections, take_projections};
mod ssh;
use ssh::{PendingSsh, fail_ssh, take_ssh};
mod ssh_ingress;
pub use ssh_ingress::{SshAgentRelay, serve_ssh_agent};

const HOST_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const FIRST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const HOST_OUTPUT_BUFFER: usize = 32;
/// How long a replaced epoch may drain. Its host leads the successor by about
/// this much and then ends it anyway; the bound also keeps a half-open old
/// transport from holding the shared request budget.
const DRAINING_LIFETIME: Duration = Duration::from_secs(90);
const RESPONSE_BODY_BUFFER: usize = 16;
/// How long one response's reader may leave its full buffer unread while the
/// host stream waits. Git reads a pack more slowly than a provider sends it.
const RESPONSE_CONSUMER_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(30)
};

type GuestOutput = mpsc::Sender<Result<v1::CredentialBridgeGuestMessage, Status>>;
type ResponseBodyItem = Result<WireBytes, io::Error>;

/// Ready-first bounded frames for the admitted peer. A terminal error closes
/// this connection; an outbound gRPC client adapter must stop at that error.
pub struct CredentialBridgeOutput {
    frames: ReceiverStream<Result<v1::CredentialBridgeGuestMessage, Status>>,
    close: oneshot::Receiver<Option<Status>>,
    closed: bool,
}

/// One fixed environment generation's material-free request/response state.
/// Copies share the active connection, request budget and replacement epoch.
/// A [`EpochReplacement::Drain`] activation keeps the replaced epoch, the
/// draining one, relaying only the requests already sent on it.
#[derive(Clone)]
pub struct CredentialBridge {
    environment_id: Uuid,
    environment_generation: u64,
    inner: Arc<Mutex<BridgeState>>,
    host_admitted: Arc<Notify>,
}

struct BridgeState {
    next_epoch: u64,
    active: Option<ActiveHost>,
    /// The epoch a [`EpochReplacement::Drain`] activation replaced. It keeps
    /// its pending entries and finishes them; new work goes only to `active`.
    /// A later Drain activation loses it, failing its requests as before.
    draining: Option<ActiveHost>,
    pending: BTreeMap<String, PendingResponse>,
    projections: BTreeMap<String, PendingProjection>,
    ssh: BTreeMap<String, PendingSsh>,
    codex_logins: BTreeMap<String, PendingCodexLogin>,
}

impl BridgeState {
    fn in_flight(&self) -> usize {
        self.pending.len() + self.projections.len() + self.ssh.len() + self.codex_logins.len()
    }

    fn contains_request(&self, request_id: &str) -> bool {
        self.pending.contains_key(request_id)
            || self.projections.contains_key(request_id)
            || self.ssh.contains_key(request_id)
            || self.codex_logins.contains_key(request_id)
    }

    /// The active or draining host of `epoch`: either may still answer, and
    /// be told to cancel, the requests registered on it.
    fn live_host(&self, epoch: u64) -> Option<&ActiveHost> {
        self.active
            .as_ref()
            .filter(|host| host.epoch == epoch)
            .or_else(|| self.draining.as_ref().filter(|host| host.epoch == epoch))
    }

    /// Remove every request registered on `epoch`, of every family.
    fn take_epoch(&mut self, epoch: u64) -> LostRequests {
        LostRequests {
            pending: take_pending(self, |pending| pending.epoch == epoch),
            projections: take_projections(self, epoch),
            ssh: take_ssh(self, epoch),
            codex_logins: take_codex_logins(self, epoch),
        }
    }

    /// Remove every request of every epoch.
    fn take_all(&mut self) -> LostRequests {
        LostRequests {
            pending: take_pending(self, |_| true),
            projections: std::mem::take(&mut self.projections)
                .into_values()
                .collect(),
            ssh: std::mem::take(&mut self.ssh).into_values().collect(),
            codex_logins: std::mem::take(&mut self.codex_logins)
                .into_values()
                .collect(),
        }
    }
}

/// Requests whose epoch was lost. Fail them only after releasing the lock.
#[derive(Default)]
struct LostRequests {
    pending: Vec<PendingResponse>,
    projections: Vec<PendingProjection>,
    ssh: Vec<PendingSsh>,
    codex_logins: Vec<PendingCodexLogin>,
}

impl LostRequests {
    fn fail(self) {
        fail_pending(self.pending, BridgeFailure::Unavailable);
        fail_projections(self.projections);
        fail_ssh(self.ssh);
        fail_codex_logins(self.codex_logins);
    }
}

/// What activating a successor does to the epoch it replaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EpochReplacement {
    /// Fail every pending request and close the replaced epoch at once.
    #[default]
    FailPending,
    /// Make before break: the replaced epoch keeps relaying the requests
    /// already sent on it until each is answered or the epoch is lost, while
    /// all new work goes to the successor. Only one epoch drains: a further
    /// Drain activation fails the older draining epoch's requests and closes
    /// it, and so do 90 seconds of draining. The shared in-flight budget
    /// counts both epochs' requests.
    Drain,
}

struct ActiveHost {
    epoch: u64,
    output: GuestOutput,
    cancel: oneshot::Sender<()>,
    /// The host's Open listed "codex-login" for this epoch.
    codex_login: bool,
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

/// Inactive connection. Creating or dropping this value never replaces the
/// currently active peer. It is not evidence that transport authentication ran.
pub struct PreparedBridgeConnection {
    bridge: CredentialBridge,
    output: GuestOutput,
    close: oneshot::Sender<Option<Status>>,
}

/// Owned response driver. The consumer must run it for the transport lifetime.
/// Normal shutdown detaches the epoch and fails all pending operations. Dropping
/// an unrun/cancelled driver also schedules material-free epoch cleanup when a
/// Tokio runtime is available; it never owns broker-side refresh work.
#[must_use = "run this driver for the lifetime of the admitted transport"]
pub struct CredentialBridgeConnection {
    bridge: CredentialBridge,
    epoch: u64,
    input: Pin<Box<dyn Stream<Item = Result<v1::CredentialBridgeHostMessage, Status>> + Send>>,
    output: GuestOutput,
    cancel: oneshot::Receiver<()>,
    close: Option<oneshot::Sender<Option<Status>>>,
    closed: bool,
}

struct BridgeHttpResponse {
    start: ResponseStart,
    body: BridgeBodyStream,
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
    /// The caller supplies coordinates already bound to its trusted transport.
    /// Nonzero coordinates are necessary, but are not authentication.
    pub fn new(environment_id: Uuid, environment_generation: u64) -> Result<Self, Status> {
        if environment_id.is_nil() || environment_generation == 0 {
            return Err(Status::invalid_argument(
                "credential bridge identity is invalid",
            ));
        }
        Ok(Self {
            environment_id,
            environment_generation,
            inner: Arc::new(Mutex::new(BridgeState {
                next_epoch: 0,
                active: None,
                draining: None,
                pending: BTreeMap::new(),
                projections: BTreeMap::new(),
                ssh: BTreeMap::new(),
                codex_logins: BTreeMap::new(),
            })),
            host_admitted: Arc::new(Notify::new()),
        })
    }

    /// Queue Ready without admitting requests or replacing an active peer.
    /// A gateway sends this stream to the private RPC before awaiting headers;
    /// a daemon prepares it after validating its authenticated Open frame.
    pub fn prepare_connection(
        &self,
    ) -> Result<(PreparedBridgeConnection, CredentialBridgeOutput), Status> {
        let (output, receiver) = mpsc::channel(HOST_OUTPUT_BUFFER);
        let (close, closed) = oneshot::channel();
        output
            .try_send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::Ready(v1::CredentialBridgeReady {
                    protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                    environment_id: self.environment_id.to_string(),
                    environment_generation: self.environment_generation,
                }),
            )))
            .map_err(|_| Status::resource_exhausted("credential bridge output is unavailable"))?;
        Ok((
            PreparedBridgeConnection {
                bridge: self.clone(),
                output,
                close,
            },
            CredentialBridgeOutput {
                frames: ReceiverStream::new(receiver),
                close: closed,
                closed: false,
            },
        ))
    }

    /// Serve only the closed managed HTTP families in [`classify_http_request`].
    /// Authentication, endpoint authority validation and removal of identity
    /// headers belong to the ingress adapter, before this method. The broker
    /// remains the final operation, policy and credential-lease authority.
    pub async fn respond(&self, request: Request<Body>) -> Response<Body> {
        match prepare_guest_request(request).await {
            Ok(request) => match self.submit(request).await {
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
                    require_live_epoch(&state, epoch)?;
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
                    require_live_epoch(&state, epoch)?;
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
                // Waiting for this bounded reader holds back the host stream, and
                // with it the broker and provider; nothing is buffered without
                // bound. A reader that stops or leaves loses only its own
                // response, never the bridge's other requests.
                if let Some(sender) = sender {
                    let sent = tokio::time::timeout(
                        RESPONSE_CONSUMER_TIMEOUT,
                        sender.send(Ok(WireBytes::from(response.data))),
                    )
                    .await;
                    if !matches!(sent, Ok(Ok(()))) {
                        self.abandon(&response.request_id, epoch).await;
                    }
                }
                Ok(())
            }
            Some(Payload::ResponseEnd(response)) => {
                let pending = {
                    let mut state = self.inner.lock().await;
                    require_live_epoch(&state, epoch)?;
                    take_registered(&mut state.pending, &response.request_id, |pending| {
                        pending.epoch == epoch && pending.phase != ResponsePhase::AwaitingStart
                    })?
                };
                // An abandoned response ends without completion, as an error.
                if pending.phase == ResponsePhase::Streaming {
                    pending.completed.store(true, Ordering::Release);
                }
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
                    require_live_epoch(&state, epoch)?;
                    take_registered(&mut state.pending, &response.request_id, |pending| {
                        pending.epoch == epoch
                    })?
                };
                fail_pending(vec![pending], reason);
                Ok(())
            }
            Some(Payload::EnvironmentProjection(response)) => {
                self.apply_projection_response(epoch, response).await
            }
            Some(Payload::Ssh(response)) => self.apply_ssh_response(epoch, response).await,
            Some(Payload::CodexLogin(response)) => {
                self.apply_codex_login_response(epoch, response).await
            }
            Some(Payload::Open(_)) | None => Err(invalid_host_frame()),
        }
    }

    /// Lose `epoch`, active or draining, and fail only its own requests.
    async fn detach(&self, epoch: u64) {
        let lost = {
            let mut state = self.inner.lock().await;
            if state
                .active
                .as_ref()
                .is_some_and(|host| host.epoch == epoch)
            {
                state.active = None;
            } else if state
                .draining
                .as_ref()
                .is_some_and(|host| host.epoch == epoch)
            {
                state.draining = None;
            } else {
                return;
            }
            state.take_epoch(epoch)
        };
        lost.fail();
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
            if state.in_flight() >= CREDENTIAL_BRIDGE_MAX_IN_FLIGHT {
                return Err(BridgeFailure::Unavailable);
            }
            if state.contains_request(&request_id) {
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

    /// Stop one streaming response whose reader stopped accepting or left.
    /// Its remaining frames are ignored, its reader sees an incomplete body,
    /// and the host is asked to stop sending it.
    async fn abandon(&self, request_id: &str, epoch: u64) {
        {
            let mut state = self.inner.lock().await;
            let Some(pending) = state.pending.get_mut(request_id) else {
                return;
            };
            if pending.epoch != epoch || pending.phase != ResponsePhase::Streaming {
                return;
            }
            // Replacing the only sender closes the reader's stream after what it
            // already buffered, without completion.
            pending.body = mpsc::channel(1).0;
        }
        self.cancel(request_id, epoch).await;
    }

    async fn cancel(&self, request_id: &str, epoch: u64) {
        let output = {
            let mut state = self.inner.lock().await;
            if let Some(pending) = state.projections.get_mut(request_id) {
                if pending.epoch != epoch || pending.response.is_none() {
                    return;
                }
                drop(pending.response.take());
            } else if let Some(pending) = state.ssh.get_mut(request_id) {
                if pending.epoch != epoch || pending.response.is_none() {
                    return;
                }
                drop(pending.response.take());
            } else if let Some(pending) = state.codex_logins.get_mut(request_id) {
                if pending.epoch != epoch || pending.response.is_none() {
                    return;
                }
                drop(pending.response.take());
            } else if let Some(pending) = state.pending.get_mut(request_id) {
                if pending.epoch != epoch || pending.phase == ResponsePhase::Cancelled {
                    return;
                }
                pending.phase = ResponsePhase::Cancelled;
                drop(pending.start.take());
            } else {
                return;
            }
            // A draining epoch still carries its own requests' cancellations.
            state.live_host(epoch).map(|host| host.output.clone())
        };
        if let Some(output) = output {
            let _ = output.try_send(Ok(guest_message(
                v1::credential_bridge_guest_message::Payload::Cancel(v1::CredentialBridgeCancel {
                    request_id: request_id.to_owned(),
                }),
            )));
        }
    }
}

impl PreparedBridgeConnection {
    /// Activate only after the consumer has authenticated/admitted this exact
    /// transport. No Open is consumed or synthesized here. Later Open frames
    /// are invalid, just like any other out-of-order frame. The epoch serves
    /// no optional operation; see [`Self::activate_with_capabilities`].
    pub async fn activate<S>(self, input: S) -> Result<CredentialBridgeConnection, Status>
    where
        S: Stream<Item = Result<v1::CredentialBridgeHostMessage, Status>> + Send + 'static,
    {
        self.activate_with_capabilities(input, &[]).await
    }

    /// Activate with the optional operations the admitted host's Open listed.
    /// Only a listed operation is ever sent on this epoch: an older host ends
    /// its epoch on an unknown frame. Unknown names are ignored; malformed or
    /// too many names refuse activation. The replaced epoch fails its pending
    /// requests; see [`Self::activate_with_replacement`].
    pub async fn activate_with_capabilities<S>(
        self,
        input: S,
        capabilities: &[String],
    ) -> Result<CredentialBridgeConnection, Status>
    where
        S: Stream<Item = Result<v1::CredentialBridgeHostMessage, Status>> + Send + 'static,
    {
        self.activate_with_replacement(input, capabilities, EpochReplacement::FailPending)
            .await
    }

    /// Activate like [`Self::activate_with_capabilities`], choosing what
    /// happens to the epoch this one replaces. Only a transport whose owner
    /// overlaps epochs, ending the replaced one itself, should choose
    /// [`EpochReplacement::Drain`].
    pub async fn activate_with_replacement<S>(
        self,
        input: S,
        capabilities: &[String],
        replacement: EpochReplacement,
    ) -> Result<CredentialBridgeConnection, Status>
    where
        S: Stream<Item = Result<v1::CredentialBridgeHostMessage, Status>> + Send + 'static,
    {
        if capabilities.len() > codewire_gateway_proto::CREDENTIAL_BRIDGE_MAX_CAPABILITIES
            || !capabilities.iter().all(|capability| {
                codewire_gateway_proto::valid_credential_bridge_capability(capability)
            })
        {
            return Err(invalid_host_frame());
        }
        let codex_login = capabilities.iter().any(|capability| {
            capability == codewire_gateway_proto::CREDENTIAL_BRIDGE_CAPABILITY_CODEX_LOGIN
        });
        let (cancel, cancelled) = oneshot::channel();
        let mut draining = None;
        let (epoch, closed, lost) = {
            let mut state = self.bridge.inner.lock().await;
            if self.output.is_closed() {
                return Err(Status::unavailable(
                    "credential bridge output is unavailable",
                ));
            }
            state.next_epoch = state
                .next_epoch
                .checked_add(1)
                .ok_or_else(|| Status::resource_exhausted("credential bridge epoch exhausted"))?;
            let epoch = state.next_epoch;
            let replaced = state.active.replace(ActiveHost {
                epoch,
                output: self.output.clone(),
                cancel,
                codex_login,
            });
            match (replacement, replaced) {
                (EpochReplacement::Drain, Some(replaced)) => {
                    draining = Some(replaced.epoch);
                    // Only one epoch drains; an older draining one is lost.
                    match state.draining.replace(replaced) {
                        Some(older) => {
                            let lost = state.take_epoch(older.epoch);
                            (epoch, vec![older], lost)
                        }
                        None => (epoch, Vec::new(), LostRequests::default()),
                    }
                }
                // The active epoch was already lost; a draining one goes on.
                (EpochReplacement::Drain, None) => (epoch, Vec::new(), LostRequests::default()),
                (EpochReplacement::FailPending, replaced) => {
                    let closed = replaced.into_iter().chain(state.draining.take()).collect();
                    (epoch, closed, state.take_all())
                }
            }
        };
        self.bridge.host_admitted.notify_waiters();
        for host in closed {
            let _ = host.cancel.send(());
        }
        lost.fail();
        if let Some(draining) = draining
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            // Measured from this activation, not from the task's first poll.
            // Holds no strong reference: a dropped bridge needs no expiry.
            let deadline = tokio::time::Instant::now() + DRAINING_LIFETIME;
            let state = Arc::downgrade(&self.bridge.inner);
            drop(runtime.spawn(async move {
                tokio::time::sleep_until(deadline).await;
                if let Some(state) = state.upgrade() {
                    expire_draining(&state, draining).await;
                }
            }));
        }
        Ok(CredentialBridgeConnection {
            bridge: self.bridge,
            epoch,
            input: Box::pin(input),
            output: self.output,
            cancel: cancelled,
            close: Some(self.close),
            closed: false,
        })
    }
}

impl CredentialBridgeConnection {
    /// Process responses until the peer closes or this epoch is closed: a
    /// fail-pending replacement closes it at once, and a draining epoch
    /// closes when a further replacement loses it.
    pub async fn run(self) {
        self.run_until(std::future::pending()).await;
    }

    /// Process responses until the peer closes, this epoch is closed (see
    /// [`Self::run`]), or the owner's shutdown completes. Await this method
    /// for orderly local cleanup.
    pub async fn run_until<F>(mut self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let result = loop {
            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                _ = &mut self.cancel => break Ok(()),
                _ = self.output.closed() => break Ok(()),
                message = self.input.next() => match message {
                    Some(Ok(message)) => {
                        if let Err(error) = self.bridge.apply_host_message(self.epoch, message).await {
                            break Err(error);
                        }
                    }
                    None => break Ok(()),
                    Some(Err(_)) => break Err(Status::unavailable("credential bridge host stream failed")),
                }
            }
        };
        if let Some(close) = self.close.take() {
            let _ = close.send(result.err());
        }
        self.bridge.detach(self.epoch).await;
        self.closed = true;
    }
}

impl Drop for CredentialBridgeConnection {
    fn drop(&mut self) {
        // Closing only tonic's response half can leave its request half alive.
        // End outgoing polling even if a sender clone or queued frame survives.
        if let Some(close) = self.close.take() {
            let _ = close.send(None);
        }
        if !self.closed {
            let bridge = self.bridge.clone();
            let epoch = self.epoch;
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    bridge.detach(epoch).await;
                });
            }
        }
    }
}

impl Stream for CredentialBridgeOutput {
    type Item = Result<v1::CredentialBridgeGuestMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.close).poll(context) {
            Poll::Ready(Ok(error)) => {
                self.closed = true;
                self.frames.close();
                return Poll::Ready(error.map(Err));
            }
            Poll::Ready(Err(_)) => {
                self.closed = true;
                self.frames.close();
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }
        Pin::new(&mut self.frames).poll_next(context)
    }
}

async fn prepare_guest_request(
    request: Request<Body>,
) -> Result<v1::CredentialBridgeRequest, StatusCode> {
    let classified = classify_http_request(request.method(), request.uri(), request.headers())?;
    let capability_slot = classified.capability_slot.to_owned();
    let route = classified.route.to_owned();
    let path = classified.path.to_owned();
    let query = classified.query.unwrap_or_default().to_owned();
    let method = request.method().as_str().to_owned();
    let headers = headers_to_proto(request.headers()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let body = to_bytes(request.into_body(), CREDENTIAL_BRIDGE_MAX_REQUEST_BYTES)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    Ok(v1::CredentialBridgeRequest {
        capability_slot,
        route,
        request_id: uuid::Uuid::new_v4().to_string(),
        method,
        path,
        query,
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

/// End a draining epoch whose time ran out: fail its remaining requests and
/// close it. A no-op once it was answered empty, lost or replaced.
async fn expire_draining(state: &Mutex<BridgeState>, epoch: u64) {
    let (host, lost) = {
        let mut state = state.lock().await;
        if state
            .draining
            .as_ref()
            .is_none_or(|host| host.epoch != epoch)
        {
            return;
        }
        (state.draining.take(), state.take_epoch(epoch))
    };
    if let Some(host) = host {
        let _ = host.cancel.send(());
    }
    lost.fail();
}

/// New work and strict releases: only the active epoch.
fn require_active_epoch(state: &BridgeState, epoch: u64) -> Result<(), Status> {
    if state.active.as_ref().map(|active| active.epoch) == Some(epoch) {
        Ok(())
    } else {
        Err(Status::aborted("credential bridge was replaced"))
    }
}

/// Frames answering registered requests: the active or the draining epoch.
fn require_live_epoch(state: &BridgeState, epoch: u64) -> Result<(), Status> {
    if state.live_host(epoch).is_some() {
        Ok(())
    } else {
        Err(Status::aborted("credential bridge was replaced"))
    }
}

/// Remove one registered request only after `owned` accepts it. A frame on
/// the wrong epoch is invalid and leaves the other epoch's entry untouched.
fn take_registered<T>(
    requests: &mut BTreeMap<String, T>,
    request_id: &str,
    owned: impl FnOnce(&T) -> bool,
) -> Result<T, Status> {
    if !requests.get(request_id).is_some_and(owned) {
        return Err(invalid_host_frame());
    }
    requests.remove(request_id).ok_or_else(invalid_host_frame)
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

#[cfg(test)]
mod tests;
