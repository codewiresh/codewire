//! Browser terminal adapter for the existing authenticated daemon PTY channel.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use codewire_daemon_bridge::client::{
    DaemonClient, DaemonClientError, DaemonRunInput, DaemonRunOutput, DaemonRunReceiver,
    DaemonRunSender, DaemonRunSession, DaemonRunStart,
};
use codewire_server_core::AppError;
use codewire_server_core::auth::{AuthUser, SESSION_COOKIE_NAME, authenticate};
use codewire_server_core::org_deletion::{
    acquire_environment_runtime_mutation_lease, mark_organization_mutation_resolution_required,
    release_organization_mutation_lease,
};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ApiState;
use super::environment_daemon::environment_daemon_bridge_client_core;
use super::prepare::plain_error;
use super::proxy::resolve_running_sandbox_target;
use crate::runtime::{ClaimReadiness, Placement, RuntimeDriver};

const MSG_TYPE_STDIN: u8 = 0x00;
const MSG_TYPE_RESIZE: u8 = 0x01;
const TERMINAL_TICKET_TTL_SECS: i64 = 30;
const TERMINAL_FRAME_BYTES: usize = 64 * 1024;
const TERMINAL_PENDING_BYTES: usize = 256 * 1024;
const TERMINAL_PENDING_FRAMES: usize = 64;
const TERMINAL_START_TIMEOUT: Duration = Duration::from_secs(15);
const TERMINAL_FINALIZE_TIMEOUT: Duration = Duration::from_secs(10);
const TERMINAL_IO_TIMEOUT: Duration = Duration::from_secs(5);
const TERMINAL_LEASE_TIMEOUT: Duration = Duration::from_secs(5);

type HmacSha256 = Hmac<Sha256>;

mod durable;

/// Single-use enforcement for terminal tickets (#2505 L3).
///
/// A ticket's HMAC proves authenticity and `exp` bounds its lifetime, but
/// nothing bound redemption to first use — the browser hands the ticket to
/// the WebSocket route as a query parameter, where it can linger in proxy
/// and browser history for the full 30s TTL and be replayed for a parallel
/// session. Every successful redemption records `sha256(nonce)` here;
/// a second presentation of the same nonce within the TTL is rejected.
///
/// This map is process-local by design: codewire-orchestration is a
/// single-replica Deployment (deployments/k8s/orchestration/deployment.yaml
/// pins `replicas: 1`). During a rolling update the old and new Pods overlap,
/// so a ticket redeemed on one could be replayed once on the other within its
/// TTL. If orchestration scales out, move the check to the shared store.
#[derive(Debug, Default)]
pub struct TerminalTicketReplayCache {
    seen: std::sync::Mutex<HashMap<[u8; 32], i64>>,
}

impl TerminalTicketReplayCache {
    /// Record `nonce_digest` as redeemed until `expires_at` (unix seconds).
    /// Returns `false` when the nonce was already redeemed and its entry has
    /// not expired — the replay case.
    pub(crate) fn record(&self, nonce_digest: [u8; 32], expires_at: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        let mut seen = self.seen.lock().expect("replay cache poisoned");
        // Opportunistic sweep: entries are tiny and TTL-bounded (≤30s), so
        // sweeping on insert keeps the map proportional to live tickets.
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(&nonce_digest) {
            return false;
        }
        seen.insert(nonce_digest, expires_at);
        true
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TerminalTicketClaims {
    user_id: String,
    #[serde(default)]
    global_admin_user_credential: bool,
    exp: i64,
    nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct TerminalQuery {
    #[serde(default)]
    ticket: String,
}

pub(crate) fn issue_terminal_ticket_core(
    state: &ApiState,
    user: &AuthUser,
) -> Result<String, AppError> {
    issue_ticket(
        &state.session_secret,
        &user.user_id,
        user.is_admin && !user.via_api_key,
    )
    .map_err(|_| AppError::InternalMsg("failed to issue ticket".into()))
}

/// Raw terminal WebSocket route. Authenticates manually because the Go
/// route is `OptionalAuth` plus a stateless `?ticket=` fallback.
pub async fn terminal_websocket(
    State(state): State<ApiState>,
    Path((org_id, env_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let headers = request.headers().clone();
    match durable::coordinates(&headers, request.uri().query()) {
        Ok(Some(coordinates)) => {
            return durable::websocket(state, org_id, env_id, coordinates, request).await;
        }
        Err(()) => {
            return terminal_error(StatusCode::BAD_REQUEST, "invalid durable terminal request");
        }
        Ok(None) => {}
    }
    // Preserve the legacy query/authentication and byte protocol. A durable
    // request cannot reach this one-shot shell-launching path by downgrade.
    let Query(query) = match Query::<TerminalQuery>::try_from_uri(request.uri()) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let user = match authenticate_socket_request(&state, &headers, &query.ticket).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let (mut parts, _body) = request.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };

    let target = match resolve_running_sandbox_target(&state, &user, &org_id, &env_id).await {
        Ok(target) => target,
        Err((status, msg)) => return terminal_error(status, msg),
    };

    let Some(runtime) = state.runtime.as_deref() else {
        return terminal_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "sandbox backend not configured",
        );
    };
    let placement = Placement::new(&target.namespace);
    if let Err(msg) = require_sandbox_claim_ready(runtime, &placement, &target.environment_id).await
    {
        return terminal_error(StatusCode::SERVICE_UNAVAILABLE, &msg);
    }

    let client =
        match environment_daemon_bridge_client_core(&state, &user, &org_id, &target.environment_id)
            .await
        {
            Ok(client) => client,
            Err(error) => return error.into_response(),
        };

    let lease = match acquire_environment_runtime_mutation_lease(
        &state.pool,
        &org_id,
        &target.environment_id,
    )
    .await
    {
        Ok(lease) => lease,
        Err(error) => return error.into_response(),
    };
    let pool = state.pool.clone();
    let failed_pool = pool.clone();
    let failed_lease = lease.id.clone();
    ws.protocols(["terminal"])
        .max_frame_size(TERMINAL_FRAME_BYTES)
        .max_message_size(TERMINAL_FRAME_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * TERMINAL_FRAME_BYTES)
        .on_failed_upgrade(move |_| {
            // No daemon start was dispatched. This bounded owner only releases
            // admission; accepted terminal operations have their own finalizer.
            tokio::spawn(async move {
                settle_terminal_lease(&failed_pool, &failed_lease, true).await;
            });
        })
        .on_upgrade(move |socket| terminal_session(socket, client, pool, lease.id))
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(crate) async fn authenticate_socket_request(
    state: &ApiState,
    headers: &HeaderMap,
    ticket: &str,
) -> Result<AuthUser, Response> {
    if !ticket.is_empty() {
        let Some(claims) = redeem_ticket(&state.session_secret, ticket) else {
            return Err(terminal_error(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"invalid or expired ticket"}"#,
            ));
        };
        // Single-use (#2505 L3): the nonce is unique per issue and the cache
        // entry dies with the ticket's own `exp`, so a ticket replayed from
        // history/proxy logs cannot open a second session. The 401 matches
        // the invalid-ticket branch so a replay is indistinguishable from a
        // forgery to the caller.
        let mut nonce_digest = [0u8; 32];
        nonce_digest.copy_from_slice(&Sha256::digest(claims.nonce.as_bytes()));
        if !state
            .terminal_ticket_replays
            .record(nonce_digest, claims.exp)
        {
            return Err(terminal_error(
                StatusCode::UNAUTHORIZED,
                r#"{"error":"invalid or expired ticket"}"#,
            ));
        }
        return Ok(AuthUser {
            user_id: claims.user_id,
            org_id: None,
            is_admin: claims.global_admin_user_credential,
            via_api_key: false,
        });
    }

    let session_token = session_cookie(headers);
    let bearer = bearer_token(headers);
    authenticate(&state.auth, session_token, bearer)
        .await
        .map_err(|err| {
            if err.is_forbidden() {
                terminal_error(StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#)
            } else {
                terminal_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#)
            }
        })
}

async fn terminal_session(
    socket: WebSocket,
    client: DaemonClient,
    pool: sqlx::PgPool,
    lease_id: String,
) {
    let (mut browser_output, mut browser_input) = socket.split();
    let proven = relay_terminal(
        &mut browser_output,
        &mut browser_input,
        client.start_run(terminal_start()),
        TerminalLimits::default(),
    )
    .await;
    settle_terminal_lease(&pool, &lease_id, proven).await;
}

async fn settle_terminal_lease(pool: &sqlx::PgPool, lease_id: &str, proven: bool) {
    let result = tokio::time::timeout(TERMINAL_LEASE_TIMEOUT, async {
        if proven {
            release_organization_mutation_lease(pool, lease_id).await
        } else {
            mark_organization_mutation_resolution_required(
                pool,
                lease_id,
                "environment_runtime_dispatch_ambiguous",
            )
            .await
        }
    })
    .await;
    if !matches!(result, Ok(Ok(_))) {
        tracing::warn!("terminal runtime admission finalization failed");
    }
}

fn terminal_start() -> DaemonRunStart {
    DaemonRunStart {
        command: Vec::new(),
        working_dir: String::new(),
        env: Vec::new(),
        allocate_tty: true,
        term: "xterm-256color".into(),
        columns: 80,
        rows: 24,
    }
}

// Private test seams use the existing typed stream contract; no private frame
// codec, daemon token, source selector, or alternate transport lives here.
trait TerminalInput: Send {
    fn send_input(
        &self,
        input: DaemonRunInput,
    ) -> impl Future<Output = Result<(), DaemonClientError>> + Send;
}
trait TerminalOutput: Send {
    fn next_output(
        &mut self,
    ) -> impl Future<Output = Result<Option<DaemonRunOutput>, DaemonClientError>> + Send;
}
trait TerminalSession: Send {
    type Input: TerminalInput;
    type Output: TerminalOutput;
    fn into_parts(self) -> (Self::Input, Self::Output);
}
impl TerminalInput for DaemonRunSender {
    async fn send_input(&self, input: DaemonRunInput) -> Result<(), DaemonClientError> {
        DaemonRunSender::send_input(self, input).await
    }
}
impl TerminalOutput for DaemonRunReceiver {
    async fn next_output(&mut self) -> Result<Option<DaemonRunOutput>, DaemonClientError> {
        DaemonRunReceiver::next_output(self).await
    }
}
impl TerminalSession for DaemonRunSession {
    type Input = DaemonRunSender;
    type Output = DaemonRunReceiver;
    fn into_parts(self) -> (Self::Input, Self::Output) {
        self.into_split()
    }
}

#[derive(Clone, Copy)]
struct TerminalLimits {
    start: Duration,
    finalize: Duration,
    io: Duration,
}
impl Default for TerminalLimits {
    fn default() -> Self {
        Self {
            start: TERMINAL_START_TIMEOUT,
            finalize: TERMINAL_FINALIZE_TIMEOUT,
            io: TERMINAL_IO_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalEnd {
    PeerClose,
    TransportClosed,
    InputLimit,
    DaemonFailure,
    Natural,
}

#[derive(Default)]
struct PendingInputs {
    frames: VecDeque<DaemonRunInput>,
    bytes: usize,
}
impl PendingInputs {
    fn push(&mut self, data: &[u8]) -> Result<(), TerminalEnd> {
        if data.len() > TERMINAL_FRAME_BYTES {
            return Err(TerminalEnd::InputLimit);
        }
        let input = match data {
            [] | [MSG_TYPE_STDIN] => return Ok(()),
            [MSG_TYPE_STDIN, bytes @ ..] => DaemonRunInput::Stdin(bytes.to_vec()),
            [MSG_TYPE_RESIZE, a, b, c, d] => {
                let columns = u16::from_be_bytes([*a, *b]);
                let rows = u16::from_be_bytes([*c, *d]);
                if columns == 0 || rows == 0 {
                    return Err(TerminalEnd::InputLimit);
                }
                DaemonRunInput::Resize {
                    columns: columns.into(),
                    rows: rows.into(),
                }
            }
            _ => return Err(TerminalEnd::InputLimit),
        };
        let bytes = input_bytes(&input);
        if self.frames.len() >= TERMINAL_PENDING_FRAMES
            || bytes > TERMINAL_PENDING_BYTES.saturating_sub(self.bytes)
        {
            return Err(TerminalEnd::InputLimit);
        }
        self.bytes += bytes;
        self.frames.push_back(input);
        Ok(())
    }
    fn pop(&mut self) {
        if let Some(input) = self.frames.pop_front() {
            self.bytes -= input_bytes(&input);
        }
    }
}
fn input_bytes(input: &DaemonRunInput) -> usize {
    match input {
        DaemonRunInput::Stdin(bytes) => bytes.len(),
        DaemonRunInput::Resize { .. } => 4,
        DaemonRunInput::CloseStdin => 0,
    }
}
fn browser_message<E>(
    message: Option<Result<Message, E>>,
    pending: &mut PendingInputs,
) -> Result<(), TerminalEnd> {
    match message {
        Some(Ok(Message::Binary(bytes))) => pending.push(&bytes),
        Some(Ok(Message::Close(_))) => Err(TerminalEnd::PeerClose),
        Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => Ok(()),
        Some(Err(_)) | None => Err(TerminalEnd::TransportClosed),
    }
}

async fn relay_terminal<Tx, Rx, E, F, S>(
    browser_output: &mut Tx,
    browser_input: &mut Rx,
    start: F,
    limits: TerminalLimits,
) -> bool
where
    Tx: Sink<Message> + Unpin + Send,
    Rx: Stream<Item = Result<Message, E>> + Unpin + Send,
    F: Future<Output = Result<S, DaemonClientError>> + Send,
    S: TerminalSession,
{
    tokio::pin!(start);
    let mut pending = PendingInputs::default();
    let start_deadline = tokio::time::Instant::now() + limits.start;
    let attachment = loop {
        if tokio::time::Instant::now() >= start_deadline {
            break Err(TerminalEnd::DaemonFailure);
        }
        tokio::select! {
            biased;
            message = browser_input.next() => {
                if let Err(end) = browser_message(message, &mut pending) {
                    break Err(end);
                }
            }
            result = &mut start => break Ok(result),
            _ = tokio::time::sleep_until(start_deadline) => {
                break Err(TerminalEnd::DaemonFailure);
            }
        }
    };
    let session = match attachment {
        Ok(Ok(session)) => session,
        Ok(Err(_)) => {
            // start_run combines readiness negotiation and issued PTY dispatch.
            // An RPC failure cannot certify that no child was created.
            close_browser(browser_output, TerminalEnd::DaemonFailure, limits.io).await;
            return false;
        }
        Err(end) => {
            // Keep the exact issued start future and its eventual response.
            // Browser cancellation does not release an ambiguous dispatch.
            let deadline = tokio::time::Instant::now() + limits.finalize;
            close_browser(browser_output, end, remaining_io(deadline, limits.io)).await;
            let Ok(Ok(session)) = tokio::time::timeout_at(deadline, &mut start).await else {
                return false;
            };
            let (input, mut output) = session.into_parts();
            drop(input); // Full transport EOF, never CloseStdin.
            return drain_terminal(&mut output, None, true, deadline).await;
        }
    };
    let (input, mut output) = session.into_parts();
    let (end, exit, valid) = loop {
        enum Event<E> {
            Browser(Option<Result<Message, E>>),
            Input(Result<Result<(), DaemonClientError>, tokio::time::error::Elapsed>),
            Output(Result<Option<DaemonRunOutput>, DaemonClientError>),
        }
        let event = tokio::select! {
            message = browser_input.next() => Event::Browser(message),
            sent = async {
                let message = pending.frames.front().expect("pending input").clone();
                tokio::time::timeout(limits.io, input.send_input(message)).await
            }, if !pending.frames.is_empty() => Event::Input(sent),
            message = output.next_output() => Event::Output(message),
        };
        match event {
            Event::Browser(message) => {
                if let Err(end) = browser_message(message, &mut pending) {
                    break (end, None, true);
                }
            }
            Event::Input(Ok(Ok(()))) => pending.pop(),
            Event::Input(_) => break (TerminalEnd::DaemonFailure, None, true),
            Event::Output(Ok(Some(
                DaemonRunOutput::Stdout(bytes) | DaemonRunOutput::Stderr(bytes),
            ))) => {
                if bytes.len() > TERMINAL_FRAME_BYTES {
                    break (TerminalEnd::DaemonFailure, None, false);
                }
                if let Err(end) = forward_output(
                    browser_output,
                    browser_input,
                    &mut pending,
                    bytes,
                    limits.io,
                )
                .await
                {
                    break (end, None, true);
                }
            }
            Event::Output(Ok(Some(DaemonRunOutput::Exit(code)))) => {
                break (TerminalEnd::Natural, Some(code), (0..=255).contains(&code));
            }
            Event::Output(Err(DaemonClientError::Remote(_))) => {
                // Error is a consumable diagnostic frame, not terminal proof.
                // Its opaque content must never reach a control log or socket.
                break (TerminalEnd::DaemonFailure, None, true);
            }
            Event::Output(Err(DaemonClientError::InvalidFrame(_))) => {
                break (TerminalEnd::DaemonFailure, None, false);
            }
            Event::Output(Ok(None) | Err(_)) => {
                drop(input);
                close_browser(browser_output, TerminalEnd::DaemonFailure, limits.io).await;
                return false;
            }
        }
    };
    // The daemon waits for control EOF after Exit too. Retaining this sender
    // while waiting for response EOF would deadlock natural terminal completion.
    drop(input);
    let deadline = tokio::time::Instant::now() + limits.finalize;
    if end != TerminalEnd::Natural {
        close_browser(browser_output, end, remaining_io(deadline, limits.io)).await;
    }
    let proven = drain_terminal(&mut output, exit, valid, deadline).await;
    if end == TerminalEnd::Natural {
        close_browser(
            browser_output,
            if proven {
                TerminalEnd::Natural
            } else {
                TerminalEnd::DaemonFailure
            },
            remaining_io(deadline, limits.io),
        )
        .await;
    }
    proven
}

async fn forward_output<Tx, Rx, E>(
    browser_output: &mut Tx,
    browser_input: &mut Rx,
    pending: &mut PendingInputs,
    bytes: Vec<u8>,
    timeout: Duration,
) -> Result<(), TerminalEnd>
where
    Tx: Sink<Message> + Unpin,
    Rx: Stream<Item = Result<Message, E>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let write = browser_output.send(Message::Binary(bytes.into()));
    tokio::pin!(write);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(TerminalEnd::TransportClosed);
        }
        tokio::select! {
            biased;
            message = browser_input.next() => browser_message(message, pending)?,
            result = &mut write => return result.map_err(|_| TerminalEnd::TransportClosed),
            _ = tokio::time::sleep_until(deadline) => return Err(TerminalEnd::TransportClosed),
        }
    }
}

async fn drain_terminal(
    output: &mut impl TerminalOutput,
    mut exit: Option<i32>,
    mut valid: bool,
    deadline: tokio::time::Instant,
) -> bool {
    loop {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        let Ok(message) = tokio::time::timeout_at(deadline, output.next_output()).await else {
            return false;
        };
        match message {
            Ok(None) => return valid && exit.is_some(),
            Ok(Some(DaemonRunOutput::Exit(code))) => {
                if exit.is_some() || !(0..=255).contains(&code) {
                    valid = false;
                }
                exit = Some(code);
            }
            Ok(Some(DaemonRunOutput::Stdout(bytes) | DaemonRunOutput::Stderr(bytes))) => {
                valid &= exit.is_none() && bytes.len() <= TERMINAL_FRAME_BYTES;
            }
            Err(DaemonClientError::Remote(_)) if exit.is_none() => {}
            Err(DaemonClientError::InvalidFrame(_) | DaemonClientError::Remote(_)) => valid = false,
            Err(_) => return false,
        }
    }
}
fn remaining_io(deadline: tokio::time::Instant, maximum: Duration) -> Duration {
    maximum.min(deadline.saturating_duration_since(tokio::time::Instant::now()))
}
async fn close_browser<Tx: Sink<Message> + Unpin>(
    browser_output: &mut Tx,
    end: TerminalEnd,
    timeout: Duration,
) {
    let _ = tokio::time::timeout(timeout, async {
        match end {
            TerminalEnd::PeerClose => {
                // Tungstenite queues the mandatory reply on read. Flush it;
                // sending another Close while closing is rejected.
                let _ = browser_output.flush().await;
            }
            TerminalEnd::TransportClosed => {}
            _ => {
                let (code, reason) = match end {
                    TerminalEnd::Natural => (1000, "session ended"),
                    TerminalEnd::InputLimit => (1009, "terminal input limit exceeded"),
                    _ => (1011, "terminal unavailable"),
                };
                let _ = browser_output
                    .send(Message::Close(Some(CloseFrame {
                        code,
                        reason: reason.into(),
                    })))
                    .await;
            }
        }
    })
    .await;
}

pub(crate) async fn require_sandbox_claim_ready(
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
    env_id: &str,
) -> Result<(), String> {
    let readiness = runtime
        .claim_readiness(placement, env_id)
        .await
        .map_err(|err| format!("get sandbox claim: {err}"))?;
    match readiness {
        ClaimReadiness::Absent => Err("sandbox claim not found".to_string()),
        ClaimReadiness::Ready => Ok(()),
        ClaimReadiness::NotReady { mut reason } => {
            if reason.is_empty() {
                reason = "not ready".to_string();
            }
            Err(format!("sandbox not ready: {reason}"))
        }
    }
}

fn terminal_error(status: StatusCode, body: &str) -> Response {
    plain_error(status, body)
}

fn issue_ticket(
    secret: &str,
    user_id: &str,
    global_admin_user_credential: bool,
) -> anyhow::Result<String> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)?;
    let claims = TerminalTicketClaims {
        user_id: user_id.to_string(),
        global_admin_user_credential,
        exp: chrono::Utc::now().timestamp() + TERMINAL_TICKET_TTL_SECS,
        nonce: hex_lower(&nonce),
    };
    let payload = serde_json::to_vec(&claims)?;
    let sig = sign_terminal_ticket(secret, &payload);
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(format!("{}.{}", engine.encode(payload), engine.encode(sig)))
}

fn redeem_ticket(secret: &str, token: &str) -> Option<TerminalTicketClaims> {
    let (payload_part, sig_part) = token.split_once('.')?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = engine.decode(payload_part).ok()?;
    let sig = engine.decode(sig_part).ok()?;
    if !constant_time_eq(&sig, &sign_terminal_ticket(secret, &payload)) {
        return None;
    }
    let claims: TerminalTicketClaims = serde_json::from_slice(&payload).ok()?;
    if claims.user_id.is_empty() || chrono::Utc::now().timestamp() > claims.exp {
        return None;
    }
    Some(claims)
}

fn sign_terminal_ticket(secret: &str, payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim_start();
        if let Some(value) = pair.strip_prefix(SESSION_COOKIE_NAME) {
            let value = value.trim_start();
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.trim_end_matches(|c: char| c.is_whitespace()));
            }
        }
    }
    None
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod relay_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::fake::FakeRuntimeDriver;

    #[tokio::test]
    async fn a_claim_that_is_not_ready_refuses_the_connection_with_its_reason() {
        let readiness = |answer| async move {
            let runtime = FakeRuntimeDriver {
                claim_readiness: std::sync::Mutex::new(Some(answer)),
                ..Default::default()
            };
            let result =
                require_sandbox_claim_ready(&runtime, &Placement::new("dev-sandboxes"), "env-1")
                    .await;
            assert_eq!(
                *runtime.placements.lock().unwrap(),
                [Placement::new("dev-sandboxes")]
            );
            result
        };

        assert_eq!(readiness(Ok(ClaimReadiness::Ready)).await, Ok(()));
        assert_eq!(
            readiness(Ok(ClaimReadiness::Absent)).await,
            Err("sandbox claim not found".to_string())
        );
        assert_eq!(
            readiness(Ok(ClaimReadiness::NotReady {
                reason: "PodPending".into()
            }))
            .await,
            Err("sandbox not ready: PodPending".to_string())
        );
        assert_eq!(
            readiness(Ok(ClaimReadiness::NotReady {
                reason: String::new()
            }))
            .await,
            Err("sandbox not ready: not ready".to_string())
        );
        assert_eq!(
            readiness(Err("forbidden".to_string())).await,
            Err("get sandbox claim: forbidden".to_string())
        );
    }

    #[test]
    fn issue_and_redeem_ticket_round_trips() {
        let ticket =
            issue_ticket("0123456789abcdef0123456789abcdef", "test-user-123", true).unwrap();
        let claims = redeem_ticket("0123456789abcdef0123456789abcdef", &ticket).unwrap();
        assert_eq!(claims.user_id, "test-user-123");
        assert!(claims.global_admin_user_credential);
    }

    /// #2505 L3 regression: a redeemed ticket cannot be replayed while its
    /// `exp` window is live, distinct tickets are independent, and entries
    /// vanish once expired so the cache cannot pin an old nonce set forever.
    #[test]
    fn ticket_replay_cache_is_single_use_per_nonce() {
        let cache = TerminalTicketReplayCache::default();
        let now = chrono::Utc::now().timestamp();
        let digest_of = |n: u8| {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&Sha256::digest([n]));
            digest
        };

        assert!(cache.record(digest_of(1), now + TERMINAL_TICKET_TTL_SECS));
        assert!(
            !cache.record(digest_of(1), now + TERMINAL_TICKET_TTL_SECS),
            "same nonce within TTL is a replay"
        );
        assert!(
            cache.record(digest_of(2), now + TERMINAL_TICKET_TTL_SECS),
            "distinct nonces are independent"
        );

        // Expired entries are swept on the next insert: the same nonce may
        // be recorded again after its ticket is long dead.
        assert!(cache.record(digest_of(3), now - 1));
        assert!(
            cache.record(digest_of(3), now + TERMINAL_TICKET_TTL_SECS),
            "expired entry must not pin its nonce"
        );
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let secret = "0123456789abcdef0123456789abcdef";
        let payload = serde_json::to_vec(&TerminalTicketClaims {
            user_id: "user".to_string(),
            global_admin_user_credential: false,
            exp: chrono::Utc::now().timestamp() - 1,
            nonce: "expired".to_string(),
        })
        .unwrap();
        let sig = sign_terminal_ticket(secret, &payload);
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let ticket = format!("{}.{}", engine.encode(payload), engine.encode(sig));
        assert!(redeem_ticket(secret, &ticket).is_none());
    }

    #[test]
    fn tampered_ticket_is_rejected() {
        let secret = "0123456789abcdef0123456789abcdef";
        let ticket = issue_ticket(secret, "user", false).unwrap();
        let (payload_part, sig_part) = ticket.split_once('.').unwrap();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut payload = engine.decode(payload_part).unwrap();
        payload[0] ^= 0x01;
        let tampered = format!("{}.{}", engine.encode(payload), sig_part);
        assert!(redeem_ticket(secret, &tampered).is_none());
    }

    #[test]
    fn invalid_ticket_is_rejected() {
        assert!(redeem_ticket("0123456789abcdef0123456789abcdef", "nonexistent").is_none());
    }
}
