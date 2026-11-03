//! Browser-only attachment to an existing durable PTY. This adapter never
//! launches, restarts or stops a session, including on malformed input/close.
//!
//! `codewire.durable-terminal.v1` is cookie-only and exact-Origin bound. Its
//! decimal cursors count decoded output bytes; ACKs refer to completed browser
//! render callbacks, never receipt alone. The shared browser/Rust fixture is
//! `packages/codewire-design/reference/contracts/durable-terminal-v1.json`.
//! Limits here bound this adapter in addition to the existing private daemon
//! channel's own bounded queues. No daemon token or diagnostic crosses the wire.

use std::collections::VecDeque;
use std::time::Duration;

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::ws::{CloseFrame, Message, WebSocketUpgrade};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use codewire_daemon_proto::daemon::v1;
use codewire_server_core::auth::{SESSION_COOKIE_NAME, authenticate, hash_session_token};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};

use super::{ApiState, require_sandbox_claim_ready, terminal_error};
use crate::api::environment_daemon::{
    attach_environment_daemon_session_core, get_environment_daemon_session_core,
};
use crate::api::proxy::resolve_running_sandbox_target;
use crate::runtime::Placement;

const PROTOCOL: &str = "codewire.durable-terminal.v1";
const FRAME_BYTES: usize = 64 * 1024;
const INPUT_BYTES: usize = 16 * 1024;
const CHUNK_BYTES: usize = 32 * 1024;
const WINDOW_BYTES: u64 = 256 * 1024;
const WINDOW_FRAMES: usize = 64;
const INPUT_QUEUE_BYTES: usize = 256 * 1024;
const INPUT_QUEUE_FRAMES: usize = 64;
/// Daemon output the relay holds beyond the browser's window. The relay
/// reads the daemon attachment as output arrives, up to this bound, even
/// while the browser has not acknowledged its window: output left unread in
/// HTTP/2 as small DATA frames counts against the daemon connection's flood
/// guard, which ends that connection and every attachment on it (#2822).
/// At the bound the relay stops reading, and flow control pauses the daemon.
const DAEMON_BACKLOG_BYTES: usize = 1024 * 1024;
/// What one held daemon message counts against that bound besides its
/// output bytes, so many small ones are bounded too.
const DAEMON_BACKLOG_MESSAGE_COST: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ADMISSION_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct Coordinates {
    account_id: String,
    session_id: String,
    output_offset: u64,
}

/// Detect intent before invoking the legacy route. Even an unsupported durable
/// version or missing protocol must not turn a reconnect into a new shell.
pub(super) fn coordinates(
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<Option<Coordinates>, ()> {
    let pairs = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes());
    let protocols = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .collect::<Vec<_>>();
    let durable = pairs
        .clone()
        .any(|(key, _)| matches!(key.as_ref(), "account_id" | "session_id" | "output_offset"))
        || protocols.iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.contains("codewire.durable-terminal"))
        });
    if !durable {
        return Ok(None);
    }
    if query.unwrap_or_default().len() > 256
        || protocols.len() != 1
        || protocols[0].to_str().ok() != Some(PROTOCOL)
    {
        return Err(());
    }
    let mut session_id = None;
    let mut output_offset = None;
    let mut account_id = None;
    for (key, value) in pairs {
        match key.as_ref() {
            "account_id" if account_id.is_none() && valid_account_id(&value) => {
                account_id = Some(value.into_owned())
            }
            "session_id" if session_id.is_none() && valid_session_id(&value) => {
                session_id = Some(value.into_owned())
            }
            "output_offset" if output_offset.is_none() => {
                output_offset = Some(cursor(&value).ok_or(())?)
            }
            _ => return Err(()),
        }
    }
    Ok(Some(Coordinates {
        account_id: account_id.ok_or(())?,
        session_id: session_id.ok_or(())?,
        output_offset: output_offset.ok_or(())?,
    }))
}

fn valid_account_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn require_account(expected: &str, authenticated: &str) -> Result<(), StatusCode> {
    if expected == authenticated {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn valid_session_id(value: &str) -> bool {
    value
        .strip_prefix("session-")
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id))
}

fn cursor(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return None;
    }
    value.parse().ok()
}

fn browser_cookie<'a>(headers: &'a HeaderMap, configured_origin: &str) -> Result<&'a str, ()> {
    let origin = url::Url::parse(configured_origin).map_err(|_| ())?;
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.origin().ascii_serialization() != configured_origin
        || headers.contains_key(header::AUTHORIZATION)
    {
        return Err(());
    }
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().and_then(|value| value.to_str().ok()) != Some(configured_origin)
        || origins.next().is_some()
    {
        return Err(());
    }
    let mut cookies = headers.get_all(header::COOKIE).iter();
    let cookie = cookies
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(())?;
    if cookies.next().is_some() || cookie.len() > 16 * 1024 {
        return Err(());
    }
    let mut token = None;
    for pair in cookie.split(';') {
        let (name, value) = pair.trim_start().split_once('=').ok_or(())?;
        if name.trim_end() == SESSION_COOKIE_NAME && name != SESSION_COOKIE_NAME {
            return Err(());
        }
        if name != SESSION_COOKIE_NAME {
            continue;
        }
        if token.is_some()
            || value.is_empty()
            || value.len() > 4096
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b',' | b'"' | b'\\'))
        {
            return Err(());
        }
        token = Some(value);
    }
    token.ok_or(())
}

pub(super) async fn websocket(
    state: ApiState,
    org_id: String,
    env_id: String,
    coordinates: Coordinates,
    request: Request<Body>,
) -> Response {
    let cookie = match browser_cookie(request.headers(), &state.frontend_url) {
        Ok(cookie) => cookie.to_owned(),
        Err(()) => {
            return terminal_error(
                StatusCode::FORBIDDEN,
                "browser terminal authentication required",
            );
        }
    };
    let (mut parts, _) = request.into_parts();
    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(error) => return error.into_response(),
    };
    let attachment = timeout(ADMISSION_TIMEOUT, async {
        let user = authenticate(&state.auth, Some(&cookie), None)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        // An account cookie can change between inventory and upgrade. Never
        // attach a previous account's saved shell under the successor account,
        // even if both accounts can operate this environment.
        require_account(&coordinates.account_id, &user.user_id)?;
        // Match the dashboard's two-factor setup boundary without reading
        // factor secrets: an enabled factor, or setup skipped by this same
        // unexpired browser session.
        let eligible: bool = sqlx::query_scalar(
            "SELECT COALESCE(u.two_factor_enabled, false) OR EXISTS ( \
                 SELECT 1 FROM sessions AS s \
                  WHERE s.token_hash = $2 AND s.user_id = u.id AND s.expires_at > NOW() \
                    AND s.two_factor_setup_skipped_at IS NOT NULL) \
             FROM users AS u WHERE u.id = $1 AND u.enabled",
        )
        .bind(&user.user_id)
        .bind(hash_session_token(&cookie))
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .unwrap_or(false);
        if !eligible {
            return Err(StatusCode::FORBIDDEN);
        }
        let target = resolve_running_sandbox_target(&state, &user, &org_id, &env_id)
            .await
            .map_err(|(status, _)| status)?;
        let runtime = state
            .runtime
            .as_deref()
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        require_sandbox_claim_ready(
            runtime,
            &Placement::new(&target.namespace),
            &target.environment_id,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let record = get_environment_daemon_session_core(
            &state,
            &user,
            &org_id,
            &env_id,
            &coordinates.session_id,
        )
        .await
        .map_err(|error| error.into_response().status())?;
        if record.session_id != coordinates.session_id
            || !record.pty
            || lifecycle(record.state).is_none()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        attach_environment_daemon_session_core(
            &state,
            &user,
            &org_id,
            &env_id,
            &coordinates.session_id,
            coordinates.output_offset,
        )
        .await
        .map_err(|error| error.into_response().status())
    })
    .await;
    let attachment = match attachment {
        Ok(Ok(attachment)) => attachment,
        Ok(Err(status)) => return terminal_error(status, "terminal session is unavailable"),
        Err(_) => {
            return terminal_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "terminal session is unavailable",
            );
        }
    };
    ws.protocols([PROTOCOL])
        .max_frame_size(FRAME_BYTES)
        .max_message_size(FRAME_BYTES)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let (mut browser_output, mut browser_input) = socket.split();
            let (input, output) = attachment.into_stream_parts();
            let session_id = coordinates.session_id.clone();
            let start_offset = coordinates.output_offset;
            let started = Instant::now();
            let stats = std::sync::Mutex::new(RelayStats::default());
            let end = relay(
                &mut browser_output,
                &mut browser_input,
                input,
                output,
                coordinates,
                IO_TIMEOUT,
                &stats,
            )
            .await;
            if !matches!(end, End::PeerClosed | End::Complete) {
                let stats = stats.into_inner().unwrap_or_default();
                tracing::warn!(
                    environment_id = %env_id,
                    session_id = %session_id,
                    reason = end.as_str(),
                    elapsed_ms = started.elapsed().as_millis(),
                    start_offset,
                    issued = stats.issued,
                    acknowledged = stats.acknowledged,
                    unacknowledged_frames = stats.unacknowledged_frames,
                    unacknowledged_bytes = stats.unacknowledged_bytes,
                    pending_input = stats.pending_input,
                    since_output_sent_ms = ?elapsed_ms(stats.last_output_sent),
                    since_input_delivered_ms = ?elapsed_ms(stats.last_input_delivered),
                    since_browser_frame_ms = ?elapsed_ms(stats.last_browser_frame),
                    "browser terminal relay ended abnormally"
                );
            }
            let code = if matches!(end, End::PeerClosed | End::Complete) {
                1000
            } else {
                1008
            };
            let _ = timeout(
                IO_TIMEOUT,
                browser_output.send(Message::Close(Some(CloseFrame {
                    code,
                    reason: "terminal detached".into(),
                }))),
            )
            .await;
        })
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum ClientFrame {
    Input { data: String },
    Resize { columns: u16, rows: u16 },
    Ack { offset: String },
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ServerFrame {
    Output {
        offset: String,
        #[serde(rename = "nextOffset")]
        next_offset: String,
        data: String,
    },
    #[serde(rename = "historyGap")]
    HistoryGap {
        #[serde(rename = "requestedOffset")]
        requested_offset: String,
        #[serde(rename = "retainedStartOffset")]
        retained_start_offset: String,
    },
    Status {
        state: &'static str,
        #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
}

fn lifecycle(state: i32) -> Option<&'static str> {
    match v1::SessionLifecycleState::try_from(state).ok()? {
        v1::SessionLifecycleState::Starting => Some("starting"),
        v1::SessionLifecycleState::Running => Some("running"),
        v1::SessionLifecycleState::Stopping => Some("stopping"),
        v1::SessionLifecycleState::Stopped => Some("stopped"),
        v1::SessionLifecycleState::Exited => Some("exited"),
        v1::SessionLifecycleState::Failed => Some("failed"),
        v1::SessionLifecycleState::Interrupted => Some("interrupted"),
        v1::SessionLifecycleState::Unspecified => None,
    }
}

struct Window {
    issued: u64,
    acknowledged: u64,
    ends: VecDeque<(u64, u64)>,
    pending_bytes: u64,
}
impl Window {
    fn new(offset: u64) -> Self {
        Self {
            issued: offset,
            acknowledged: offset,
            ends: VecDeque::new(),
            pending_bytes: 0,
        }
    }
    // Reserve space for one whole maximum-size chunk before polling upstream.
    // A variable-sized final chunk must not overrun the window or be discarded.
    fn has_capacity(&self) -> bool {
        self.pending_bytes <= WINDOW_BYTES - CHUNK_BYTES as u64 && self.ends.len() < WINDOW_FRAMES
    }
    fn acknowledge(&mut self, offset: &str) -> Result<(), End> {
        let offset = cursor(offset).ok_or(End::Invalid)?;
        if offset == self.acknowledged {
            return Ok(());
        }
        if offset < self.acknowledged || !self.ends.iter().any(|(end, _)| *end == offset) {
            return Err(End::Invalid);
        }
        while self.ends.front().is_some_and(|(end, _)| *end <= offset) {
            let (_, bytes) = self.ends.pop_front().expect("acknowledged frame");
            self.pending_bytes -= bytes;
        }
        self.acknowledged = offset;
        Ok(())
    }
    fn history_gap(&mut self, gap: v1::SessionOutputGap) -> Result<ServerFrame, End> {
        if !self.has_capacity()
            || gap.requested_offset != self.issued
            || gap.retained_start_offset <= self.issued
        {
            return Err(End::Invalid);
        }
        // Skipped history is not output debt. Keep older outstanding ACKs
        // intact, and require an ACK for the ordered rendered gap notice.
        self.issued = gap.retained_start_offset;
        self.ends.push_back((self.issued, 0));
        Ok(ServerFrame::HistoryGap {
            requested_offset: gap.requested_offset.to_string(),
            retained_start_offset: gap.retained_start_offset.to_string(),
        })
    }

    fn output(&mut self, chunk: v1::SessionOutputChunk) -> Result<ServerFrame, End> {
        if !self.has_capacity()
            || chunk.data.is_empty()
            || chunk.data.len() > CHUNK_BYTES
            || chunk.offset != self.issued
            || chunk.offset.checked_add(chunk.data.len() as u64) != Some(chunk.next_offset)
            || self.pending_bytes + chunk.data.len() as u64 > WINDOW_BYTES
            || !matches!(
                v1::SessionOutputStream::try_from(chunk.stream),
                Ok(v1::SessionOutputStream::Pty)
            )
        {
            return Err(End::Invalid);
        }
        self.issued = chunk.next_offset;
        self.pending_bytes += chunk.data.len() as u64;
        self.ends
            .push_back((chunk.next_offset, chunk.data.len() as u64));
        Ok(ServerFrame::Output {
            offset: chunk.offset.to_string(),
            next_offset: chunk.next_offset.to_string(),
            data: STANDARD.encode(chunk.data),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    Complete,
    PeerClosed,
    Invalid,
    /// The browser did not take an output frame within the I/O deadline.
    BrowserStalled,
    /// The browser connection failed while reading or writing.
    BrowserClosed,
    /// The daemon attachment did not take queued input within the deadline.
    DaemonInputStalled,
    /// The daemon attachment ended or failed before a final session status.
    DaemonClosed,
}

impl End {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PeerClosed => "peer_closed",
            Self::Invalid => "invalid",
            Self::BrowserStalled => "browser_stalled",
            Self::BrowserClosed => "browser_closed",
            Self::DaemonInputStalled => "daemon_input_stalled",
            Self::DaemonClosed => "daemon_closed",
        }
    }
}

/// What the relay had in flight when it ended, so an abnormal end names the
/// side that stopped moving rather than reading as a silent stall.
#[derive(Debug, Default)]
struct RelayStats {
    issued: u64,
    acknowledged: u64,
    unacknowledged_frames: usize,
    unacknowledged_bytes: u64,
    pending_input: usize,
    last_output_sent: Option<Instant>,
    last_input_delivered: Option<Instant>,
    last_browser_frame: Option<Instant>,
}

fn elapsed_ms(since: Option<Instant>) -> Option<u128> {
    since.map(|instant| instant.elapsed().as_millis())
}

struct PendingInput {
    message: v1::SessionAttachMessage,
    bytes: usize,
    deadline: Instant,
}

async fn relay<Tx, Rx, Output, E>(
    browser_output: &mut Tx,
    browser_input: &mut Rx,
    input: mpsc::Sender<v1::SessionAttachMessage>,
    output: Output,
    coordinates: Coordinates,
    io_timeout: Duration,
    stats: &std::sync::Mutex<RelayStats>,
) -> End
where
    Tx: Sink<Message> + Unpin,
    Rx: Stream<Item = Result<Message, E>> + Unpin,
    Output: Stream<Item = Result<v1::SessionAttachMessage, tonic::Status>> + Unpin,
{
    let (writer, mut frames) = mpsc::channel::<Message>(1);
    let reader = async move {
        let result = relay_input(
            browser_input,
            input,
            output,
            &writer,
            coordinates,
            io_timeout,
            stats,
        )
        .await;
        drop(writer);
        result
    };
    // One persistent writer owns SinkExt::send through completion. Polling
    // input/ACKs must not cancel a partially flushed WebSocket send and retry it.
    let writer = async {
        while let Some(frame) = frames.recv().await {
            match timeout(io_timeout, browser_output.send(frame)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return End::BrowserClosed,
                Err(_) => return End::BrowserStalled,
            }
        }
        End::Complete
    };
    tokio::pin!(reader, writer);
    tokio::select! {
        end = &mut reader => {
            if end == End::Complete { writer.await } else { end }
        }
        end = &mut writer => end,
    }
}

async fn relay_input<Rx, Output, E>(
    browser: &mut Rx,
    input: mpsc::Sender<v1::SessionAttachMessage>,
    mut output: Output,
    writer: &mpsc::Sender<Message>,
    coordinates: Coordinates,
    io_timeout: Duration,
    stats: &std::sync::Mutex<RelayStats>,
) -> End
where
    Rx: Stream<Item = Result<Message, E>> + Unpin,
    Output: Stream<Item = Result<v1::SessionAttachMessage, tonic::Status>> + Unpin,
{
    let mut window = Window::new(coordinates.output_offset);
    let mut pending_frame: Option<(Message, Instant)> = None;
    let mut pending_input: VecDeque<PendingInput> = VecDeque::new();
    let mut input_bytes = 0;
    let mut terminal_seen = false;
    // Daemon output read ahead of the browser window, in order; `None` is
    // the end of the daemon stream, or its failure.
    let mut backlog: VecDeque<Option<v1::SessionAttachMessage>> = VecDeque::new();
    let mut backlog_bytes = 0;
    loop {
        while pending_frame.is_none() && window.has_capacity() {
            let Some(message) = backlog.pop_front() else {
                break;
            };
            backlog_bytes -= daemon_backlog_cost(message.as_ref());
            let frame = match daemon_frame(message, &mut window, &mut terminal_seen, &coordinates) {
                Ok(frame) => frame,
                Err(end) => return end,
            };
            let Ok(encoded) = serde_json::to_string(&frame) else {
                return End::Invalid;
            };
            if encoded.len() > FRAME_BYTES {
                return End::Invalid;
            }
            pending_frame = Some((Message::Text(encoded.into()), Instant::now() + io_timeout));
        }
        if let Ok(mut stats) = stats.lock() {
            stats.issued = window.issued;
            stats.acknowledged = window.acknowledged;
            stats.unacknowledged_frames = window.ends.len();
            stats.unacknowledged_bytes = window.pending_bytes;
            stats.pending_input = pending_input.len();
        }
        let input_deadline = pending_input
            .front()
            .map_or_else(Instant::now, |entry| entry.deadline);
        let frame_deadline = pending_frame
            .as_ref()
            .map_or_else(Instant::now, |(_, deadline)| *deadline);
        tokio::select! {
            message = browser.next() => {
                let message = match message {
                    Some(Ok(Message::Text(text))) if text.len() <= FRAME_BYTES => text,
                    Some(Ok(Message::Close(_))) | None => return End::PeerClosed,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                    Some(Err(_)) => return End::BrowserClosed,
                    _ => return End::Invalid,
                };
                if let Ok(mut stats) = stats.lock() {
                    stats.last_browser_frame = Some(Instant::now());
                }
                let frame: ClientFrame = match serde_json::from_str(&message) {
                    Ok(frame) => frame,
                    Err(_) => return End::Invalid,
                };
                let (payload, bytes) = match frame {
                    ClientFrame::Ack { offset } => {
                        if window.acknowledge(&offset).is_err() {
                            return End::Invalid;
                        }
                        continue;
                    }
                    ClientFrame::Input { data } if !data.is_empty() && data.len() <= INPUT_BYTES => {
                        let bytes = data.len();
                        (v1::session_attach_message::Payload::Input(v1::SessionInput {
                            data: data.into_bytes(),
                        }), bytes)
                    }
                    ClientFrame::Resize { columns, rows } if columns > 0 && rows > 0 => {
                        (v1::session_attach_message::Payload::Resize(v1::ResizeRequest {
                            width: i32::from(columns), height: i32::from(rows),
                        }), 4)
                    }
                    _ => return End::Invalid,
                };
                if pending_input.len() >= INPUT_QUEUE_FRAMES || input_bytes + bytes > INPUT_QUEUE_BYTES {
                    return End::Invalid;
                }
                input_bytes += bytes;
                pending_input.push_back(PendingInput {
                    message: v1::SessionAttachMessage { payload: Some(payload) },
                    bytes, deadline: Instant::now() + io_timeout,
                });
            }
            permit = timeout_at(input_deadline, input.reserve()), if !pending_input.is_empty() => {
                let permit = match permit {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return End::DaemonClosed,
                    Err(_) => return End::DaemonInputStalled,
                };
                let entry = pending_input.pop_front().expect("pending input");
                input_bytes -= entry.bytes;
                permit.send(entry.message);
                if let Ok(mut stats) = stats.lock() {
                    stats.last_input_delivered = Some(Instant::now());
                }
            }
            permit = timeout_at(frame_deadline, writer.reserve()), if pending_frame.is_some() => {
                let permit = match permit {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => return End::BrowserClosed,
                    Err(_) => return End::BrowserStalled,
                };
                permit.send(pending_frame.take().expect("pending output").0);
                if let Ok(mut stats) = stats.lock() {
                    stats.last_output_sent = Some(Instant::now());
                }
            }
            message = output.next(), if backlog.back().is_none_or(Option::is_some) && backlog_bytes < DAEMON_BACKLOG_BYTES => {
                let message = match message {
                    Some(Ok(message)) => Some(message),
                    Some(Err(_)) | None => None,
                };
                backlog_bytes += daemon_backlog_cost(message.as_ref());
                backlog.push_back(message);
            }
        }
    }
}

fn daemon_backlog_cost(message: Option<&v1::SessionAttachMessage>) -> usize {
    let output = match message.and_then(|message| message.payload.as_ref()) {
        Some(v1::session_attach_message::Payload::Output(chunk)) => chunk.data.len(),
        _ => 0,
    };
    DAEMON_BACKLOG_MESSAGE_COST + output
}

/// The browser frame for one daemon message, in order, or how the relay ends.
/// `None` is the end, or failure, of the daemon stream.
fn daemon_frame(
    message: Option<v1::SessionAttachMessage>,
    window: &mut Window,
    terminal_seen: &mut bool,
    coordinates: &Coordinates,
) -> Result<ServerFrame, End> {
    let Some(message) = message else {
        return Err(if *terminal_seen {
            End::Complete
        } else {
            End::DaemonClosed
        });
    };
    match message.payload {
        Some(v1::session_attach_message::Payload::Output(chunk)) => {
            if *terminal_seen {
                return Err(End::Invalid);
            }
            window.output(chunk)
        }
        Some(v1::session_attach_message::Payload::HistoryGap(gap)) => {
            if *terminal_seen {
                return Err(End::Invalid);
            }
            window.history_gap(gap)
        }
        Some(v1::session_attach_message::Payload::Status(status)) => {
            if status.session_id != coordinates.session_id
                || status.output_end_offset < window.issued
            {
                return Err(End::Invalid);
            }
            let Some(state) = lifecycle(status.state) else {
                return Err(End::Invalid);
            };
            let terminal = !matches!(state, "starting" | "running" | "stopping");
            if *terminal_seen
                || (!terminal && status.exit_code.is_some())
                || (terminal && status.output_end_offset != window.issued)
            {
                return Err(End::Invalid);
            }
            *terminal_seen = terminal;
            Ok(ServerFrame::Status {
                state,
                exit_code: status.exit_code,
            })
        }
        _ => Err(End::DaemonClosed),
    }
}

#[cfg(test)]
mod tests;
