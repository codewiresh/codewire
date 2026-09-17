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
use codewire_gateway_proto::daemon::v1;
use codewire_server_core::auth::{SESSION_COOKIE_NAME, authenticate};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};

use super::{ApiState, require_sandbox_claim_ready, terminal_error};
use crate::api::environment_daemon::{
    attach_environment_daemon_session_core, get_environment_daemon_session_core,
};
use crate::api::proxy::resolve_running_sandbox_target;
use crate::sandbox::client::SandboxClient;

const PROTOCOL: &str = "codewire.durable-terminal.v1";
const FRAME_BYTES: usize = 64 * 1024;
const INPUT_BYTES: usize = 16 * 1024;
const CHUNK_BYTES: usize = 32 * 1024;
const WINDOW_BYTES: u64 = 256 * 1024;
const WINDOW_FRAMES: usize = 64;
const INPUT_QUEUE_BYTES: usize = 256 * 1024;
const INPUT_QUEUE_FRAMES: usize = 64;
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
        // The existing IdP always returns skip_2fa_setup=false. Match the
        // dashboard's mandatory setup boundary without reading factor secrets.
        let eligible: bool = sqlx::query_scalar(
            "SELECT COALESCE(two_factor_enabled, false) FROM users WHERE id = $1 AND enabled",
        )
        .bind(&user.user_id)
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
        let kube = state.kube.clone().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        require_sandbox_claim_ready(
            &SandboxClient::new(kube, &target.namespace),
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
            let end = relay(
                &mut browser_output,
                &mut browser_input,
                input,
                output,
                coordinates,
                IO_TIMEOUT,
            )
            .await;
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
    Transport,
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
        )
        .await;
        drop(writer);
        result
    };
    // One persistent writer owns SinkExt::send through completion. Polling
    // input/ACKs must not cancel a partially flushed WebSocket send and retry it.
    let writer = async {
        while let Some(frame) = frames.recv().await {
            if !matches!(
                timeout(io_timeout, browser_output.send(frame)).await,
                Ok(Ok(()))
            ) {
                return End::Transport;
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
    loop {
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
                    _ => return End::Invalid,
                };
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
                let Ok(Ok(permit)) = permit else { return End::Transport };
                let entry = pending_input.pop_front().expect("pending input");
                input_bytes -= entry.bytes;
                permit.send(entry.message);
            }
            permit = timeout_at(frame_deadline, writer.reserve()), if pending_frame.is_some() => {
                let Ok(Ok(permit)) = permit else { return End::Transport };
                permit.send(pending_frame.take().expect("pending output").0);
            }
            message = output.next(), if pending_frame.is_none() && window.has_capacity() => {
                let frame = match message {
                    Some(Ok(v1::SessionAttachMessage { payload: Some(v1::session_attach_message::Payload::Output(chunk)) })) => {
                        if terminal_seen {
                            return End::Invalid;
                        }
                        match window.output(chunk) {
                            Ok(frame) => frame,
                            Err(end) => return end,
                        }
                    }
                    Some(Ok(v1::SessionAttachMessage { payload: Some(v1::session_attach_message::Payload::HistoryGap(gap)) })) => {
                        if terminal_seen { return End::Invalid; }
                        match window.history_gap(gap) {
                            Ok(frame) => frame,
                            Err(end) => return end,
                        }
                    }
                    Some(Ok(v1::SessionAttachMessage { payload: Some(v1::session_attach_message::Payload::Status(status)) })) => {
                        if status.session_id != coordinates.session_id || status.output_end_offset < window.issued {
                            return End::Invalid;
                        }
                        let Some(state) = lifecycle(status.state) else { return End::Invalid };
                        let terminal = !matches!(state, "starting" | "running" | "stopping");
                        if terminal_seen || (!terminal && status.exit_code.is_some())
                            || (terminal && status.output_end_offset != window.issued)
                        {
                            return End::Invalid;
                        }
                        terminal_seen = terminal;
                        ServerFrame::Status { state, exit_code: status.exit_code }
                    }
                    None if terminal_seen => return End::Complete,
                    _ => return End::Transport,
                };
                let Ok(encoded) = serde_json::to_string(&frame) else { return End::Invalid };
                if encoded.len() > FRAME_BYTES {
                    return End::Invalid;
                }
                pending_frame = Some((Message::Text(encoded.into()), Instant::now() + io_timeout));
            }
        }
    }
}

#[cfg(test)]
mod tests;
