//! Live setup stages for the Sandbox page (Program #2238, A5c).
//!
//! `GET /{slug}/{environment_id}/_events/setup-progress` answers with
//! `text/event-stream` for the page's native `EventSource`. It relays the
//! environment's own log rows from orchestration's `StreamLogs`, read with the
//! viewer's session so orchestration applies its usual environment access
//! check, and it reshapes each row into a closed set of fields:
//!
//! - `stage` events carry `phase`, `status`, `label`, and, when present, the
//!   A5a clone fields `repoIndex`, `repoCount`, `stage` and `percent`, plus
//!   `durationMs` and `createdAt`. Every value is validated here; nothing
//!   else from the row is forwarded.
//! - Each `stage` event's `id` is the row's log id, so a reconnecting
//!   `EventSource` resumes strictly after the last row it showed, through the
//!   same composite cursor the CLI uses (`after_log_id`).
//! - An `end` event follows a terminal row (`complete`, or a `failed`
//!   status); the page then closes its source instead of reconnecting.
//! - Orchestration's heartbeats become comments.
//!
//! A first connection shows only the current run: rows before the start that
//! is in progress (or that ended last) are history, not progress. One
//! connection lives at most [`STREAM_LIFETIME`]; the browser then reconnects
//! and resumes.
//!
//! A page whose Sandbox is starting asks for `?run=next&since=<its render
//! time>` (#3772): a run that ended before the page was rendered belongs to an
//! earlier start, so it is not replayed and the connection waits for this
//! start's rows. A run that ended since is this start's, and is shown.
//!
//! A page following a Retry setup (#4767) first asks for
//! `?run=before&since=<when the Retry was asked for>`: the run that ended
//! last before then, which is the failed run the Retry resumes. Its steps
//! before the failed one are done, and the Retry's own run follows as
//! `?run=next` with the same time.

use std::{convert::Infallible, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use codewire_proto::codewire::v1::{StreamLogsResponse, stream_logs_response::Event};
use connectrpc::{ConnectError, ErrorCode};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};

use crate::{environment_connect, state::AppState};

/// One relayed connection's maximum lifetime. The page's `EventSource`
/// reconnects with `Last-Event-ID` and resumes.
const STREAM_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// A first connection keeps at most this many of the newest history rows;
/// the current run is at the end of the history.
const MAX_BACKLOG_ROWS: usize = 2_000;
const MAX_LABEL_CHARS: usize = 300;

/// One log row, owned and still unvalidated.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct LogRow {
    pub(super) id: String,
    pub(super) phase: String,
    pub(super) status: String,
    pub(super) message: String,
    pub(super) metadata: Option<serde_json::Value>,
    pub(super) created_at: String,
}

impl LogRow {
    /// The same rule orchestration uses to end a log stream.
    pub(super) fn terminal(&self) -> bool {
        self.phase == "complete" || self.status == "failed"
    }
}

enum Item {
    Row(LogRow),
    Heartbeat,
}

fn item(response: StreamLogsResponse) -> Option<Item> {
    match response.event? {
        Event::Log(log) => Some(Item::Row(LogRow {
            id: log.id,
            phase: log.phase,
            status: log.status,
            message: log.message,
            metadata: log
                .metadata
                .into_option()
                .and_then(|metadata| serde_json::to_value(metadata).ok()),
            created_at: log
                .created_at
                .into_option()
                .and_then(|time| DateTime::<Utc>::from_timestamp(time.seconds, time.nanos as u32))
                // To the millisecond, as a page's `since` is: a run that ends
                // in the same second as a Retry, but after it, is the Retry's.
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
                .unwrap_or_default(),
        })),
        Event::Heartbeat(_) => Some(Item::Heartbeat),
    }
}

/// The fields a page may see, all validated.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct StageEvent {
    phase: String,
    status: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    percent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

fn token(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A log id from orchestration: 32 hex digits, or a hyphenated UUID.
pub(super) fn log_id(value: &str) -> bool {
    let hex = |value: &str| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    (value.len() == 32 && hex(value))
        || uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

/// A whole number from row metadata. `google.protobuf.Struct` carries numbers
/// as doubles, so `3` may arrive as `3.0`.
fn count(metadata: &serde_json::Value, name: &str, max: u64) -> Option<u64> {
    let value = metadata.get(name)?;
    value
        .as_u64()
        .or_else(|| {
            value
                .as_f64()
                .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
                .filter(|number| *number <= max as f64)
                .map(|number| number as u64)
        })
        .filter(|number| *number <= max)
}

fn label(message: &str) -> String {
    message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(MAX_LABEL_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub(super) fn stage_event(row: &LogRow) -> Option<StageEvent> {
    if !log_id(&row.id) || !token(&row.phase, 64) || !token(&row.status, 32) {
        return None;
    }
    let metadata = row
        .metadata
        .as_ref()
        .filter(|metadata| metadata.is_object());
    let field = |name, max| metadata.and_then(|metadata| count(metadata, name, max));
    let repo_count = field("repo_count", 1_000).filter(|count| *count >= 1);
    Some(StageEvent {
        phase: row.phase.clone(),
        status: row.status.clone(),
        label: label(&row.message),
        repo_index: field("repo_index", 1_000)
            .filter(|index| *index >= 1 && repo_count.is_none_or(|count| *index <= count)),
        repo_count,
        stage: metadata
            .and_then(|metadata| metadata.get("stage"))
            .and_then(serde_json::Value::as_str)
            .filter(|stage| token(stage, 40))
            .map(str::to_owned),
        percent: field("percent", 100),
        duration_ms: field("duration_ms", 86_400_000),
        created_at: DateTime::parse_from_rfc3339(&row.created_at)
            .ok()
            .map(|time| {
                time.with_timezone(&Utc)
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
            }),
    })
}

/// Which run a first connection shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Run {
    /// The run in progress, or the one that ended last.
    Current,
    /// A starting Sandbox's run: a run that ended before `since` (the page's
    /// render time) is an earlier start's. Without `since`, any ended run is.
    Next { since: Option<DateTime<Utc>> },
    /// A Retry's page: the run that ended last before `since`, and nothing
    /// after it.
    Before { since: DateTime<Utc> },
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct EventsQuery {
    run: Option<String>,
    since: Option<String>,
}

impl EventsQuery {
    /// An unknown run asks for the current one, as a page that sends nothing
    /// does; a malformed `since` is no bound, and `before` without one is
    /// the current run.
    pub(super) fn run(&self) -> Run {
        let since = || {
            self.since
                .as_deref()
                .and_then(|since| DateTime::parse_from_rfc3339(since).ok())
                .map(|since| since.with_timezone(&Utc))
        };
        match self.run.as_deref() {
            Some("next") => Run::Next { since: since() },
            Some("before") => since().map_or(Run::Current, |since| Run::Before { since }),
            _ => Run::Current,
        }
    }
}

impl Run {
    /// Whether a run that ended on `last` belongs to an earlier start.
    fn earlier(self, last: &LogRow) -> bool {
        match self {
            Self::Current | Self::Before { .. } => false,
            Self::Next { since: None } => true,
            Self::Next { since: Some(since) } => ended_before(last, since),
        }
    }
}

fn ended_before(row: &LogRow, since: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(&row.created_at)
        .map_or(true, |ended| ended.with_timezone(&Utc) < since)
}

/// The rows of the current run in a full history: everything after the last
/// terminal row, unless the history itself ends on a terminal row, in which
/// case the run that row ended, or nothing when that run is an earlier
/// start's ([`Run::Next`]).
pub(super) fn current_run(rows: &[LogRow], run: Run) -> &[LogRow] {
    if let Run::Before { since } = run {
        let Some(end) = rows
            .iter()
            .rposition(|row| row.terminal() && ended_before(row, since))
        else {
            return &rows[..0];
        };
        let start = rows[..end]
            .iter()
            .rposition(LogRow::terminal)
            .map_or(0, |index| index + 1);
        return &rows[start..=end];
    }
    let ends_terminal = rows.last().is_some_and(LogRow::terminal);
    if ends_terminal && rows.last().is_some_and(|last| run.earlier(last)) {
        return &rows[rows.len()..];
    }
    let scan = if ends_terminal {
        &rows[..rows.len() - 1]
    } else {
        rows
    };
    let start = scan
        .iter()
        .rposition(LogRow::terminal)
        .map_or(0, |index| index + 1);
    &rows[start..]
}

fn stage_frame(row: &LogRow) -> Option<Bytes> {
    let event = stage_event(row)?;
    let data = serde_json::to_string(&event).ok()?;
    Some(Bytes::from(format!(
        "id: {}\nevent: stage\ndata: {data}\n\n",
        row.id
    )))
}

fn end_frame(row: &LogRow) -> Bytes {
    let outcome = if row.status == "failed" {
        "failed"
    } else {
        "complete"
    };
    Bytes::from(format!(
        "event: end\ndata: {{\"outcome\":\"{outcome}\"}}\n\n"
    ))
}

const HEARTBEAT_FRAME: &str = ": heartbeat\n\n";
/// A Retry's page asked for the run before its time, and none ended then.
const NO_RUN_FRAME: &str = "event: end\ndata: {\"outcome\":\"none\"}\n\n";
/// The account already holds orchestration's limit of live log follows. The
/// page stops retrying and says so.
const BUSY_FRAME: &str = "event: busy\ndata: {}\n\n";

/// Sends a row, and the end after a terminal row. `false` stops the relay.
async fn send_row(frames: &mpsc::Sender<Bytes>, row: &LogRow) -> bool {
    if let Some(frame) = stage_frame(row)
        && frames.send(frame).await.is_err()
    {
        return false;
    }
    if row.terminal() {
        let _ = frames.send(end_frame(row)).await;
        return false;
    }
    true
}

/// Where rows come from. Production reads orchestration; tests script it.
pub(super) trait LogSource: Send + 'static {
    fn open(
        &self,
        after_log_id: &str,
        follow: bool,
    ) -> mpsc::Receiver<Result<StreamLogsResponse, ConnectError>>;
}

struct Orchestration {
    state: AppState,
    cookie: HeaderValue,
    org_id: String,
    environment_id: String,
}

impl LogSource for Orchestration {
    fn open(
        &self,
        after_log_id: &str,
        follow: bool,
    ) -> mpsc::Receiver<Result<StreamLogsResponse, ConnectError>> {
        environment_connect::environment_log_events(
            &self.state,
            self.cookie.clone(),
            &self.org_id,
            &self.environment_id,
            after_log_id,
            follow,
        )
    }
}

/// Relays rows to `frames` until a terminal row, a read error, or the
/// browser leaving. A read error simply ends this connection; the browser's
/// reconnect resumes after the last row it received.
pub(super) async fn relay(
    source: impl LogSource,
    resume: Option<String>,
    run: Run,
    frames: mpsc::Sender<Bytes>,
) {
    let cursor = match resume {
        Some(cursor) => cursor,
        None => {
            let mut history = std::collections::VecDeque::new();
            let mut events = source.open("", false);
            while let Some(event) = events.recv().await {
                let Ok(response) = event else { return };
                if let Some(Item::Row(row)) = item(response) {
                    if history.len() == MAX_BACKLOG_ROWS {
                        history.pop_front();
                    }
                    history.push_back(row);
                }
            }
            let history = Vec::from(history);
            let shown = current_run(&history, run);
            for row in shown {
                if !send_row(&frames, row).await {
                    return;
                }
            }
            // An ended run is all a Retry's page asks for first. With none in
            // the backlog, the end says so, and the page goes on to the
            // retry's run instead of reconnecting.
            if matches!(run, Run::Before { .. }) {
                if shown.is_empty() {
                    let _ = frames
                        .send(Bytes::from_static(NO_RUN_FRAME.as_bytes()))
                        .await;
                }
                return;
            }
            match history.last() {
                // The last run already ended; there is nothing to follow,
                // unless it was an earlier start's and the page waits for this
                // one.
                Some(row) if row.terminal() && !run.earlier(row) => return,
                Some(row) => row.id.clone(),
                None => String::new(),
            }
        }
    };
    let mut events = source.open(&cursor, true);
    loop {
        // Leave as soon as the browser does, releasing orchestration's
        // live-follow slot for this account.
        let event = tokio::select! {
            () = frames.closed() => return,
            event = events.recv() => event,
        };
        let Some(event) = event else { return };
        let response = match event {
            Ok(response) => response,
            Err(error) => {
                if error.code == ErrorCode::ResourceExhausted {
                    let _ = frames.send(Bytes::from_static(BUSY_FRAME.as_bytes())).await;
                }
                return;
            }
        };
        let follow = match item(response) {
            Some(Item::Row(row)) => send_row(&frames, &row).await,
            Some(Item::Heartbeat) => frames
                .send(Bytes::from_static(HEARTBEAT_FRAME.as_bytes()))
                .await
                .is_ok(),
            None => true,
        };
        if !follow {
            return;
        }
    }
}

fn status(code: StatusCode) -> Response {
    let mut response = code.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The resume cursor from `Last-Event-ID`. A present but malformed value is
/// refused rather than read as a first connection.
pub(super) fn resume_cursor(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if value.is_empty() {
        return Ok(None);
    }
    log_id(value).then(|| Some(value.to_owned())).ok_or(())
}

pub(super) async fn events(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    Query(query): Query<EventsQuery>,
    headers: HeaderMap,
) -> Response {
    let run = query.run();
    if !codewire_server_core::organization_slug::valid_organization_slug(&slug)
        || !super::terminal::canonical_environment_id(&environment_id)
    {
        return status(StatusCode::NOT_FOUND);
    }
    let Ok(resume) = resume_cursor(&headers) else {
        return status(StatusCode::BAD_REQUEST);
    };
    let continuation = super::terminal::terminal_path(&slug, &environment_id);
    let (_, organization, cookie) =
        match super::organization_governance::get_context(&state, &headers, &slug, &continuation)
            .await
        {
            Ok(context) => context,
            // An event stream must not follow redirects or return HTML.
            Err(response) => {
                return status(if response.status().is_redirection() {
                    StatusCode::UNAUTHORIZED
                } else {
                    response.status()
                });
            }
        };
    // Confirm the viewer may read this Sandbox before committing to a stream,
    // so a refusal is an HTTP status the page's EventSource will not retry.
    match environment_connect::environment_data(
        &state,
        cookie.clone(),
        &organization.id,
        &environment_id,
    )
    .await
    {
        Ok(environment) if environment.id == environment_id => {}
        Ok(_) => return status(StatusCode::BAD_GATEWAY),
        Err(error) => {
            return status(match error.code {
                ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
                ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
                ErrorCode::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            });
        }
    }
    let source = Orchestration {
        state,
        cookie,
        org_id: organization.id,
        environment_id,
    };
    let (frames, receiver) = mpsc::channel(32);
    tokio::spawn(async move {
        let _ = tokio::time::timeout(STREAM_LIFETIME, relay(source, resume, run, frames)).await;
    });
    let body = ReceiverStream::new(receiver).map(Ok::<Bytes, Infallible>);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::VARY, "Cookie")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(body))
        .expect("static setup progress headers")
}

#[cfg(test)]
mod tests;
