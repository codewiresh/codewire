//! `GET /_events/live` (#4762): the page's one live stream, a relay of
//! orchestration's `LiveService.Watch` built as setup progress is
//! (private-docs `designs/live-updates.md` §2.3, §3a).
//!
//! - Orchestration authorizes the watch; a refusal is a plain HTTP status,
//!   which EventSource does not retry.
//! - Every event carries ids only: `sandbox`, `resize` and `audit` name the
//!   organization and the Sandbox, `credit` the organization. The page
//!   re-fetches through routes that re-authorize.
//! - `resync` passes through; heartbeats become comments; over the account's
//!   limit of watches the page gets `busy` and falls back.

use std::{convert::Infallible, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use codewire_proto::codewire::console::v1::{WatchResponse, watch_response::Event};
use connectrpc::{ConnectError, ErrorCode};
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};

use crate::{live_connect, security::canonical_cookie, state::AppState};

/// Orchestration ends a watch after ten minutes; the relay holds no longer.
const STREAM_LIFETIME: Duration = Duration::from_secs(10 * 60);
const HEARTBEAT_FRAME: &str = ": heartbeat\n\n";
/// The account holds orchestration's limit of watches: the page falls back.
const BUSY_FRAME: &str = "event: busy\ndata: {}\n\n";

/// One SSE frame for an event, or `None` for a kind this page doesn't know.
pub(super) fn frame(response: &WatchResponse) -> Option<Bytes> {
    let (name, data) = match response.event.as_ref()? {
        Event::Resync(_) => ("resync", json!({})),
        Event::Heartbeat(_) => return Some(Bytes::from_static(HEARTBEAT_FRAME.as_bytes())),
        Event::Sandbox(change) => (
            "sandbox",
            json!({"organization": change.org_id, "environment": change.environment_id}),
        ),
        Event::Resize(change) => (
            "resize",
            json!({"organization": change.org_id, "environment": change.environment_id}),
        ),
        Event::Credit(change) => ("credit", json!({"organization": change.org_id})),
        Event::Audit(change) => (
            "audit",
            json!({"organization": change.org_id, "environment": change.environment_id}),
        ),
    };
    Some(Bytes::from(format!("event: {name}\ndata: {data}\n\n")))
}

/// The status a refused watch answers with, before any stream is committed.
fn refusal(error: &ConnectError) -> StatusCode {
    match error.code {
        ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Relays events to `frames` until the watch ends or fails, or the browser
/// leaves. `first` is the event that opened the stream.
pub(super) async fn relay(
    first: WatchResponse,
    mut events: mpsc::Receiver<Result<WatchResponse, ConnectError>>,
    frames: mpsc::Sender<Bytes>,
) {
    let mut event: Option<Result<WatchResponse, ConnectError>> = Some(Ok(first));
    while let Some(next) = event {
        let response = match next {
            Ok(response) => response,
            Err(error) => {
                if error.code == ErrorCode::ResourceExhausted {
                    let _ = frames.send(Bytes::from_static(BUSY_FRAME.as_bytes())).await;
                }
                return;
            }
        };
        if let Some(frame) = frame(&response)
            && frames.send(frame).await.is_err()
        {
            return;
        }
        // Leave as soon as the browser does, releasing orchestration's
        // watch slot for this account.
        event = tokio::select! {
            () = frames.closed() => return,
            event = events.recv() => event,
        };
    }
}

fn status(code: StatusCode) -> Response {
    let mut response = code.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn stream(body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::VARY, "Cookie")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header("x-accel-buffering", "no")
        .body(body)
        .expect("static live stream headers")
}

pub(super) async fn events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Ok(cookie) = canonical_cookie(&headers) else {
        return status(StatusCode::UNAUTHORIZED);
    };
    let mut events = live_connect::watch_events(&state, cookie);
    // Orchestration sends `resync` first; waiting for it lets a refusal be a
    // status rather than a stream that ends at once.
    let first = match events.recv().await {
        Some(Ok(first)) => first,
        Some(Err(error)) if error.code == ErrorCode::ResourceExhausted => {
            return stream(Body::from(BUSY_FRAME));
        }
        Some(Err(error)) => return status(refusal(&error)),
        None => return status(StatusCode::SERVICE_UNAVAILABLE),
    };
    let (frames, receiver) = mpsc::channel(32);
    tokio::spawn(async move {
        let _ = tokio::time::timeout(STREAM_LIFETIME, relay(first, events, frames)).await;
    });
    stream(Body::from_stream(
        ReceiverStream::new(receiver).map(Ok::<Bytes, Infallible>),
    ))
}

#[cfg(test)]
mod tests;
