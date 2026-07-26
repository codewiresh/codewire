//! Environment logs (#38 slice 5) — port of `environment_logs.go`.
//!
//! A RAW handler in Go (chi, not huma): rejections are `http.Error`
//! text/plain `{"error":…}` bodies, the JSON list is `json.NewEncoder`
//! output, and SSE mode streams `data: {log}\n\n` frames fed by
//! `LISTEN environment_logs` with 15s keepalive comments and a
//! terminal short-circuit (phase=complete or status=failed).
//!
//! Byte-parity notes:
//! - `metadata` is embedded as the raw `jsonb::text` rendering (Go's
//!   `json.RawMessage`), NOT re-serialized — jsonb's text form uses
//!   `{"k": "v"}` spacing that a Value round-trip would normalize.
//! - `created_at` is Go `time.RFC3339` of a timestamptz: seconds
//!   precision, `Z` for UTC.

use std::convert::Infallible;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use chrono::{DateTime, Utc};
use codewire_server_core::auth::{AuthUser, authenticate};
use codewire_server_core::{AppError, AppResult};
use serde::Serialize;
use sqlx::postgres::PgListener;
use sqlx::{PgPool, Row};

use super::ApiState;
use super::environments::{require_environment_access, require_org_member};
use super::prepare::{json_response, plain_error, read_bearer, read_session_cookie};

const LOG_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Mirrors `api.EnvironmentLog`.
#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentLog {
    pub id: String,
    pub environment_id: String,
    pub phase: String,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Box<serde_json::value::RawValue>>,
    pub created_at: String,
}

/// One event from the shared environment-log source. SSE renders heartbeats as
/// comments; Connect renders them as the typed `StreamHeartbeat` arm.
#[derive(Debug, Clone)]
pub(crate) enum LogStreamEvent {
    Log(EnvironmentLog),
    Heartbeat(DateTime<Utc>),
}

/// Mirrors Go's `json.Compact` as applied to embedded RawMessage:
/// strips insignificant whitespace WITHOUT reparsing (key order and
/// number formatting stay exactly as jsonb rendered them).
fn compact_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
}

/// Mirrors `isTerminalLog`.
fn is_terminal_log(l: &EnvironmentLog) -> bool {
    l.phase == "complete" || l.status == "failed"
}

/// Mirrors `queryEnvironmentLogs` (after_id empty = all).
async fn query_environment_logs(
    pool: &PgPool,
    env_id: &str,
    after_id: &str,
) -> Result<Vec<EnvironmentLog>, sqlx::Error> {
    let rows = if after_id.is_empty() {
        sqlx::query(
            r#"SELECT id, environment_id, phase, status, COALESCE(message, '') AS message,
                      COALESCE(metadata::text, 'null') AS metadata, created_at
               FROM environment_logs
               WHERE environment_id = $1
               ORDER BY created_at ASC, id ASC"#,
        )
        .bind(env_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            r#"SELECT id, environment_id, phase, status, COALESCE(message, '') AS message,
                      COALESCE(metadata::text, 'null') AS metadata, created_at
               FROM environment_logs
               WHERE environment_id = $1
                 AND (created_at, id) > (
                   SELECT created_at, id
                   FROM environment_logs
                   WHERE environment_id = $1 AND id = $2
                 )
               ORDER BY created_at ASC, id ASC"#,
        )
        .bind(env_id)
        .bind(after_id)
        .fetch_all(pool)
        .await?
    };

    rows.iter()
        .map(|r| {
            let created_at: chrono::DateTime<chrono::Utc> = r.try_get("created_at")?;
            let meta_text: String = r.try_get("metadata")?;
            Ok(EnvironmentLog {
                id: r.try_get("id")?,
                environment_id: r.try_get("environment_id")?,
                phase: r.try_get("phase")?,
                status: r.try_get("status")?,
                message: r.try_get("message")?,
                metadata: serde_json::value::RawValue::from_string(compact_json(&meta_text)).ok(),
                created_at: created_at.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            })
        })
        .collect()
}

/// Opens the one authorized backfill/follow source used by REST JSON, SSE, and
/// Connect. Membership is checked before environment existence and access so
/// every renderer shares the same existence-hiding boundary.
pub(crate) async fn open_environment_log_stream(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    after_log_id: &str,
    follow: bool,
) -> AppResult<tokio::sync::mpsc::UnboundedReceiver<AppResult<LogStreamEvent>>> {
    require_org_member(&state.pool, user, org_id).await?;

    let belongs_to_org: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM environments WHERE id = $1 AND org_id = $2")
            .bind(env_id)
            .bind(org_id)
            .fetch_optional(&state.pool)
            .await?;
    if belongs_to_org.is_none() {
        return Err(AppError::Coded {
            status: StatusCode::NOT_FOUND,
            code: "env_not_found",
            detail: "environment not found".into(),
        });
    }

    require_environment_access(&state.pool, user, env_id, org_id, "viewer", "access denied")
        .await?;

    Ok(start_environment_log_stream(
        state.pool.clone(),
        env_id.to_owned(),
        after_log_id.to_owned(),
        follow,
    ))
}

fn start_environment_log_stream(
    pool: PgPool,
    env_id: String,
    after_log_id: String,
    follow: bool,
) -> tokio::sync::mpsc::UnboundedReceiver<AppResult<LogStreamEvent>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        // Subscribe before backfill so a row committed during the initial query
        // leaves a queued notification and cannot be missed.
        let mut listener = if follow {
            let mut listener = match PgListener::connect_with(&pool).await {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = tx.send(Err(error.into()));
                    return;
                }
            };
            if let Err(error) = listener.listen("environment_logs").await {
                let _ = tx.send(Err(error.into()));
                return;
            }
            Some(listener)
        } else {
            None
        };

        let logs = match query_environment_logs(&pool, &env_id, &after_log_id).await {
            Ok(logs) => logs,
            Err(error) => {
                let _ = tx.send(Err(error.into()));
                return;
            }
        };
        let mut last_id = after_log_id;
        let mut terminal = false;
        for log in logs {
            terminal |= is_terminal_log(&log);
            last_id = log.id.clone();
            if tx.send(Ok(LogStreamEvent::Log(log))).is_err() {
                return;
            }
        }
        if terminal || !follow {
            return;
        }

        let Some(listener) = listener.as_mut() else {
            return;
        };
        let mut heartbeat = tokio::time::interval(LOG_HEARTBEAT_INTERVAL);
        heartbeat.tick().await; // first tick is immediate; skip it
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    if tx.send(Ok(LogStreamEvent::Heartbeat(Utc::now()))).is_err() {
                        return;
                    }
                }
                notification = listener.recv() => {
                    let notification = match notification {
                        Ok(notification) => notification,
                        Err(error) => {
                            let _ = tx.send(Err(error.into()));
                            return;
                        }
                    };
                    if notification.payload() != env_id {
                        continue;
                    }
                    let new_logs = match query_environment_logs(&pool, &env_id, &last_id).await {
                        Ok(logs) => logs,
                        Err(error) => {
                            let _ = tx.send(Err(error.into()));
                            return;
                        }
                    };
                    for log in new_logs {
                        let terminal = is_terminal_log(&log);
                        last_id = log.id.clone();
                        if tx.send(Ok(LogStreamEvent::Log(log))).is_err() {
                            return;
                        }
                        if terminal {
                            return;
                        }
                    }
                }
            }
        }
    });

    rx
}

/// `GET /api/v1/organizations/{org_id}/environments/{env_id}/logs` —
/// mirrors `environmentLogsHandler` (raw; SSE on Accept).
pub async fn environment_logs(
    State(state): State<ApiState>,
    Path((org_id, env_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let session_token = read_session_cookie(&headers);
    let bearer = read_bearer(&headers);
    let user = match authenticate(&state.auth, session_token.as_deref(), bearer.as_deref()).await {
        Ok(u) => u,
        Err(err) if err.is_forbidden() => {
            return plain_error(StatusCode::FORBIDDEN, r#"{"error":"forbidden"}"#);
        }
        Err(_) => return plain_error(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#),
    };

    let wants_sse = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/event-stream"));

    let stream =
        match open_environment_log_stream(&state, &user, &org_id, &env_id, "", wants_sse).await {
            Ok(stream) => stream,
            Err(error) => return raw_log_error(error),
        };

    if wants_sse {
        stream_environment_logs(stream)
    } else {
        match collect_environment_logs(stream).await {
            Ok(logs) => json_response(StatusCode::OK, &logs),
            Err(error) => raw_log_error(error),
        }
    }
}

async fn collect_environment_logs(
    mut stream: tokio::sync::mpsc::UnboundedReceiver<AppResult<LogStreamEvent>>,
) -> AppResult<Vec<EnvironmentLog>> {
    let mut logs = Vec::new();
    while let Some(event) = stream.recv().await {
        match event? {
            LogStreamEvent::Log(log) => logs.push(log),
            LogStreamEvent::Heartbeat(_) => {}
        }
    }
    Ok(logs)
}

fn raw_log_error(error: AppError) -> Response {
    match error {
        AppError::Coded {
            code: "org_not_found",
            ..
        } => plain_error(
            StatusCode::NOT_FOUND,
            r#"{"error":"organization not found"}"#,
        ),
        AppError::Coded {
            code: "env_not_found",
            ..
        } => plain_error(
            StatusCode::NOT_FOUND,
            r#"{"error":"environment not found"}"#,
        ),
        AppError::Coded {
            code: "access_denied",
            ..
        } => plain_error(StatusCode::FORBIDDEN, r#"{"error":"access denied"}"#),
        error => {
            tracing::error!(%error, "environment logs source failed");
            plain_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"internal error"}"#,
            )
        }
    }
}

pub(crate) fn environment_log_sse_frame(event: &LogStreamEvent) -> String {
    match event {
        LogStreamEvent::Log(log) => serde_json::to_string(log)
            .map(|data| format!("data: {data}\n\n"))
            .unwrap_or_default(),
        LogStreamEvent::Heartbeat(_) => ": keepalive\n\n".to_owned(),
    }
}

/// Mirrors `streamEnvironmentLogs` while consuming the shared typed source.
fn stream_environment_logs(
    stream: tokio::sync::mpsc::UnboundedReceiver<AppResult<LogStreamEvent>>,
) -> Response {
    let stream = futures::stream::unfold(stream, |mut rx| async move {
        match rx.recv().await? {
            Ok(event) => Some((Ok::<_, Infallible>(environment_log_sse_frame(&event)), rx)),
            Err(error) => {
                tracing::error!(%error, "environment logs SSE source failed");
                None
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .body(Body::from_stream(stream))
        .expect("sse response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_predicate_mirrors_go() {
        let log = |phase: &str, status: &str| EnvironmentLog {
            id: "l1".into(),
            environment_id: "e1".into(),
            phase: phase.into(),
            status: status.into(),
            message: String::new(),
            metadata: None,
            created_at: "2026-06-12T00:00:00Z".into(),
        };
        assert!(is_terminal_log(&log("complete", "ok")));
        assert!(is_terminal_log(&log("setup", "failed")));
        assert!(!is_terminal_log(&log("setup", "completed")));
    }

    #[test]
    fn log_serializes_with_raw_metadata_and_omitempty_message() {
        let l = EnvironmentLog {
            id: "l1".into(),
            environment_id: "e1".into(),
            phase: "lifecycle_intent".into(),
            status: "completed".into(),
            message: String::new(),
            // jsonb::text spacing is COMPACTED (Go json.Marshal compacts
            // embedded RawMessage), key order preserved.
            metadata: serde_json::value::RawValue::from_string(compact_json(
                r#"{"b txt": 1, "a": "x y"}"#,
            ))
            .ok(),
            created_at: "2026-06-12T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&l).unwrap();
        // Whitespace outside strings stripped; inside strings kept;
        // key order untouched (NOT alphabetized).
        assert!(s.contains(r#""metadata":{"b txt":1,"a":"x y"}"#), "{s}");
        assert!(!s.contains("message"), "{s}");
        // NULL metadata column arrives as the literal string "null".
        let l2 = EnvironmentLog {
            metadata: serde_json::value::RawValue::from_string("null".to_string()).ok(),
            message: "hi".into(),
            ..l
        };
        let s = serde_json::to_string(&l2).unwrap();
        assert!(s.contains(r#""metadata":null"#), "{s}");
        assert!(s.contains(r#""message":"hi""#), "{s}");
    }

    #[test]
    fn sse_frames_remain_frozen_and_heartbeats_are_comments() {
        let log = EnvironmentLog {
            id: "log_1".into(),
            environment_id: "env_1".into(),
            phase: "setup".into(),
            status: "running".into(),
            message: "installing".into(),
            metadata: serde_json::value::RawValue::from_string(
                r#"{"step":2,"nested":{"ok":true}}"#.into(),
            )
            .ok(),
            created_at: "2026-07-18T21:00:00Z".into(),
        };
        assert_eq!(
            environment_log_sse_frame(&LogStreamEvent::Log(log)),
            "data: {\"id\":\"log_1\",\"environment_id\":\"env_1\",\"phase\":\"setup\",\"status\":\"running\",\"message\":\"installing\",\"metadata\":{\"step\":2,\"nested\":{\"ok\":true}},\"created_at\":\"2026-07-18T21:00:00Z\"}\n\n"
        );
        assert_eq!(
            environment_log_sse_frame(&LogStreamEvent::Heartbeat(Utc::now())),
            ": keepalive\n\n"
        );
    }
}
