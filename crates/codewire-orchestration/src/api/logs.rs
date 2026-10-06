//! Environment-log query and follow support for Connect EnvironmentService.
//!
//! The shared source backfills persisted logs, follows the process-wide
//! `LISTEN environment_logs` fan-out ([`super::log_notifications`]), emits a
//! heartbeat every 15 seconds, and stops when the environment reaches a
//! terminal phase. Connect owns the wire framing and typed heartbeat
//! representation.

use std::future::Future;
use std::time::Duration;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use serde::Serialize;
use sqlx::{PgPool, Row};
use tokio::sync::broadcast::error::RecvError;

use super::ApiState;
use super::environments::{require_environment_access, require_org_member};
use super::log_notifications::{FollowPermit, LogSignal};

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

/// Opens the authorized backfill/follow source used by Connect. Membership is
/// checked before environment existence and access so the service preserves
/// the same existence-hiding boundary for every stream.
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

    // Bound each account's live follows; a bounded backfill read is free.
    let follow = if follow {
        Some(
            state
                .environment_logs
                .acquire_follow(&user.user_id)
                .ok_or_else(follow_limit_exceeded)?,
        )
    } else {
        None
    };
    Ok(start_environment_log_stream(
        state.pool.clone(),
        env_id.to_owned(),
        after_log_id.to_owned(),
        follow,
    ))
}

fn follow_limit_exceeded() -> AppError {
    AppError::Coded {
        status: StatusCode::TOO_MANY_REQUESTS,
        code: "log_stream_limit_exceeded",
        detail: "too many live log streams are open for this account; close one and try again"
            .into(),
    }
}

/// Where a follower reads rows: strictly after `after_id`, or all of them
/// when it is empty.
pub(crate) trait LogRows: Send + Sync + 'static {
    fn after(
        &self,
        env_id: &str,
        after_id: &str,
    ) -> impl Future<Output = Result<Vec<EnvironmentLog>, sqlx::Error>> + Send;
}

impl LogRows for PgPool {
    fn after(
        &self,
        env_id: &str,
        after_id: &str,
    ) -> impl Future<Output = Result<Vec<EnvironmentLog>, sqlx::Error>> + Send {
        query_environment_logs(self, env_id, after_id)
    }
}

/// Backfills, then (with a follow permit) follows the shared notifications.
/// A follower re-reads after the last row it sent when its environment is
/// signalled, after a listener resync, when it fell behind the shared
/// channel, and on every heartbeat, so a missed notification delays a row by
/// at most one heartbeat and never loses it. The permit is released when the
/// stream ends, including when its reader goes away.
pub(crate) fn start_environment_log_stream<R: LogRows>(
    rows: R,
    env_id: String,
    after_log_id: String,
    follow: Option<FollowPermit>,
) -> tokio::sync::mpsc::UnboundedReceiver<AppResult<LogStreamEvent>> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        // Subscribe before backfill so a row committed during the initial query
        // leaves a queued signal and cannot be missed.
        let mut signals = follow.as_ref().map(FollowPermit::subscribe);

        let logs = match rows.after(&env_id, &after_log_id).await {
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
        let Some(signals) = signals.as_mut() else {
            return;
        };
        if terminal {
            return;
        }

        let mut heartbeat = tokio::time::interval(LOG_HEARTBEAT_INTERVAL);
        heartbeat.tick().await; // first tick is immediate; skip it
        loop {
            let reread = tokio::select! {
                () = tx.closed() => return,
                _ = heartbeat.tick() => {
                    if tx.send(Ok(LogStreamEvent::Heartbeat(Utc::now()))).is_err() {
                        return;
                    }
                    true
                }
                signal = signals.recv() => match signal {
                    Ok(LogSignal::Environment(id)) => *id == *env_id,
                    Ok(LogSignal::Resync) | Err(RecvError::Lagged(_)) => true,
                    Err(RecvError::Closed) => {
                        let _ = tx.send(Err(AppError::ServiceUnavailable(
                            "environment log notifications stopped".into(),
                        )));
                        return;
                    }
                },
            };
            if !reread {
                continue;
            }
            let new_logs = match rows.after(&env_id, &last_id).await {
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
    });

    rx
}

#[cfg(test)]
mod follow_tests;

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
}
