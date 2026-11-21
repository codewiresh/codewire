//! Following an environment's setup: the `environment_logs` rows that
//! `StreamLogs` delivers, the facts a row carries, and the follower that
//! resumes after the last row it handed on when a connection drops or stops
//! sending heartbeats, so a reconnect neither repeats nor skips a row.
//!
//! `cw create`, `cw start` and `cw logs ENV --setup --follow` follow setup
//! through this module, and the iOS app follows a create the same way
//! (#3825). [`await_setup`] is the whole wait of a create: the follow, a
//! guard for a setup that stops without a `failed` row, and the workspace
//! daemon's readiness. The words a person reads stay with each surface: this module
//! carries rows, typed facts about them and the state of the connection.
//!
//! # The daemon status setup read (#3684)
//!
//! Setup reads the workspace daemon's status in-cluster beside its health
//! check and reports it, before `complete`, as one row:
//!
//! - `phase`: `daemon_ready`; `status`: `completed`.
//! - `metadata.state`: the state token `cw daemon status` prints (`ready`,
//!   `starting`, `upgrade_required`, `unsupported`, `unhealthy`,
//!   `unspecified`); `metadata.message`: the daemon's message.
//!
//! [`daemon_ready_row`] reads it. A daemon still starting, or a server that
//! writes no such row, is asked through the API instead.

mod follow;
mod retry;
mod wait;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ClientError, CodewireClient, EnvironmentLog, ErrorCode, StreamLogsRequest, StreamLogsResponse,
    Timestamp, stream_logs_response,
};

pub use follow::{
    EnvironmentLogFeed, FollowEnd, FollowError, FollowPolicy, Interruption, LogFeedConnection,
    LogFeedEvent, PlatformLogFeed, SetupObserver, follow_setup, wait_with_ticks,
};
pub use retry::RECLONE_UNCONFIRMED;
pub use wait::{
    CONFIDENTIAL_READY_TIMEOUT, DAEMON_READY_TIMEOUT, DaemonObservation, DaemonWaitError,
    EnvironmentFacts, GetEnvironmentError, PlatformEnd, READY_POLL, READY_TIMEOUT,
    SETUP_GUARD_INTERVAL, SetupEnd, SetupStop, SetupWaitError, SetupWaitObserver,
    await_daemon_ready, await_setup, daemon_state_token, desired_state_token,
    environment_state_token, get_environment_facts, lifecycle_ready_timeout, ready_poll,
    watch_environment,
};

/// One `environment_logs` row as a client shows it. Its JSON shape is the
/// one `cw logs --output json` prints.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct EnvironmentLogRow {
    pub id: String,
    pub environment_id: String,
    pub phase: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub created_at: String,
}

impl EnvironmentLogRow {
    /// The row a `StreamLogs` log event carries. Fails only when its metadata
    /// cannot be represented as JSON.
    pub fn from_proto(value: EnvironmentLog) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: value.id,
            environment_id: value.environment_id,
            phase: value.phase,
            status: value.status,
            message: value.message,
            metadata: value
                .metadata
                .into_option()
                .map(serde_json::to_value)
                .transpose()?,
            created_at: value
                .created_at
                .into_option()
                .map(timestamp_to_rfc3339)
                .unwrap_or_default(),
        })
    }
}

/// The row in one `StreamLogs` message, or `None` for a heartbeat.
pub fn log_row_from_stream(
    message: StreamLogsResponse,
) -> Result<Option<EnvironmentLogRow>, serde_json::Error> {
    match message.event {
        Some(stream_logs_response::Event::Log(log)) => {
            EnvironmentLogRow::from_proto(*log).map(Some)
        }
        Some(stream_logs_response::Event::Heartbeat(_)) | None => Ok(None),
    }
}

/// An out-of-range timestamp reads as the empty string, as an absent one does.
fn timestamp_to_rfc3339(timestamp: Timestamp) -> String {
    u32::try_from(timestamp.nanos)
        .ok()
        .and_then(|nanos| DateTime::<Utc>::from_timestamp(timestamp.seconds, nanos))
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// One event from a following environment-log stream.
#[derive(Clone, Debug, PartialEq)]
pub enum EnvironmentLogStreamEvent {
    Log(EnvironmentLogRow),
    Heartbeat,
}

/// Why a log stream connection failed.
#[derive(Debug, thiserror::Error)]
pub enum LogStreamError {
    #[error(transparent)]
    Client(#[from] ClientError),
    /// A row this client cannot decode; it would fail again after a
    /// reconnect.
    #[error(transparent)]
    Decode(#[from] serde_json::Error),
}

/// Why one environment-log stream connection ended early.
#[derive(Debug)]
pub struct EnvironmentLogStreamFailure {
    pub error: LogStreamError,
    pub recovery: LogStreamRecovery,
}

/// How a follower recovers from an ended log stream connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStreamRecovery {
    /// The client's whole-call deadline, which also bounds streams, ended the
    /// connection. Resume at once.
    Resume,
    /// A transient failure. Resume after a backoff, within a bounded budget.
    Retry,
    /// Reconnecting cannot help: authorization, a missing environment, a
    /// rejected request, or a row this client cannot decode.
    Fatal,
}

pub fn log_stream_recovery(code: ErrorCode) -> LogStreamRecovery {
    match code {
        ErrorCode::DeadlineExceeded => LogStreamRecovery::Resume,
        ErrorCode::Unauthenticated
        | ErrorCode::PermissionDenied
        | ErrorCode::NotFound
        | ErrorCode::InvalidArgument
        | ErrorCode::FailedPrecondition
        | ErrorCode::Unimplemented => LogStreamRecovery::Fatal,
        _ => LogStreamRecovery::Retry,
    }
}

impl CodewireClient {
    /// Opens one following `StreamLogs` connection that resumes strictly
    /// after `after_log_id` (the server's composite cursor). Heartbeats are
    /// surfaced so the caller can detect a silent connection; returning
    /// `false` from `on_event` closes the stream.
    pub async fn follow_environment_log_stream<F>(
        &self,
        org_id: &str,
        environment_id: &str,
        after_log_id: Option<&str>,
        mut on_event: F,
    ) -> Result<(), EnvironmentLogStreamFailure>
    where
        F: FnMut(EnvironmentLogStreamEvent) -> bool,
    {
        let mut conversion_error = None;
        let result = self
            .stream_logs(
                StreamLogsRequest {
                    org_id: org_id.to_string(),
                    environment_id: environment_id.to_string(),
                    follow: true,
                    after_log_id: after_log_id.unwrap_or_default().to_string(),
                    ..Default::default()
                },
                |message| match message.event {
                    Some(stream_logs_response::Event::Log(log)) => {
                        match EnvironmentLogRow::from_proto(*log) {
                            Ok(log) => on_event(EnvironmentLogStreamEvent::Log(log)),
                            Err(error) => {
                                conversion_error = Some(error);
                                false
                            }
                        }
                    }
                    Some(stream_logs_response::Event::Heartbeat(_)) => {
                        on_event(EnvironmentLogStreamEvent::Heartbeat)
                    }
                    None => true,
                },
            )
            .await;
        if let Some(error) = conversion_error {
            // The same row would fail again after a reconnect.
            return Err(EnvironmentLogStreamFailure {
                error: error.into(),
                recovery: LogStreamRecovery::Fatal,
            });
        }
        result.map_err(|error| EnvironmentLogStreamFailure {
            recovery: log_stream_recovery(error.code()),
            error: error.into(),
        })
    }
}

/// The server's own steps, which mean nothing to someone waiting for an
/// environment (#4596): checking its sidecars and daemon, or preparing the
/// sandbox (its namespace, binding the workspace, recording the backend,
/// state transitions and timestamps, marking it running and queueing setup).
/// Each surface names them in its own words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerStep {
    DaemonWait,
    SandboxPrep,
}

pub fn server_step(phase: &str) -> Option<ServerStep> {
    match phase {
        "health_check" | "daemon_ready" => Some(ServerStep::DaemonWait),
        "ensure_namespace"
        | "workspace_bind"
        | "store_backend"
        | "lifecycle_transition"
        | "lifecycle_checkpoint"
        | "mark_running"
        | "publish_setup" => Some(ServerStep::SandboxPrep),
        _ => None,
    }
}

/// The workspace daemon's state as `cw daemon status` names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonState {
    Ready,
    Starting,
    UpgradeRequired,
    Unsupported,
    Unhealthy,
    Unspecified,
    /// A token this client does not know, kept as written.
    Other(String),
}

impl DaemonState {
    pub fn from_token(token: &str) -> Self {
        match token {
            "ready" => Self::Ready,
            "starting" => Self::Starting,
            "upgrade_required" => Self::UpgradeRequired,
            "unsupported" => Self::Unsupported,
            "unhealthy" => Self::Unhealthy,
            "unspecified" => Self::Unspecified,
            other => Self::Other(other.to_owned()),
        }
    }

    pub fn token(&self) -> &str {
        match self {
            Self::Ready => "ready",
            Self::Starting => "starting",
            Self::UpgradeRequired => "upgrade_required",
            Self::Unsupported => "unsupported",
            Self::Unhealthy => "unhealthy",
            Self::Unspecified => "unspecified",
            Self::Other(token) => token,
        }
    }
}

/// The daemon status a setup `daemon_ready` row reports (#3684).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonReadyRow {
    pub state: DaemonState,
    pub message: String,
}

/// The daemon status in a setup `daemon_ready` row, whose metadata carries
/// the state token and the daemon's message.
pub fn daemon_ready_row(row: &EnvironmentLogRow) -> Option<DaemonReadyRow> {
    if row.phase != "daemon_ready" {
        return None;
    }
    let metadata = row.metadata.as_ref()?;
    let state = metadata.get("state")?.as_str()?;
    Some(DaemonReadyRow {
        state: DaemonState::from_token(state),
        message: metadata
            .get("message")
            .and_then(|message| message.as_str())
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A non-negative whole number from row metadata. Metadata crosses Connect
/// as `google.protobuf.Struct`, whose numbers are doubles, so `3` arrives as
/// `3.0`.
pub fn metadata_count(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
            // A whole, finite, non-negative double below 2^64 converts exactly
            // to its integer part.
            .filter(|number| *number < u64::MAX as f64)
            .map(|number| number as u64)
    })
}

/// `repo_index` when the row is scoped to one repository.
pub fn repository_scope(metadata: Option<&Value>) -> Option<u64> {
    metadata
        .and_then(|metadata| metadata.get("repo_index"))
        .and_then(metadata_count)
}

/// The stage a row belongs to: its phase, per repository when it is scoped
/// to one.
pub fn stage_key(phase: &str, repository: Option<u64>) -> String {
    match repository {
        Some(index) => format!("{phase}#{index}"),
        None => phase.to_owned(),
    }
}

/// The stage's duration the server measured, in `duration_ms` metadata.
pub fn reported_duration_ms(metadata: Option<&Value>) -> Option<u64> {
    metadata
        .and_then(|metadata| metadata.get("duration_ms"))
        .and_then(metadata_count)
}
