//! Host operations (#3609, slice 2): where the `HostDriver`, in the Temporal
//! worker, meets the session that holds a host's stream, in whichever
//! replica accepted its `AttachHost`.
//!
//! The driver enqueues an operation and waits for its outcome. The session
//! begins with a fresh generation, claims the pending operations for its
//! host only while that generation is current, sends them, and completes
//! each with the host's result. After a reattach it sends every `sent`
//! operation again, unchanged: the host's supervisor journals operations by
//! ID and answers a repeat with its first result. Payloads and results are
//! the encoded `HostOperation` and `HostOperationResult` protos, kept byte for
//! byte. Migration 0026 has the tables and their rules.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgExecutor, PgPool};

/// The channel an inserted operation is notified on, with its host's ID.
pub const OPERATION_CHANNEL: &str = "host_operation";
/// A waiter reads its operation's row every second at first, then less
/// often as the operation ages, up to every ten seconds: a day-long wait
/// costs about 8,700 short reads, and holds no connection between them.
const POLL_INTERVAL_MIN: Duration = Duration::from_secs(1);
const POLL_INTERVAL_MAX: Duration = Duration::from_secs(10);
/// The reason recorded for a failure the host gave none for.
const NO_REASON: &str = "no reason given";

/// What an operation does to its environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOperationKind {
    Create,
    Start,
    Stop,
    Destroy,
}

impl HostOperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Destroy => "destroy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "create" => Some(Self::Create),
            "start" => Some(Self::Start),
            "stop" => Some(Self::Stop),
            "destroy" => Some(Self::Destroy),
            _ => None,
        }
    }
}

/// Where an operation is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostOperationState {
    /// Waiting for the host's current session to take it.
    Pending,
    /// Sent on `session_generation`; the host has not answered yet.
    Sent { session_generation: i64 },
    /// The host's result, an encoded `HostOperationResult`.
    Done { result: Vec<u8> },
    /// The host's result, when it sent one, and why it failed.
    Failed {
        result: Option<Vec<u8>>,
        reason: String,
    },
}

impl HostOperationState {
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Done { .. } | Self::Failed { .. })
    }
}

/// An operation to enqueue. The driver chooses `operation_id`, so a retried
/// enqueue is the same operation.
#[derive(Clone, Debug)]
pub struct NewHostOperation<'a> {
    pub operation_id: &'a str,
    pub host_id: &'a str,
    pub environment_id: &'a str,
    pub expected_generation: i64,
    pub kind: HostOperationKind,
    /// The encoded `HostOperation`.
    pub payload: &'a [u8],
}

/// A stored operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostOperation {
    pub operation_id: String,
    pub host_id: String,
    pub environment_id: String,
    pub expected_generation: i64,
    pub kind: HostOperationKind,
    pub payload: Vec<u8>,
    pub state: HostOperationState,
    pub created_at: DateTime<Utc>,
}

/// How the host answered an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostOperationOutcome {
    Done {
        result: Vec<u8>,
    },
    Failed {
        result: Option<Vec<u8>>,
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum HostOperationError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    /// An operation with this ID exists with a different host, environment,
    /// kind, generation or payload.
    #[error("operation {operation_id} already exists with a different request")]
    Collision { operation_id: String },
    /// The environment already has an operation that has not finished.
    #[error("environment {environment_id} already has an unfinished host operation")]
    Busy { environment_id: String },
    /// The environment isn't an environment placed on this host.
    #[error("environment {environment_id} is not placed on host {host_id}")]
    NotPlaced {
        environment_id: String,
        host_id: String,
    },
    /// The host was revoked: nothing more is sent to it.
    #[error("host {host_id} is revoked")]
    Revoked { host_id: String },
    #[error("operation {operation_id} is unknown")]
    Unknown { operation_id: String },
    #[error("operation {operation_id} did not finish within {waited:?}")]
    TimedOut {
        operation_id: String,
        waited: Duration,
    },
    /// A stored row the schema allows but this code cannot read.
    #[error("operation {operation_id} has an unreadable {field}")]
    Unreadable {
        operation_id: String,
        field: &'static str,
    },
    /// A stored report the schema allows but this code cannot read.
    #[error("host {host_id}'s report of environment {environment_id} has an unreadable {field}")]
    UnreadableReport {
        host_id: String,
        environment_id: String,
        field: &'static str,
    },
}

#[derive(FromRow)]
struct OperationRow {
    operation_id: String,
    host_id: String,
    environment_id: String,
    expected_generation: i64,
    kind: String,
    payload: Vec<u8>,
    state: String,
    session_generation: Option<i64>,
    result: Option<Vec<u8>>,
    failure: Option<String>,
    created_at: DateTime<Utc>,
}

const COLUMNS: &str = "operation_id, host_id, environment_id, expected_generation, kind, \
     payload, state, session_generation, result, failure, created_at";
/// [`COLUMNS`] of the claimed rows, `o`.
const CLAIMED_COLUMNS: &str = "o.operation_id, o.host_id, o.environment_id, \
     o.expected_generation, o.kind, o.payload, o.state, o.session_generation, o.result, \
     o.failure, o.created_at";

impl TryFrom<OperationRow> for HostOperation {
    type Error = HostOperationError;

    fn try_from(row: OperationRow) -> Result<Self, Self::Error> {
        let unreadable = |field| HostOperationError::Unreadable {
            operation_id: row.operation_id.clone(),
            field,
        };
        let kind = HostOperationKind::parse(&row.kind).ok_or_else(|| unreadable("kind"))?;
        let state = match (row.state.as_str(), row.session_generation) {
            ("pending", None) => HostOperationState::Pending,
            ("sent", Some(session_generation)) => HostOperationState::Sent { session_generation },
            ("done", Some(_)) => HostOperationState::Done {
                result: row.result.clone().ok_or_else(|| unreadable("result"))?,
            },
            ("failed", Some(_)) => HostOperationState::Failed {
                result: row.result.clone(),
                reason: row.failure.clone().ok_or_else(|| unreadable("failure"))?,
            },
            _ => return Err(unreadable("state")),
        };
        Ok(Self {
            operation_id: row.operation_id,
            host_id: row.host_id,
            environment_id: row.environment_id,
            expected_generation: row.expected_generation,
            kind,
            payload: row.payload,
            state,
            created_at: row.created_at,
        })
    }
}

fn operations(rows: Vec<OperationRow>) -> Result<Vec<HostOperation>, HostOperationError> {
    let mut operations = rows
        .into_iter()
        .map(HostOperation::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    operations
        .sort_by(|a, b| (a.created_at, &a.operation_id).cmp(&(b.created_at, &b.operation_id)));
    Ok(operations)
}

// ── The driver's side ─────────────────────────────────────────────────────

/// Enqueues `operation`, or returns it as stored when it was enqueued
/// before. The environment must be placed on the operation's host, a host
/// that isn't revoked (`NotPlaced`, `Revoked`). A different request under
/// the same ID is a `Collision`; a second unfinished operation for the
/// environment is `Busy`.
///
/// A Temporal retry of one activity enqueues the same operation ID again
/// and so finds its operation as stored, answered or not: the ID is the
/// whole identity of a command.
pub async fn enqueue(
    pool: &PgPool,
    operation: &NewHostOperation<'_>,
) -> Result<HostOperation, HostOperationError> {
    let inserted = sqlx::query(
        "INSERT INTO host_operations (operation_id, host_id, environment_id, \
         expected_generation, kind, payload) \
         SELECT $1, h.id, e.id, $4, $5, $6 \
           FROM environments e JOIN hosts h ON h.id = e.host_id \
          WHERE e.id = $3 AND e.host_id = $2 AND e.runtime_backend = 'host' \
            AND h.revoked_at IS NULL \
         ON CONFLICT (operation_id) DO NOTHING",
    )
    .bind(operation.operation_id)
    .bind(operation.host_id)
    .bind(operation.environment_id)
    .bind(operation.expected_generation)
    .bind(operation.kind.as_str())
    .bind(operation.payload)
    .execute(pool)
    .await;
    match inserted {
        Err(sqlx::Error::Database(error))
            if error.constraint() == Some("host_operations_one_open_per_environment") =>
        {
            return Err(HostOperationError::Busy {
                environment_id: operation.environment_id.to_owned(),
            });
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let Some(stored) = get(pool, operation.operation_id).await? else {
        // Nothing was inserted and nothing was there: the placement refused.
        let revoked: Option<bool> =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM hosts WHERE id = $1")
                .bind(operation.host_id)
                .fetch_optional(pool)
                .await?;
        return Err(match revoked {
            Some(true) => HostOperationError::Revoked {
                host_id: operation.host_id.to_owned(),
            },
            _ => HostOperationError::NotPlaced {
                environment_id: operation.environment_id.to_owned(),
                host_id: operation.host_id.to_owned(),
            },
        });
    };
    if stored.host_id != operation.host_id
        || stored.environment_id != operation.environment_id
        || stored.expected_generation != operation.expected_generation
        || stored.kind != operation.kind
        || stored.payload != operation.payload
    {
        return Err(HostOperationError::Collision {
            operation_id: operation.operation_id.to_owned(),
        });
    }
    Ok(stored)
}

/// The operation with this ID, if there is one.
pub async fn get(
    pool: &PgPool,
    operation_id: &str,
) -> Result<Option<HostOperation>, HostOperationError> {
    let row: Option<OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM host_operations WHERE operation_id = $1"
    ))
    .bind(operation_id)
    .fetch_optional(pool)
    .await?;
    row.map(HostOperation::try_from).transpose()
}

/// The environment's unfinished operation, if it has one; it can have at
/// most one.
pub async fn open_for_environment(
    pool: &PgPool,
    environment_id: &str,
) -> Result<Option<HostOperation>, HostOperationError> {
    let row: Option<OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM host_operations \
          WHERE environment_id = $1 AND state IN ('pending', 'sent')"
    ))
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    row.map(HostOperation::try_from).transpose()
}

/// Withdraws an operation no session has taken: the host never saw it, so
/// it is removed as if never asked, and its environment is free for the
/// next one. False when a session took it, or it ended, first; a sent
/// operation is only ever ended by the host's answer.
pub async fn withdraw(pool: &PgPool, operation_id: &str) -> sqlx::Result<bool> {
    let deleted =
        sqlx::query("DELETE FROM host_operations WHERE operation_id = $1 AND state = 'pending'")
            .bind(operation_id)
            .execute(pool)
            .await?;
    Ok(deleted.rows_affected() == 1)
}

/// Waits until the operation is done or failed, for at most `timeout`,
/// reading its row on [`poll_interval`]. An operation withdrawn meanwhile
/// is `Unknown`.
pub async fn wait_finished(
    pool: &PgPool,
    operation_id: &str,
    timeout: Duration,
) -> Result<HostOperation, HostOperationError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let operation =
            get(pool, operation_id)
                .await?
                .ok_or_else(|| HostOperationError::Unknown {
                    operation_id: operation_id.to_owned(),
                })?;
        if operation.state.is_finished() {
            return Ok(operation);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(HostOperationError::TimedOut {
                operation_id: operation_id.to_owned(),
                waited: timeout,
            });
        }
        let age = (Utc::now() - operation.created_at)
            .to_std()
            .unwrap_or_default();
        tokio::time::sleep(poll_interval(age).min(deadline - now)).await;
    }
}

/// How long a waiter sleeps between reads of an operation `age` old: a
/// tenth of its age, from one to ten seconds.
fn poll_interval(age: Duration) -> Duration {
    (age / 10).clamp(POLL_INTERVAL_MIN, POLL_INTERVAL_MAX)
}

// ── The session's side ────────────────────────────────────────────────────

/// Begins a session for a host that is not revoked: the host's next
/// generation, which supersedes every earlier session. `None` when the host
/// is revoked or gone. It waits for any claim in flight, which holds the
/// host's row.
pub async fn begin_session(pool: &PgPool, host_id: &str) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(
        "UPDATE hosts SET session_generation = session_generation + 1 \
          WHERE id = $1 AND revoked_at IS NULL RETURNING session_generation",
    )
    .bind(host_id)
    .fetch_optional(pool)
    .await
}

/// Claims the host's pending operations for the session holding
/// `session_generation`, oldest first, marking them sent on it. A superseded
/// session claims nothing: the claim holds the host's row FOR SHARE, so a
/// new session's [`begin_session`] waits for it to commit and then sees what
/// it sent as sent.
pub async fn claim_pending<'e>(
    executor: impl PgExecutor<'e>,
    host_id: &str,
    session_generation: i64,
) -> Result<Vec<HostOperation>, HostOperationError> {
    let rows: Vec<OperationRow> = sqlx::query_as(&format!(
        "WITH current AS ( \
             SELECT id FROM hosts \
              WHERE id = $1 AND session_generation = $2 AND revoked_at IS NULL \
                FOR SHARE) \
         UPDATE host_operations AS o \
            SET state = 'sent', session_generation = $2, sent_at = now() \
           FROM current \
          WHERE o.host_id = current.id AND o.state = 'pending' \
          RETURNING {CLAIMED_COLUMNS}"
    ))
    .bind(host_id)
    .bind(session_generation)
    .fetch_all(executor)
    .await?;
    operations(rows)
}

/// The host's operations that were sent and not answered, oldest first: a
/// reattached session sends each of them again, unchanged.
pub async fn sent_unanswered(
    pool: &PgPool,
    host_id: &str,
) -> Result<Vec<HostOperation>, HostOperationError> {
    let rows: Vec<OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM host_operations WHERE host_id = $1 AND state = 'sent'"
    ))
    .bind(host_id)
    .fetch_all(pool)
    .await?;
    operations(rows)
}

/// Records the host's answer to a sent operation. The answer is a fact about
/// the host, so any session of the host may record it, but only once: false
/// when the operation is not this host's, not sent, or already answered. A
/// failure with no reason is recorded as having none given.
pub async fn complete(
    pool: &PgPool,
    host_id: &str,
    operation_id: &str,
    outcome: &HostOperationOutcome,
) -> sqlx::Result<bool> {
    let (state, result, failure) = match outcome {
        HostOperationOutcome::Done { result } => ("done", Some(result.as_slice()), None),
        HostOperationOutcome::Failed { result, reason } => (
            "failed",
            result.as_deref(),
            Some(if reason.is_empty() {
                NO_REASON
            } else {
                reason.as_str()
            }),
        ),
    };
    let updated = sqlx::query(
        "UPDATE host_operations \
            SET state = $3, result = $4, failure = $5, completed_at = now() \
          WHERE operation_id = $1 AND host_id = $2 AND state = 'sent'",
    )
    .bind(operation_id)
    .bind(host_id)
    .bind(state)
    .bind(result)
    .bind(failure)
    .execute(pool)
    .await?;
    Ok(updated.rows_affected() == 1)
}

// ── What the host reports ─────────────────────────────────────────────────

/// An environment's state on its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEnvironmentState {
    Stopped,
    Starting,
    Running,
    Error,
    /// The host no longer has the VM: destroyed, or lost.
    Absent,
}

impl HostEnvironmentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Error => "error",
            Self::Absent => "absent",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stopped" => Some(Self::Stopped),
            "starting" => Some(Self::Starting),
            "running" => Some(Self::Running),
            "error" => Some(Self::Error),
            "absent" => Some(Self::Absent),
            _ => None,
        }
    }
}

/// What a host reports of one environment it holds: the contract's
/// `HostEnvironmentObservation`. RUNNING is the daemon ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEnvironmentObservation {
    pub environment_id: String,
    /// The local supervisor's own ID for the VM.
    pub local_environment_id: uuid::Uuid,
    pub generation: i64,
    pub state: HostEnvironmentState,
    /// A machine-readable cause when the state is `Error`, at most 64 bytes.
    pub error_code: Option<String>,
    pub vcpus: i32,
    pub memory_mib: i32,
    pub disk_bytes: i64,
    /// The guest's SSH host key, in OpenSSH public-key form, while running.
    pub ssh_host_key: Option<String>,
}

/// Records a host's report of an environment, unless a report of a later
/// generation is already stored. False when it was older, and kept out.
pub async fn record_observation(
    pool: &PgPool,
    host_id: &str,
    observation: &HostEnvironmentObservation,
) -> sqlx::Result<bool> {
    let written = sqlx::query(
        "INSERT INTO host_environments (host_id, environment_id, local_environment_id, \
         generation, state, error_code, vcpus, memory_mib, disk_bytes, ssh_host_key, \
         observed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now()) \
         ON CONFLICT (host_id, environment_id) DO UPDATE SET \
           local_environment_id = EXCLUDED.local_environment_id, \
           generation = EXCLUDED.generation, state = EXCLUDED.state, \
           error_code = EXCLUDED.error_code, vcpus = EXCLUDED.vcpus, \
           memory_mib = EXCLUDED.memory_mib, disk_bytes = EXCLUDED.disk_bytes, \
           ssh_host_key = EXCLUDED.ssh_host_key, observed_at = EXCLUDED.observed_at \
         WHERE host_environments.generation <= EXCLUDED.generation",
    )
    .bind(host_id)
    .bind(&observation.environment_id)
    .bind(observation.local_environment_id)
    .bind(observation.generation)
    .bind(observation.state.as_str())
    .bind(&observation.error_code)
    .bind(observation.vcpus)
    .bind(observation.memory_mib)
    .bind(observation.disk_bytes)
    .bind(&observation.ssh_host_key)
    .execute(pool)
    .await?;
    Ok(written.rows_affected() == 1)
}

#[derive(FromRow)]
struct ObservationRow {
    environment_id: String,
    local_environment_id: uuid::Uuid,
    generation: i64,
    state: String,
    error_code: Option<String>,
    vcpus: i32,
    memory_mib: i32,
    disk_bytes: i64,
    ssh_host_key: Option<String>,
    observed_at: DateTime<Utc>,
}

/// The host's last report of an environment, and when it came.
pub async fn latest_observation(
    pool: &PgPool,
    host_id: &str,
    environment_id: &str,
) -> Result<Option<(HostEnvironmentObservation, DateTime<Utc>)>, HostOperationError> {
    let row: Option<ObservationRow> = sqlx::query_as(
        "SELECT environment_id, local_environment_id, generation, state, error_code, vcpus, \
                memory_mib, disk_bytes, ssh_host_key, observed_at \
           FROM host_environments WHERE host_id = $1 AND environment_id = $2",
    )
    .bind(host_id)
    .bind(environment_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let state = HostEnvironmentState::parse(&row.state).ok_or_else(|| {
        HostOperationError::UnreadableReport {
            host_id: host_id.to_owned(),
            environment_id: row.environment_id.clone(),
            field: "state",
        }
    })?;
    Ok(Some((
        HostEnvironmentObservation {
            environment_id: row.environment_id,
            local_environment_id: row.local_environment_id,
            generation: row.generation,
            state,
            error_code: row.error_code,
            vcpus: row.vcpus,
            memory_mib: row.memory_mib,
            disk_bytes: row.disk_bytes,
            ssh_host_key: row.ssh_host_key,
        },
        row.observed_at,
    )))
}

#[cfg(test)]
mod database_tests;
