//! Idle suspend (#5529, `docs/dev/IDLE-STOP.md`, "Suspend"): a running
//! `standard` Sandbox with `idle_suspend` on and no activity for that long is
//! asked to suspend, and its daemon's acknowledgement marks it. A marked
//! Sandbox's pause is then checked against the runtime's own records, never
//! against anything the guest says: no pause within [`PAUSE_DEADLINE`] of the
//! mark clears it, and a resume its daemon hasn't reported within
//! [`WAKE_DEADLINE`] is an error.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use futures::StreamExt as _;
use sqlx::PgPool;

use super::WorkerContext;
use super::idle_stop::NO_OPEN_REQUEST;
use crate::api::environment_daemon::{
    DaemonActivity, DaemonSuspend, environment_daemon_activity_for_worker,
    environment_daemon_suspend_for_worker,
};
use crate::lifecycle::{PgLifecycleStore, Service};
use crate::pause_records::{self, Record, VmState};
use crate::runtime::{Placement, RuntimeDriver};
use crate::sandbox::template::RUNTIME_PROFILE_STANDARD;

/// Daemons asked at once in one check.
const DAEMON_CALLS_AT_ONCE: usize = 8;

/// A pause record follows the acknowledgement within this, or the pause
/// failed.
pub(crate) const PAUSE_DEADLINE: Duration = Duration::from_secs(30);
/// A resumed Sandbox's daemon reports the wake within this, or its workload
/// stayed frozen.
pub(crate) const WAKE_DEADLINE: Duration = Duration::from_secs(60);
/// How far the Pod's node and the database clocks may disagree.
const CLOCK_SLACK_MS: i64 = 5_000;

/// The error of a Sandbox that resumed but whose daemon never reported it.
pub(crate) const WAKE_NOT_REPORTED: &str =
    "the sandbox resumed but its daemon did not report the wake";

/// The Pods whose daemon or runtime can't suspend, by environment and Pod: a
/// `standard` Sandbox is never re-rendered, so such a Pod is never asked
/// again. Kept in this worker only; a restart asks each once more.
static CANT_SUSPEND: LazyLock<Mutex<HashSet<(String, String)>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct Candidate {
    pub(super) id: String,
    namespace: String,
    pod_name: Option<String>,
    idle_suspend_seconds: i32,
}

/// The running, unmarked `standard` Sandboxes whose own activity is older
/// than their suspend timeout, with no request open.
pub(super) async fn candidates(pool: &PgPool) -> Result<Vec<Candidate>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"SELECT e.id, b.namespace, b.pod_name, e.idle_suspend_seconds
           FROM environments e
           JOIN sandbox_environment_backend b ON b.environment_id = e.id
           WHERE e.idle_suspend_seconds > 0 AND e.runtime_profile = $1
             AND e.desired_state = 'started' AND e.state = 'running'
             AND e.suspended_at IS NULL
             AND COALESCE(e.last_activity_at, e.started_at, e.created_at)
                 < NOW() - make_interval(secs => e.idle_suspend_seconds)
             AND {NO_OPEN_REQUEST}
           ORDER BY e.id"#
    ))
    .bind(RUNTIME_PROFILE_STANDARD)
    .fetch_all(pool)
    .await
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct Marked {
    pub(super) id: String,
    namespace: String,
    pod_name: Option<String>,
    pub(super) suspended_at: chrono::DateTime<chrono::Utc>,
}

pub(super) async fn marked(pool: &PgPool) -> Result<Vec<Marked>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT e.id, b.namespace, b.pod_name, e.suspended_at
           FROM environments e
           JOIN sandbox_environment_backend b ON b.environment_id = e.id
           WHERE e.suspended_at IS NOT NULL
             AND e.desired_state = 'started' AND e.state = 'running'
           ORDER BY e.id"#,
    )
    .fetch_all(pool)
    .await
}

/// What a marked Sandbox's records say of its mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkCheck {
    /// Paused since the mark.
    Paused,
    /// Not decided yet.
    Waiting,
    /// No pause followed the acknowledgement: clear the mark.
    PauseFailed,
    /// It resumed after the mark and its daemon never reported the wake.
    WakeNotReported,
}

/// The boot's state as the latest record in a read says, and since when.
fn latest(records: &[Record]) -> Option<(VmState, i64)> {
    records.last().map(|record| {
        let (state, since) = match record {
            Record::Pause(pause) => (
                match pause.event {
                    pause_records::PauseEvent::Paused => VmState::Paused,
                    pause_records::PauseEvent::Resumed => VmState::Running,
                },
                pause.at_unix_ms,
            ),
            Record::State(state) => (state.state, state.since_unix_ms),
        };
        (state, i64::try_from(since).unwrap_or(i64::MAX))
    })
}

/// Decides a mark set at `marked_ms` from the records read at `now_ms`.
pub(crate) fn check(records: &[Record], marked_ms: i64, now_ms: i64) -> MarkCheck {
    let deadline = |since: i64, limit: Duration| {
        now_ms.saturating_sub(since) >= i64::try_from(limit.as_millis()).unwrap_or(i64::MAX)
    };
    let after_mark = |since: i64| since >= marked_ms.saturating_sub(CLOCK_SLACK_MS);
    match latest(records) {
        Some((VmState::Paused, since)) if after_mark(since) => MarkCheck::Paused,
        Some((VmState::Running, since)) if after_mark(since) => {
            if deadline(since, WAKE_DEADLINE) {
                MarkCheck::WakeNotReported
            } else {
                MarkCheck::Waiting
            }
        }
        // Nothing since the mark says paused.
        _ if deadline(marked_ms, PAUSE_DEADLINE) => MarkCheck::PauseFailed,
        _ => MarkCheck::Waiting,
    }
}

/// Asks the idle candidates to suspend and checks the marked Sandboxes,
/// once per reconciler tick.
pub(crate) async fn suspend_idle_environments(ctx: &WorkerContext) {
    let Some(runtime) = ctx.runtime.as_deref() else {
        return;
    };
    match candidates(&ctx.pool).await {
        Ok(candidates) => ask(ctx, runtime, candidates).await,
        Err(error) => tracing::error!(error = %error, "reconciler: query idle suspend candidates"),
    }
    match marked(&ctx.pool).await {
        Ok(marked) => check_marked(ctx, runtime, marked).await,
        Err(error) => tracing::error!(error = %error, "reconciler: query suspended sandboxes"),
    }
}

async fn ask(ctx: &WorkerContext, runtime: &dyn RuntimeDriver, candidates: Vec<Candidate>) {
    // A standard Sandbox's guest kernel is its own VM's, so its Docker
    // container's CPU counts too.
    let include_guest_cpu = true;
    futures::stream::iter(candidates)
        .for_each_concurrent(DAEMON_CALLS_AT_ONCE, |candidate| async move {
            let Ok(pod) = pod_name(runtime, &candidate.namespace, &candidate.id, candidate.pod_name.as_deref()).await
            else {
                return;
            };
            let key = (candidate.id.clone(), pod);
            if cant_suspend().contains(&key) {
                return;
            }
            let activity = environment_daemon_activity_for_worker(
                &ctx.pool,
                Some(runtime),
                &ctx.sandbox_cfg.session_secret,
                &candidate.namespace,
                &candidate.id,
                include_guest_cpu,
            )
            .await;
            let timeout = i64::from(candidate.idle_suspend_seconds);
            let now = chrono::Utc::now();
            let seen = match activity {
                Ok(DaemonActivity::LastActive(seen)) => seen
                    .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
                    .map(|seen| seen.min(now)),
                Ok(DaemonActivity::Unsupported) => {
                    cant_suspend().insert(key);
                    return;
                }
                Err(error) => {
                    tracing::debug!(environment_id = candidate.id, error = %error, "reconciler: idle suspend check could not reach the daemon");
                    return;
                }
            };
            if let Some(seen) = seen {
                if let Err(error) = super::idle_stop::record_activity(&ctx.pool, &candidate.id, seen).await {
                    tracing::warn!(environment_id = candidate.id, error = %error, "reconciler: record daemon activity");
                }
                if now.signed_duration_since(seen).num_seconds() < timeout {
                    return;
                }
            }
            let answer = environment_daemon_suspend_for_worker(
                &ctx.pool,
                Some(runtime),
                &ctx.sandbox_cfg.session_secret,
                &candidate.namespace,
                &candidate.id,
            )
            .await;
            match answer {
                Ok(DaemonSuspend::Accepted) => match mark(&ctx.pool, &candidate.id).await {
                    Ok(()) => tracing::info!(
                        environment_id = candidate.id,
                        idle_suspend_seconds = candidate.idle_suspend_seconds,
                        "reconciler: suspending an idle sandbox"
                    ),
                    Err(error) => tracing::error!(environment_id = candidate.id, error = %error, "reconciler: mark a sandbox suspended"),
                },
                Ok(DaemonSuspend::NotAccepted) => {}
                Ok(DaemonSuspend::CantSuspend) => {
                    tracing::info!(environment_id = candidate.id, "reconciler: this sandbox's runtime can't suspend");
                    cant_suspend().insert(key);
                }
                Err(error) => {
                    tracing::warn!(environment_id = candidate.id, error = %error, "reconciler: ask a sandbox to suspend");
                }
            }
        })
        .await;
}

async fn check_marked(ctx: &WorkerContext, runtime: &dyn RuntimeDriver, marked: Vec<Marked>) {
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    for sandbox in marked {
        let Ok(pod) = pod_name(
            runtime,
            &sandbox.namespace,
            &sandbox.id,
            sandbox.pod_name.as_deref(),
        )
        .await
        else {
            continue;
        };
        let log = match runtime
            .runtime_log_since(
                &Placement::new(&sandbox.namespace),
                &pod,
                pause_records::READ_WINDOW,
                pause_records::READ_LIMIT_BYTES,
            )
            .await
        {
            Ok(log) => log,
            Err(_) => {
                // The error may quote what was read; only that it failed is kept.
                tracing::warn!(
                    environment_id = sandbox.id,
                    "reconciler: read a suspended sandbox's pause records"
                );
                continue;
            }
        };
        let read = pause_records::read(&log);
        if read.refused > 0 {
            tracing::warn!(
                environment_id = sandbox.id,
                refused = read.refused,
                "reconciler: refused malformed pause records"
            );
        }
        match check(
            &read.records,
            sandbox.suspended_at.timestamp_millis(),
            chrono::Utc::now().timestamp_millis(),
        ) {
            MarkCheck::Paused | MarkCheck::Waiting => {}
            MarkCheck::PauseFailed => {
                match clear_mark(&ctx.pool, &sandbox.id, sandbox.suspended_at).await {
                    Ok(()) => tracing::info!(
                        environment_id = sandbox.id,
                        "reconciler: no pause followed a suspend; the sandbox runs"
                    ),
                    Err(error) => {
                        tracing::error!(environment_id = sandbox.id, error = %error, "reconciler: clear a failed suspend")
                    }
                }
            }
            MarkCheck::WakeNotReported => {
                match svc
                    .mark_error_for_states(&sandbox.id, WAKE_NOT_REPORTED, &["running"])
                    .await
                {
                    Ok(_) => tracing::warn!(
                        environment_id = sandbox.id,
                        "reconciler: {WAKE_NOT_REPORTED}"
                    ),
                    Err(error) => {
                        tracing::error!(environment_id = sandbox.id, error = %error, "reconciler: mark a sandbox whose wake was not reported")
                    }
                }
            }
        }
    }
}

fn cant_suspend() -> std::sync::MutexGuard<'static, HashSet<(String, String)>> {
    CANT_SUSPEND
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

async fn pod_name(
    runtime: &dyn RuntimeDriver,
    namespace: &str,
    environment_id: &str,
    known: Option<&str>,
) -> anyhow::Result<String> {
    match known.map(str::trim) {
        Some(known) if !known.is_empty() => Ok(known.to_owned()),
        _ => {
            runtime
                .member_name(&Placement::new(namespace), environment_id)
                .await
        }
    }
}

/// Marks a running Sandbox suspended, the daemon having acknowledged.
pub(super) async fn mark(pool: &PgPool, environment_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE environments SET suspended_at = NOW() \
         WHERE id = $1 AND state = 'running' AND suspended_at IS NULL",
    )
    .bind(environment_id)
    .execute(pool)
    .await
    .map(drop)
}

/// Clears the mark set at `suspended_at`, and no later one.
pub(super) async fn clear_mark(
    pool: &PgPool,
    environment_id: &str,
    suspended_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE environments SET suspended_at = NULL WHERE id = $1 AND suspended_at = $2")
        .bind(environment_id)
        .bind(suspended_at)
        .execute(pool)
        .await
        .map(drop)
}

#[cfg(test)]
#[path = "idle_suspend/tests.rs"]
mod tests;
