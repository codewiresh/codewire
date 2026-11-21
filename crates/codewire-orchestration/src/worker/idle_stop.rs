//! Idle stop (#3384, `docs/dev/IDLE-STOP.md`): a running cloud Sandbox with
//! an idle timeout that has had no activity for that long stops itself, as
//! the ordinary stop, keeping its disk.
//!
//! Activity has two halves. Orchestration keeps `environments.last_activity_at`:
//! a start, a finished agent or `cw` runtime request, and a preview request
//! from anyone, at most once a minute ([`note_activity`]). An agent or runtime
//! request still open counts as activity now. The Sandbox's daemon keeps the
//! rest, CPU, terminal input or output and inbound connections, and answers
//! `GetActivity`.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt as _;
use sqlx::PgPool;

use super::WorkerContext;
use crate::api::environment_daemon::{DaemonActivity, environment_daemon_activity_for_worker};
use crate::lifecycle::{PgLifecycleStore, Service};
use crate::sandbox::template::{RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL};

/// `on` or `off`. Unset or empty is off.
pub const IDLE_STOP_ENV: &str = "CODEWIRE_IDLE_STOP";

/// Whether this deployment stops idle Sandboxes. Off unless a deployment
/// turns it on, so a release never starts stopping Sandboxes by itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IdleStop {
    #[default]
    Off,
    On,
}

impl IdleStop {
    /// Anything else than `on` or `off` is refused, so a typo stops the
    /// service instead of quietly choosing whether Sandboxes stop.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim) {
            None | Some("" | "off") => Ok(Self::Off),
            Some("on") => Ok(Self::On),
            Some(value) => Err(format!(
                "{IDLE_STOP_ENV} must be \"on\" or \"off\"; got {value:?}"
            )),
        }
    }

    /// [`Self::parse`] of [`IDLE_STOP_ENV`].
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(std::env::var(IDLE_STOP_ENV).ok().as_deref()).map_err(anyhow::Error::msg)
    }

    pub fn is_on(self) -> bool {
        self == Self::On
    }
}

/// No agent or `cw` runtime request of the Sandbox `e` is open. A request
/// open for over a day no longer counts, so a row that never closes can't
/// hold a Sandbox up for ever.
pub(crate) const NO_OPEN_REQUEST: &str = r#"NOT EXISTS (
        SELECT 1 FROM environment_platform_agent_requests r
        WHERE r.organization_id = e.org_id AND r.environment_id = e.id
          AND r.terminal_at IS NULL AND r.admitted_at > NOW() - interval '24 hours')
    AND NOT EXISTS (
        SELECT 1 FROM environment_cw_runtime_requests r
        WHERE r.organization_id = e.org_id AND r.environment_id = e.id
          AND r.terminal_at IS NULL AND r.admitted_at > NOW() - interval '24 hours')"#;

/// Whether the guest kernel's CPU is this Sandbox's own. Under Kata
/// (`commodity`, `confidential`) each Sandbox is one VM, so the guest's CPU
/// counts its Docker container, which runs beside the workspace in a cgroup
/// of its own. Under `runc` or `none`, which only diagnostics use, the kernel
/// is the host's, so only the workspace container's CPU counts.
pub(crate) fn counts_guest_cpu(runtime_profile: &str) -> bool {
    matches!(
        runtime_profile.trim(),
        RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL
    )
}

/// Daemons asked at once in one check.
const DAEMON_CALLS_AT_ONCE: usize = 8;

/// How often one Sandbox's own activity is written, at most.
const NOTE_INTERVAL: Duration = Duration::from_secs(60);

/// A running Sandbox past its timeout by what orchestration saw.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct Candidate {
    pub id: String,
    pub namespace: String,
    pub idle_stop_seconds: i32,
    pub last_activity_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The running Sandboxes whose own activity is older than their timeout,
/// with no request open. Each is idle unless its daemon saw use.
pub(crate) async fn candidates(pool: &PgPool) -> Result<Vec<Candidate>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"SELECT e.id, b.namespace, e.idle_stop_seconds, e.last_activity_at
           FROM environments e
           JOIN sandbox_environment_backend b ON b.environment_id = e.id
           WHERE e.idle_stop_seconds > 0
             AND e.desired_state = 'started' AND e.state = 'running'
             AND COALESCE(e.last_activity_at, e.started_at, e.created_at)
                 < NOW() - make_interval(secs => e.idle_stop_seconds)
             AND {NO_OPEN_REQUEST}
           ORDER BY e.id"#
    ))
    .fetch_all(pool)
    .await
}

/// What the check does with one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    /// In use: record this as its activity, so the check skips it until its
    /// timeout passes again.
    Active(chrono::DateTime<chrono::Utc>),
    /// Its daemon has not answered for less than a timeout: ask again.
    Wait,
    /// Idle: stop it.
    Stop,
}

/// Decides one candidate from its daemon's answer. `silent_since` is when
/// its daemon first failed to answer, as this worker remembers it.
pub(crate) fn decide(
    idle_stop_seconds: i32,
    answer: &Result<DaemonActivity, String>,
    silent_since: Option<Instant>,
    now: chrono::DateTime<chrono::Utc>,
    now_instant: Instant,
) -> Decision {
    let timeout = Duration::from_secs(u64::try_from(idle_stop_seconds).unwrap_or(0));
    match answer {
        Ok(DaemonActivity::LastActive(Some(seconds))) => {
            let seen = chrono::DateTime::from_timestamp(*seconds, 0).unwrap_or(now);
            // A time in the future counts as now.
            let seen = seen.min(now);
            if now.signed_duration_since(seen).to_std().unwrap_or_default() < timeout {
                Decision::Active(seen)
            } else {
                Decision::Stop
            }
        }
        Ok(DaemonActivity::LastActive(None)) => Decision::Stop,
        Ok(DaemonActivity::Unsupported) => Decision::Active(now),
        // Silent for a whole timeout: its CPU and input are unknown, and
        // nothing orchestration saw is recent, so it stops.
        Err(_) => match silent_since {
            Some(since) if now_instant.duration_since(since) >= timeout => Decision::Stop,
            _ => Decision::Wait,
        },
    }
}

/// When each Sandbox's daemon first failed to answer. Kept in this worker
/// only: a restart forgets it, which only delays a stop by up to a timeout.
static SILENT_SINCE: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Forgets the silence of every Sandbox that is not a candidate now: one
/// that was active, stopped or gone since starts its silence again if it is
/// ever a candidate, so an old silence never stops it at its first failure.
pub(crate) fn forget_silence_of_others(
    silent: &mut HashMap<String, Instant>,
    candidates: &[Candidate],
) {
    silent.retain(|id, _| candidates.iter().any(|candidate| &candidate.id == id));
}

/// Stops the idle Sandboxes, once per reconciler tick.
pub(crate) async fn stop_idle_environments(ctx: &WorkerContext) {
    if !ctx.idle_stop.is_on() {
        return;
    }
    let candidates = match candidates(&ctx.pool).await {
        Ok(candidates) => candidates,
        Err(error) => {
            tracing::error!(error = %error, "reconciler: query idle environments");
            return;
        }
    };
    forget_silence_of_others(
        &mut SILENT_SINCE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()),
        &candidates,
    );
    let include_guest_cpu = counts_guest_cpu(&ctx.sandbox_cfg.runtime_profile);
    let answers: Vec<(Candidate, Result<DaemonActivity, String>)> =
        futures::stream::iter(candidates)
            .map(|candidate| async move {
                let answer = environment_daemon_activity_for_worker(
                    &ctx.pool,
                    ctx.runtime.as_deref(),
                    &ctx.sandbox_cfg.session_secret,
                    &candidate.namespace,
                    &candidate.id,
                    include_guest_cpu,
                )
                .await
                .map_err(|error| error.to_string());
                (candidate, answer)
            })
            .buffer_unordered(DAEMON_CALLS_AT_ONCE)
            .collect()
            .await;
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    for (candidate, answer) in answers {
        let silent_since = {
            let mut silent = SILENT_SINCE
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match &answer {
                Ok(_) => {
                    silent.remove(&candidate.id);
                    None
                }
                Err(_) => Some(
                    *silent
                        .entry(candidate.id.clone())
                        .or_insert_with(Instant::now),
                ),
            }
        };
        let decision = decide(
            candidate.idle_stop_seconds,
            &answer,
            silent_since,
            chrono::Utc::now(),
            Instant::now(),
        );
        match decision {
            Decision::Active(seen) => {
                if let Err(error) = record_activity(&ctx.pool, &candidate.id, seen).await {
                    tracing::warn!(environment_id = candidate.id, error = %error, "reconciler: record daemon activity");
                }
            }
            Decision::Wait => {
                tracing::debug!(
                    environment_id = candidate.id,
                    "reconciler: idle check waits for a silent daemon"
                );
            }
            Decision::Stop => {
                match svc
                    .request_idle_stop(&candidate.id, candidate.last_activity_at)
                    .await
                {
                    Ok(true) => {
                        SILENT_SINCE
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .remove(&candidate.id);
                        tracing::info!(
                            environment_id = candidate.id,
                            idle_stop_seconds = candidate.idle_stop_seconds,
                            "reconciler: stopping an idle sandbox"
                        );
                        if let Err(error) = super::loops::enqueue_environment_reconcile(
                            ctx,
                            &candidate.id,
                            false,
                            "idle",
                        )
                        .await
                        {
                            tracing::error!(environment_id = candidate.id, error = %error, "reconciler: failed to enqueue reconcile for idle stop");
                        }
                    }
                    // Activity arrived during the check.
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!(environment_id = candidate.id, error = %error, "reconciler: idle stop");
                    }
                }
            }
        }
    }
}

/// Records `seen` as the Sandbox's activity, never moving it back.
async fn record_activity(
    pool: &PgPool,
    environment_id: &str,
    seen: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE environments SET last_activity_at = $2 \
         WHERE id = $1 AND (last_activity_at IS NULL OR last_activity_at < $2)",
    )
    .bind(environment_id)
    .bind(seen)
    .execute(pool)
    .await
    .map(|_| ())
}

/// When this process last wrote each Sandbox's activity.
static NOTED: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Notes activity orchestration carries itself, such as a preview request,
/// at most once a minute per Sandbox, without waiting for the write.
pub(crate) fn note_activity(pool: &PgPool, environment_id: &str) {
    let now = Instant::now();
    {
        let mut noted = NOTED.lock().unwrap_or_else(|poison| poison.into_inner());
        if noted
            .get(environment_id)
            .is_some_and(|last| now.duration_since(*last) < NOTE_INTERVAL)
        {
            return;
        }
        // Forget the Sandboxes not seen for a while, so the map stays small.
        noted.retain(|_, last| now.duration_since(*last) < NOTE_INTERVAL);
        noted.insert(environment_id.to_owned(), now);
    }
    let pool = pool.clone();
    let environment_id = environment_id.to_owned();
    tokio::spawn(async move {
        if let Err(error) = record_activity(&pool, &environment_id, chrono::Utc::now()).await {
            tracing::warn!(environment_id, error = %error, "record activity");
        }
    });
}

#[cfg(test)]
#[path = "idle_stop/tests.rs"]
mod tests;
