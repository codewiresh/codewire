//! Idle hibernate (#6647, `docs/dev/SANDBOX-SLEEP.md`): a running (or
//! suspended) `standard` Sandbox with `idle_hibernate_seconds > 0` and no
//! activity for that long is transitioned to a hibernate stop
//! (`stop_reason = 'hibernate_idle'`), where the serialized Temporal stop
//! handler asks the daemon to hibernate, observes the host-side
//! `vm-hibernate-record {"event":"hibernated"}` Pod log line, deletes the Pod,
//! and marks the Sandbox `hibernated`.
//!
//! Time spent `suspended` counts toward `idle_hibernate` without waking the VM
//! to poll activity. On `standard`, when `idle_hibernate` is on, it takes
//! `idle_stop`'s place.

use futures::StreamExt as _;
use sqlx::PgPool;

use super::WorkerContext;
use super::idle_stop::NO_OPEN_REQUEST;
use crate::api::environment_daemon::{DaemonActivity, environment_daemon_activity_for_worker};
use crate::lifecycle::{PgLifecycleStore, Service};
use crate::sandbox::template::RUNTIME_PROFILE_STANDARD;

const DAEMON_CALLS_AT_ONCE: usize = 8;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct Candidate {
    pub(super) id: String,
    pub(super) org_id: String,
    namespace: String,
    idle_hibernate_seconds: i32,
    suspended: bool,
}

/// Running `standard` Sandboxes past their `idle_hibernate` timeout by
/// orchestration's own activity timestamp, with no open agent or `cw` runtime
/// request.
pub(super) async fn candidates(pool: &PgPool) -> Result<Vec<Candidate>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"SELECT e.id, e.org_id, b.namespace, e.idle_hibernate_seconds,
                  e.suspended_at IS NOT NULL AS suspended
           FROM environments e
           JOIN sandbox_environment_backend b ON b.environment_id = e.id
           WHERE e.idle_hibernate_seconds > 0 AND e.runtime_profile = $1
             AND e.desired_state = 'started' AND e.state = 'running'
             AND COALESCE(e.last_activity_at, e.started_at, e.created_at)
                 < NOW() - make_interval(secs => e.idle_hibernate_seconds)
             AND {NO_OPEN_REQUEST}
           ORDER BY e.id"#
    ))
    .bind(RUNTIME_PROFILE_STANDARD)
    .fetch_all(pool)
    .await
}

/// Transitions idle `standard` Sandboxes with `idle_hibernate` on into a
/// serialized hibernate stop, once per reconciler tick.
pub(crate) async fn hibernate_idle_environments(ctx: &WorkerContext) {
    let Some(runtime) = ctx.runtime.as_deref() else {
        return;
    };
    let candidates = match candidates(&ctx.pool).await {
        Ok(candidates) => candidates,
        Err(error) => {
            tracing::error!(error = %error, "reconciler: query idle hibernate candidates");
            return;
        }
    };
    let svc = Service::<PgLifecycleStore>::for_pool(ctx.pool.clone());
    futures::stream::iter(candidates)
        .for_each_concurrent(DAEMON_CALLS_AT_ONCE, |candidate| {
            let svc = &svc;
            async move {
                // Suspended Sandboxes are not polled (polling port 7777 would
                // wake the paused VM); their suspended stretch counts directly
                // toward `idle_hibernate`.
                if !candidate.suspended {
                    let activity = environment_daemon_activity_for_worker(
                        &ctx.pool,
                        Some(runtime),
                        &ctx.sandbox_cfg.session_secret,
                        &candidate.namespace,
                        &candidate.id,
                        true,
                    )
                    .await;
                    let timeout = i64::from(candidate.idle_hibernate_seconds);
                    let now = chrono::Utc::now();
                    let seen = match activity {
                        Ok(DaemonActivity::LastActive(seen)) => seen
                            .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
                            .map(|seen| seen.min(now)),
                        Ok(DaemonActivity::Unsupported) => return,
                        Err(error) => {
                            tracing::debug!(
                                environment_id = candidate.id,
                                error = %error,
                                "reconciler: idle hibernate check could not reach the daemon"
                            );
                            return;
                        }
                    };
                    if let Some(seen) = seen {
                        if let Err(error) =
                            super::idle_stop::record_activity(&ctx.pool, &candidate.id, seen).await
                        {
                            tracing::warn!(
                                environment_id = candidate.id,
                                error = %error,
                                "reconciler: record daemon activity for idle hibernate"
                            );
                        }
                        if now.signed_duration_since(seen).num_seconds() < timeout {
                            return;
                        }
                    }
                }
                match svc
                    .request_hibernate(&candidate.id, &candidate.org_id, "hibernate_idle")
                    .await
                {
                    Ok(true) => {
                        tracing::info!(
                            environment_id = candidate.id,
                            idle_hibernate_seconds = candidate.idle_hibernate_seconds,
                            "reconciler: hibernating an idle standard sandbox"
                        );
                        if let Err(error) = super::loops::enqueue_environment_reconcile(
                            ctx,
                            &candidate.id,
                            false,
                            "stop",
                        )
                        .await
                        {
                            tracing::error!(
                                environment_id = candidate.id,
                                error = %error,
                                "reconciler: failed to enqueue stop workflow for idle hibernate"
                            );
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!(
                            environment_id = candidate.id,
                            error = %error,
                            "reconciler: request idle hibernate"
                        );
                    }
                }
            }
        })
        .await;
}
