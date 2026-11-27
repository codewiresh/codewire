//! Hibernate stop and restore-on-start helpers for `standard` Sandboxes
//! (#6647, `docs/dev/SANDBOX-SLEEP.md`).

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::api::environment_daemon::{DaemonHibernate, environment_daemon_hibernate_for_worker};
use crate::hibernate_records::{self, HibernateRecord, HibernatedRecord};
use crate::runtime::{Placement, RuntimeDriver};
use crate::sandbox::template::RUNTIME_PROFILE_STANDARD;
use crate::worker::WorkerContext;
use crate::worker::activity_authority::ActivityAuthority;

/// How long orchestration polls the Pod log for a host-observed
/// `vm-hibernate-record {"event":"hibernated"}` (or `hibernate-failed`) line
/// after the daemon accepts `Hibernate`.
const HIBERNATE_RECORD_WAIT: Duration = Duration::from_secs(45);
const HIBERNATE_RECORD_POLL: Duration = Duration::from_millis(250);
/// Admission allowlist window for restoring a hibernated Sandbox on its
/// recorded runtime/image-disk digests (`docs/dev/SANDBOX-SLEEP.md`).
const RESTORE_ALLOW_WINDOW_DAYS: i64 = 30;

/// Stored hibernate state loaded from `environments` for stop/start.
#[derive(Debug, Clone)]
pub(super) struct StoredHibernateState {
    pub(super) stop_reason: Option<String>,
    pub(super) hibernated_at: Option<DateTime<Utc>>,
    pub(super) hibernate_record: Option<serde_json::Value>,
}

pub(super) async fn load_hibernate_state(
    pool: &PgPool,
    env_id: &str,
) -> Result<StoredHibernateState, sqlx::Error> {
    let row: (
        Option<String>,
        Option<DateTime<Utc>>,
        Option<serde_json::Value>,
    ) = sqlx::query_as(
        "SELECT stop_reason, hibernated_at, hibernate_record FROM environments WHERE id = $1",
    )
    .bind(env_id)
    .fetch_one(pool)
    .await?;
    Ok(StoredHibernateState {
        stop_reason: row.0,
        hibernated_at: row.1,
        hibernate_record: row.2,
    })
}

/// Maps `stop_reason` on a hibernate-requested stop to the stored
/// `hibernate_reason` (`user` or `idle`), or `None` for an ordinary stop.
pub(super) fn hibernate_reason_for_stop(stop_reason: Option<&str>) -> Option<&'static str> {
    match stop_reason {
        Some("hibernate_user") => Some("user"),
        Some("hibernate_idle") => Some("idle"),
        _ => None,
    }
}

/// Armed hibernate handoff waiting for Kubernetes SIGTERM (`scale_down`) to
/// trigger `cw __pod-runtime`'s freeze and memory write
/// (`docs/dev/SANDBOX-SLEEP.md`, "Hibernating a Sandbox" steps 2–5).
#[derive(Debug, Clone)]
pub(super) struct ArmedHibernate {
    pub(super) reason: &'static str,
    pub(super) pod_name: String,
}

/// Step 1 (before `scale_down`): invokes `DaemonService.Hibernate` to drop old
/// Pod credentials and arm hibernate-on-SIGTERM in `pod-runtime`, and captures
/// the target Pod name whose logs will be polled concurrently with
/// `wait_scaled_down` after `scale_down` delivers SIGTERM.
///
/// Returns `None` on non-`standard` profiles, ordinary stops, or any daemon
/// refusal/error so the caller completes a plain stop instead.
pub(super) async fn arm_pre_stop_hibernate(
    ctx: &WorkerContext,
    runtime: &dyn RuntimeDriver,
    runtime_profile: &str,
    namespace: &str,
    env_id: &str,
    pod_name_hint: &str,
    stop_reason: Option<&str>,
) -> Option<ArmedHibernate> {
    if runtime_profile != RUNTIME_PROFILE_STANDARD {
        return None;
    }
    let reason = hibernate_reason_for_stop(stop_reason)?;
    let placement = Placement::new(namespace);
    let pod_name = if !pod_name_hint.trim().is_empty() {
        pod_name_hint.trim().to_owned()
    } else {
        match runtime.member_name(&placement, env_id).await {
            Ok(pod) => pod,
            Err(error) => {
                tracing::warn!(
                    environment_id = env_id,
                    error = %error,
                    "environment.stop: could not resolve pod name to observe hibernate record"
                );
                return None;
            }
        }
    };
    let answer = match environment_daemon_hibernate_for_worker(
        &ctx.pool,
        Some(runtime),
        &ctx.sandbox_cfg.session_secret,
        namespace,
        env_id,
    )
    .await
    {
        Ok(answer) => answer,
        Err(error) => {
            tracing::warn!(
                environment_id = env_id,
                error = %error,
                "environment.stop: daemon hibernate call failed; falling back to plain stop"
            );
            return None;
        }
    };
    if answer != DaemonHibernate::Accepted {
        tracing::info!(
            environment_id = env_id,
            answer = ?answer,
            "environment.stop: daemon did not accept hibernate; falling back to plain stop"
        );
        return None;
    }
    Some(ArmedHibernate { reason, pod_name })
}

/// Step 2 (after `scale_down` delivers SIGTERM, running concurrently with
/// `wait_scaled_down`): polls the terminating Pod's log for a host-observed
/// `standard runtime: vm-hibernate-record {"event":"hibernated",...}` line.
///
/// Stops as soon as `hibernated` or `hibernate-failed` is observed, or does one
/// final read once `scaled_down` cancels after the Pod terminates. Returns
/// `Some((reason, record))` ONLY on a valid host-observed `hibernated` record.
pub(super) async fn observe_hibernate_during_scale_down(
    runtime: &dyn RuntimeDriver,
    placement: &Placement,
    env_id: &str,
    armed: &ArmedHibernate,
    scaled_down: tokio_util::sync::CancellationToken,
) -> Option<(&'static str, HibernatedRecord)> {
    let deadline = tokio::time::Instant::now() + HIBERNATE_RECORD_WAIT;
    loop {
        if let Ok(log) = runtime
            .runtime_log_since(
                placement,
                &armed.pod_name,
                hibernate_records::READ_WINDOW,
                hibernate_records::READ_LIMIT_BYTES,
            )
            .await
        {
            let parsed = hibernate_records::read(&log);
            if parsed.refused > 0 {
                tracing::warn!(
                    environment_id = env_id,
                    refused = parsed.refused,
                    "environment.stop: refused malformed hibernate records"
                );
            }
            if let Some((_, record)) = parsed.last_hibernated() {
                tracing::info!(
                    environment_id = env_id,
                    restore_generation = record.restore_generation,
                    memory_bytes = record.memory_bytes,
                    "environment.stop: observed host-side vm-hibernate-record hibernated"
                );
                return Some((armed.reason, record.clone()));
            }
            if parsed
                .records()
                .iter()
                .any(|entry| matches!(entry, HibernateRecord::HibernateFailed(_)))
            {
                tracing::warn!(
                    environment_id = env_id,
                    "environment.stop: runtime reported hibernate-failed; completing plain stop"
                );
                return None;
            }
        }
        if scaled_down.is_cancelled() || tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                environment_id = env_id,
                "environment.stop: pod terminated without host-observed vm-hibernate-record; completing plain stop"
            );
            return None;
        }
        tokio::select! {
            () = scaled_down.cancelled() => {
                // Pod just finished scaling down; loop once more for a final log read.
            }
            () = tokio::time::sleep(HIBERNATE_RECORD_POLL) => {}
        }
    }
}

/// Marks a stopped environment as hibernated after orchestration has observed
/// the host-side `hibernated` record and scaled the Pod down.
pub(super) async fn mark_hibernated(
    authority: &ActivityAuthority,
    env_id: &str,
    reason: &str,
    record: &HibernatedRecord,
) -> anyhow::Result<()> {
    let at = DateTime::from_timestamp_millis(
        i64::try_from(record.at_unix_ms).unwrap_or_else(|_| Utc::now().timestamp_millis()),
    )
    .unwrap_or_else(Utc::now);
    authority
        .execute_for_states(
            &["stopped"],
            sqlx::query(
                "UPDATE environments
                    SET hibernated_at = $2,
                        hibernate_reason = $3,
                        hibernate_record = $4,
                        hibernate_fallback_reason = NULL
                  WHERE id = $1 AND state = 'stopped'",
            )
            .bind(env_id)
            .bind(at)
            .bind(reason)
            .bind(record.to_metadata_json()),
        )
        .await?;
    Ok(())
}

/// Decision made before scaling up a stopped `standard` Sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StartRestorePlan {
    /// Ordinary cold start (was not hibernated).
    ColdStart,
    /// Restore from the recorded hibernate generation.
    Restore { restore_generation: u64 },
    /// Hibernated state cannot be restored (expired or invalid metadata);
    /// cold-boot and surface `reason` as `hibernate_fallback_reason`.
    ExpiredFallback { reason: &'static str },
}

pub(super) fn plan_start_restore(
    runtime_profile: &str,
    state: &StoredHibernateState,
    now: DateTime<Utc>,
) -> StartRestorePlan {
    if runtime_profile != RUNTIME_PROFILE_STANDARD {
        return StartRestorePlan::ColdStart;
    }
    let Some(hibernated_at) = state.hibernated_at else {
        return StartRestorePlan::ColdStart;
    };
    if now.signed_duration_since(hibernated_at) > chrono::Duration::days(RESTORE_ALLOW_WINDOW_DAYS)
    {
        return StartRestorePlan::ExpiredFallback {
            reason: "runtime-image-expired",
        };
    }
    match state
        .hibernate_record
        .as_ref()
        .and_then(HibernatedRecord::from_metadata_json)
    {
        Some(record) => StartRestorePlan::Restore {
            restore_generation: record.restore_generation,
        },
        None => StartRestorePlan::ExpiredFallback {
            reason: "damaged-memory-file",
        },
    }
}

/// Clears the hibernated mark on start and records any host-observed fallback
/// reason from the restoring Pod's container log.
pub(super) async fn finalize_start_restore(
    runtime: &dyn RuntimeDriver,
    authority: &ActivityAuthority,
    states: &[&str],
    placement: &Placement,
    env_id: &str,
    pod_name: &str,
    plan: &StartRestorePlan,
) {
    let fallback_reason: Option<String> = match plan {
        StartRestorePlan::ColdStart => None,
        StartRestorePlan::ExpiredFallback { reason } => Some((*reason).to_owned()),
        StartRestorePlan::Restore { restore_generation } => {
            let mut observed_fallback = None;
            if let Ok(log) = runtime
                .runtime_log_since(
                    placement,
                    pod_name,
                    hibernate_records::READ_WINDOW,
                    hibernate_records::READ_LIMIT_BYTES,
                )
                .await
            {
                let parsed = hibernate_records::read(&log);
                if let Some(HibernateRecord::Fallback(fallback)) =
                    parsed.last_restore_outcome(*restore_generation)
                {
                    observed_fallback = Some(fallback.reason.clone());
                }
            }
            observed_fallback
        }
    };

    // Strip any restore generation from the Sandbox CR so future stops/starts
    // never reuse a consumed generation.
    if matches!(plan, StartRestorePlan::Restore { .. })
        && let Err(error) = runtime
            .set_vm_restore_generation(placement, env_id, None)
            .await
    {
        tracing::warn!(
            environment_id = env_id,
            error = %error,
            "environment.start: failed to clear CODEWIRE_VM_RESTORE_GENERATION after start"
        );
    }

    if let Err(error) = authority
        .execute_for_states(
            states,
            sqlx::query(
                "UPDATE environments
                    SET hibernated_at = NULL,
                        hibernate_reason = NULL,
                        hibernate_record = NULL,
                        hibernate_fallback_reason = $2
                  WHERE id = $1",
            )
            .bind(env_id)
            .bind(fallback_reason.as_deref()),
        )
        .await
    {
        tracing::warn!(
            environment_id = env_id,
            error = %error,
            "environment.start: failed to finalize hibernate restore state"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(generation: u64) -> serde_json::Value {
        HibernatedRecord {
            restore_generation: generation,
            vmm_sha256: "a".repeat(64),
            runtime_image_digest: format!("sha256:{}", "b".repeat(64)),
            image_disk_id: "c".repeat(64),
            build_id: "d".repeat(32),
            memory_bytes: 4_294_967_296,
            at_unix_ms: 1_764_249_000_000,
        }
        .to_metadata_json()
    }

    #[test]
    fn plan_start_restore_honors_30_day_window_and_validates_record() {
        let now = Utc::now();
        let fresh = StoredHibernateState {
            stop_reason: Some("hibernate_user".into()),
            hibernated_at: Some(now - chrono::Duration::days(5)),
            hibernate_record: Some(sample_record(7)),
        };
        assert_eq!(
            plan_start_restore("standard", &fresh, now),
            StartRestorePlan::Restore {
                restore_generation: 7
            }
        );
        assert_eq!(
            plan_start_restore("commodity", &fresh, now),
            StartRestorePlan::ColdStart
        );

        let expired = StoredHibernateState {
            hibernated_at: Some(now - chrono::Duration::days(31)),
            ..fresh.clone()
        };
        assert_eq!(
            plan_start_restore("standard", &expired, now),
            StartRestorePlan::ExpiredFallback {
                reason: "runtime-image-expired"
            }
        );

        let corrupt = StoredHibernateState {
            hibernate_record: Some(serde_json::json!({"bad": true})),
            ..fresh
        };
        assert_eq!(
            plan_start_restore("standard", &corrupt, now),
            StartRestorePlan::ExpiredFallback {
                reason: "damaged-memory-file"
            }
        );
    }
}
