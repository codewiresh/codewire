//! Manual suspend and resume of a `standard` Sandbox (#5529,
//! `docs/dev/IDLE-STOP.md`, "Manual suspend and resume").

use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::api::environment_daemon::{DaemonSuspend, environment_daemon_suspend_for_worker};
use crate::sandbox::template::{
    RUNTIME_PROFILE_STANDARD, WORKSPACE_DAEMON_PORT, workspace_daemon_service_name,
};

const WAKE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WAKE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const WAKE_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, sqlx::FromRow)]
struct SuspendTarget {
    state: String,
    runtime_profile: String,
    suspended_at: Option<chrono::DateTime<chrono::Utc>>,
    namespace: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuspendCheck {
    AlreadySuspended,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResumeCheck {
    AlreadyRunning,
    Ready,
}

fn require_standard_runtime(runtime_profile: &str, action: &str) -> AppResult<()> {
    if runtime_profile == RUNTIME_PROFILE_STANDARD {
        return Ok(());
    }
    let profile = if runtime_profile.is_empty() {
        "none"
    } else {
        runtime_profile
    };
    Err(coded_owned(
        StatusCode::PRECONDITION_FAILED,
        "suspend_unsupported",
        format!("only a sandbox on the standard runtime can {action}; this one runs on {profile}"),
    ))
}

fn check_suspend_target(target: &SuspendTarget) -> AppResult<SuspendCheck> {
    require_standard_runtime(&target.runtime_profile, "suspend")?;
    if target.state != "running" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment must be running to suspend",
        ));
    }
    if target.suspended_at.is_some() {
        return Ok(SuspendCheck::AlreadySuspended);
    }
    Ok(SuspendCheck::Ready)
}

fn check_resume_target(target: &SuspendTarget) -> AppResult<ResumeCheck> {
    if target.state == "stopped" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment is stopped; use cw start to start it",
        ));
    }
    if target.state != "running" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment must be running to resume",
        ));
    }
    require_standard_runtime(&target.runtime_profile, "resume")?;
    if target.suspended_at.is_none() {
        return Ok(ResumeCheck::AlreadyRunning);
    }
    Ok(ResumeCheck::Ready)
}

async fn fetch_suspend_target(
    pool: &PgPool,
    org_id: &str,
    env_id: &str,
) -> AppResult<SuspendTarget> {
    let target: Option<SuspendTarget> = sqlx::query_as(
        "SELECT e.state, e.runtime_profile, e.suspended_at, b.namespace \
         FROM environments e \
         LEFT JOIN sandbox_environment_backend b ON b.environment_id = e.id \
         WHERE e.id = $1 AND e.org_id = $2",
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(pool)
    .await?;
    target.ok_or_else(|| {
        coded(
            StatusCode::NOT_FOUND,
            "env_not_found",
            "environment not found",
        )
    })
}

/// Pauses a running `standard` Sandbox's VM inside its Pod on demand.
pub(crate) async fn suspend_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can suspend environments",
    )
    .await?;
    let target = fetch_suspend_target(&state.pool, org_id, env_id).await?;
    if check_suspend_target(&target)? == SuspendCheck::AlreadySuspended {
        return Ok(StatusResponse {
            status: "already suspended",
        });
    }
    let namespace = target.namespace.as_deref().ok_or_else(|| {
        coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment has no active runtime to suspend",
        )
    })?;
    let answer = environment_daemon_suspend_for_worker(
        &state.pool,
        state.runtime.as_deref(),
        &state.sandbox_cfg.session_secret,
        namespace,
        env_id,
    )
    .await;
    match answer {
        Ok(DaemonSuspend::Accepted) => {
            sqlx::query(
                "UPDATE environments SET suspended_at = NOW() \
                 WHERE id = $1 AND state = 'running' AND suspended_at IS NULL",
            )
            .bind(env_id)
            .execute(&state.pool)
            .await?;
            Ok(StatusResponse {
                status: "suspended",
            })
        }
        Ok(DaemonSuspend::NotAccepted) => Err(coded(
            StatusCode::CONFLICT,
            "suspend_refused",
            "the sandbox could not suspend right now; try again in a moment",
        )),
        Ok(DaemonSuspend::CantSuspend) => Err(coded(
            StatusCode::PRECONDITION_FAILED,
            "suspend_unsupported",
            "this sandbox's runtime can't suspend",
        )),
        Err(error) => {
            tracing::warn!(environment_id = env_id, error = %error, "manual suspend could not reach daemon");
            Err(coded(
                StatusCode::BAD_GATEWAY,
                "daemon_unreachable",
                "could not reach the sandbox daemon to suspend it",
            ))
        }
    }
}

/// Wakes a suspended `standard` Sandbox's VM inside its Pod on demand.
pub(crate) async fn resume_environment_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<StatusResponse> {
    require_org_member(&state.pool, user, org_id).await?;
    require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        "operator",
        "access denied",
    )
    .await?;
    let target = fetch_suspend_target(&state.pool, org_id, env_id).await?;
    if check_resume_target(&target)? == ResumeCheck::AlreadyRunning {
        return Ok(StatusResponse {
            status: "already running",
        });
    }
    let namespace = target.namespace.as_deref().ok_or_else(|| {
        coded(
            StatusCode::BAD_REQUEST,
            "invalid_state",
            "environment has no active runtime to resume",
        )
    })?;
    let address = format!(
        "{}.{namespace}.svc.cluster.local:{WORKSPACE_DAEMON_PORT}",
        workspace_daemon_service_name(env_id)
    );
    match tokio::time::timeout(
        WAKE_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(&address),
    )
    .await
    {
        Ok(Ok(_stream)) => {}
        Ok(Err(error)) => {
            tracing::warn!(environment_id = env_id, error = %error, "manual resume connect failed");
            return Err(coded(
                StatusCode::BAD_GATEWAY,
                "daemon_unreachable",
                "could not reach the sandbox daemon to resume it",
            ));
        }
        Err(_) => {
            tracing::warn!(environment_id = env_id, "manual resume connect timed out");
            return Err(coded(
                StatusCode::GATEWAY_TIMEOUT,
                "daemon_unreachable",
                "timed out waiting for the sandbox daemon to resume",
            ));
        }
    }
    // Opening the port-7777 connection already woke the Pod's Suspender; wait
    // briefly for the guest daemon's wake report to clear `suspended_at` so a
    // following `cw ls` or `cw info` immediately reads `running`.
    let deadline = Instant::now() + WAKE_CONFIRM_TIMEOUT;
    loop {
        let cleared: Option<bool> = sqlx::query_scalar(
            "SELECT suspended_at IS NULL FROM environments WHERE id = $1 AND org_id = $2",
        )
        .bind(env_id)
        .bind(org_id)
        .fetch_optional(&state.pool)
        .await?;
        if cleared.unwrap_or(true) || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(WAKE_POLL_INTERVAL).await;
    }
    Ok(StatusResponse { status: "resumed" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(state: &str, runtime_profile: &str, suspended: bool) -> SuspendTarget {
        SuspendTarget {
            state: state.to_owned(),
            runtime_profile: runtime_profile.to_owned(),
            suspended_at: suspended.then(chrono::Utc::now),
            namespace: Some("dev-sandboxes".to_owned()),
        }
    }

    #[test]
    fn suspend_checks_runtime_state_and_idempotency() {
        assert_eq!(
            check_suspend_target(&target("running", "standard", false)).unwrap(),
            SuspendCheck::Ready
        );
        assert_eq!(
            check_suspend_target(&target("running", "standard", true)).unwrap(),
            SuspendCheck::AlreadySuspended
        );
        for profile in ["commodity", "confidential", "runc", ""] {
            let err = check_suspend_target(&target("running", profile, false)).unwrap_err();
            assert!(
                format!("{err:?}").contains("suspend_unsupported"),
                "{profile}: {err:?}"
            );
        }
        let err = check_suspend_target(&target("stopped", "standard", false)).unwrap_err();
        assert!(format!("{err:?}").contains("invalid_state"), "{err:?}");
    }

    #[test]
    fn resume_checks_stopped_runtime_and_idempotency() {
        assert_eq!(
            check_resume_target(&target("running", "standard", true)).unwrap(),
            ResumeCheck::Ready
        );
        assert_eq!(
            check_resume_target(&target("running", "standard", false)).unwrap(),
            ResumeCheck::AlreadyRunning
        );
        let stopped = check_resume_target(&target("stopped", "standard", false)).unwrap_err();
        assert!(
            format!("{stopped:?}").contains("invalid_state")
                && format!("{stopped:?}").contains("cw start"),
            "{stopped:?}"
        );
        let commodity = check_resume_target(&target("running", "commodity", false)).unwrap_err();
        assert!(
            format!("{commodity:?}").contains("suspend_unsupported"),
            "{commodity:?}"
        );
    }
}
