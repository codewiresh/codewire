//! Shared authorization and lifecycle gate for interactive sandbox services.

use axum::http::StatusCode;
use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use sqlx::Row;

use super::ApiState;
use super::environments::require_environment_access;
use crate::confidential_storage::{confidential_refusal_reason, require_confidential_access};
use crate::runtime::{Placement, RuntimeProbe};

/// Mirrors `sandboxTarget`.
pub(crate) struct SandboxTarget {
    pub environment_id: String,
    pub namespace: String,
    pub pod_name: String,
}

/// Resolves a running sandbox target or returns its typed gate failure.
pub(crate) async fn resolve_running_sandbox_target(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> Result<SandboxTarget, (StatusCode, &'static str)> {
    resolve_running_sandbox_target_inner(state, user, org_id, env_id, "operator").await
}

pub(crate) async fn resolve_running_sandbox_target_for_repair(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> Result<SandboxTarget, (StatusCode, &'static str)> {
    resolve_running_sandbox_target_inner(state, user, org_id, env_id, "operator").await
}

pub(crate) async fn resolve_running_sandbox_target_for_role(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    required_role: &str,
) -> Result<SandboxTarget, (StatusCode, &'static str)> {
    resolve_running_sandbox_target_inner(state, user, org_id, env_id, required_role).await
}

async fn resolve_running_sandbox_target_inner(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    required_role: &str,
) -> Result<SandboxTarget, (StatusCode, &'static str)> {
    if user_org_role(&state.pool, user, org_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "organization not found"));
    }
    if require_environment_access(
        &state.pool,
        user,
        env_id,
        org_id,
        required_role,
        "access denied",
    )
    .await
    .is_err()
    {
        return Err((StatusCode::FORBIDDEN, "access denied"));
    }

    let row = sqlx::query(
        "SELECT id, state, desired_state, type, isolation_tier \
         FROM environments WHERE id = $1 AND org_id = $2",
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "environment not found"));
    };
    let id: String = row.get("id");
    let state_value: String = row.get("state");
    let desired_state: String = row.get("desired_state");
    let environment_type: String = row.get("type");
    let isolation_tier: String = row.get("isolation_tier");
    if let Err(error) = require_confidential_access(
        &state.pool,
        state.confidential_storage_flags,
        user,
        org_id,
        &isolation_tier,
    )
    .await
    {
        return match error {
            AppError::Coded { status, code, .. } => {
                Err((status, confidential_refusal_reason(code)))
            }
            _ => Err((StatusCode::FORBIDDEN, "access denied")),
        };
    }
    if state_value != "running" || desired_state != "started" {
        return Err((StatusCode::BAD_REQUEST, "environment must be running"));
    }
    if environment_type != "sandbox" {
        return Err((
            StatusCode::BAD_REQUEST,
            "only supported for sandbox environments",
        ));
    }

    let backend = sqlx::query(
        "SELECT namespace, COALESCE(pod_name, '') AS pod_name, COALESCE(pod_ip, '') AS pod_ip \
         FROM sandbox_environment_backend WHERE environment_id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let namespace: String = backend
        .as_ref()
        .map(|row| row.get::<String, _>("namespace"))
        .unwrap_or_default();
    if namespace.is_empty() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "sandbox backend not found"));
    }
    let pod_name: String = backend
        .as_ref()
        .map(|row| row.get::<String, _>("pod_name"))
        .unwrap_or_default();
    let pod_ip: String = backend
        .map(|row| row.get::<String, _>("pod_ip"))
        .unwrap_or_default();

    let runtime = state.runtime.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "sandbox backend not configured",
    ))?;
    let probe = runtime
        .probe(&Placement::new(&namespace), &id)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "environment runtime is unavailable",
            )
        })?;
    if !runtime_is_current(&pod_name, &pod_ip, &probe) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "environment runtime is not current",
        ));
    }
    let pod_name = probe.pod_name;

    Ok(SandboxTarget {
        environment_id: id,
        namespace,
        pod_name,
    })
}

fn runtime_is_current(backend_pod_name: &str, backend_pod_ip: &str, probe: &RuntimeProbe) -> bool {
    probe.claim_exists
        && probe.claim_ready
        && probe.pod_exists
        && probe.pod_phase == "Running"
        && !probe.pod_name.is_empty()
        && !probe.pod_uid.is_empty()
        && !probe.pod_ip.is_empty()
        && backend_pod_name == probe.pod_name
        && backend_pod_ip == probe.pod_ip
}

/// Maps sandbox gate failures into application errors for Connect handlers.
pub(crate) fn huma_error(status: StatusCode, message: &'static str) -> AppError {
    match status {
        StatusCode::UNAUTHORIZED => AppError::Coded {
            status,
            code: "",
            detail: std::borrow::Cow::Borrowed(message),
        },
        StatusCode::NOT_FOUND => AppError::NotFound(std::borrow::Cow::Borrowed(message)),
        StatusCode::BAD_REQUEST => AppError::BadRequest(std::borrow::Cow::Borrowed(message)),
        StatusCode::FORBIDDEN => AppError::Coded {
            status,
            code: "",
            detail: std::borrow::Cow::Borrowed(message),
        },
        StatusCode::SERVICE_UNAVAILABLE => {
            AppError::ServiceUnavailable(std::borrow::Cow::Borrowed(message))
        }
        _ => AppError::InternalMsg(std::borrow::Cow::Borrowed(message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_probe() -> RuntimeProbe {
        RuntimeProbe {
            claim_exists: true,
            claim_ready: true,
            pod_exists: true,
            pod_phase: "Running".into(),
            pod_name: "pod-current".into(),
            pod_uid: "pod-uid-current".into(),
            pod_ip: "10.0.0.9".into(),
            ..Default::default()
        }
    }

    #[test]
    fn interactive_runtime_requires_current_database_pod_binding_and_observed_uid() {
        let current = current_probe();
        assert!(runtime_is_current("pod-current", "10.0.0.9", &current));

        let replacement = current_probe();
        assert!(!runtime_is_current(
            "pod-previous",
            "10.0.0.8",
            &replacement
        ));
    }
}
