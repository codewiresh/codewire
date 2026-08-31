//! Shared authorization and lifecycle gate for interactive sandbox services.

use axum::http::StatusCode;
use codewire_server_core::AppError;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use sqlx::Row;

use super::ApiState;
use super::environments::require_environment_access;
use crate::confidential_storage::require_interactive_access;

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
    resolve_running_sandbox_target_for_role(state, user, org_id, env_id, "operator").await
}

pub(crate) async fn resolve_running_sandbox_target_for_role(
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
        "SELECT id, state, type, isolation_tier FROM environments WHERE id = $1 AND org_id = $2",
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
    let environment_type: String = row.get("type");
    let isolation_tier: String = row.get("isolation_tier");
    if let Err(error) =
        require_interactive_access(state.confidential_storage_flags, user, &isolation_tier)
    {
        return match error {
            AppError::Coded { status, .. } => Err((
                status,
                if status == StatusCode::SERVICE_UNAVAILABLE {
                    "confidential persistent storage is disabled"
                } else {
                    "global administrator user credential required"
                },
            )),
            _ => Err((StatusCode::FORBIDDEN, "access denied")),
        };
    }
    if state_value != "running" {
        return Err((StatusCode::BAD_REQUEST, "environment must be running"));
    }
    if environment_type != "sandbox" {
        return Err((
            StatusCode::BAD_REQUEST,
            "only supported for sandbox environments",
        ));
    }

    let backend = sqlx::query(
        "SELECT namespace, COALESCE(pod_name, '') AS pod_name FROM sandbox_environment_backend WHERE environment_id = $1",
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
        .map(|row| row.get::<String, _>("pod_name"))
        .unwrap_or_default();

    Ok(SandboxTarget {
        environment_id: id,
        namespace,
        pod_name,
    })
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
