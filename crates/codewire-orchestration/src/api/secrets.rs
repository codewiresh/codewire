//! Shared organization and user secret service logic.

use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::{
    OrganizationTenantSecretMutationError, run_organization_tenant_secret_mutation,
};
use codewire_server_core::{AppError, AppResult};

use super::ApiState;

#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub key: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretMetadata>,
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// huma `Error403Forbidden(detail)` parity: 403 with a caller-visible detail
/// (the unit `AppError::Forbidden` carries a fixed "forbidden" detail).
pub(super) fn forbidden(detail: &'static str) -> AppError {
    AppError::Coded {
        status: axum::http::StatusCode::FORBIDDEN,
        code: "",
        detail: detail.into(),
    }
}

fn org_secret_path(org_id: &str) -> String {
    format!("/org-secrets/{org_id}")
}
fn user_secret_path(user_id: &str) -> String {
    format!("/users/{user_id}")
}

pub(super) fn validate_secret_key(key: &str) -> AppResult<()> {
    if !crate::worker::secrets::is_valid_secret_key(key) {
        return Err(AppError::BadRequest(
            "secret key must contain only ASCII letters, digits, or underscores".into(),
        ));
    }
    Ok(())
}
/// Shared existence-hiding organization gate for Connect services.
pub(super) async fn org_role(state: &ApiState, user: &AuthUser, org_id: &str) -> AppResult<String> {
    user_org_role(&state.pool, user, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("organization not found".into()))
}

/// Owner/admin gate shared by the org set/delete/rename handlers.
fn require_manage_role(role: &str) -> AppResult<()> {
    if role != "owner" && role != "admin" {
        return Err(forbidden("only owners and admins can manage secrets"));
    }
    Ok(())
}

/// Audit log (mirrors `auth.LogAuditEvent`; ip/ua empty as in the sibling
/// ported handlers).
pub(super) async fn log_audit(
    state: &ApiState,
    action: &str,
    user_id: &str,
    metadata: serde_json::Value,
    severity: &str,
) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
           VALUES ($1, NOW(), $2, $3, '', '', $4, $5)"#,
    )
    .bind(&id)
    .bind(action)
    .bind(user_id)
    .bind(&metadata)
    .bind(severity)
    .execute(&state.pool)
    .await
    {
        tracing::error!(action, error = %e, "failed to log audit event");
    }
}

pub(super) fn to_metadata(
    secrets: Vec<crate::worker::secrets::InfisicalSecret>,
) -> Vec<SecretMetadata> {
    secrets
        .into_iter()
        .map(|s| SecretMetadata {
            key: s.key,
            created_at: s.created_at,
            updated_at: s.updated_at,
        })
        .collect()
}

/// Maps a `RenameSecretAtPath` error to the Go status (404 / 409 / 500).
pub(super) fn rename_error(e: anyhow::Error) -> AppError {
    let msg = e.to_string();
    if msg.contains("not found") {
        AppError::NotFound("secret not found".into())
    } else if msg.contains("already exists") {
        AppError::Conflict("a secret with that key already exists".into())
    } else {
        tracing::error!(error = %e, "secrets: rename failed");
        AppError::InternalMsg("failed to rename secret".into())
    }
}

pub(super) fn ambiguous_secret_provider_error(
    error: anyhow::Error,
    detail: &'static str,
) -> OrganizationTenantSecretMutationError {
    tracing::error!(error = %error, "tenant secret provider mutation failed");
    OrganizationTenantSecretMutationError::ambiguous(AppError::InternalMsg(detail.into()))
}

pub(super) fn rename_provider_error(error: anyhow::Error) -> OrganizationTenantSecretMutationError {
    let mapped = rename_error(error);
    if matches!(&mapped, AppError::NotFound(_) | AppError::Conflict(_)) {
        OrganizationTenantSecretMutationError::known(mapped)
    } else {
        OrganizationTenantSecretMutationError::ambiguous(mapped)
    }
}

pub(crate) async fn list_secrets_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<ListSecretsResponse> {
    org_role(state, user, org_id).await?;
    let secrets = state
        .secrets
        .get_secrets_raw_at_path(&org_secret_path(org_id))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, org_id, "secrets: list failed");
            AppError::InternalMsg("failed to list secrets".into())
        })?;
    Ok(ListSecretsResponse {
        secrets: to_metadata(secrets),
    })
}

pub(crate) async fn set_secret_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    key: &str,
    value: &str,
) -> AppResult<()> {
    let role = org_role(state, user, org_id).await?;
    require_manage_role(&role)?;
    validate_secret_key(key)?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        state
            .secrets
            .create_folder_at_path("/org-secrets", org_id)
            .await
            .map_err(|error| {
                ambiguous_secret_provider_error(error, "failed to initialize secrets storage")
            })?;
        state
            .secrets
            .set_secret_at_path(&org_secret_path(org_id), key, value)
            .await
            .map_err(|error| ambiguous_secret_provider_error(error, "failed to set secret"))?;
        Ok(())
    })
    .await?;

    log_audit(
        state,
        "org.secret.set",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "key": key}),
        "info",
    )
    .await;
    Ok(())
}

pub(crate) async fn delete_secret_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    key: &str,
) -> AppResult<()> {
    let role = org_role(state, user, org_id).await?;
    require_manage_role(&role)?;
    validate_secret_key(key)?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        state
            .secrets
            .delete_secret_at_path(&org_secret_path(org_id), key)
            .await
            .map_err(|error| ambiguous_secret_provider_error(error, "failed to delete secret"))?;
        Ok(())
    })
    .await?;

    log_audit(
        state,
        "org.secret.deleted",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "key": key}),
        "warn",
    )
    .await;
    Ok(())
}

pub(crate) async fn rename_secret_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    key: &str,
    new_key: &str,
) -> AppResult<()> {
    if key == new_key {
        return Err(AppError::BadRequest(
            "new key must differ from current key".into(),
        ));
    }
    let role = org_role(state, user, org_id).await?;
    require_manage_role(&role)?;
    validate_secret_key(key)?;
    validate_secret_key(new_key)?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        state
            .secrets
            .rename_secret_at_path(&org_secret_path(org_id), key, new_key)
            .await
            .map_err(rename_provider_error)?;
        Ok(())
    })
    .await?;

    log_audit(
        state,
        "org.secret.renamed",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "old_key": key, "new_key": new_key}),
        "info",
    )
    .await;
    Ok(())
}

pub(crate) async fn list_user_secrets_core(
    state: &ApiState,
    user: &AuthUser,
) -> AppResult<ListSecretsResponse> {
    let secrets = state
        .secrets
        .get_secrets_raw_at_path(&user_secret_path(&user.user_id))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "user-secrets: list failed");
            AppError::InternalMsg("failed to list secrets".into())
        })?;
    Ok(ListSecretsResponse {
        secrets: to_metadata(secrets),
    })
}

pub(crate) async fn set_user_secret_core(
    state: &ApiState,
    user: &AuthUser,
    key: &str,
    value: &str,
) -> AppResult<()> {
    validate_secret_key(key)?;
    state
        .secrets
        .create_folder_at_path("/users", &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "user-secrets: init storage failed");
            AppError::InternalMsg("failed to initialize secrets storage".into())
        })?;
    state
        .secrets
        .set_secret_at_path(&user_secret_path(&user.user_id), key, value)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "user-secrets: set failed");
            AppError::InternalMsg("failed to set secret".into())
        })?;

    log_audit(
        state,
        "user.secret.set",
        &user.user_id,
        serde_json::json!({"key": key}),
        "info",
    )
    .await;
    Ok(())
}

pub(crate) async fn delete_user_secret_core(
    state: &ApiState,
    user: &AuthUser,
    key: &str,
) -> AppResult<()> {
    validate_secret_key(key)?;
    state
        .secrets
        .delete_secret_at_path(&user_secret_path(&user.user_id), key)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "user-secrets: delete failed");
            AppError::InternalMsg("failed to delete secret".into())
        })?;

    log_audit(
        state,
        "user.secret.deleted",
        &user.user_id,
        serde_json::json!({"key": key}),
        "warn",
    )
    .await;
    Ok(())
}

pub(crate) async fn rename_user_secret_core(
    state: &ApiState,
    user: &AuthUser,
    key: &str,
    new_key: &str,
) -> AppResult<()> {
    validate_secret_key(key)?;
    validate_secret_key(new_key)?;
    if key == new_key {
        return Err(AppError::BadRequest(
            "new key must differ from current key".into(),
        ));
    }
    state
        .secrets
        .rename_secret_at_path(&user_secret_path(&user.user_id), key, new_key)
        .await
        .map_err(rename_error)?;

    log_audit(
        state,
        "user.secret.renamed",
        &user.user_id,
        serde_json::json!({"old_key": key, "new_key": new_key}),
        "info",
    )
    .await;
    Ok(())
}
