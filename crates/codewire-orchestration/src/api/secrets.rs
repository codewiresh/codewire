//! `/secrets` (org) + `/user/secrets` (#38).
//!
//! Org + user secret-key management. Names + metadata are listed (never
//! values); values live in the tenant `SecretStore` at `/org-secrets/{org_id}`
//! or `/users/{user_id}`. Org mutations require owner/admin; user secrets are
//! scoped to the authenticated user.
//!
//! Wire-parity notes:
//! - huma single-object success bodies carried `$schema` on the Go side only
//!   (accepted drift). `{ "status": "ok" }` on
//!   set/delete/rename success; the user-delete is 204.
//! - The list body is `{ "secrets": [ { key, created_at?, updated_at? } ] }`;
//!   `created_at`/`updated_at` are `omitempty` (skipped when empty).
//! - The Go handlers guard `infisical == nil → 503`; the Rust `SecretStore` is
//!   always present (same accepted drift as the other ports), so that branch
//!   is unreachable here.

use axum::Json;
use axum::extract::{Path, Query, State};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::{
    OrganizationTenantSecretMutationError, run_organization_tenant_secret_mutation,
};
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ApiState;

// ── Wire types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SecretMetadata {
    pub key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretMetadata>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StatusResponse {
    pub status: &'static str,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OrgIdQuery {
    pub org_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetSecretBody {
    pub org_id: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameSecretBody {
    pub org_id: String,
    pub new_key: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetUserSecretBody {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameUserSecretBody {
    pub new_key: String,
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

/// Shared existence-hiding organization gate for REST and Connect.
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

// ── Org secrets handlers ─────────────────────────────────────────────────

/// `GET /api/v1/secrets?org_id=` — mirrors `listSecrets`.
pub async fn list_secrets(
    State(state): State<ApiState>,
    user: AuthUser,
    Query(q): Query<OrgIdQuery>,
) -> AppResult<Json<ListSecretsResponse>> {
    Ok(Json(list_secrets_core(&state, &user, &q.org_id).await?))
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

/// `PUT /api/v1/secrets` — mirrors `setSecret`.
pub async fn set_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<SetSecretBody>,
) -> AppResult<Json<StatusResponse>> {
    set_secret_core(&state, &user, &body.org_id, &body.key, &body.value).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

/// `DELETE /api/v1/secrets/{key}?org_id=` — mirrors `deleteSecret`.
pub async fn delete_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(key): Path<String>,
    Query(q): Query<OrgIdQuery>,
) -> AppResult<Json<StatusResponse>> {
    delete_secret_core(&state, &user, &q.org_id, &key).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

/// `POST /api/v1/secrets/{key}/rename` — mirrors `renameSecret`.
pub async fn rename_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(key): Path<String>,
    ValidatedJson(body): ValidatedJson<RenameSecretBody>,
) -> AppResult<Json<StatusResponse>> {
    rename_secret_core(&state, &user, &body.org_id, &key, &body.new_key).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

// ── User secrets handlers ────────────────────────────────────────────────

/// `GET /api/v1/user/secrets` — mirrors `listUserSecrets`.
pub async fn list_user_secrets(
    State(state): State<ApiState>,
    user: AuthUser,
) -> AppResult<Json<ListSecretsResponse>> {
    Ok(Json(list_user_secrets_core(&state, &user).await?))
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

/// `PUT /api/v1/user/secrets` — mirrors `setUserSecret`.
pub async fn set_user_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    ValidatedJson(body): ValidatedJson<SetUserSecretBody>,
) -> AppResult<Json<StatusResponse>> {
    set_user_secret_core(&state, &user, &body.key, &body.value).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

/// `DELETE /api/v1/user/secrets/{key}` — mirrors `deleteUserSecret` (204).
pub async fn delete_user_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(key): Path<String>,
) -> AppResult<axum::http::StatusCode> {
    delete_user_secret_core(&state, &user, &key).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
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

/// `POST /api/v1/user/secrets/{key}/rename` — mirrors `renameUserSecret`.
pub async fn rename_user_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(key): Path<String>,
    ValidatedJson(body): ValidatedJson<RenameUserSecretBody>,
) -> AppResult<Json<StatusResponse>> {
    rename_user_secret_core(&state, &user, &key, &body.new_key).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn secret_paths_match_go() {
        assert_eq!(org_secret_path("org_1"), "/org-secrets/org_1");
        assert_eq!(user_secret_path("usr_1"), "/users/usr_1");
    }

    #[test]
    fn rename_error_maps_to_go_status() {
        assert!(matches!(
            rename_error(anyhow::anyhow!("secret \"x\" not found")),
            AppError::NotFound(_)
        ));
        assert!(matches!(
            rename_error(anyhow::anyhow!("secret \"y\" already exists")),
            AppError::Conflict(_)
        ));
        assert!(matches!(
            rename_error(anyhow::anyhow!("connection reset")),
            AppError::InternalMsg(_)
        ));
    }

    #[test]
    fn manage_role_gate_allows_owner_admin_only() {
        assert!(require_manage_role("owner").is_ok());
        assert!(require_manage_role("admin").is_ok());
        assert!(require_manage_role("member").is_err());
        assert!(require_manage_role("viewer").is_err());
    }

    #[test]
    fn secret_key_contract_blocks_infisical_path_shaping() {
        for valid in ["A", "DATABASE_URL", "github_token", "KEY123"] {
            assert!(validate_secret_key(valid).is_ok(), "rejected {valid:?}");
        }
        for invalid in [
            "",
            "db/password",
            "stage?prod",
            "name#fragment",
            "..",
            "na-me",
        ] {
            assert!(
                validate_secret_key(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn org_secret_schemas_require_go_required_fields() {
        let set_schema = serde_json::to_value(schemars::schema_for!(SetSecretBody)).unwrap();
        assert_eq!(
            set_schema["required"],
            serde_json::json!(["org_id", "key", "value"])
        );

        let rename_schema = serde_json::to_value(schemars::schema_for!(RenameSecretBody)).unwrap();
        assert_eq!(
            rename_schema["required"],
            serde_json::json!(["org_id", "new_key"])
        );
    }

    #[test]
    fn user_secret_schemas_require_go_required_fields() {
        let set_schema = serde_json::to_value(schemars::schema_for!(SetUserSecretBody)).unwrap();
        assert_eq!(set_schema["required"], serde_json::json!(["key", "value"]));

        let rename_schema =
            serde_json::to_value(schemars::schema_for!(RenameUserSecretBody)).unwrap();
        assert_eq!(rename_schema["required"], serde_json::json!(["new_key"]));
    }

    #[test]
    fn set_secret_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<SetSecretBody>(serde_json::json!({
                "org_id": "org_1",
                "key": "DATABASE_URL"
            }))
        else {
            panic!("expected missing value to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("value"));
    }

    #[test]
    fn rename_user_secret_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<RenameUserSecretBody>(serde_json::json!({
                "new_key": 7
            }))
        else {
            panic!("expected type-invalid new_key to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/new_key");
        assert!(errors[0].message.contains("string"));
    }
}
