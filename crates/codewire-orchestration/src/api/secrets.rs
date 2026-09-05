//! Shared organization and user secret service logic.

use std::collections::BTreeSet;

use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::{
    OrganizationTenantSecretMutationError, run_organization_tenant_secret_mutation,
};
use codewire_server_core::{AppError, AppResult};
use codewire_workload_secrets::{
    MAX_WORKLOAD_SECRET_KEY_BYTES, MAX_WORKLOAD_SECRET_VALUE_BYTES, MAX_WORKLOAD_SECRETS,
    ResolvedWorkloadSecretMetadata, WorkloadSecretCodecError, WorkloadSecretSource,
    resolve_workload_secret_metadata, validate_workload_secret_key, validate_workload_secret_value,
};

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
            format!(
                "secret key must be 1 to {MAX_WORKLOAD_SECRET_KEY_BYTES} bytes, start with an ASCII letter or underscore, and contain only ASCII letters, digits, or underscores"
            )
            .into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_secret_value(value: &str) -> AppResult<()> {
    validate_workload_secret_value(value.as_bytes()).map_err(|_| {
        AppError::BadRequest(format!(
            "secret value must be non-empty UTF-8 without NUL bytes and at most {MAX_WORKLOAD_SECRET_VALUE_BYTES} bytes"
        )
        .into())
    })
}

pub(crate) async fn preview_workload_secret_resolution_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    organization: bool,
    secret_project_id: Option<&str>,
    include_user: bool,
    explicit_environment_keys: &[String],
) -> AppResult<Vec<ResolvedWorkloadSecretMetadata>> {
    org_role(state, user, org_id).await?;
    validate_preview_explicit_environment_keys(explicit_environment_keys)?;

    let mut source_keys = Vec::<(WorkloadSecretSource, String)>::new();
    if organization {
        append_preview_source_keys(
            state,
            &org_secret_path(org_id),
            WorkloadSecretSource::Organization,
            &mut source_keys,
        )
        .await?;
    }
    if let Some(project_id) = secret_project_id.filter(|value| !value.is_empty()) {
        let project = super::secret_projects::get_project(state, project_id, org_id).await?;
        append_preview_source_keys(
            state,
            &super::secret_projects::secret_project_path(org_id, &project.id),
            WorkloadSecretSource::Project,
            &mut source_keys,
        )
        .await?;
    }
    if include_user {
        append_preview_source_keys(
            state,
            &user_secret_path(&user.user_id),
            WorkloadSecretSource::User,
            &mut source_keys,
        )
        .await?;
    }
    source_keys.extend(
        explicit_environment_keys
            .iter()
            .cloned()
            .map(|key| (WorkloadSecretSource::ExplicitEnvironment, key)),
    );

    resolve_workload_secret_metadata(
        source_keys
            .iter()
            .map(|(source, key)| (*source, key.as_str())),
    )
    .map_err(map_preview_resolution_error)
}

fn map_preview_resolution_error(error: WorkloadSecretCodecError) -> AppError {
    if error == WorkloadSecretCodecError::InvalidEntryCount {
        return AppError::BadRequest(
            "selected workload-secret sources resolve to too many keys".into(),
        );
    }
    tracing::error!(error = %error, "workload-secret preview metadata is invalid");
    AppError::InternalMsg("failed to preview workload-secret resolution".into())
}

fn validate_preview_explicit_environment_keys(
    explicit_environment_keys: &[String],
) -> AppResult<()> {
    if explicit_environment_keys.len() > MAX_WORKLOAD_SECRETS {
        return Err(AppError::BadRequest(
            "too many explicit environment keys".into(),
        ));
    }
    let mut unique_explicit = BTreeSet::new();
    for key in explicit_environment_keys {
        validate_workload_secret_key(key)
            .map_err(|_| AppError::BadRequest("invalid explicit environment key".into()))?;
        if !unique_explicit.insert(key.as_str()) {
            return Err(AppError::BadRequest(
                "duplicate explicit environment key".into(),
            ));
        }
    }
    Ok(())
}

async fn append_preview_source_keys(
    state: &ApiState,
    path: &str,
    source: WorkloadSecretSource,
    destination: &mut Vec<(WorkloadSecretSource, String)>,
) -> AppResult<()> {
    let query_limit = MAX_WORKLOAD_SECRETS
        .checked_add(1)
        .ok_or_else(|| AppError::InternalMsg("workload-secret preview limit invalid".into()))?;
    let metadata = state
        .secrets
        .get_secret_metadata_at_path_bounded(path, query_limit)
        .await
        .map_err(|error| {
            tracing::error!(%error, ?source, "workload-secret preview source unavailable");
            AppError::InternalMsg("selected workload-secret source is unavailable".into())
        })?;
    let source_count = extend_preview_source_keys(destination, metadata, source);
    if source_count > MAX_WORKLOAD_SECRETS {
        return Err(AppError::BadRequest(
            "selected workload-secret source has too many keys".into(),
        ));
    }
    Ok(())
}

fn extend_preview_source_keys(
    destination: &mut Vec<(WorkloadSecretSource, String)>,
    metadata: Vec<crate::worker::secrets::StoredSecretMetadata>,
    source: WorkloadSecretSource,
) -> usize {
    let initial_len = destination.len();
    destination.extend(metadata.into_iter().map(|secret| (source, secret.key)));
    destination.len() - initial_len
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
    secrets: Vec<crate::worker::secrets::StoredSecretMetadata>,
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
        .get_secret_metadata_at_path(&org_secret_path(org_id))
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
    validate_secret_value(value)?;

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
        .get_secret_metadata_at_path(&user_secret_path(&user.user_id))
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
    validate_secret_value(value)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_secret_keys_use_the_canonical_workload_grammar() {
        let maximum = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES - 1));
        let too_long = format!("A{}", "_".repeat(MAX_WORKLOAD_SECRET_KEY_BYTES));

        assert!(validate_secret_key(&maximum).is_ok());
        assert!(validate_secret_key(&too_long).is_err());
        assert!(validate_secret_key("_UNDERSCORE_FIRST").is_ok());
        assert!(matches!(
            validate_secret_key("1DIGIT_FIRST"),
            Err(AppError::BadRequest(message))
                if message.contains("start with an ASCII letter or underscore")
        ));
    }

    #[test]
    fn workload_secret_values_use_the_shared_bounds_without_rendering_material() {
        assert!(validate_secret_value(" leading and trailing \n").is_ok());
        for invalid in [
            String::new(),
            "contains\0nul".to_string(),
            "x".repeat(MAX_WORKLOAD_SECRET_VALUE_BYTES + 1),
        ] {
            let error = validate_secret_value(&invalid).unwrap_err();
            if !invalid.is_empty() {
                assert!(!format!("{error:?}").contains(&invalid));
            }
        }
    }

    #[test]
    fn preview_source_bound_counts_every_source_key() {
        let metadata = |count: usize| {
            (0..count)
                .map(|index| crate::worker::secrets::StoredSecretMetadata {
                    key: format!("KEY_{index}"),
                    ..Default::default()
                })
                .collect::<Vec<_>>()
        };
        let mut source_keys = Vec::new();
        assert_eq!(
            extend_preview_source_keys(
                &mut source_keys,
                metadata(MAX_WORKLOAD_SECRETS),
                WorkloadSecretSource::User,
            ),
            MAX_WORKLOAD_SECRETS
        );
        source_keys.clear();
        assert_eq!(
            extend_preview_source_keys(
                &mut source_keys,
                metadata(MAX_WORKLOAD_SECRETS + 1),
                WorkloadSecretSource::User,
            ),
            MAX_WORKLOAD_SECRETS + 1
        );
    }

    #[test]
    fn preview_rejects_noncanonical_or_duplicate_explicit_environment_keys() {
        assert!(
            validate_preview_explicit_environment_keys(&["CANONICAL".into(), "_ALSO_OK".into()])
                .is_ok()
        );
        assert!(validate_preview_explicit_environment_keys(&["1LEGACY".into()]).is_err());
        assert!(
            validate_preview_explicit_environment_keys(&["DUPLICATE".into(), "DUPLICATE".into()])
                .is_err()
        );
    }

    #[test]
    fn preview_reports_aggregate_source_overflow_as_bad_request() {
        let organization_keys = (0..MAX_WORKLOAD_SECRETS)
            .map(|index| (WorkloadSecretSource::Organization, format!("ORG_{index}")))
            .collect::<Vec<_>>();
        let mut source_keys = organization_keys;
        source_keys.push((WorkloadSecretSource::Project, "PROJECT_ONLY".into()));

        let error = resolve_workload_secret_metadata(
            source_keys
                .iter()
                .map(|(source, key)| (*source, key.as_str())),
        )
        .unwrap_err();
        assert!(matches!(
            map_preview_resolution_error(error),
            AppError::BadRequest(message)
                if message == "selected workload-secret sources resolve to too many keys"
        ));
    }
}
