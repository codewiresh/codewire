//! Shared project-secret service logic.

use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationTenantSecretMutationError, run_organization_database_mutation,
    run_organization_tenant_secret_mutation,
};
use codewire_server_core::{AppError, AppResult};
use sqlx::Row;

use super::ApiState;
use super::environments::format_time;
use super::secrets::{
    ListSecretsResponse, ambiguous_secret_provider_error, forbidden, log_audit, org_role,
    rename_provider_error, to_metadata, validate_secret_key, validate_secret_value,
};

// ── Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SecretProject {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub secret_count: i64,
    pub created_at: String,
}

pub(super) fn secret_project_path(org_id: &str, project_id: &str) -> String {
    format!("/projects/{org_id}/{project_id}")
}

// ── DB helpers (mirror secret_groups_db.go) ──────────────────────────────

fn row_to_project(r: &sqlx::postgres::PgRow) -> Result<SecretProject, AppError> {
    let created_at: chrono::NaiveDateTime = r.try_get("created_at").map_err(AppError::from)?;
    Ok(SecretProject {
        id: r.try_get("id").map_err(AppError::from)?,
        org_id: r.try_get("org_id").map_err(AppError::from)?,
        name: r.try_get("name").map_err(AppError::from)?,
        secret_count: 0,
        created_at: format_time(created_at),
    })
}

/// Loads a project and verifies it belongs to `org_id` (404 on either miss),
/// mirroring the Go `getSecretProject` + org-match guard.
pub(super) async fn get_project(
    state: &ApiState,
    project_id: &str,
    org_id: &str,
) -> AppResult<SecretProject> {
    let row = sqlx::query("SELECT id, org_id, name, created_at FROM secret_projects WHERE id = $1")
        .bind(project_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "secret-projects: load failed");
            AppError::InternalMsg("failed to load secret project".into())
        })?
        .ok_or_else(|| AppError::NotFound("secret project not found".into()))?;
    let project = row_to_project(&row)?;
    if project.org_id != org_id {
        return Err(AppError::NotFound("secret project not found".into()));
    }
    Ok(project)
}

/// Owner/admin gate after membership (the 403 detail varies by route).
async fn require_manage(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    detail: &'static str,
) -> AppResult<()> {
    let role = org_role(state, user, org_id).await?;
    if role != "owner" && role != "admin" {
        return Err(forbidden(detail));
    }
    Ok(())
}
pub(crate) async fn create_secret_project_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    requested_name: &str,
) -> AppResult<SecretProject> {
    require_manage(
        state,
        user,
        org_id,
        "only owners and admins can manage secret projects",
    )
    .await?;

    let name = requested_name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }

    run_organization_database_mutation(&state.pool, org_id, async {
        let row = sqlx::query(
            "INSERT INTO secret_projects (org_id, name) VALUES ($1, $2) \
             RETURNING id, org_id, name, created_at",
        )
        .bind(org_id)
        .bind(name)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("unique constraint") || msg.contains("duplicate key") {
                return AppError::Conflict("secret project with this name already exists".into());
            }
            tracing::error!(error = %e, "secret-projects: create failed");
            AppError::InternalMsg("failed to create secret project".into())
        })?;
        let project = row_to_project(&row)?;

        log_audit(
            state,
            "org.secretproject.created",
            &user.user_id,
            serde_json::json!({"org_id": org_id, "project_id": project.id, "name": name}),
            "info",
        )
        .await;
        Ok(project)
    })
    .await
}

pub(crate) async fn list_secret_projects_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> AppResult<Vec<SecretProject>> {
    org_role(state, user, org_id).await?;

    let rows = sqlx::query(
        "SELECT id, org_id, name, created_at FROM secret_projects WHERE org_id = $1 ORDER BY name",
    )
    .bind(org_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "secret-projects: list failed");
        AppError::InternalMsg("failed to list secret projects".into())
    })?;

    let mut projects: Vec<SecretProject> = Vec::with_capacity(rows.len());
    for r in &rows {
        let mut p = row_to_project(r)?;
        let secrets = state
            .secrets
            .get_secret_metadata_at_path(&secret_project_path(org_id, &p.id))
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    project_id = p.id,
                    "secret-projects: count failed"
                );
                AppError::InternalMsg("failed to list secret projects".into())
            })?;
        p.secret_count = i64::try_from(secrets.len()).map_err(|error| {
            tracing::error!(error = %error, project_id = p.id, "secret-projects: count overflow");
            AppError::InternalMsg("failed to list secret projects".into())
        })?;
        projects.push(p);
    }
    Ok(projects)
}

pub(crate) async fn delete_secret_project_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    project_id: &str,
) -> AppResult<()> {
    require_manage(
        state,
        user,
        org_id,
        "only owners and admins can manage secret projects",
    )
    .await?;
    let project = get_project(state, project_id, org_id).await?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        delete_secret_project_storage(&state.pool, &state.secrets, org_id, &project.id).await
    })
    .await?;

    log_audit(
        state,
        "org.secretproject.deleted",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "project_id": project.id, "name": project.name}),
        "warn",
    )
    .await;
    Ok(())
}

pub(crate) async fn delete_secret_project_storage(
    pool: &sqlx::PgPool,
    secrets: &crate::worker::secrets::SecretStore,
    org_id: &str,
    project_id: &str,
) -> Result<(), OrganizationTenantSecretMutationError> {
    secrets
        .delete_path(&secret_project_path(org_id, project_id))
        .await
        .map_err(|error| {
            ambiguous_secret_provider_error(error, "failed to delete secret project storage")
        })?;

    sqlx::query("DELETE FROM secret_projects WHERE id = $1 AND org_id = $2")
        .bind(project_id)
        .bind(org_id)
        .execute(pool)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "secret-projects: delete discovery row failed");
            OrganizationTenantSecretMutationError::known(AppError::InternalMsg(
                "failed to delete secret project".into(),
            ))
        })?;
    Ok(())
}

pub(crate) async fn list_project_secrets_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    project_id: &str,
) -> AppResult<ListSecretsResponse> {
    org_role(state, user, org_id).await?;
    let project = get_project(state, project_id, org_id).await?;

    let secrets = state
        .secrets
        .get_secret_metadata_at_path(&secret_project_path(org_id, &project.id))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "secret-projects: list secrets failed");
            AppError::InternalMsg("failed to list secrets".into())
        })?;
    Ok(ListSecretsResponse {
        secrets: to_metadata(secrets),
    })
}

pub(crate) async fn set_project_secret_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    project_id: &str,
    key: &str,
    value: &str,
) -> AppResult<()> {
    require_manage(
        state,
        user,
        org_id,
        "only owners and admins can manage secrets",
    )
    .await?;
    validate_secret_key(key)?;
    validate_secret_value(value)?;
    let project = get_project(state, project_id, org_id).await?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        state
            .secrets
            .create_folder_at_path("/projects", org_id)
            .await
            .map_err(|error| {
                ambiguous_secret_provider_error(error, "failed to initialize secrets storage")
            })?;
        state
            .secrets
            .create_folder_at_path(&format!("/projects/{org_id}"), &project.id)
            .await
            .map_err(|error| {
                ambiguous_secret_provider_error(error, "failed to initialize secrets storage")
            })?;
        state
            .secrets
            .set_secret_at_path(&secret_project_path(org_id, &project.id), key, value)
            .await
            .map_err(|error| ambiguous_secret_provider_error(error, "failed to set secret"))?;
        Ok(())
    })
    .await?;

    log_audit(
        state,
        "org.secretproject.secret.set",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "project_id": project.id, "key": key}),
        "info",
    )
    .await;
    Ok(())
}

pub(crate) async fn delete_project_secret_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    project_id: &str,
    key: &str,
) -> AppResult<()> {
    require_manage(
        state,
        user,
        org_id,
        "only owners and admins can manage secrets",
    )
    .await?;
    validate_secret_key(key)?;
    let project = get_project(state, project_id, org_id).await?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        state
            .secrets
            .delete_secret_at_path(&secret_project_path(org_id, &project.id), key)
            .await
            .map_err(|error| ambiguous_secret_provider_error(error, "failed to delete secret"))?;
        Ok(())
    })
    .await?;

    log_audit(
        state,
        "org.secretproject.secret.deleted",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "project_id": project.id, "key": key}),
        "warn",
    )
    .await;
    Ok(())
}

pub(crate) async fn rename_project_secret_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    project_id: &str,
    key: &str,
    new_key: &str,
) -> AppResult<()> {
    // Same-key check precedes the role/project checks (mirrors Go's order).
    if key == new_key {
        return Err(AppError::BadRequest(
            "new key must differ from current key".into(),
        ));
    }
    require_manage(
        state,
        user,
        org_id,
        "only owners and admins can manage secrets",
    )
    .await?;
    validate_secret_key(key)?;
    validate_secret_key(new_key)?;
    let project = get_project(state, project_id, org_id).await?;

    run_organization_tenant_secret_mutation(&state.pool, org_id, async {
        state
            .secrets
            .rename_secret_at_path(&secret_project_path(org_id, &project.id), key, new_key)
            .await
            .map_err(rename_provider_error)?;
        Ok(())
    })
    .await?;

    log_audit(
        state,
        "org.secretproject.secret.renamed",
        &user.user_id,
        serde_json::json!({"org_id": org_id, "project_id": project.id, "old_key": key, "new_key": new_key}),
        "info",
    )
    .await;
    Ok(())
}
