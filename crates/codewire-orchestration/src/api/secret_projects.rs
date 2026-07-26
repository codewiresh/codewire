//! `/organizations/{org}/secret-projects` (#38).
//!
//! Project-scoped secrets: a `secret_projects` row groups secrets stored in
//! the tenant `SecretStore` at `/projects/{org_id}/{project_id}`. Same
//! owner/admin gating + audit + parity discipline as the `/secrets` port;
//! shares its helpers.

use axum::Json;
use axum::extract::{Path, State};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    OrganizationTenantSecretMutationError, run_organization_database_mutation,
    run_organization_tenant_secret_mutation,
};
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::ApiState;
use super::environments::format_time;
use super::secrets::{
    ListSecretsResponse, StatusResponse, ambiguous_secret_provider_error, forbidden, log_audit,
    org_role, rename_provider_error, to_metadata, validate_secret_key,
};

// ── Types ──────────────────────────────────────────────────────────────

/// Mirrors `api.SecretProject` (`secret_count` is `omitempty` — omitted at 0).
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SecretProject {
    pub id: String,
    pub org_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub secret_count: i64,
    pub created_at: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateProjectBody {
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetProjectSecretBody {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameProjectSecretBody {
    pub new_key: String,
}

fn secret_project_path(org_id: &str, project_id: &str) -> String {
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
async fn get_project(state: &ApiState, project_id: &str, org_id: &str) -> AppResult<SecretProject> {
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

// ── Handlers ─────────────────────────────────────────────────────────────

/// `POST /…/secret-projects` — mirrors `createSecretProject` (201).
pub async fn create_secret_project(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    ValidatedJson(body): ValidatedJson<CreateProjectBody>,
) -> AppResult<(axum::http::StatusCode, Json<SecretProject>)> {
    let project = create_secret_project_core(&state, &user, &org_id, &body.name).await?;
    Ok((axum::http::StatusCode::CREATED, Json(project)))
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

/// `GET /…/secret-projects` — mirrors `listSecretProjects` (enriched counts).
pub async fn list_secret_projects(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<Vec<SecretProject>>> {
    Ok(Json(
        list_secret_projects_core(&state, &user, &org_id).await?,
    ))
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
        // Enrich with the secret count (best-effort, like Go).
        if let Ok(secrets) = state
            .secrets
            .get_secrets_raw_at_path(&secret_project_path(org_id, &p.id))
            .await
        {
            p.secret_count = secrets.len() as i64;
        }
        projects.push(p);
    }
    Ok(projects)
}

/// `DELETE /…/secret-projects/{projectId}` — mirrors `deleteSecretProject` (204).
pub async fn delete_secret_project(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, project_id)): Path<(String, String)>,
) -> AppResult<axum::http::StatusCode> {
    delete_secret_project_core(&state, &user, &org_id, &project_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
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

/// `GET /…/secret-projects/{projectId}/secrets` — mirrors `listProjectSecrets`.
pub async fn list_project_secrets(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, project_id)): Path<(String, String)>,
) -> AppResult<Json<ListSecretsResponse>> {
    Ok(Json(
        list_project_secrets_core(&state, &user, &org_id, &project_id).await?,
    ))
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
        .get_secrets_raw_at_path(&secret_project_path(org_id, &project.id))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "secret-projects: list secrets failed");
            AppError::InternalMsg("failed to list secrets".into())
        })?;
    Ok(ListSecretsResponse {
        secrets: to_metadata(secrets),
    })
}

/// `PUT /…/secret-projects/{projectId}/secrets` — mirrors `setProjectSecret`.
pub async fn set_project_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, project_id)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<SetProjectSecretBody>,
) -> AppResult<Json<StatusResponse>> {
    set_project_secret_core(&state, &user, &org_id, &project_id, &body.key, &body.value).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

/// `DELETE /…/secret-projects/{projectId}/secrets/{key}` — mirrors `deleteProjectSecret` (204).
pub async fn delete_project_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, project_id, key)): Path<(String, String, String)>,
) -> AppResult<axum::http::StatusCode> {
    delete_project_secret_core(&state, &user, &org_id, &project_id, &key).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
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

/// `POST /…/secret-projects/{projectId}/secrets/{key}/rename` — mirrors `renameProjectSecret`.
pub async fn rename_project_secret(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, project_id, key)): Path<(String, String, String)>,
    ValidatedJson(body): ValidatedJson<RenameProjectSecretBody>,
) -> AppResult<Json<StatusResponse>> {
    rename_project_secret_core(&state, &user, &org_id, &project_id, &key, &body.new_key).await?;
    Ok(Json(StatusResponse { status: "ok" }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn project_path_matches_go() {
        assert_eq!(secret_project_path("o1", "p1"), "/projects/o1/p1");
    }

    #[test]
    fn secret_count_omitted_at_zero() {
        let v = serde_json::to_value(SecretProject {
            id: "p1".into(),
            org_id: "o1".into(),
            name: "proj".into(),
            secret_count: 0,
            created_at: "2026-01-01T00:00:00Z".into(),
        })
        .unwrap();
        assert!(!v.as_object().unwrap().contains_key("secret_count"));
        let v2 = serde_json::to_value(SecretProject {
            id: "p1".into(),
            org_id: "o1".into(),
            name: "proj".into(),
            secret_count: 3,
            created_at: "2026-01-01T00:00:00Z".into(),
        })
        .unwrap();
        assert_eq!(v2["secret_count"], 3);
    }

    #[test]
    fn project_secret_schemas_require_go_required_fields() {
        let create_schema = serde_json::to_value(schemars::schema_for!(CreateProjectBody)).unwrap();
        assert_eq!(create_schema["required"], serde_json::json!(["name"]));

        let set_schema = serde_json::to_value(schemars::schema_for!(SetProjectSecretBody)).unwrap();
        assert_eq!(set_schema["required"], serde_json::json!(["key", "value"]));

        let rename_schema =
            serde_json::to_value(schemars::schema_for!(RenameProjectSecretBody)).unwrap();
        assert_eq!(rename_schema["required"], serde_json::json!(["new_key"]));
    }

    #[test]
    fn create_project_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<CreateProjectBody>(serde_json::json!({}))
        else {
            panic!("expected missing name to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("name"));
    }

    #[test]
    fn set_project_secret_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<SetProjectSecretBody>(serde_json::json!({
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
    fn rename_project_secret_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<RenameProjectSecretBody>(serde_json::json!({
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
