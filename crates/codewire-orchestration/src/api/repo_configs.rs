//! Saved repo-config CRUD (#38 slice 4) — port of `repo_config.go`.
//! These are huma handlers with PLAIN errors (`huma.Error404NotFound`
//! etc. — no code/hint), so the Rust side uses the plain AppError
//! variants; `$schema` stays the accepted drift.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org::user_org_role;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppError, AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::Deserialize;
use sqlx::Row;

use super::ApiState;
use super::prepare::RepoConfig;

/// Plain-error org gate (`huma.Error404NotFound("organization not
/// found")` — unlike the environments handlers' CodedError).
async fn require_org_member_plain(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
) -> Result<(), AppError> {
    if user_org_role(&state.pool, user, org_id).await?.is_none() {
        return Err(AppError::NotFound("organization not found".into()));
    }
    Ok(())
}

fn scan_repo_config(row: &sqlx::postgres::PgRow) -> Result<RepoConfig, sqlx::Error> {
    Ok(RepoConfig {
        id: row.try_get("id")?,
        org_id: row.try_get("org_id")?,
        repo_url: row.try_get("repo_url")?,
        preset_id: row.try_get("preset_id")?,
        setup_config: row
            .try_get::<Option<serde_json::Value>, _>("setup_config")?
            .unwrap_or(serde_json::Value::Null),
        created_by: row.try_get("created_by")?,
        updated_at: super::environments::format_time(row.try_get("updated_at")?),
    })
}

const REPO_CONFIG_SELECT: &str = r#"SELECT id, org_id, repo_url, preset_id, setup_config,
    created_by, updated_at FROM repo_configs"#;

#[derive(Debug, Deserialize)]
pub struct LookupQuery {
    #[serde(default)]
    pub repo_url: String,
}

/// Mirrors `lookupRepoConfig` (the handler).
pub async fn lookup_repo_config(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    Query(q): Query<LookupQuery>,
) -> AppResult<Json<RepoConfig>> {
    require_org_member_plain(&state, &user, &org_id).await?;
    let sql = format!("{REPO_CONFIG_SELECT} WHERE org_id = $1 AND repo_url = $2");
    let row = sqlx::query(&sql)
        .bind(&org_id)
        .bind(&q.repo_url)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound("no saved config for this repo".into()))?;
    Ok(Json(scan_repo_config(&row)?))
}

/// Mirrors `listRepoConfigs`.
pub async fn list_repo_configs(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
) -> AppResult<Json<Vec<RepoConfig>>> {
    require_org_member_plain(&state, &user, &org_id).await?;
    let sql = format!("{REPO_CONFIG_SELECT} WHERE org_id = $1 ORDER BY updated_at DESC");
    let rows = sqlx::query(&sql)
        .bind(&org_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list repo configs failed");
            AppError::InternalMsg("failed to list repo configs".into())
        })?;
    let configs = rows
        .iter()
        .map(scan_repo_config)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::InternalMsg("failed to scan repo config".into()))?;
    Ok(Json(configs))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpsertRepoConfigBody {
    pub repo_url: String,
    #[serde(default)]
    pub preset_id: Option<String>,
    #[serde(default)]
    pub setup_config: Option<serde_json::Value>,
}

/// Mirrors `upsertRepoConfig` (PUT, 200).
pub async fn upsert_repo_config(
    State(state): State<ApiState>,
    user: AuthUser,
    Path(org_id): Path<String>,
    ValidatedJson(body): ValidatedJson<UpsertRepoConfigBody>,
) -> AppResult<Json<RepoConfig>> {
    require_org_member_plain(&state, &user, &org_id).await?;
    let setup_config = body.setup_config.unwrap_or_else(|| serde_json::json!({}));

    run_organization_database_mutation(&state.pool, &org_id, async {
        let row = sqlx::query(
            r#"INSERT INTO repo_configs (org_id, repo_url, preset_id, setup_config, created_by)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (org_id, repo_url)
               DO UPDATE SET preset_id = EXCLUDED.preset_id,
                            setup_config = EXCLUDED.setup_config,
                            updated_at = NOW()
               RETURNING id, org_id, repo_url, preset_id, setup_config, created_by, updated_at"#,
        )
        .bind(&org_id)
        .bind(&body.repo_url)
        .bind(&body.preset_id)
        .bind(&setup_config)
        .bind(&user.user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "upsert repo config failed");
            AppError::InternalMsg("failed to save repo config".into())
        })?;
        Ok(Json(scan_repo_config(&row)?))
    })
    .await
}

/// Mirrors `deleteRepoConfig` (204).
pub async fn delete_repo_config(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, config_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
    require_org_member_plain(&state, &user, &org_id).await?;
    run_organization_database_mutation(&state.pool, &org_id, async {
        let result = sqlx::query("DELETE FROM repo_configs WHERE id = $1 AND org_id = $2")
            .bind(&config_id)
            .bind(&org_id)
            .execute(&state.pool)
            .await
            .map_err(|_| AppError::InternalMsg("failed to delete repo config".into()))?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("repo config not found".into()));
        }
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn upsert_repo_config_schema_requires_go_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(UpsertRepoConfigBody)).unwrap();

        assert_eq!(schema["required"], serde_json::json!(["repo_url"]));
    }

    #[test]
    fn upsert_repo_config_validation_rejects_missing_repo_url() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpsertRepoConfigBody>(serde_json::json!({
                "preset_id": "preset_1"
            }))
        else {
            panic!("expected missing repo_url to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("repo_url"));
    }

    #[test]
    fn upsert_repo_config_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<UpsertRepoConfigBody>(serde_json::json!({
                "repo_url": "https://git.example.com/acme/app",
                "preset_id": 7
            }))
        else {
            panic!("expected type-invalid preset_id to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/preset_id");
        assert!(errors[0].message.contains("string"));
    }

    #[test]
    fn upsert_repo_config_validation_keeps_optional_fields_optional() {
        let body = validate_value::<UpsertRepoConfigBody>(serde_json::json!({
            "repo_url": "https://git.example.com/acme/app"
        }))
        .expect("optional repo-config fields should remain optional");

        assert_eq!(body.repo_url, "https://git.example.com/acme/app");
        assert!(body.preset_id.is_none());
        assert!(body.setup_config.is_none());
    }
}
