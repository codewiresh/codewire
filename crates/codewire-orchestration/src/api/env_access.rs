//! Environment-access management CRUD (#169, part of the #38 HTTP surface).
//!
//! Orchestration already ENFORCES the `environment_access` ACL via
//! [`require_environment_access`]; this adds the management endpoints so
//! retiring Go (#162) doesn't drop grant/revoke.
//!
//! Wire parity notes:
//! - These are huma handlers on the Go side, so the success bodies carry
//!   huma's `$schema` on single objects (the documented accepted drift); the
//!   list endpoint is a bare JSON array with no `$schema`.
//! - `created_at::text` on the Go side returns the raw Postgres
//!   timestamp text (NOT `formatTime`), so we reproduce it with a
//!   `::text` cast rather than `format_time`.
//! - Error envelopes are huma `CodedError` shapes via [`coded`]:
//!   org_not_found (404), access_denied (403), invalid_access (400),
//!   forbidden (400), env_not_found (404), internal_error (500) — each
//!   with the CLI hint Go's `hintForCode` attaches.
//! - Grant/revoke emit `info`-severity audit events, matching Go's
//!   `auth.LogAuditEvent(..., "info")`.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::run_organization_database_mutation;
use codewire_server_core::{AppResult, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use super::ApiState;
use super::environments::{coded, require_environment_access, require_org_member};

/// Mirrors `api.AccessGrant` field-for-field (JSON tags included).
#[derive(Debug, Clone, Serialize)]
pub struct AccessGrant {
    pub id: String,
    pub environment_id: String,
    pub user_id: String,
    pub permission: String,
    pub granted_by: String,
    pub created_at: String,
}

/// Mirrors `api.GrantAccessInput.Body`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GrantAccessBody {
    pub user_id: String,
    pub permission: String,
}

/// `info`-severity audit event, matching Go's
/// `auth.LogAuditEvent(..., "info")`. (The shared environments helper is
/// `warning`-only; grant/revoke are routine, so they log at `info`.)
async fn log_audit_info(pool: &PgPool, action: &str, user_id: &str, metadata: serde_json::Value) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
           VALUES ($1, NOW(), $2, $3, '', '', $4, 'info')"#,
    )
    .bind(&id)
    .bind(action)
    .bind(user_id)
    .bind(&metadata)
    .execute(pool)
    .await
    {
        tracing::error!(action, error = %e, "failed to log audit event");
    }
}

/// Mirrors `listEnvironmentAccess`.
/// `GET /api/v1/organizations/{org_id}/environments/{env_id}/access`.
pub async fn list_environment_access(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
) -> AppResult<Json<Vec<AccessGrant>>> {
    Ok(Json(
        list_environment_access_core(&state, &user, &org_id, &env_id).await?,
    ))
}

pub(crate) async fn list_environment_access_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> AppResult<Vec<AccessGrant>> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;
    require_environment_access(
        pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can view access grants",
    )
    .await?;

    let rows = sqlx::query(
        r#"SELECT id, environment_id, user_id, permission, granted_by, created_at::text
           FROM environment_access
           WHERE environment_id = $1
           ORDER BY created_at"#,
    )
    .bind(env_id)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "list access grants failed");
        coded(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "failed to list access grants",
        )
    })?;

    // Go skips rows that fail to scan (`continue`); a clean column list
    // makes that a non-issue, but mirror the empty-array shape.
    let grants = rows
        .iter()
        .map(|r| -> Result<AccessGrant, sqlx::Error> {
            Ok(AccessGrant {
                id: r.try_get("id")?,
                environment_id: r.try_get("environment_id")?,
                user_id: r.try_get("user_id")?,
                permission: r.try_get("permission")?,
                granted_by: r.try_get("granted_by")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(grants)
}

/// Mirrors `grantEnvironmentAccess` (201).
/// `POST /api/v1/organizations/{org_id}/environments/{env_id}/access`.
pub async fn grant_environment_access(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id)): Path<(String, String)>,
    ValidatedJson(body): ValidatedJson<GrantAccessBody>,
) -> AppResult<(StatusCode, Json<AccessGrant>)> {
    let grant = grant_environment_access_core(&state, &user, &org_id, &env_id, body).await?;
    Ok((StatusCode::CREATED, Json(grant)))
}

pub(crate) async fn grant_environment_access_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    body: GrantAccessBody,
) -> AppResult<AccessGrant> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;
    require_environment_access(
        pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can grant access",
    )
    .await?;
    let perm = body.permission.as_str();
    if perm != "owner" && perm != "operator" && perm != "viewer" {
        return Err(coded(
            StatusCode::BAD_REQUEST,
            "invalid_access",
            "permission must be owner, operator, or viewer",
        ));
    }

    run_organization_database_mutation(pool, org_id, async {
        // Validate the target user is a member of the org. Go uses
        // getUserOrgRole; the API-key org-scope guard there is a function of
        // the request context (already satisfied by require_org_member
        // above), so the target lookup is a plain org_members query.
        let target_role: Option<String> =
            sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
                .bind(org_id)
                .bind(&body.user_id)
                .fetch_optional(pool)
                .await?;
        if target_role.is_none() {
            return Err(coded(
                StatusCode::BAD_REQUEST,
                "forbidden",
                "target user is not a member of this organization",
            ));
        }

        let row = sqlx::query(
            r#"INSERT INTO environment_access (environment_id, user_id, permission, granted_by)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (environment_id, user_id) DO UPDATE
                 SET permission = EXCLUDED.permission, granted_by = EXCLUDED.granted_by
               RETURNING id, environment_id, user_id, permission, granted_by, created_at::text"#,
        )
        .bind(env_id)
        .bind(&body.user_id)
        .bind(perm)
        .bind(&user.user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "grant access failed");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to grant access",
            )
        })?;

        let grant = AccessGrant {
            id: row.try_get("id")?,
            environment_id: row.try_get("environment_id")?,
            user_id: row.try_get("user_id")?,
            permission: row.try_get("permission")?,
            granted_by: row.try_get("granted_by")?,
            created_at: row.try_get("created_at")?,
        };

        log_audit_info(
            pool,
            "environment.access.granted",
            &user.user_id,
            serde_json::json!({
                "org_id": org_id, "environment_id": env_id,
                "target_user_id": body.user_id, "permission": perm,
            }),
        )
        .await;

        Ok(grant)
    })
    .await
}

/// Mirrors `revokeEnvironmentAccess` (204).
/// `DELETE /api/v1/organizations/{org_id}/environments/{env_id}/access/{user_id}`.
pub async fn revoke_environment_access(
    State(state): State<ApiState>,
    user: AuthUser,
    Path((org_id, env_id, target_user_id)): Path<(String, String, String)>,
) -> AppResult<StatusCode> {
    revoke_environment_access_core(&state, &user, &org_id, &env_id, &target_user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn revoke_environment_access_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
    target_user_id: &str,
) -> AppResult<()> {
    let pool = &state.pool;
    require_org_member(pool, user, org_id).await?;
    require_environment_access(
        pool,
        user,
        env_id,
        org_id,
        "owner",
        "only environment owners can revoke access",
    )
    .await?;
    run_organization_database_mutation(pool, org_id, async {
        // Cannot revoke the creator's implicit access.
        let created_by: Option<String> =
            sqlx::query_scalar("SELECT created_by FROM environments WHERE id = $1")
                .bind(env_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
        if created_by.as_deref() == Some(target_user_id) {
            return Err(coded(
                StatusCode::BAD_REQUEST,
                "forbidden",
                "cannot revoke access from the environment creator",
            ));
        }

        let result = sqlx::query(
            "DELETE FROM environment_access WHERE environment_id = $1 AND user_id = $2",
        )
        .bind(env_id)
        .bind(target_user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "revoke access failed");
            coded(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "failed to revoke access",
            )
        })?;
        if result.rows_affected() == 0 {
            return Err(coded(
                StatusCode::NOT_FOUND,
                "env_not_found",
                "access grant not found",
            ));
        }

        log_audit_info(
            pool,
            "environment.access.revoked",
            &user.user_id,
            serde_json::json!({
                "org_id": org_id, "environment_id": env_id,
                "target_user_id": target_user_id,
            }),
        )
        .await;

        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_server_core::AppError;
    use codewire_server_core::validation::validate_value;

    #[test]
    fn grant_access_schema_requires_go_required_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(GrantAccessBody)).unwrap();

        assert_eq!(
            schema["required"],
            serde_json::json!(["user_id", "permission"])
        );
    }

    #[test]
    fn grant_access_validation_rejects_missing_required_fields() {
        let Err(AppError::Validation { errors }) =
            validate_value::<GrantAccessBody>(serde_json::json!({
                "user_id": "usr_1"
            }))
        else {
            panic!("expected missing permission to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("permission"));
    }

    #[test]
    fn grant_access_validation_rejects_type_errors() {
        let Err(AppError::Validation { errors }) =
            validate_value::<GrantAccessBody>(serde_json::json!({
                "user_id": 7,
                "permission": "viewer"
            }))
        else {
            panic!("expected type-invalid user_id to be rejected");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/user_id");
        assert!(errors[0].message.contains("string"));
    }
}
