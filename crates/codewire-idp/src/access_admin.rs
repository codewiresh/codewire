//! Global-administrator account access review endpoints.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::NaiveDateTime;
use codewire_email::EmailClient;
use codewire_server_core::account_deletion::DELETED_USER_ID;
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::auth_session::{hex_id, request_info};
use crate::email_password::send_access_enabled_email;

#[derive(Clone)]
struct AccessAdminState {
    pool: PgPool,
    frontend_url: String,
    email: EmailClient,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct AccountAccessRow {
    id: String,
    email: String,
    name: Option<String>,
    email_verified: bool,
    enabled: bool,
    access_reason: Option<String>,
    created_at: NaiveDateTime,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountAccessList {
    accounts: Vec<AccountAccessRow>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SetAccountEnabledRequest {
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct SetAccountEnabledResponse {
    enabled: bool,
}

#[derive(sqlx::FromRow)]
struct LockedAccount {
    email: String,
    email_verified: bool,
    enabled: bool,
    access_reason: Option<String>,
}

async fn list_accounts(
    State(state): State<AccessAdminState>,
    actor: AuthUser,
) -> Result<Json<AccountAccessList>, AppError> {
    actor.require_global_admin()?;
    let accounts = sqlx::query_as::<_, AccountAccessRow>(
        r#"SELECT id,
                  email,
                  name,
                  COALESCE(email_verified, false) AS email_verified,
                  enabled,
                  access_reason,
                  COALESCE(created_at, NOW()::timestamp) AS created_at
           FROM users
           WHERE id <> $1
           ORDER BY enabled ASC,
                    (access_reason IS NOT NULL) DESC,
                    created_at DESC NULLS LAST
           LIMIT 500"#,
    )
    .bind(DELETED_USER_ID)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "failed to list account access state");
        AppError::InternalMsg("Failed to list accounts".into())
    })?;
    Ok(Json(AccountAccessList { accounts }))
}

async fn set_account_enabled(
    State(state): State<AccessAdminState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    actor: AuthUser,
    ValidatedJson(request): ValidatedJson<SetAccountEnabledRequest>,
) -> Result<Json<SetAccountEnabledResponse>, AppError> {
    actor.require_global_admin()?;
    if user_id == DELETED_USER_ID {
        return Err(AppError::Coded {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            detail: "Account not found".into(),
        });
    }
    if !request.enabled && actor.user_id == user_id {
        return Err(AppError::BadRequest(
            "You cannot disable your own account".into(),
        ));
    }

    let (ip, user_agent) = request_info(&headers);
    let mut tx = state.pool.begin().await.map_err(|error| {
        tracing::error!(%error, "failed to begin account access update");
        AppError::InternalMsg("Failed to update account".into())
    })?;
    let account = sqlx::query_as::<_, LockedAccount>(
        r#"SELECT email,
                  COALESCE(email_verified, false) AS email_verified,
                  enabled,
                  access_reason
           FROM users
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "failed to load account access state");
        AppError::InternalMsg("Failed to update account".into())
    })?
    .ok_or(AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "not_found",
        detail: "Account not found".into(),
    })?;

    // An account being deleted stays disabled until its deletion completes
    // (#3679); the user row lock above orders this after the request.
    if request.enabled {
        let deleting: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_deletion_operations WHERE user_id = $1)",
        )
        .bind(&user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to check account deletion state");
            AppError::InternalMsg("Failed to update account".into())
        })?;
        if deleting {
            return Err(AppError::Conflict("This account is being deleted".into()));
        }
    }
    if request.enabled && account.access_reason.is_some() && !account.email_verified {
        return Err(AppError::BadRequest(
            "Verify the account email before enabling access".into(),
        ));
    }
    if request.enabled && !state.email.is_configured() {
        return Err(AppError::ServiceUnavailable(
            "Account email is temporarily unavailable".into(),
        ));
    }

    if account.enabled != request.enabled {
        sqlx::query("UPDATE users SET enabled = $1, updated_at = NOW() WHERE id = $2")
            .bind(request.enabled)
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                tracing::error!(%error, "failed to update account access state");
                AppError::InternalMsg("Failed to update account".into())
            })?;

        sqlx::query(
            r#"INSERT INTO audit_logs
                   (id, timestamp, action, user_id, target_user_id, ip_address,
                    user_agent, metadata, severity)
               VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, 'info')"#,
        )
        .bind(hex_id())
        .bind(if request.enabled {
            "admin.account.enabled"
        } else {
            "admin.account.disabled"
        })
        .bind(&actor.user_id)
        .bind(&user_id)
        .bind(&ip)
        .bind(&user_agent)
        .bind(json!({ "enabled": request.enabled, "email": &account.email }))
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to audit account access update");
            AppError::InternalMsg("Failed to update account".into())
        })?;
    }

    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "failed to commit account access update");
        AppError::InternalMsg("Failed to update account".into())
    })?;

    if request.enabled {
        let login_url = format!("{}/login", state.frontend_url.trim_end_matches('/'));
        if let Err(error) =
            send_access_enabled_email(&state.email, &account.email, &login_url).await
        {
            tracing::error!(%error, target_user_id = %user_id, "failed to send account enabled email");
            return Err(AppError::ServiceUnavailable(
                "Account access was updated, but the ready email could not be sent. Try again shortly."
                    .into(),
            ));
        }
    }

    Ok(Json(SetAccountEnabledResponse {
        enabled: request.enabled,
    }))
}

pub fn router(pool: PgPool, frontend_url: String, email: EmailClient, auth: AuthState) -> Router {
    Router::new()
        .route("/api/admin/accounts", get(list_accounts))
        .route(
            "/api/admin/accounts/{user_id}/enabled",
            post(set_account_enabled),
        )
        .route_layer(middleware::from_fn_with_state(auth, require_session_auth))
        .with_state(AccessAdminState {
            pool,
            frontend_url,
            email,
        })
}
