//! Global-administrator account access review endpoints.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, NaiveDateTime, Utc};
use codewire_email::EmailClient;
use codewire_server_core::account_deletion::DELETED_USER_ID;
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::auth_session::{hex_id, request_info};
use crate::email_password::{
    VerificationPurpose, create_verification_in_transaction, send_access_enabled_email,
    send_verification_email,
};
use crate::oauth::LINKED_ACCOUNT_SQL;

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
    /// Who vouched for the address on a server with no mail (#4121):
    /// `invitation`, `bootstrap` or `admin`.
    vouched_by: Option<String>,
    /// The GitHub and Google identities that sign in to this account.
    #[sqlx(skip)]
    linked_identities: Vec<LinkedIdentityRow>,
    /// The invitation whose link let this account in, so an admin who gave a
    /// link to the wrong person sees it here and can disable the account.
    #[sqlx(skip)]
    joined_via: Option<JoinedViaRow>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct JoinedViaRow {
    #[serde(skip)]
    user_id: String,
    invitation_id: String,
    organization: Option<String>,
    inviter_name: Option<String>,
    inviter_email: Option<String>,
    joined_at: NaiveDateTime,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct LinkedIdentityRow {
    #[serde(skip)]
    user_id: String,
    provider: String,
    /// The provider's stable subject: GitHub's numeric id, Google's `sub`.
    subject: String,
    /// The provider account it was linked as, when the audit log names it.
    account: Option<String>,
    linked_at: NaiveDateTime,
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

#[derive(Debug, Serialize)]
struct ResendVerificationResponse {
    sent: bool,
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
    let mut accounts = sqlx::query_as::<_, AccountAccessRow>(
        r#"SELECT id,
                  email,
                  name,
                  COALESCE(email_verified, false) AS email_verified,
                  enabled,
                  access_reason,
                  COALESCE(created_at, NOW()::timestamp) AS created_at,
                  email_vouched_by AS vouched_by
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
    let ids: Vec<&str> = accounts.iter().map(|account| account.id.as_str()).collect();
    let identities = sqlx::query_as::<_, LinkedIdentityRow>(&format!(
        "SELECT a.user_id, a.provider_id AS provider, a.account_id AS subject, \
                {LINKED_ACCOUNT_SQL} AS account, \
                COALESCE(a.created_at, NOW()::timestamp) AS linked_at \
           FROM accounts a \
          WHERE a.user_id = ANY($1) AND a.provider_id IN ('github', 'google') \
          ORDER BY a.provider_id, a.created_at"
    ))
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "failed to list linked identities");
        AppError::InternalMsg("Failed to list accounts".into())
    })?;
    // An invited sign-up's audit row names its invitation, never the token.
    let joined = sqlx::query_as::<_, JoinedViaRow>(
        "SELECT a.user_id, i.id AS invitation_id, o.name AS organization, \
                inviter.name AS inviter_name, inviter.email AS inviter_email, \
                a.timestamp AS joined_at \
           FROM audit_logs a \
           JOIN org_invitations i ON i.id = a.metadata ->> 'invitation_id' \
           LEFT JOIN organizations o ON o.id = i.org_id \
           LEFT JOIN users inviter ON inviter.id = i.invited_by \
          WHERE a.user_id = ANY($1) AND a.action = 'user.signup'",
    )
    .bind(&ids)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| {
        tracing::error!(%error, "failed to list how accounts joined");
        AppError::InternalMsg("Failed to list accounts".into())
    })?;
    for identity in identities {
        if let Some(account) = accounts
            .iter_mut()
            .find(|account| account.id == identity.user_id)
        {
            account.linked_identities.push(identity);
        }
    }
    for joined_via in joined {
        if let Some(account) = accounts
            .iter_mut()
            .find(|account| account.id == joined_via.user_id)
        {
            account.joined_via = Some(joined_via);
        }
    }
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
    // With mail an access request is verified first, and enabling sends the
    // ready email. A server with no mail cannot verify anyone, so enabling is
    // the admin vouching for the address (#4121), and nothing is sent.
    let mail = state.email.is_configured();
    if request.enabled && mail && account.access_reason.is_some() && !account.email_verified {
        return Err(AppError::BadRequest(
            "Verify the account email before enabling access".into(),
        ));
    }
    let vouches = request.enabled && !mail && !account.email_verified;

    if account.enabled != request.enabled {
        sqlx::query(
            "UPDATE users SET enabled = $1, updated_at = NOW(), \
             email_vouched_by = CASE WHEN $3 THEN COALESCE(email_vouched_by, 'admin') \
                                     ELSE email_vouched_by END \
             WHERE id = $2",
        )
        .bind(request.enabled)
        .bind(&user_id)
        .bind(vouches)
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
        .bind(json!({ "enabled": request.enabled, "email": &account.email, "vouched": vouches }))
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

    if request.enabled && mail {
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

/// At most one verification link per address in this window, however often an
/// administrator asks; the same window as a sign-in's resend.
const RESEND_VERIFICATION_INTERVAL_SECS: i64 = 5 * 60;

fn account_not_found() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "not_found",
        detail: "Account not found".into(),
    }
}

/// Sends a fresh 24-hour verification link to an account that hasn't
/// verified its email, for an administrator helping someone whose link was
/// lost. Audited with the administrator as the actor.
async fn resend_account_verification(
    State(state): State<AccessAdminState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    actor: AuthUser,
) -> Result<(StatusCode, Json<ResendVerificationResponse>), AppError> {
    actor.require_global_admin()?;
    if user_id == DELETED_USER_ID {
        return Err(account_not_found());
    }
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to resend account verification");
        AppError::InternalMsg("Failed to resend verification".into())
    };
    let (ip, user_agent) = request_info(&headers);
    let mut tx = state.pool.begin().await.map_err(failed)?;
    let (email, email_verified) = sqlx::query_as::<_, (String, bool)>(
        "SELECT email, COALESCE(email_verified, false) FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed)?
    .ok_or_else(account_not_found)?;
    if email_verified {
        return Err(AppError::Conflict(
            "This account's email is already verified".into(),
        ));
    }
    // A link sent in the last few minutes counts as this one, so repeated
    // clicks don't flood the inbox or pile up rows. `created_at` is a
    // timestamp without time zone that create_verification writes from
    // Utc::now(), so it compares exactly with this UTC value; a row written
    // with the column's DEFAULT now() would match only in a UTC session.
    let since = Utc::now().naive_utc() - Duration::seconds(RESEND_VERIFICATION_INTERVAL_SECS);
    let recent: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM verifications WHERE identifier = $1 AND purpose = $2 AND created_at > $3)",
    )
    .bind(&email)
    .bind(VerificationPurpose::EmailVerification.as_str())
    .bind(since)
    .fetch_one(&mut *tx)
    .await
    .map_err(failed)?;
    if recent {
        tx.commit().await.map_err(failed)?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(ResendVerificationResponse { sent: true }),
        ));
    }
    if !state.email.is_configured() {
        return Err(AppError::ServiceUnavailable(
            "Account email is temporarily unavailable".into(),
        ));
    }
    let token = create_verification_in_transaction(
        &mut tx,
        &email,
        VerificationPurpose::EmailVerification,
        Duration::hours(24),
    )
    .await?;
    tx.commit().await.map_err(failed)?;

    let verify_url = format!(
        "{}/verify-email?token={token}",
        state.frontend_url.trim_end_matches('/')
    );
    let delivered = match send_verification_email(&state.email, &email, &verify_url).await {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(%error, target_user_id = %user_id, "failed to send account verification email");
            false
        }
    };
    // Audited after the send, so the entry says whether the email went out.
    sqlx::query(
        r#"INSERT INTO audit_logs
               (id, timestamp, action, user_id, target_user_id, ip_address,
                user_agent, metadata, severity)
           VALUES ($1, NOW(), 'admin.account.verification_resent', $2, $3, $4, $5, $6, 'info')"#,
    )
    .bind(hex_id())
    .bind(&actor.user_id)
    .bind(&user_id)
    .bind(&ip)
    .bind(&user_agent)
    .bind(json!({ "email": &email, "delivered": delivered }))
    .execute(&state.pool)
    .await
    .map_err(failed)?;
    if !delivered {
        return Err(AppError::ServiceUnavailable(
            "The verification email could not be sent. Try again shortly.".into(),
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(ResendVerificationResponse { sent: true }),
    ))
}

pub fn router(pool: PgPool, frontend_url: String, email: EmailClient, auth: AuthState) -> Router {
    Router::new()
        .route("/api/admin/accounts", get(list_accounts))
        .route(
            "/api/admin/accounts/{user_id}/enabled",
            post(set_account_enabled),
        )
        .route(
            "/api/admin/accounts/{user_id}/resend-verification",
            post(resend_account_verification),
        )
        .route_layer(middleware::from_fn_with_state(auth, require_session_auth))
        .with_state(AccessAdminState {
            pool,
            frontend_url,
            email,
        })
}
