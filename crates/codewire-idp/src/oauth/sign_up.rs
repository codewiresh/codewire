//! Completing a provider sign-up (#4062): `POST /api/auth/oauth/signup/pending`
//! reads the `sign_up` row for the dashboard's `/signup/complete` page, and
//! `POST /api/auth/oauth/signup/complete` creates the account with the same
//! reason, invite policy and Turnstile as email sign-up, deleting the row.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::NaiveDateTime;
use codewire_server_core::auth::hash_session_token;
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use super::{OAuthState, Provider, valid_handle};
use crate::auth_session::{
    MAX_ACCESS_REASON_CHARS, SessionResponse, UserResponse, create_session, format_time, hex_id,
    log_audit_in, request_info, session_cookie_string, validate_turnstile,
};
use crate::email_password::send_access_request_received_email;

pub(super) fn router() -> Router<OAuthState> {
    Router::new()
        .route("/api/auth/oauth/signup/pending", post(pending_signup))
        .route("/api/auth/oauth/signup/complete", post(complete_signup))
}

#[derive(Deserialize, JsonSchema)]
struct PendingSignupRequest {
    token: String,
}

#[derive(Deserialize, JsonSchema)]
struct CompleteSignupRequest {
    token: String,
    #[serde(default)]
    invite_code: String,
    #[serde(default)]
    reason: String,
    #[serde(default, rename = "turnstile_token")]
    turnstile_token: String,
}

#[derive(Deserialize)]
struct PendingIdentity {
    subject: String,
    email: String,
    #[serde(default)]
    name: Option<String>,
    /// GitHub login or Google email; rows written before it was kept have none.
    #[serde(default)]
    account: String,
}

#[derive(sqlx::FromRow)]
struct PendingRow {
    provider: String,
    provider_identity: serde_json::Value,
    return_auth_request_id: Option<String>,
    return_to: Option<String>,
}

#[derive(Serialize)]
struct PendingSignupBody {
    provider: &'static str,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_to: Option<String>,
}

#[derive(Serialize)]
struct CompleteSignupBody {
    user: UserResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionResponse>,
    #[serde(rename = "accessPending", skip_serializing_if = "std::ops::Not::not")]
    access_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_to: Option<String>,
}

fn signup_expired() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "oauth_signup_expired",
        detail: "This sign-up has expired. Start again.".into(),
    }
}

fn account_exists() -> AppError {
    AppError::Conflict("An account with this email already exists".into())
}

async fn live_pending_row(pool: &PgPool, token: &str) -> Result<PendingRow, AppError> {
    if !valid_handle(token) {
        return Err(signup_expired());
    }
    sqlx::query_as::<_, PendingRow>(
        r#"
        SELECT provider, provider_identity, return_auth_request_id, return_to
          FROM oauth_states
         WHERE token_hash = $1 AND intent = 'sign_up' AND expires_at > NOW()
        "#,
    )
    .bind(hash_session_token(token))
    .fetch_optional(pool)
    .await?
    .ok_or_else(signup_expired)
}

fn pending_parts(row: &PendingRow) -> Result<(Provider, PendingIdentity), AppError> {
    let provider = Provider::parse(&row.provider).ok_or_else(signup_expired)?;
    let identity: PendingIdentity =
        serde_json::from_value(row.provider_identity.clone()).map_err(|_| signup_expired())?;
    Ok((provider, identity))
}

async fn pending_signup(
    State(state): State<OAuthState>,
    ValidatedJson(request): ValidatedJson<PendingSignupRequest>,
) -> Result<Response, AppError> {
    let row = live_pending_row(&state.session.pool, &request.token).await?;
    let (provider, identity) = pending_parts(&row)?;
    Ok(Json(PendingSignupBody {
        provider: provider.as_str(),
        email: identity.email,
        auth_request_id: row.return_auth_request_id,
        return_to: row.return_to,
    })
    .into_response())
}

async fn complete_signup(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    ValidatedJson(request): ValidatedJson<CompleteSignupRequest>,
) -> Result<Response, AppError> {
    let session = &state.session;
    let row = live_pending_row(&session.pool, &request.token).await?;
    let (provider, identity) = pending_parts(&row)?;

    // The same checks as email sign-up, before the row is used up, so a
    // failed challenge or a missing reason can be corrected on the page.
    validate_turnstile(session, &identity.email, &request.turnstile_token).await?;
    let enabled = session.signup_invite_policy.accepts(&request.invite_code);
    let access_reason = request.reason.trim();
    if !enabled
        && (access_reason.is_empty() || access_reason.chars().count() > MAX_ACCESS_REASON_CHARS)
    {
        return Err(AppError::BadRequest(
            "Tell us why you want to use Codewire".into(),
        ));
    }

    let mut tx = session.pool.begin().await?;
    let claimed: Option<String> = sqlx::query_scalar(
        r#"
        DELETE FROM oauth_states
         WHERE token_hash = $1 AND intent = 'sign_up' AND expires_at > NOW()
        RETURNING id
        "#,
    )
    .bind(hash_session_token(&request.token))
    .fetch_optional(&mut *tx)
    .await?;
    if claimed.is_none() {
        tx.commit().await?;
        return Err(signup_expired());
    }

    let taken: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))
            OR EXISTS (SELECT 1 FROM accounts WHERE provider_id = $2 AND account_id = $3)
        "#,
    )
    .bind(&identity.email)
    .bind(provider.as_str())
    .bind(&identity.subject)
    .fetch_one(&mut *tx)
    .await?;
    if taken {
        // The row stays used: the identity now signs in or links instead.
        tx.commit().await?;
        return Err(account_exists());
    }

    let user_id = hex_id();
    let stored_access_reason = (!enabled).then_some(access_reason);
    // The provider verified the email, so the account starts verified and
    // has no password; `enabled` follows the invite policy.
    let created_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO users
            (id, email, email_verified, name, enabled, access_reason, created_at, updated_at)
        VALUES ($1, $2, true, $3, $4, $5, NOW(), NOW())
        RETURNING created_at
        "#,
    )
    .bind(&user_id)
    .bind(&identity.email)
    .bind(&identity.name)
    .bind(enabled)
    .bind(stored_access_reason)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| conflict_or_internal(error, "failed to create OAuth user"))?;
    sqlx::query(
        r#"
        INSERT INTO accounts (id, user_id, provider_id, account_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        "#,
    )
    .bind(hex_id())
    .bind(&user_id)
    .bind(provider.as_str())
    .bind(&identity.subject)
    .execute(&mut *tx)
    .await
    .map_err(|error| conflict_or_internal(error, "failed to link OAuth identity"))?;

    let (ip, ua) = request_info(&headers);
    log_audit_in(
        &mut tx,
        if enabled {
            "user.signup"
        } else {
            "user.signup.access_requested"
        },
        &user_id,
        &ip,
        &ua,
        json!({
            "email": &identity.email,
            "enabled": enabled,
            "method": provider.as_str(),
            // Settings names the identity from these.
            "provider": provider.as_str(),
            "provider_subject": &identity.subject,
            "provider_account": &identity.account,
        }),
        "info",
    )
    .await?;
    tx.commit().await?;

    let user = UserResponse {
        id: user_id.clone(),
        email: identity.email.clone(),
        email_verified: true,
        name: identity.name.clone(),
        image: None,
        is_admin: false,
        two_factor_enabled: false,
        cli_signed_in: false,
        created_at: format_time(created_at),
    };

    if !enabled {
        if session.email.is_configured()
            && let Err(error) =
                send_access_request_received_email(&session.email, &identity.email).await
        {
            tracing::error!(%error, user_id = %user_id, "failed to send access request receipt");
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(CompleteSignupBody {
                user,
                session: None,
                access_pending: true,
                auth_request_id: row.return_auth_request_id,
                return_to: row.return_to,
            }),
        )
            .into_response());
    }

    let created = create_session(&session.pool, &user_id, &ip, &ua)
        .await
        .map_err(|_| AppError::InternalMsg("Account created but session failed".into()))?;
    let mut response = Json(CompleteSignupBody {
        user,
        session: Some(created.response),
        access_pending: false,
        auth_request_id: row.return_auth_request_id,
        return_to: row.return_to,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie_string(&created.token, session.secure))
            .expect("session cookies are ASCII"),
    );
    Ok(response)
}

/// A unique violation means another sign-up won the email or the identity.
fn conflict_or_internal(error: sqlx::Error, context: &'static str) -> AppError {
    if error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
    {
        return account_exists();
    }
    tracing::error!(%error, "{context}");
    AppError::InternalMsg("Failed to create account".into())
}
