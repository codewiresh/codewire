//! Email verification and password-reset auth handlers.
//!
//! Owns `/api/auth/{verify-email,forget-password,reset-password,
//! send-verification-email}`.

use anyhow::{Context, bail};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, NaiveDateTime, Utc};
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::auth_session::{hash_password, hex_id, hex_token, validate_password};

const RESEND_API: &str = "https://api.resend.com/emails";

#[derive(Clone)]
pub struct EmailPasswordState {
    pool: PgPool,
    frontend_url: String,
    resend_api_key: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct VerifyEmailQuery {
    #[serde(default)]
    token: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ForgetPasswordRequest {
    email: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ResetPasswordRequest {
    token: String,
    #[serde(rename = "newPassword")]
    new_password: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct VerifyEmailResponse {
    verified: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ForgetPasswordResponse {
    sent: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ResetPasswordResponse {
    reset: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SendVerificationResponse {
    #[serde(skip_serializing_if = "is_false")]
    sent: bool,
    #[serde(skip_serializing_if = "is_false")]
    already_verified: bool,
}

#[derive(sqlx::FromRow)]
struct VerificationRow {
    identifier: String,
    expires_at: NaiveDateTime,
}

#[derive(sqlx::FromRow)]
struct EmailUserRow {
    email: String,
    email_verified: Option<bool>,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'static str,
    to: Vec<&'a str>,
    subject: &'static str,
    html: String,
}

fn is_false(v: &bool) -> bool {
    !*v
}

fn bad_request(detail: &'static str) -> AppError {
    AppError::BadRequest(detail.into())
}

async fn create_verification(
    pool: &PgPool,
    email: &str,
    expires_in: Duration,
) -> Result<String, AppError> {
    let id = hex_id();
    let token = hex_token();
    let now = Utc::now().naive_utc();
    let expires_at = now + expires_in;

    sqlx::query(
        r#"INSERT INTO verifications (id, identifier, value, expires_at, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $5)"#,
    )
    .bind(&id)
    .bind(email)
    .bind(&token)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create verification");
        AppError::InternalMsg("Failed to send verification".into())
    })?;

    Ok(token)
}

async fn verification_by_token(pool: &PgPool, token: &str) -> Result<VerificationRow, sqlx::Error> {
    sqlx::query_as::<_, VerificationRow>(
        "SELECT identifier, expires_at FROM verifications WHERE value = $1",
    )
    .bind(token)
    .fetch_one(pool)
    .await
}

async fn delete_verification(pool: &PgPool, token: &str) {
    let _ = sqlx::query("DELETE FROM verifications WHERE value = $1")
        .bind(token)
        .execute(pool)
        .await;
}

async fn send_resend_email(
    api_key: &str,
    to: &str,
    subject: &'static str,
    html: String,
) -> anyhow::Result<()> {
    let req = ResendRequest {
        from: "Codewire <ops@example.invalid>",
        to: vec![to],
        subject,
        html,
    };

    let resp = reqwest::Client::new()
        .post(RESEND_API)
        .bearer_auth(api_key)
        .json(&req)
        .send()
        .await
        .context("send email")?;
    let status = resp.status();
    if status.is_client_error() || status.is_server_error() {
        let body = resp.text().await.unwrap_or_default();
        bail!("resend API error {}: {}", status.as_u16(), body);
    }
    Ok(())
}

async fn send_password_reset_email(api_key: &str, to: &str, reset_url: &str) -> anyhow::Result<()> {
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Reset your password</h2>
	<p>We received a request to reset your Codewire password. Click the link below to choose a new one:</p>
	<p><a href="{reset_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;">Reset Password</a></p>
	<p style="color: #666; font-size: 14px;">This link expires in 1 hour. If you didn't request this, you can ignore this email.</p>
</div>"#
    );
    send_resend_email(api_key, to, "Reset your Codewire password", html).await
}

async fn send_verification_email(api_key: &str, to: &str, verify_url: &str) -> anyhow::Result<()> {
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Verify your email</h2>
	<p>Please verify your email address by clicking the link below:</p>
	<p><a href="{verify_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;">Verify Email</a></p>
	<p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
</div>"#
    );
    send_resend_email(api_key, to, "Verify your Codewire email", html).await
}

async fn verify_email(
    State(state): State<EmailPasswordState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Result<Json<VerifyEmailResponse>, AppError> {
    let row = verification_by_token(&state.pool, &query.token)
        .await
        .map_err(|_| bad_request("Invalid or expired verification token"))?;

    if Utc::now().naive_utc() > row.expires_at {
        delete_verification(&state.pool, &query.token).await;
        return Err(bad_request("Verification token has expired"));
    }

    sqlx::query("UPDATE users SET email_verified = true, updated_at = NOW() WHERE email = $1")
        .bind(&row.identifier)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to verify email");
            AppError::InternalMsg("Failed to verify email".into())
        })?;
    delete_verification(&state.pool, &query.token).await;

    Ok(Json(VerifyEmailResponse { verified: true }))
}

async fn forget_password(
    State(state): State<EmailPasswordState>,
    ValidatedJson(req): ValidatedJson<ForgetPasswordRequest>,
) -> Result<Json<ForgetPasswordResponse>, AppError> {
    let exists: Option<String> = match sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            tracing::error!(error = %e, "failed to lookup password reset user");
            None
        }
    };

    if exists.is_some() {
        match create_verification(&state.pool, &req.email, Duration::hours(1)).await {
            Ok(token) => {
                let reset_url = format!("{}/reset-password?token={}", state.frontend_url, token);
                if state.resend_api_key.is_empty() {
                    tracing::warn!(email = %req.email, "RESEND_API_KEY not set, skipping password reset email");
                } else if let Err(e) =
                    send_password_reset_email(&state.resend_api_key, &req.email, &reset_url).await
                {
                    tracing::error!(email = %req.email, error = %e, "failed to send password reset email");
                }
            }
            Err(e) => {
                tracing::error!(email = %req.email, error = %e, "failed to create password reset verification");
            }
        }
    }

    Ok(Json(ForgetPasswordResponse { sent: true }))
}

async fn reset_password(
    State(state): State<EmailPasswordState>,
    ValidatedJson(req): ValidatedJson<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, AppError> {
    if let Err(msg) = validate_password(&req.new_password) {
        return Err(AppError::BadRequest(msg.into()));
    }

    let row = verification_by_token(&state.pool, &req.token)
        .await
        .map_err(|_| bad_request("Invalid or expired reset token"))?;

    if Utc::now().naive_utc() > row.expires_at {
        delete_verification(&state.pool, &req.token).await;
        return Err(bad_request("Reset token has expired"));
    }

    let hash = hash_password(&req.new_password)
        .map_err(|_| AppError::InternalMsg("Failed to reset password".into()))?;
    sqlx::query(
        r#"UPDATE accounts SET password = $1, updated_at = NOW()
           WHERE user_id = (SELECT id FROM users WHERE email = $2) AND provider_id = 'credential'"#,
    )
    .bind(&hash)
    .bind(&row.identifier)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to reset password");
        AppError::InternalMsg("Failed to reset password".into())
    })?;

    delete_verification(&state.pool, &req.token).await;
    Ok(Json(ResetPasswordResponse { reset: true }))
}

async fn send_verification(
    State(state): State<EmailPasswordState>,
    user: AuthUser,
) -> Result<Json<SendVerificationResponse>, AppError> {
    let row = sqlx::query_as::<_, EmailUserRow>(
        "SELECT email, email_verified FROM users WHERE id = $1",
    )
    .bind(&user.user_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, user_id = %user.user_id, "failed to lookup verification user");
        AppError::InternalMsg("Failed to send verification".into())
    })?
    .ok_or(AppError::Coded {
        status: StatusCode::UNAUTHORIZED,
        code: "",
        detail: "Must be logged in".into(),
    })?;

    if row.email_verified.unwrap_or(false) {
        return Ok(Json(SendVerificationResponse {
            sent: false,
            already_verified: true,
        }));
    }

    let token = create_verification(&state.pool, &row.email, Duration::hours(24)).await?;
    let verify_url = format!("{}/verify-email?token={}", state.frontend_url, token);
    if state.resend_api_key.is_empty() {
        tracing::warn!(email = %row.email, "RESEND_API_KEY not set, skipping verification email");
    } else if let Err(e) =
        send_verification_email(&state.resend_api_key, &row.email, &verify_url).await
    {
        tracing::error!(email = %row.email, error = %e, "failed to send verification email");
        return Err(AppError::InternalMsg(
            "Failed to send verification email".into(),
        ));
    }

    Ok(Json(SendVerificationResponse {
        sent: true,
        already_verified: false,
    }))
}

pub fn router(
    pool: PgPool,
    frontend_url: String,
    resend_api_key: String,
    auth: AuthState,
) -> Router {
    let state = EmailPasswordState {
        pool,
        frontend_url,
        resend_api_key,
    };

    let required = Router::new()
        .route("/api/auth/send-verification-email", post(send_verification))
        .route_layer(middleware::from_fn_with_state(auth, require_session_auth));

    Router::new()
        .route("/api/auth/verify-email", get(verify_email))
        .route("/api/auth/forget-password", post(forget_password))
        .route("/api/auth/reset-password", post(reset_password))
        .merge(required)
        .with_state(state)
}
