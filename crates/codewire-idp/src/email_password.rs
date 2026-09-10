//! Email verification and password-reset auth handlers.
//!
//! Owns `/api/auth/{verify-email,forget-password,reset-password,
//! send-verification-email}`.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, NaiveDateTime, Utc};
use codewire_email::EmailClient;
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

use crate::auth_session::{hash_password, hex_id, hex_lower, hex_token, validate_password};

#[derive(Clone)]
pub struct EmailPasswordState {
    pool: PgPool,
    frontend_url: String,
    email: EmailClient,
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
    #[serde(rename = "accessPending", skip_serializing_if = "is_false")]
    access_pending: bool,
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

#[derive(Clone, Copy)]
pub(crate) enum VerificationPurpose {
    EmailVerification,
    PasswordReset,
}

impl VerificationPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
        }
    }
}

#[derive(sqlx::FromRow)]
struct EmailUserRow {
    email: String,
    email_verified: Option<bool>,
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
    purpose: VerificationPurpose,
    expires_in: Duration,
) -> Result<String, AppError> {
    let id = hex_id();
    let token = hex_token();
    let token_hash = verification_token_hash(purpose, &token);
    let now = Utc::now().naive_utc();
    let expires_at = now + expires_in;

    sqlx::query(
        r#"INSERT INTO verifications
               (id, identifier, purpose, token_hash, expires_at, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $6)"#,
    )
    .bind(&id)
    .bind(email)
    .bind(purpose.as_str())
    .bind(&token_hash)
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

pub(crate) async fn create_verification_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    email: &str,
    purpose: VerificationPurpose,
    expires_in: Duration,
) -> Result<String, AppError> {
    let id = hex_id();
    let token = hex_token();
    let token_hash = verification_token_hash(purpose, &token);
    let now = Utc::now().naive_utc();
    let expires_at = now + expires_in;

    sqlx::query(
        r#"INSERT INTO verifications
               (id, identifier, purpose, token_hash, expires_at, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $6)"#,
    )
    .bind(&id)
    .bind(email)
    .bind(purpose.as_str())
    .bind(&token_hash)
    .bind(expires_at)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create verification");
        AppError::InternalMsg("Failed to send verification".into())
    })?;

    Ok(token)
}

fn verification_token_hash(purpose: VerificationPurpose, token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codewire/idp/verification/v1\0");
    digest.update(purpose.as_str().as_bytes());
    digest.update(b"\0");
    digest.update(token.as_bytes());
    hex_lower(&digest.finalize())
}

async fn claim_verification(
    tx: &mut Transaction<'_, Postgres>,
    purpose: VerificationPurpose,
    token: &str,
) -> Result<Option<VerificationRow>, sqlx::Error> {
    let token_hash = verification_token_hash(purpose, token);
    sqlx::query_as::<_, VerificationRow>(
        r#"DELETE FROM verifications
           WHERE purpose = $1 AND token_hash = $2
           RETURNING identifier, expires_at"#,
    )
    .bind(purpose.as_str())
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
}

async fn send_password_reset_email(
    email: &EmailClient,
    to: &str,
    reset_url: &str,
) -> anyhow::Result<()> {
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Reset your password</h2>
	<p>We received a request to reset your Codewire password. Click the link below to choose a new one:</p>
	<p><a href="{reset_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;">Reset Password</a></p>
	<p style="color: #666; font-size: 14px;">This link expires in 1 hour. If you didn't request this, you can ignore this email.</p>
</div>"#
    );
    email
        .send_html(to, "Reset your Codewire password", &html)
        .await
}

pub(crate) async fn send_verification_email(
    email: &EmailClient,
    to: &str,
    verify_url: &str,
) -> anyhow::Result<()> {
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Verify your email</h2>
	<p>Please verify your email address by clicking the link below:</p>
	<p><a href="{verify_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;">Verify Email</a></p>
	<p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
</div>"#
    );
    email
        .send_html(to, "Verify your Codewire email", &html)
        .await
}

pub(crate) async fn send_access_request_received_email(
    email: &EmailClient,
    to: &str,
) -> anyhow::Result<()> {
    let html = r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Your Codewire email is verified</h2>
	<p>We received your request for Codewire access. We will email you when your account is enabled.</p>
</div>"#
        .to_owned();
    email
        .send_html(to, "Your Codewire access request is verified", &html)
        .await
}

pub(crate) async fn send_access_enabled_email(
    email: &EmailClient,
    to: &str,
    login_url: &str,
) -> anyhow::Result<()> {
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Your Codewire account is enabled</h2>
	<p>Your access is ready. Sign in to finish setting up your account.</p>
	<p><a href="{login_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 999px;">Sign in to Codewire</a></p>
</div>"#
    );
    email
        .send_html(to, "Your Codewire access is ready", &html)
        .await
}

async fn verify_email(
    State(state): State<EmailPasswordState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Result<Json<VerifyEmailResponse>, AppError> {
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin email verification claim");
        AppError::InternalMsg("Failed to verify email".into())
    })?;
    let row = claim_verification(
        &mut tx,
        VerificationPurpose::EmailVerification,
        &query.token,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to claim email verification");
        AppError::InternalMsg("Failed to verify email".into())
    })?
    .ok_or_else(|| bad_request("Invalid or expired verification token"))?;

    if Utc::now().naive_utc() > row.expires_at {
        tx.commit().await?;
        return Err(bad_request("Verification token has expired"));
    }

    let access_pending: bool = sqlx::query_scalar(
        "UPDATE users SET email_verified = true, updated_at = NOW() WHERE email = $1 \
         RETURNING NOT enabled AND access_reason IS NOT NULL",
    )
    .bind(&row.identifier)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to verify email");
        AppError::InternalMsg("Failed to verify email".into())
    })?
    .ok_or_else(|| bad_request("Invalid or expired verification token"))?;
    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit email verification");
        AppError::InternalMsg("Failed to verify email".into())
    })?;

    if access_pending
        && state.email.is_configured()
        && let Err(error) = send_access_request_received_email(&state.email, &row.identifier).await
    {
        tracing::error!(%error, "failed to send access request receipt");
    }

    Ok(Json(VerifyEmailResponse {
        verified: true,
        access_pending,
    }))
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
        match create_verification(
            &state.pool,
            &req.email,
            VerificationPurpose::PasswordReset,
            Duration::hours(1),
        )
        .await
        {
            Ok(token) => {
                let reset_url = format!("{}/reset-password?token={}", state.frontend_url, token);
                if !state.email.is_configured() {
                    tracing::warn!(email = %req.email, "transactional email delivery is not configured, skipping password reset email");
                } else if let Err(e) =
                    send_password_reset_email(&state.email, &req.email, &reset_url).await
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

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin password reset claim");
        AppError::InternalMsg("Failed to reset password".into())
    })?;
    let row = claim_verification(&mut tx, VerificationPurpose::PasswordReset, &req.token)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to claim password reset");
            AppError::InternalMsg("Failed to reset password".into())
        })?
        .ok_or_else(|| bad_request("Invalid or expired reset token"))?;

    if Utc::now().naive_utc() > row.expires_at {
        tx.commit().await?;
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
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to reset password");
        AppError::InternalMsg("Failed to reset password".into())
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit password reset");
        AppError::InternalMsg("Failed to reset password".into())
    })?;
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

    let token = create_verification(
        &state.pool,
        &row.email,
        VerificationPurpose::EmailVerification,
        Duration::hours(24),
    )
    .await?;
    let verify_url = format!("{}/verify-email?token={}", state.frontend_url, token);
    if !state.email.is_configured() {
        tracing::warn!(email = %row.email, "transactional email delivery is not configured, skipping verification email");
    } else if let Err(e) = send_verification_email(&state.email, &row.email, &verify_url).await {
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

pub fn router(pool: PgPool, frontend_url: String, email: EmailClient, auth: AuthState) -> Router {
    let state = EmailPasswordState {
        pool,
        frontend_url,
        email,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_digests_are_purpose_bound_and_value_blind() {
        let raw = "verification-capability-marker";
        let email = verification_token_hash(VerificationPurpose::EmailVerification, raw);
        let reset = verification_token_hash(VerificationPurpose::PasswordReset, raw);

        assert_ne!(email, reset);
        for digest in [email, reset] {
            assert_eq!(digest.len(), 64);
            assert!(digest.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')));
            assert!(!digest.contains(raw));
        }
    }
}
