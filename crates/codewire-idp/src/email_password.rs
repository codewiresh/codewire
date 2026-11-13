//! Email verification and password-reset auth handlers.
//!
//! Owns `/api/auth/{verify-email,forget-password,reset-password,
//! send-verification-email,resend-verification}`.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, NaiveDateTime, Utc};
use codewire_email::EmailClient;
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

use crate::auth_session::{
    hash_password, hex_id, hex_lower, hex_token, log_audit, request_info, validate_password,
};

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
pub(crate) struct ResendVerificationRequest {
    token: String,
}

#[derive(Serialize)]
pub(crate) struct ResendVerificationResponse {
    sent: bool,
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
    /// Lets an account that can't sign in until it verifies its email ask
    /// for a new link. Its identifier is the user id, not the email.
    ResendVerification,
}

impl VerificationPurpose {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
            Self::ResendVerification => "resend_verification",
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
	<p>Someone created a Codewire account with this address. If it was you, verify your email to finish setting it up.</p>
	<p><a href="{verify_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 6px;">Verify email</a></p>
	<p>If it wasn't you, ignore this email. Nobody can sign in to the account unless this link is opened.</p>
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

/// The notice an account's address gets when a provider is linked to it.
/// `provider` is a fixed label ("GitHub", "Google"), never provider text.
pub(crate) async fn send_provider_linked_email(
    email: &EmailClient,
    to: &str,
    provider: &'static str,
    settings_url: &str,
) -> anyhow::Result<()> {
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>{provider} was linked to your Codewire account</h2>
	<p>Someone signed in to Codewire with a {provider} account that has this verified email address, so it can now be used to sign in to your account. Your two-factor authentication still applies.</p>
	<p>If this wasn't you, change your password and review your account's sessions.</p>
	<p><a href="{settings_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 999px;">Review your account</a></p>
</div>"#
    );
    email
        .send_html(
            to,
            &format!("{provider} was linked to your Codewire account"),
            &html,
        )
        .await
}

/// The notice an account's address gets when its owner connects a provider
/// from Settings. `provider` is a fixed label; `account` is the provider
/// account (GitHub login or Google email), escaped here.
pub(crate) async fn send_provider_connected_email(
    email: &EmailClient,
    to: &str,
    provider: &'static str,
    account: &str,
    settings_url: &str,
) -> anyhow::Result<()> {
    let named = provider_account_phrase(provider, account);
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>{provider} was connected to your Codewire account</h2>
	<p>{named} was connected from your account's Settings and can now be used to sign in to your account. Your two-factor authentication still applies.</p>
	<p>If this wasn't you, disconnect it, change your password and review your account's sessions.</p>
	<p><a href="{settings_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 999px;">Review sign-in methods</a></p>
</div>"#
    );
    email
        .send_html(
            to,
            &format!("{provider} was connected to your Codewire account"),
            &html,
        )
        .await
}

/// The notice an account's address gets when a provider is disconnected
/// from Settings.
pub(crate) async fn send_provider_disconnected_email(
    email: &EmailClient,
    to: &str,
    provider: &'static str,
    account: &str,
    settings_url: &str,
) -> anyhow::Result<()> {
    let named = provider_account_phrase(provider, account);
    let html = format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>{provider} was disconnected from your Codewire account</h2>
	<p>{named} was disconnected from your account's Settings and can no longer be used to sign in to your account.</p>
	<p>If this wasn't you, change your password and review your account's sessions.</p>
	<p><a href="{settings_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 999px;">Review sign-in methods</a></p>
</div>"#
    );
    email
        .send_html(
            to,
            &format!("{provider} was disconnected from your Codewire account"),
            &html,
        )
        .await
}

/// "The GitHub account octocat", or "A GitHub account" when no account name
/// is known. The name is escaped.
fn provider_account_phrase(provider: &'static str, account: &str) -> String {
    if account.is_empty() {
        format!("A {provider} account")
    } else {
        format!(
            "The {provider} account <strong>{}</strong>",
            html_text(account)
        )
    }
}

/// Escape text for an HTML email body.
pub(crate) fn html_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The one-time confirmation that links a provider identity to an existing
/// account, sent to that account's own address. `provider` is a fixed label;
/// `account` (a GitHub login or Google email) comes from the provider, so it
/// is escaped and kept out of the subject.
pub(crate) async fn send_provider_link_confirmation_email(
    email: &EmailClient,
    to: &str,
    provider: &'static str,
    account: &str,
    confirm_url: &str,
) -> anyhow::Result<()> {
    let html = provider_link_confirmation_html(provider, account, confirm_url);
    email
        .send_html(
            to,
            &format!("Connect {provider} to your Codewire account"),
            &html,
        )
        .await
}

fn provider_link_confirmation_html(provider: &str, account: &str, confirm_url: &str) -> String {
    let account = html_text(account);
    format!(
        r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>Connect the {provider} account {account} to your Codewire account?</h2>
	<p>Someone signed in to Codewire with the {provider} account <strong>{account}</strong>, which uses this email address. If that was you, open this link in the same browser and confirm, and that {provider} account will be able to sign in to your Codewire account:</p>
	<p><a href="{confirm_url}" style="display: inline-block; padding: 12px 24px; background: #171717; color: #fff; text-decoration: none; border-radius: 999px;">Review and connect</a></p>
	<p style="color: #666; font-size: 14px;">The link works once, only in the browser where you started signing in, and expires in 30 minutes. Your two-factor authentication still applies when you sign in. If you don't recognize {account}, ignore this email and nothing changes.</p>
</div>"#
    )
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
    headers: HeaderMap,
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
    let failed = |e: sqlx::Error| {
        tracing::error!(error = %e, "failed to reset password");
        AppError::InternalMsg("Failed to reset password".into())
    };
    let user_id: Option<String> = sqlx::query_scalar(
        r#"UPDATE accounts SET password = $1, updated_at = NOW()
           WHERE user_id = (SELECT id FROM users WHERE email = $2) AND provider_id = 'credential'
           RETURNING user_id"#,
    )
    .bind(&hash)
    .bind(&row.identifier)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed)?;
    // Whoever reads the address's mail now holds the account, and may be its
    // owner taking it back from whoever chose the old password (#4481). What
    // signing in with the old password minted ends with it: browser sessions,
    // second-factor challenges, and the CLI's and apps' OAuth grants and
    // tokens. API keys are the organization's automation and stay.
    let mut signed_out_sessions = 0;
    if let Some(user_id) = &user_id {
        for statement in [
            "DELETE FROM two_factor_tokens WHERE user_id = $1",
            "DELETE FROM oidc_auth_requests WHERE user_id = $1",
            "DELETE FROM oidc_access_tokens WHERE user_id = $1",
            "DELETE FROM oidc_refresh_tokens WHERE user_id = $1",
            "DELETE FROM oidc_device_authorizations WHERE user_id = $1",
        ] {
            sqlx::query(statement)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(failed)?;
        }
        signed_out_sessions = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(failed)?
            .rows_affected();
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit password reset");
        AppError::InternalMsg("Failed to reset password".into())
    })?;
    if let Some(user_id) = &user_id {
        let (ip, ua) = request_info(&headers);
        log_audit(
            &state.pool,
            "user.password.reset",
            user_id,
            &ip,
            &ua,
            json!({ "signed_out_sessions": signed_out_sessions }),
            "info",
        )
        .await;
    }
    Ok(Json(ResetPasswordResponse { reset: true }))
}

/// At most one verification link per address in this window, however often
/// the account asks.
const RESEND_VERIFICATION_INTERVAL_SECS: i64 = 5 * 60;

/// `POST /api/auth/resend-verification` (public): a new 24-hour verification
/// link for an account that can't sign in until it verifies its email. The
/// token is the single-use one sign-in returned with `email_unverified`, after
/// the password matched, so only the account holder can ask. A link sent in
/// the last five minutes counts as this one.
async fn resend_verification(
    State(state): State<EmailPasswordState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<ResendVerificationRequest>,
) -> Result<(StatusCode, Json<ResendVerificationResponse>), AppError> {
    let failed = |error: sqlx::Error| {
        tracing::error!(%error, "failed to resend a verification");
        AppError::InternalMsg("Failed to send verification".into())
    };
    let mut tx = state.pool.begin().await.map_err(failed)?;
    let claim = claim_verification(&mut tx, VerificationPurpose::ResendVerification, &req.token)
        .await
        .map_err(failed)?
        .filter(|row| Utc::now().naive_utc() <= row.expires_at)
        .ok_or_else(|| bad_request("Invalid or expired resend token"))?;
    let user = sqlx::query_as::<_, (String, bool)>(
        "SELECT email, COALESCE(email_verified, false) FROM users WHERE id = $1 FOR UPDATE",
    )
    .bind(&claim.identifier)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed)?;
    let Some((email, false)) = user else {
        // Deleted, or verified since: there is nothing to send.
        tx.commit().await.map_err(failed)?;
        return Ok((
            StatusCode::OK,
            Json(ResendVerificationResponse { sent: false }),
        ));
    };
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
    let token = create_verification_in_transaction(
        &mut tx,
        &email,
        VerificationPurpose::EmailVerification,
        Duration::hours(24),
    )
    .await?;
    tx.commit().await.map_err(failed)?;
    let (ip, ua) = request_info(&headers);
    log_audit(
        &state.pool,
        "user.verification.resent",
        &claim.identifier,
        &ip,
        &ua,
        json!({ "email": &email }),
        "info",
    )
    .await;
    let verify_url = format!(
        "{}/verify-email?token={token}",
        state.frontend_url.trim_end_matches('/')
    );
    if !state.email.is_configured() {
        tracing::warn!(user_id = %claim.identifier, "transactional email delivery is not configured, skipping resent verification email");
    } else if let Err(error) = send_verification_email(&state.email, &email, &verify_url).await {
        tracing::error!(%error, user_id = %claim.identifier, "failed to send resent verification email");
        return Err(AppError::ServiceUnavailable(
            "Failed to send verification email".into(),
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(ResendVerificationResponse { sent: true }),
    ))
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
        .route("/api/auth/resend-verification", post(resend_verification))
        .route("/api/auth/reset-password", post(reset_password))
        .merge(required)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_and_disconnect_notices_escape_the_provider_account() {
        assert_eq!(
            provider_account_phrase("GitHub", "<octo&cat>"),
            "The GitHub account <strong>&lt;octo&amp;cat&gt;</strong>"
        );
        assert_eq!(provider_account_phrase("Google", ""), "A Google account");
    }

    #[test]
    fn link_confirmation_names_and_escapes_the_provider_account() {
        let html = provider_link_confirmation_html(
            "GitHub",
            "octocat<script>",
            "https://app.example/login/link?token=t",
        );
        assert!(html.contains(
            "Connect the GitHub account octocat&lt;script&gt; to your Codewire account?"
        ));
        assert!(html.contains("<strong>octocat&lt;script&gt;</strong>"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("href=\"https://app.example/login/link?token=t\""));
    }

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
