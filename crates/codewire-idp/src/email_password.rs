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
use codewire_email::{Email, EmailClient};
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
use crate::oauth::Provider;

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

/// The password reset email. Every value is raw; the layout escapes it.
pub(crate) fn password_reset_email(reset_url: &str) -> Email {
    Email::new("Reset your Codewire password", "Reset your password")
        .paragraph(
            "We received a request to reset your Codewire password. Click the link below to choose a new one:",
        )
        .button("Reset Password", reset_url)
        .note("This link expires in 1 hour. If you didn't request this, you can ignore this email.")
        .reason(
            "You got this email because someone asked to reset the password for this address on Codewire.",
        )
}

async fn send_password_reset_email(
    email: &EmailClient,
    to: &str,
    reset_url: &str,
) -> anyhow::Result<()> {
    email.send(to, &password_reset_email(reset_url)).await
}

/// The email that verifies a new account's address.
pub(crate) fn verification_email(verify_url: &str) -> Email {
    Email::new("Verify your Codewire email", "Verify your email")
        .paragraph(
            "Someone created a Codewire account with this address. If it was you, verify your email to finish setting it up.",
        )
        .button("Verify email", verify_url)
        .paragraph(
            "If it wasn't you, ignore this email. Nobody can sign in to the account unless this link is opened.",
        )
        .note("This link expires in 24 hours.")
        .reason("You got this email because this address was used to sign up for Codewire.")
}

/// What "Forgot password" sends an account that has no password (#4528): how it
/// signs in, and no link that could set one.
async fn send_provider_sign_in_email(
    email: &EmailClient,
    to: &str,
    providers: &[&'static str],
    login_url: &str,
) -> anyhow::Result<()> {
    email
        .send(to, &provider_sign_in_email(providers, login_url))
        .await
}

fn provider_sign_in_email(providers: &[&'static str], login_url: &str) -> Email {
    let providers = providers.join(" or ");
    Email::new(
        "How you sign in to Codewire",
        "Your Codewire account has no password",
    )
    .paragraph(format!(
        "Someone asked to reset the password for the Codewire account with this address. This account doesn't use a password: you sign in with {providers}."
    ))
    .button("Go to sign in", login_url)
    .note("If this wasn't you, you can ignore this email. Nothing has changed.")
    .reason(
        "You got this email because someone asked to reset the password for this address on Codewire.",
    )
}

pub(crate) async fn send_verification_email(
    email: &EmailClient,
    to: &str,
    verify_url: &str,
) -> anyhow::Result<()> {
    email.send(to, &verification_email(verify_url)).await
}

/// The confirmation that an access request's address is verified.
pub(crate) fn access_request_received_email() -> Email {
    Email::new(
        "Your Codewire access request is verified",
        "Your Codewire email is verified",
    )
    .paragraph(
        "We received your request for Codewire access. We will email you when your account is enabled.",
    )
    .reason("You got this email because this address was used to ask for access to Codewire.")
}

pub(crate) async fn send_access_request_received_email(
    email: &EmailClient,
    to: &str,
) -> anyhow::Result<()> {
    email.send(to, &access_request_received_email()).await
}

const SIGN_IN_METHOD_REASON: &str =
    "You got this email because a sign-in method changed on the Codewire account for this address.";

/// The notice an account's address gets when a provider is linked to it.
pub(crate) fn provider_linked_email(provider: &str, settings_url: &str) -> Email {
    let title = format!("{provider} was linked to your Codewire account");
    Email::new(title.clone(), title)
        .paragraph(format!(
            "Someone signed in to Codewire with a {provider} account that has this verified email address, so it can now be used to sign in to your account. Your two-factor authentication still applies."
        ))
        .paragraph("If this wasn't you, change your password and review your account's sessions.")
        .button("Review your account", settings_url)
        .reason(SIGN_IN_METHOD_REASON)
}

/// The notice an account's address gets when a provider is linked to it.
/// `provider` is a fixed label ("GitHub", "Google"), never provider text.
pub(crate) async fn send_provider_linked_email(
    email: &EmailClient,
    to: &str,
    provider: &'static str,
    settings_url: &str,
) -> anyhow::Result<()> {
    email
        .send(to, &provider_linked_email(provider, settings_url))
        .await
}

/// The notice an account's address gets when its owner connects a provider
/// from Settings.
pub(crate) fn provider_connected_email(provider: &str, account: &str, settings_url: &str) -> Email {
    let title = format!("{provider} was connected to your Codewire account");
    let named = provider_account_phrase(provider, account);
    Email::new(title.clone(), title)
        .paragraph(format!(
            "{named} was connected from your account's Settings and can now be used to sign in to your account. Your two-factor authentication still applies."
        ))
        .paragraph(
            "If this wasn't you, disconnect it, change your password and review your account's sessions.",
        )
        .button("Review sign-in methods", settings_url)
        .reason(SIGN_IN_METHOD_REASON)
}

/// The notice an account's address gets when its owner connects a provider
/// from Settings. `provider` is a fixed label; `account` is the provider
/// account (GitHub login or Google email), escaped by the layout.
pub(crate) async fn send_provider_connected_email(
    email: &EmailClient,
    to: &str,
    provider: &'static str,
    account: &str,
    settings_url: &str,
) -> anyhow::Result<()> {
    email
        .send(
            to,
            &provider_connected_email(provider, account, settings_url),
        )
        .await
}

/// The notice an account's address gets when a provider is disconnected
/// from Settings.
pub(crate) fn provider_disconnected_email(
    provider: &str,
    account: &str,
    settings_url: &str,
) -> Email {
    let title = format!("{provider} was disconnected from your Codewire account");
    let named = provider_account_phrase(provider, account);
    Email::new(title.clone(), title)
        .paragraph(format!(
            "{named} was disconnected from your account's Settings and can no longer be used to sign in to your account."
        ))
        .paragraph("If this wasn't you, change your password and review your account's sessions.")
        .button("Review sign-in methods", settings_url)
        .reason(SIGN_IN_METHOD_REASON)
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
    email
        .send(
            to,
            &provider_disconnected_email(provider, account, settings_url),
        )
        .await
}

/// "The GitHub account octocat", or "A GitHub account" when no account name
/// is known. The name is raw; the layout escapes it.
fn provider_account_phrase(provider: &str, account: &str) -> String {
    if account.is_empty() {
        format!("A {provider} account")
    } else {
        format!("The {provider} account {account}")
    }
}

/// The one-time confirmation that links a provider identity to an existing
/// account. `account` comes from the provider, so it stays out of the
/// subject; the layout escapes it in the body.
pub(crate) fn provider_link_confirmation_email(
    provider: &str,
    account: &str,
    confirm_url: &str,
) -> Email {
    Email::new(
        format!("Connect {provider} to your Codewire account"),
        format!("Connect the {provider} account {account} to your Codewire account?"),
    )
    .paragraph(format!(
        "Someone signed in to Codewire with the {provider} account {account}, which uses this email address. If that was you, open this link in the same browser and confirm, and that {provider} account will be able to sign in to your Codewire account:"
    ))
    .button("Review and connect", confirm_url)
    .note(format!(
        "The link works once, only in the browser where you started signing in, and expires in 30 minutes. Your two-factor authentication still applies when you sign in. If you don't recognize {account}, ignore this email and nothing changes."
    ))
    .reason(
        "You got this email because someone signed in to Codewire with an account that uses this address.",
    )
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
    email
        .send(
            to,
            &provider_link_confirmation_email(provider, account, confirm_url),
        )
        .await
}

/// The notice that an access request was approved.
pub(crate) fn access_enabled_email(login_url: &str) -> Email {
    Email::new(
        "Your Codewire access is ready",
        "Your Codewire account is enabled",
    )
    .paragraph("Your access is ready. Sign in to finish setting up your account.")
    .button("Sign in to Codewire", login_url)
    .reason("You got this email because this address was used to ask for access to Codewire.")
}

pub(crate) async fn send_access_enabled_email(
    email: &EmailClient,
    to: &str,
    login_url: &str,
) -> anyhow::Result<()> {
    email.send(to, &access_enabled_email(login_url)).await
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

    // The mailbox proof replaces a vouch (#4121): a server that adds mail
    // later asks its vouched accounts, the setup admin included, to verify,
    // and the two are never set together.
    let access_pending: bool = sqlx::query_scalar(
        "UPDATE users SET email_verified = true, email_vouched_by = NULL, updated_at = NOW() \
         WHERE email = $1 \
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
    // An account with no password signs in with GitHub or Google only. Its
    // reset link would set nothing (#4528), so it is told how it signs in
    // instead. The answer is the same either way, so it says nothing about
    // the address.
    // Logs name the account by id, never by address.
    let account: Option<(String, bool, Vec<String>)> = match sqlx::query_as(
        r#"SELECT u.id,
                  EXISTS (SELECT 1 FROM accounts a WHERE a.user_id = u.id AND a.provider_id = 'credential'),
                  ARRAY(SELECT a.provider_id FROM accounts a
                         WHERE a.user_id = u.id AND a.provider_id IN ('github', 'google')
                         ORDER BY a.provider_id)
             FROM users u WHERE u.email = $1"#,
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(account) => account,
        Err(e) => {
            tracing::error!(error = %e, "failed to lookup password reset user");
            None
        }
    };
    if let Some((user_id, false, providers)) = &account {
        let labels: Vec<&'static str> = providers
            .iter()
            .filter_map(|provider| Provider::parse(provider))
            .map(Provider::label)
            .collect();
        if labels.is_empty() {
            tracing::warn!(%user_id, "password reset requested for an account with no sign-in method");
        } else if !state.email.is_configured() {
            tracing::warn!(%user_id, "transactional email delivery is not configured, skipping provider sign-in email");
        } else {
            let login_url = format!("{}/login", state.frontend_url.trim_end_matches('/'));
            if let Err(e) =
                send_provider_sign_in_email(&state.email, &req.email, &labels, &login_url).await
            {
                tracing::error!(%user_id, error = %e, "failed to send provider sign-in email");
            }
        }
    }

    if let Some((user_id, true, _)) = &account {
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
                    tracing::warn!(%user_id, "transactional email delivery is not configured, skipping password reset email");
                } else if let Err(e) =
                    send_password_reset_email(&state.email, &req.email, &reset_url).await
                {
                    tracing::error!(%user_id, error = %e, "failed to send password reset email");
                }
            }
            Err(e) => {
                tracing::error!(%user_id, error = %e, "failed to create password reset verification");
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
        // The order is load-bearing: challenges go before sessions. A
        // second-factor completion consumes its challenge and issues its
        // session in one transaction, so either this delete waits for it and
        // the sessions delete below then sees its session, or it finds no
        // challenge left to complete.
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
    // No password to replace: the account signs in with GitHub or Google
    // only, and a reset sets nothing (#4528). The token is spent either way.
    let Some(user_id) = &user_id else {
        return Err(bad_request("Invalid or expired reset token"));
    };
    {
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
        tracing::warn!(user_id = %user.user_id, "transactional email delivery is not configured, skipping verification email");
    } else if let Err(e) = send_verification_email(&state.email, &row.email, &verify_url).await {
        tracing::error!(user_id = %user.user_id, error = %e, "failed to send verification email");
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
            "The GitHub account <octo&cat>"
        );
        assert_eq!(provider_account_phrase("Google", ""), "A Google account");
        for email in [
            provider_connected_email("GitHub", "<octo&cat>", "https://app.example/settings"),
            provider_disconnected_email("GitHub", "<octo&cat>", "https://app.example/settings"),
        ] {
            let html = email.html();
            assert!(html.contains("The GitHub account &lt;octo&amp;cat&gt;"));
            assert!(!html.contains("<octo"));
            assert!(email.text().contains("The GitHub account <octo&cat>"));
        }
    }

    #[test]
    fn link_confirmation_names_and_escapes_the_provider_account() {
        let email = provider_link_confirmation_email(
            "GitHub",
            "octocat<script>",
            "https://app.example/login/link?token=t",
        );
        let html = email.html();
        assert!(html.contains(
            "Connect the GitHub account octocat&lt;script&gt; to your Codewire account?"
        ));
        assert!(html.contains("with the GitHub account octocat&lt;script&gt;, which uses"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("href=\"https://app.example/login/link?token=t\""));
        assert!(!email.subject.contains("octocat"));
        assert!(
            email
                .text()
                .contains("Review and connect: https://app.example/login/link?token=t")
        );
    }

    #[test]
    fn the_verification_email_keeps_the_owner_wording() {
        let text = verification_email("https://app.example/verify-email?token=abc").text();
        for line in [
            "Someone created a Codewire account with this address. If it was you, verify your email to finish setting it up.",
            "Verify email: https://app.example/verify-email?token=abc",
            "If it wasn't you, ignore this email. Nobody can sign in to the account unless this link is opened.",
            "This link expires in 24 hours.",
        ] {
            assert!(text.contains(line), "{line}");
        }
    }

    /// Writes every IdP email, with synthetic values, as `<name>.html` and
    /// `<name>.txt` into `EMAIL_PREVIEW_DIR`, for review. Without the
    /// variable it does nothing.
    #[test]
    #[ignore = "writes email previews"]
    fn write_email_previews() {
        let Some(dir) = std::env::var_os("EMAIL_PREVIEW_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let settings = "https://codewire.sh/settings";
        let invitation = crate::invitation_email::ClaimedEmail {
            invitation_id: "invitation-example".into(),
            recipient: "grace@example.com".into(),
            org_name: "Acme".into(),
            org_slug: "acme".into(),
            inviter: "Ada".into(),
            role: "member".into(),
            expires_at: chrono::NaiveDate::from_ymd_opt(2026, 11, 20)
                .unwrap()
                .and_hms_opt(12, 0, 0)
                .unwrap(),
            attempts: 1,
        };
        let mut emails = vec![
            (
                "idp-password-reset",
                password_reset_email("https://codewire.sh/reset-password?token=EXAMPLE"),
            ),
            (
                "idp-provider-sign-in",
                provider_sign_in_email(&["GitHub"], "https://codewire.sh/login"),
            ),
            (
                "idp-verification",
                verification_email("https://codewire.sh/verify-email?token=EXAMPLE"),
            ),
            (
                "idp-access-request-received",
                access_request_received_email(),
            ),
            (
                "idp-access-enabled",
                access_enabled_email("https://codewire.sh/login"),
            ),
            (
                "idp-provider-linked",
                provider_linked_email("GitHub", settings),
            ),
            (
                "idp-provider-connected",
                provider_connected_email("GitHub", "ada-lovelace", settings),
            ),
            (
                "idp-provider-disconnected",
                provider_disconnected_email("Google", "ada@example.com", settings),
            ),
            (
                "idp-provider-link-confirmation",
                provider_link_confirmation_email(
                    "GitHub",
                    "ada-lovelace",
                    "https://codewire.sh/login/link?token=EXAMPLE",
                ),
            ),
            (
                "idp-organization-invitation",
                crate::invitation_email::invitation_email(
                    &invitation,
                    "https://codewire.sh",
                    Some("https://codewire.sh/accept-invite?token=EXAMPLE"),
                ),
            ),
        ];
        emails.extend(crate::two_factor::notice_previews(
            "https://codewire.sh/forgot-password",
        ));
        for (name, email) in emails {
            std::fs::write(dir.join(format!("{name}.html")), email.html()).unwrap();
            std::fs::write(dir.join(format!("{name}.txt")), email.text()).unwrap();
        }
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
