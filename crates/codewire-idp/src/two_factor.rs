//! TOTP two-factor auth handlers.
//!
//! Owns `/api/auth/two-factor/{enable,verify,disable,validate}`, and through
//! [`replacement`] the fresh-proof replace and recovery-code routes. The
//! encrypted DB columns use the stable AES-256-GCM layout:
//! `base64(nonce(12B) || ciphertext || tag)`, key = sha256(session secret).

use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use chrono::{NaiveDateTime, Utc};
use codewire_server_core::auth::hash_session_token;
use codewire_server_core::auth::{AuthState, AuthUser, require_session_auth, session_cookie};
use codewire_server_core::{AppError, ValidatedJson};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::auth_session::{
    AuthResponse, LOCKOUT_DURATION_SECS, MAX_FAILED_ATTEMPTS, UserAuthRow, account_disabled,
    create_session_in, hex_id, request_info, session_cookie_string, too_many_requests,
    user_response,
};

mod replacement;

#[cfg(test)]
pub(crate) use replacement::notice_previews;
pub(crate) use replacement::{
    Proof, ProofKeys, ProofRequest, account_locked, fresh_proof, malformed, proof_rejected,
    validate_proof_request,
};
pub use replacement::{TwoFactorReplacementBounds, replacement_router};

/// TOTP period in seconds. Steps are `unix_time / TOTP_PERIOD_SECS`.
const TOTP_PERIOD_SECS: u64 = 30;

#[derive(Clone)]
pub struct TwoFactorState {
    pool: PgPool,
    session_secret: String,
    secure: bool,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct CodeRequest {
    code: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ValidateRequest {
    code: String,
    token: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct EnableResponse {
    #[serde(rename = "totpUri")]
    totp_uri: String,
    secret: String,
    #[serde(rename = "backupCodes")]
    backup_codes: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct VerifyResponse {
    enabled: bool,
}

/// An empty JSON object. Requiring a JSON body keeps this state change out of
/// reach of plain cross-origin form posts, as for the other factor endpoints.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SkipSetupRequest {}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SkipSetupResponse {
    skipped: bool,
}

#[derive(sqlx::FromRow)]
struct TwoFactorUser {
    id: String,
    email: String,
    two_factor_enabled: Option<bool>,
}

fn bare_unauthorized(detail: &'static str) -> AppError {
    AppError::Coded {
        status: StatusCode::UNAUTHORIZED,
        code: "",
        detail: detail.into(),
    }
}

fn derive_key(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn encrypt(plaintext: &str, secret: &str) -> Result<String, AppError> {
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        tracing::error!(error = %e, "failed to create 2FA cipher");
        AppError::InternalMsg("Failed to encrypt 2FA data".into())
    })?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|e| {
            tracing::error!(error = ?e, "failed to encrypt 2FA data");
            AppError::InternalMsg("Failed to encrypt 2FA data".into())
        })?;
    out.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

fn decrypt(encrypted: &str, secret: &str) -> Result<String, AppError> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(encrypted)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to decode 2FA ciphertext");
            AppError::InternalMsg("Failed to decrypt 2FA data".into())
        })?;
    if data.len() < 12 {
        return Err(AppError::InternalMsg("Failed to decrypt 2FA data".into()));
    }
    let (nonce, ciphertext) = data.split_at(12);
    let key = derive_key(secret);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        tracing::error!(error = %e, "failed to create 2FA cipher");
        AppError::InternalMsg("Failed to decrypt 2FA data".into())
    })?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| {
            tracing::error!(error = ?e, "failed to decrypt 2FA data");
            AppError::InternalMsg("Failed to decrypt 2FA data".into())
        })?;
    String::from_utf8(plaintext).map_err(|e| {
        tracing::error!(error = %e, "decrypted 2FA data was not UTF-8");
        AppError::InternalMsg("Failed to decrypt 2FA data".into())
    })
}

fn generate_backup_codes(count: usize, length: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let mut bytes = vec![0u8; (length / 2) + 1];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let hex = crate::auth_session::hex_lower(&bytes);
            hex[..length].to_string()
        })
        .collect()
}

fn pquerna_totp_uri(secret: &str, email: &str) -> String {
    let issuer = "Codewire";
    let label = format!(
        "{}:{}",
        urlencoding::encode(issuer),
        urlencoding::encode(email)
    );
    format!(
        "otpauth://totp/{label}?algorithm=SHA1&digits=6&issuer={}&period=30&secret={}",
        urlencoding::encode(issuer),
        urlencoding::encode(secret)
    )
}

fn totp_from_secret(secret: &str, account_name: &str) -> Option<TOTP> {
    let bytes = Secret::Encoded(secret.to_string()).to_bytes().ok()?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("Codewire".to_string()),
        account_name.to_string(),
    )
    .ok()
}

fn unix_time() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

/// The time step a TOTP code belongs to, within the same one-step skew that
/// `check_current` accepts. Every candidate is compared in constant time; the
/// latest matching step wins. Recording it lets a later proof refuse a code
/// that was already accepted.
fn matching_totp_step(code: &str, secret: &str, account_name: &str, time: u64) -> Option<i64> {
    let totp = totp_from_secret(secret, account_name)?;
    let current = time / TOTP_PERIOD_SECS;
    let mut matched = None;
    for step in current.saturating_sub(1)..=current.saturating_add(1) {
        if constant_time_eq(
            totp.generate(step * TOTP_PERIOD_SECS).as_bytes(),
            code.as_bytes(),
        ) {
            matched = Some(step);
        }
    }
    matched.and_then(|step| i64::try_from(step).ok())
}

fn current_totp_step(code: &str, secret: &str, account_name: &str) -> Option<i64> {
    matching_totp_step(code, secret, account_name, unix_time()?)
}

/// Remember the newest accepted step. Callers hold the account lock, then
/// this factor-row lock, matching every other factor mutation.
async fn record_totp_step(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
    step: i64,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE two_factor SET last_totp_step = GREATEST(last_totp_step, $2) WHERE user_id = $1",
    )
    .bind(user_id)
    .bind(step)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn enable(
    State(state): State<TwoFactorState>,
    auth: AuthUser,
) -> Result<Json<EnableResponse>, AppError> {
    let mut tx = state.pool.begin().await?;
    let user: TwoFactorUser = sqlx::query_as(
        r#"
        SELECT id, email, two_factor_enabled
        FROM users WHERE id = $1 AND enabled
        FOR UPDATE
        "#,
    )
    .bind(&auth.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    if user.two_factor_enabled.unwrap_or(false) {
        return Err(AppError::BadRequest("2FA is already enabled".into()));
    }

    let pending: Option<(String, String)> =
        sqlx::query_as("SELECT secret, backup_codes FROM two_factor WHERE user_id = $1")
            .bind(&user.id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((encrypted_secret, encrypted_backup_codes)) = pending {
        let secret = decrypt(&encrypted_secret, &state.session_secret)
            .map_err(|_| AppError::InternalMsg("Failed to decrypt 2FA secret".into()))?;
        let backup_json = decrypt(&encrypted_backup_codes, &state.session_secret)
            .map_err(|_| AppError::InternalMsg("Failed to decrypt backup codes".into()))?;
        let backup_codes = serde_json::from_str(&backup_json)
            .map_err(|_| AppError::InternalMsg("Failed to decrypt backup codes".into()))?;
        tx.commit().await?;
        return Ok(Json(EnableResponse {
            totp_uri: pquerna_totp_uri(&secret, &user.email),
            secret,
            backup_codes,
        }));
    }

    let raw_secret = Secret::generate_secret();
    let secret = raw_secret.to_encoded().to_string();
    let totp_uri = pquerna_totp_uri(&secret, &user.email);
    let backup_codes = generate_backup_codes(10, 10);

    let enc_secret = encrypt(&secret, &state.session_secret)
        .map_err(|_| AppError::InternalMsg("Failed to encrypt 2FA secret".into()))?;
    let backup_json = serde_json::to_string(&backup_codes)
        .map_err(|_| AppError::InternalMsg("Failed to encrypt backup codes".into()))?;
    let enc_backup = encrypt(&backup_json, &state.session_secret)
        .map_err(|_| AppError::InternalMsg("Failed to encrypt backup codes".into()))?;

    sqlx::query(
        r#"
        INSERT INTO two_factor (id, user_id, secret, backup_codes)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(hex_id())
    .bind(&user.id)
    .bind(&enc_secret)
    .bind(&enc_backup)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to store 2FA data");
        AppError::InternalMsg("Failed to store 2FA data".into())
    })?;

    tx.commit().await?;
    Ok(Json(EnableResponse {
        totp_uri,
        secret,
        backup_codes,
    }))
}

async fn verify(
    State(state): State<TwoFactorState>,
    auth: AuthUser,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<CodeRequest>,
) -> Result<Json<VerifyResponse>, AppError> {
    if req.code.is_empty() {
        return Err(AppError::BadRequest("Code is required".into()));
    }
    let mut tx = state.pool.begin().await?;
    let user: TwoFactorUser = sqlx::query_as(
        r#"
        SELECT id, email, two_factor_enabled
        FROM users WHERE id = $1 AND enabled
        FOR UPDATE
        "#,
    )
    .bind(&auth.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::Unauthorized)?;
    let enc_secret: String = sqlx::query_scalar("SELECT secret FROM two_factor WHERE user_id = $1")
        .bind(&user.id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::BadRequest("2FA not set up. Call enable first.".into()))?;
    let secret = decrypt(&enc_secret, &state.session_secret)
        .map_err(|_| AppError::InternalMsg("Failed to decrypt 2FA secret".into()))?;
    let Some(step) = current_totp_step(&req.code, &secret, &user.email) else {
        return Err(AppError::BadRequest("Invalid 2FA code".into()));
    };
    record_totp_step(&mut tx, &user.id, step).await?;

    sqlx::query("UPDATE users SET two_factor_enabled = true, updated_at = NOW() WHERE id = $1")
        .bind(&user.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to enable 2FA");
            AppError::InternalMsg("Failed to enable 2FA".into())
        })?;
    // An enabled factor supersedes any skipped setup; clear it so no later
    // factor change can revive an old session's skip.
    sqlx::query(
        "UPDATE sessions SET two_factor_setup_skipped_at = NULL \
         WHERE user_id = $1 AND two_factor_setup_skipped_at IS NOT NULL",
    )
    .bind(&user.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let (ip, ua) = request_info(&headers);
    crate::auth_session::log_audit(
        &state.pool,
        "user.2fa.enabled",
        &user.id,
        &ip,
        &ua,
        json!(null),
        "info",
    )
    .await;

    Ok(Json(VerifyResponse { enabled: true }))
}

/// Skip two-factor setup for the caller's current browser session only. An
/// account with an enabled factor cannot skip; its sign-in still requires the
/// factor. The next sign-in creates a new session and asks again.
async fn skip_setup(
    State(state): State<TwoFactorState>,
    auth: AuthUser,
    headers: HeaderMap,
    ValidatedJson(SkipSetupRequest {}): ValidatedJson<SkipSetupRequest>,
) -> Result<Json<SkipSetupResponse>, AppError> {
    let token = session_cookie(&headers).ok_or(AppError::Unauthorized)?;
    let skipped: Option<String> = sqlx::query_scalar(
        r#"
        UPDATE sessions AS session
           SET two_factor_setup_skipped_at =
                   COALESCE(session.two_factor_setup_skipped_at, NOW()),
               updated_at = NOW()
          FROM users AS user_account
         WHERE session.token_hash = $1
           AND session.expires_at > NOW()
           AND session.user_id = $2
           AND user_account.id = session.user_id
           AND user_account.enabled
           AND NOT COALESCE(user_account.two_factor_enabled, false)
        RETURNING session.id
        "#,
    )
    .bind(hash_session_token(token))
    .bind(&auth.user_id)
    .fetch_optional(&state.pool)
    .await?;
    if skipped.is_none() {
        let enabled: Option<bool> = sqlx::query_scalar(
            "SELECT COALESCE(two_factor_enabled, false) FROM users WHERE id = $1 AND enabled",
        )
        .bind(&auth.user_id)
        .fetch_optional(&state.pool)
        .await?;
        return Err(match enabled {
            Some(true) => AppError::BadRequest("2FA is already enabled".into()),
            _ => AppError::Unauthorized,
        });
    }

    let (ip, ua) = request_info(&headers);
    crate::auth_session::log_audit(
        &state.pool,
        "user.2fa.setup_skipped",
        &auth.user_id,
        &ip,
        &ua,
        json!(null),
        "info",
    )
    .await;

    Ok(Json(SkipSetupResponse { skipped: true }))
}

async fn disable(_auth: AuthUser) -> Result<StatusCode, AppError> {
    // A browser session alone cannot turn off an enrolled factor. Keep the
    // existing public path fail-closed while replacement uses fresh proof and
    // leaves the current factor active until the new one is verified.
    Err(AppError::Precondition(
        "Direct two-factor disable is unavailable; replace the authenticator instead".into(),
    ))
}

/// Finish a sign-in inside the transaction that consumed its challenge. The
/// account lock is still held, so an account-wide revocation (an authenticator
/// replacement or a disablement) either sees this session and deletes it, or
/// runs first and leaves no challenge to complete. Issuing the session after
/// commit would let it slip in behind such a revocation.
async fn complete_login(
    state: &TwoFactorState,
    headers: &HeaderMap,
    mut tx: Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<Response, AppError> {
    let user: UserAuthRow = sqlx::query_as(
        r#"
        SELECT id, email, email_verified, name, image, is_admin,
               two_factor_enabled, cli_signed_in_at IS NOT NULL AS cli_signed_in,
               enabled, failed_login_attempts, locked_until, created_at
        FROM users WHERE id = $1 AND enabled
        "#,
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(account_disabled)?;
    let (ip, ua) = request_info(headers);
    let created_session = create_session_in(&mut *tx, user_id, &ip, &ua).await?;
    tx.commit().await?;

    let body = AuthResponse {
        user: user_response(user),
        session: created_session.response,
        skip_2fa_setup: false,
    };
    let cookie = session_cookie_string(&created_session.token, state.secure);
    let mut resp = Json(body).into_response();
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

async fn claim_token(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
) -> Result<Option<String>, AppError> {
    let token_hash = hash_session_token(token);
    let user_id = sqlx::query_scalar(
        r#"
        DELETE FROM two_factor_tokens
        WHERE token_hash = $1 AND expires_at > NOW()
        RETURNING user_id
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await?;

    sqlx::query("DELETE FROM two_factor_tokens WHERE expires_at <= NOW()")
        .execute(&mut **tx)
        .await?;
    Ok(user_id)
}

// Find the subject without taking the challenge-row lock. `validate` locks
// that subject before it consumes the one-use challenge, matching account
// disablement's user -> challenge lock order.
async fn token_subject(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
) -> Result<Option<String>, AppError> {
    let token_hash = hash_session_token(token);
    sqlx::query_scalar(
        r#"
        SELECT user_id
        FROM two_factor_tokens
        WHERE token_hash = $1 AND expires_at > NOW()
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::from)
}

async fn record_failed_attempt(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<bool, AppError> {
    let attempts: i32 = sqlx::query_scalar(
        r#"
        UPDATE users
           SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1,
               locked_until = CASE
                   WHEN COALESCE(failed_login_attempts, 0) + 1 >= $2
                   THEN NOW() + ($3::bigint * interval '1 second')
                   ELSE locked_until
               END,
               updated_at = NOW()
         WHERE id = $1
         RETURNING failed_login_attempts
        "#,
    )
    .bind(user_id)
    .bind(MAX_FAILED_ATTEMPTS)
    .bind(LOCKOUT_DURATION_SECS)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| AppError::InternalMsg("Failed to record 2FA attempt".into()))?;
    Ok(attempts >= MAX_FAILED_ATTEMPTS)
}

async fn reset_failed_attempts(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err(AppError::InternalMsg("Failed to complete login".into()));
    }
    Ok(())
}

async fn validate(
    State(state): State<TwoFactorState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<ValidateRequest>,
) -> Result<Response, AppError> {
    if req.token.is_empty() {
        return Err(AppError::BadRequest("Code and token are required".into()));
    }

    let mut tx = state.pool.begin().await?;
    let candidate_user_id = token_subject(&mut tx, &req.token).await?;
    if candidate_user_id.is_none() && req.code.is_empty() {
        tx.commit().await?;
        return Err(AppError::BadRequest("Code and token are required".into()));
    }
    let Some(user_id) = candidate_user_id else {
        tx.commit().await?;
        return Err(bare_unauthorized("Invalid or expired 2FA token"));
    };

    // Take the account lock before the token-row lock in `claim_token`. A
    // disablement takes this same account lock then deletes challenges, so
    // either operation wins cleanly instead of forming a lock cycle.
    let user: Option<(String, Option<NaiveDateTime>, bool)> = sqlx::query_as(
        r#"
        SELECT email, locked_until, enabled
        FROM users
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, locked_until, enabled)) = user else {
        tx.commit().await?;
        return Err(AppError::BadRequest("2FA not enabled".into()));
    };
    if !enabled {
        tx.commit().await?;
        return Err(account_disabled());
    }
    // This must be a fresh statement after the account lock is granted. A
    // joined factor row from the lock-waiting statement can carry an older
    // MVCC snapshot and let concurrent backup-code validation reuse a code.
    // Every intentional factor mutation takes the account lock first, then
    // this factor lock, so the order also remains compatible with disablement.
    let (enc_secret, enc_backup): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT secret, backup_codes FROM two_factor WHERE user_id = $1 FOR UPDATE")
            .bind(&user_id)
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or((None, None));
    let claimed_user_id = claim_token(&mut tx, &req.token).await?;
    if req.code.is_empty() {
        tx.commit().await?;
        return Err(AppError::BadRequest("Code and token are required".into()));
    }
    if claimed_user_id.as_deref() != Some(user_id.as_str()) {
        tx.commit().await?;
        return Err(bare_unauthorized("Invalid or expired 2FA token"));
    }
    let Some(enc_secret) = enc_secret else {
        tx.commit().await?;
        return Err(AppError::BadRequest("2FA not enabled".into()));
    };
    if locked_until.is_some_and(|locked| locked > Utc::now().naive_utc()) {
        tx.commit().await?;
        return Err(too_many_requests(
            "Account is temporarily locked. Please try again later.",
        ));
    }

    let secret = decrypt(&enc_secret, &state.session_secret).ok();
    if let Some(secret) = secret
        && let Some(step) = current_totp_step(&req.code, &secret, &email)
    {
        // Sign-in keeps accepting a code within its window, but a fresh proof
        // for an account change must use a later step than this one.
        record_totp_step(&mut tx, &user_id, step).await?;
        reset_failed_attempts(&mut tx, &user_id).await?;
        return complete_login(&state, &headers, tx, &user_id).await;
    }

    if let Some(enc_backup) = enc_backup
        && let Ok(backup_str) = decrypt(&enc_backup, &state.session_secret)
        && let Ok(mut codes) = serde_json::from_str::<Vec<String>>(&backup_str)
        && let Some(pos) = codes.iter().position(|code| code == &req.code)
    {
        codes.remove(pos);
        let new_backup_json = serde_json::to_string(&codes)
            .map_err(|_| AppError::InternalMsg("Failed to update backup codes".into()))?;
        let new_enc_backup = encrypt(&new_backup_json, &state.session_secret)
            .map_err(|_| AppError::InternalMsg("Failed to update backup codes".into()))?;
        sqlx::query("UPDATE two_factor SET backup_codes = $1 WHERE user_id = $2")
            .bind(new_enc_backup)
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to consume backup code");
                AppError::InternalMsg("Failed to update backup codes".into())
            })?;
        reset_failed_attempts(&mut tx, &user_id).await?;
        return complete_login(&state, &headers, tx, &user_id).await;
    }

    let locked = record_failed_attempt(&mut tx, &user_id).await?;
    tx.commit().await?;
    if locked {
        return Err(too_many_requests(
            "Account is temporarily locked. Please try again later.",
        ));
    }
    Err(bare_unauthorized("Invalid 2FA code or backup code"))
}

pub fn router(pool: PgPool, session_secret: String, secure: bool, auth: AuthState) -> Router {
    let state = TwoFactorState {
        pool,
        session_secret,
        secure,
    };

    let required = Router::new()
        .route("/api/auth/two-factor/enable", post(enable))
        .route("/api/auth/two-factor/verify", post(verify))
        .route("/api/auth/two-factor/skip-setup", post(skip_setup))
        .route("/api/auth/two-factor/disable", post(disable))
        .route_layer(middleware::from_fn_with_state(auth, require_session_auth));

    Router::new()
        .route("/api/auth/two-factor/validate", post(validate))
        .merge(required)
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_roundtrips_and_rejects_wrong_secret() {
        let encrypted = encrypt(r#"["abc123def0"]"#, "session-secret").unwrap();
        assert_ne!(encrypted, r#"["abc123def0"]"#);
        assert_eq!(
            decrypt(&encrypted, "session-secret").unwrap(),
            r#"["abc123def0"]"#
        );
        assert!(decrypt(&encrypted, "wrong").is_err());
    }

    #[test]
    fn decrypts_accepted_aes_gcm_fixture() {
        let encrypted = "AAECAwQFBgcICQoLLYY3dbWpcbc6RZ8ALjZtMW+NPilraGP3sMCB8lK85So=";
        assert_eq!(
            decrypt(encrypted, "go-session-secret").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn backup_codes_match_go_shape() {
        let codes = generate_backup_codes(10, 10);
        assert_eq!(codes.len(), 10);
        assert!(codes.iter().all(|c| c.len() == 10));
        assert!(
            codes
                .iter()
                .all(|c| c.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')))
        );
    }

    #[test]
    fn totp_uri_matches_pquerna_shape() {
        assert_eq!(
            pquerna_totp_uri("JBSWY3DPEHPK3PXP", "a+b@example.com"),
            "otpauth://totp/Codewire:a%2Bb%40example.com?algorithm=SHA1&digits=6&issuer=Codewire&period=30&secret=JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn totp_secret_validates_current_token() {
        let secret = Secret::generate_secret().to_encoded().to_string();
        let totp = totp_from_secret(&secret, "user@example.com").unwrap();
        let code = totp.generate_current().unwrap();
        assert!(current_totp_step(&code, &secret, "user@example.com").is_some());
        let wrong = if code == "000000" { "000001" } else { "000000" };
        assert!(current_totp_step(wrong, &secret, "user@example.com").is_none());
    }

    #[test]
    fn totp_step_is_exact_within_one_step_of_skew() {
        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let totp = totp_from_secret(secret, "user@example.com").unwrap();
        let time = 1_790_000_015;
        let current = (time / TOTP_PERIOD_SECS) as i64;
        for offset in [-1_i64, 0, 1] {
            let step = current + offset;
            let code = totp.generate(step as u64 * TOTP_PERIOD_SECS);
            assert_eq!(
                matching_totp_step(&code, secret, "user@example.com", time),
                Some(step)
            );
        }
        for offset in [-2_i64, 2] {
            let code = totp.generate((current + offset) as u64 * TOTP_PERIOD_SECS);
            let within = [-1_i64, 0, 1]
                .map(|near| totp.generate((current + near) as u64 * TOTP_PERIOD_SECS));
            if !within.contains(&code) {
                assert_eq!(
                    matching_totp_step(&code, secret, "user@example.com", time),
                    None
                );
            }
        }
        assert_eq!(
            matching_totp_step("12345", secret, "user@example.com", time),
            None
        );
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"123457"));
        assert!(!constant_time_eq(b"123456", b"1234567"));
    }
}
