//! Fresh-proof authenticator replacement and recovery-code regeneration.
//!
//! Owns `POST /api/auth/two-factor/replace/start`,
//! `POST /api/auth/two-factor/replace/confirm` and
//! `POST /api/auth/two-factor/recovery-codes/regenerate`.
//!
//! Every route uses the account-session boundary: the exact frontend Origin,
//! the session cookie only (an `Authorization` header is refused, so API keys,
//! OAuth tokens and bearer sessions never reach a factor change), an
//! `account_id` echo, closed request bodies of at most 2 KiB, a bounded
//! transaction and `no-store` responses.
//!
//! A fresh proof is the password **and** either a code from the enrolled
//! authenticator in a later time step than any already accepted, or an unused
//! recovery code, which it consumes. It locks the account, then the session,
//! then the factor; refuses a locked account; and counts every failure against
//! the lockout that sign-in uses, answering with one generic 422.
//!
//! Each change and its audit row commit together; a best-effort notice is
//! sent only after the commit.
//!
//! Replacement never deactivates the enrolled factor early. `start` stores an
//! encrypted pending secret tied to this browser session and returns it once.
//! `confirm` verifies a code from the new authenticator, then in one
//! transaction swaps the secret and recovery codes in place, removes pending
//! sign-in challenges, deletes every session of the account and issues a new
//! one for this browser. Nothing can read the pending secret again.

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, SecondsFormat, Utc};
use codewire_email::EmailClient;
use codewire_server_core::AppError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use totp_rs::Secret;

use super::{
    constant_time_eq, current_totp_step, decrypt, encrypt, generate_backup_codes, pquerna_totp_uri,
    record_failed_attempt, record_totp_step, reset_failed_attempts,
};
use crate::auth_session::{
    bounded_transaction, cookie_digest, create_session_in, exact_origin, hex_id,
    lock_account_actor, log_audit_in, private, request_info, session_cookie_string, unavailable,
    valid_id, verify_password,
};

const REQUEST_BUDGET: Duration = Duration::from_secs(5);
const BODY_LIMIT_BYTES: usize = 2_048;
const REPLACEMENT_TTL_SECS: i64 = 10 * 60;
const MAX_CONFIRM_ATTEMPTS: i32 = 5;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_PROOF_BYTES: usize = 64;
const TOTP_DIGITS: usize = 6;
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_LENGTH: usize = 10;

#[derive(Clone)]
struct ReplacementState {
    pool: PgPool,
    session_secret: String,
    secure: bool,
    frontend_url: String,
    email: EmailClient,
}

/// The password plus a current authenticator code or an unused recovery code.
/// Deliberately not `Debug`: every field except the account is a secret.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofRequest {
    account_id: String,
    password: String,
    proof: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmRequest {
    account_id: String,
    replacement_id: String,
    code: String,
}

#[derive(Serialize)]
struct StartResponse {
    replacement_id: String,
    totp_uri: String,
    secret: String,
    expires_at: String,
}

#[derive(Serialize)]
struct ConfirmResponse {
    backup_codes: Vec<String>,
    signed_out_sessions: i64,
}

#[derive(Serialize)]
struct RegenerateResponse {
    backup_codes: Vec<String>,
}

/// The routes that change an enrolled factor. They need the frontend origin
/// for the exact-Origin check and the email client for the post-commit notice.
pub fn replacement_router(
    pool: PgPool,
    session_secret: String,
    secure: bool,
    frontend_url: String,
    email: EmailClient,
) -> Router {
    Router::new()
        .route("/api/auth/two-factor/replace/start", post(start))
        .route("/api/auth/two-factor/replace/confirm", post(confirm))
        .route(
            "/api/auth/two-factor/recovery-codes/regenerate",
            post(regenerate),
        )
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .with_state(ReplacementState {
            pool,
            session_secret,
            secure,
            frontend_url,
            email,
        })
}

fn malformed() -> AppError {
    AppError::BadRequest("Invalid two-factor request".into())
}

fn proof_rejected() -> AppError {
    AppError::Coded {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code: "proof_rejected",
        detail: "The password or verification code is incorrect".into(),
    }
}

fn account_locked() -> AppError {
    AppError::Coded {
        status: StatusCode::TOO_MANY_REQUESTS,
        code: "account_locked",
        detail: "Account is temporarily locked. Please try again later.".into(),
    }
}

fn not_enrolled() -> AppError {
    AppError::Coded {
        status: StatusCode::CONFLICT,
        code: "two_factor_not_enabled",
        detail: "Two-factor authentication is not enabled".into(),
    }
}

fn replacement_not_found() -> AppError {
    AppError::Coded {
        status: StatusCode::NOT_FOUND,
        code: "replacement_not_found",
        detail: "No authenticator replacement is in progress".into(),
    }
}

fn replacement_expired() -> AppError {
    AppError::Coded {
        status: StatusCode::GONE,
        code: "replacement_expired",
        detail: "The authenticator replacement ended. Start again.".into(),
    }
}

fn code_rejected() -> AppError {
    AppError::Coded {
        status: StatusCode::UNPROCESSABLE_ENTITY,
        code: "code_rejected",
        detail: "The code does not match the new authenticator".into(),
    }
}

fn valid_replacement_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

enum ProofKind {
    Authenticator(String),
    RecoveryCode(String),
    Unrecognized,
}

/// Accept a code as people type it: spaces and hyphens are ignored and a
/// recovery code is case-insensitive.
fn classify_proof(proof: &str) -> ProofKind {
    let proof = compact(proof);
    if proof.len() == TOTP_DIGITS && proof.bytes().all(|b| b.is_ascii_digit()) {
        ProofKind::Authenticator(proof)
    } else if proof.len() == RECOVERY_CODE_LENGTH && proof.bytes().all(|b| b.is_ascii_hexdigit()) {
        ProofKind::RecoveryCode(proof.to_ascii_lowercase())
    } else {
        ProofKind::Unrecognized
    }
}

fn validate_proof_request(request: &ProofRequest) -> Result<(), AppError> {
    if !valid_id(&request.account_id)
        || request.password.is_empty()
        || request.password.len() > MAX_PASSWORD_BYTES
        || request.proof.trim().is_empty()
        || request.proof.len() > MAX_PROOF_BYTES
    {
        return Err(malformed());
    }
    Ok(())
}

fn rfc3339(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

struct ProvenAccount {
    user_id: String,
    email: String,
    session_id: String,
    used_recovery_code: bool,
}

enum Proof {
    Accepted(ProvenAccount),
    /// The password or second factor was wrong; one failure was recorded.
    Rejected {
        user_id: String,
        now_locked: bool,
    },
    /// The account was already locked; nothing was checked or recorded.
    Locked {
        user_id: String,
    },
}

/// What a prepared transaction means once it commits.
enum Outcome {
    ProofFailed {
        user_id: String,
        operation: &'static str,
        reason: &'static str,
        locked: bool,
    },
    Started {
        user_id: String,
        response: StartResponse,
        replaced_pending: bool,
        used_recovery_code: bool,
    },
    /// A confirmation that recorded an attempt or retired an ended
    /// replacement; the enrolled factor is unchanged.
    ConfirmRefused(AppError),
    Replaced {
        user_id: String,
        email: String,
        backup_codes: Vec<String>,
        signed_out_sessions: i64,
        session_token: String,
    },
    Regenerated {
        user_id: String,
        email: String,
        backup_codes: Vec<String>,
        used_recovery_code: bool,
    },
}

type Prepared = (Transaction<'static, Postgres>, Outcome);

async fn store_recovery_codes(
    tx: &mut Transaction<'_, Postgres>,
    state: &ReplacementState,
    user_id: &str,
    codes: &[String],
) -> Result<(), AppError> {
    let json = serde_json::to_string(codes).map_err(|_| unavailable())?;
    let encrypted = encrypt(&json, &state.session_secret).map_err(|_| unavailable())?;
    let updated = sqlx::query("UPDATE two_factor SET backup_codes = $2 WHERE user_id = $1")
        .bind(user_id)
        .bind(encrypted)
        .execute(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
    if updated.rows_affected() != 1 {
        return Err(unavailable());
    }
    Ok(())
}

/// The shared fresh-proof check. The slow password hash is verified before
/// the transaction so no lock is held during it; the hash is re-read under
/// the locks and must be the one that was verified.
async fn fresh_proof(
    state: &ReplacementState,
    digest: &str,
    request: &ProofRequest,
) -> Result<(Transaction<'static, Postgres>, Proof), AppError> {
    // Unlocked preflight: an anonymous or foreign caller never reaches the
    // password hash. The locked checks below remain the authority.
    let preflight: Option<(String, Option<String>, bool)> = sqlx::query_as(
        "SELECT session.user_id, account.password, \
                COALESCE(owner.locked_until > clock_timestamp()::timestamp, false) \
         FROM sessions AS session \
         JOIN users AS owner ON owner.id = session.user_id \
         LEFT JOIN accounts AS account \
           ON account.user_id = session.user_id AND account.provider_id = 'credential' \
         WHERE session.token_hash = $1 AND session.expires_at > clock_timestamp()",
    )
    .bind(digest)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| unavailable())?;
    let Some((owner, verified_hash, locked_before)) = preflight else {
        return Err(AppError::Unauthorized);
    };
    if owner != request.account_id {
        return Err(AppError::Forbidden);
    }
    // A locked account is refused below without checking anything, so do not
    // spend the password hash on it.
    let password_matches = match verified_hash.clone().filter(|_| !locked_before) {
        Some(hash) => {
            let password = request.password.clone();
            tokio::task::spawn_blocking(move || verify_password(&password, &hash))
                .await
                .unwrap_or(false)
        }
        None => false,
    };

    let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
    bounded_transaction(&mut tx).await?;
    // users FOR UPDATE, then this session FOR UPDATE, then a clock check.
    let (user_id, session) = lock_account_actor(&mut tx, digest, &request.account_id, true).await?;
    let (email, enrolled, locked): (String, bool, bool) = sqlx::query_as(
        "SELECT email, COALESCE(two_factor_enabled, false), \
                COALESCE(locked_until > clock_timestamp()::timestamp, false) \
         FROM users WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if !enrolled {
        return Err(not_enrolled());
    }
    let factor: Option<(Option<String>, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT secret, backup_codes, last_totp_step FROM two_factor WHERE user_id = $1 FOR UPDATE",
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    let Some((Some(encrypted_secret), encrypted_codes, last_step)) = factor else {
        return Err(not_enrolled());
    };
    if locked {
        return Ok((tx, Proof::Locked { user_id }));
    }
    let current_hash: Option<String> = sqlx::query_scalar(
        "SELECT password FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    let password_matches =
        password_matches && current_hash.is_some() && current_hash == verified_hash;

    let secret = decrypt(&encrypted_secret, &state.session_secret).map_err(|_| unavailable())?;
    let mut accepted_step = None;
    let mut remaining_codes = None;
    match classify_proof(&request.proof) {
        ProofKind::Authenticator(code) => {
            accepted_step = current_totp_step(&code, &secret, &email)
                .filter(|step| last_step.is_none_or(|last| *step > last));
        }
        ProofKind::RecoveryCode(code) => {
            let codes = encrypted_codes
                .as_deref()
                .and_then(|codes| decrypt(codes, &state.session_secret).ok())
                .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
                .unwrap_or_default();
            let mut matched = None;
            for (index, candidate) in codes.iter().enumerate() {
                if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
                    matched = Some(index);
                }
            }
            if let Some(index) = matched {
                let mut codes = codes;
                codes.remove(index);
                remaining_codes = Some(codes);
            }
        }
        ProofKind::Unrecognized => {}
    }

    if !password_matches || (accepted_step.is_none() && remaining_codes.is_none()) {
        let now_locked = record_failed_attempt(&mut tx, &user_id).await?;
        return Ok((
            tx,
            Proof::Rejected {
                user_id,
                now_locked,
            },
        ));
    }
    if let Some(step) = accepted_step {
        record_totp_step(&mut tx, &user_id, step).await?;
    }
    if let Some(codes) = &remaining_codes {
        store_recovery_codes(&mut tx, state, &user_id, codes).await?;
    }
    reset_failed_attempts(&mut tx, &user_id).await?;
    Ok((
        tx,
        Proof::Accepted(ProvenAccount {
            user_id,
            email,
            session_id: session.id,
            used_recovery_code: remaining_codes.is_some(),
        }),
    ))
}

fn proof_failure(proof: Proof, operation: &'static str) -> Outcome {
    match proof {
        Proof::Rejected {
            user_id,
            now_locked,
        } => Outcome::ProofFailed {
            user_id,
            operation,
            reason: "rejected",
            locked: now_locked,
        },
        Proof::Locked { user_id } => Outcome::ProofFailed {
            user_id,
            operation,
            reason: "locked",
            locked: true,
        },
        Proof::Accepted(_) => unreachable!("accepted proofs are handled by the caller"),
    }
}

async fn prepare_start(
    state: &ReplacementState,
    headers: &HeaderMap,
    request: Result<Json<ProofRequest>, JsonRejection>,
) -> Result<Prepared, AppError> {
    exact_origin(headers, &state.frontend_url)?;
    let digest = cookie_digest(headers)?;
    let Json(request) = request.map_err(|_| malformed())?;
    validate_proof_request(&request)?;
    let (mut tx, proof) = fresh_proof(state, &digest, &request).await?;
    let account = match proof {
        Proof::Accepted(account) => account,
        failure => return Ok((tx, proof_failure(failure, "replace"))),
    };

    let secret = Secret::generate_secret().to_encoded().to_string();
    let encrypted = encrypt(&secret, &state.session_secret).map_err(|_| unavailable())?;
    // A newer start replaces any older pending replacement for the account.
    let replaced: Option<String> =
        sqlx::query_scalar("DELETE FROM two_factor_replacements WHERE user_id = $1 RETURNING id")
            .bind(&account.user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
    let id = hex_id();
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO two_factor_replacements (id, user_id, session_id, secret, created_at, expires_at) \
         SELECT $1, $2, $3, $4, now.at, now.at + ($5::bigint * interval '1 second') \
         FROM (SELECT clock_timestamp() AS at) AS now \
         RETURNING expires_at",
    )
    .bind(&id)
    .bind(&account.user_id)
    .bind(&account.session_id)
    .bind(&encrypted)
    .bind(REPLACEMENT_TTL_SECS)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    Ok((
        tx,
        Outcome::Started {
            response: StartResponse {
                replacement_id: id,
                totp_uri: pquerna_totp_uri(&secret, &account.email),
                secret,
                expires_at: rfc3339(expires_at),
            },
            user_id: account.user_id,
            replaced_pending: replaced.is_some(),
            used_recovery_code: account.used_recovery_code,
        },
    ))
}

async fn prepare_confirm(
    state: &ReplacementState,
    headers: &HeaderMap,
    request: Result<Json<ConfirmRequest>, JsonRejection>,
) -> Result<Prepared, AppError> {
    exact_origin(headers, &state.frontend_url)?;
    let digest = cookie_digest(headers)?;
    let Json(request) = request.map_err(|_| malformed())?;
    let code = compact(&request.code);
    if !valid_id(&request.account_id)
        || !valid_replacement_id(&request.replacement_id)
        || code.len() != TOTP_DIGITS
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(malformed());
    }

    let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
    bounded_transaction(&mut tx).await?;
    let (user_id, session) =
        lock_account_actor(&mut tx, &digest, &request.account_id, true).await?;
    let (email, enrolled): (String, bool) = sqlx::query_as(
        "SELECT email, COALESCE(two_factor_enabled, false) FROM users WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if !enrolled {
        return Err(not_enrolled());
    }
    let factor: Option<String> = sqlx::query_scalar(
        "SELECT id FROM two_factor WHERE user_id = $1 AND secret IS NOT NULL FOR UPDATE",
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if factor.is_none() {
        return Err(not_enrolled());
    }
    let pending: Option<(String, String, String, i32)> = sqlx::query_as(
        "SELECT id, session_id, secret, attempts \
         FROM two_factor_replacements WHERE user_id = $1 FOR UPDATE",
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    let Some((pending_id, owner_session, pending_secret, attempts)) = pending else {
        return Err(replacement_not_found());
    };
    // Judge expiry with wall-clock time after the row lock is held, not with a
    // value computed before a lock wait.
    let live: bool = sqlx::query_scalar(
        "SELECT expires_at > clock_timestamp() FROM two_factor_replacements WHERE user_id = $1",
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    // Only the exact replacement, from the browser session that proved the
    // account, can be confirmed. Anything else is indistinguishable from none.
    if !constant_time_eq(pending_id.as_bytes(), request.replacement_id.as_bytes())
        || owner_session != session.id
    {
        return Err(replacement_not_found());
    }
    if !live {
        retire_replacement(&mut tx, &user_id).await?;
        return Ok((tx, Outcome::ConfirmRefused(replacement_expired())));
    }
    let secret = decrypt(&pending_secret, &state.session_secret).map_err(|_| unavailable())?;
    let Some(step) = current_totp_step(&code, &secret, &email) else {
        if attempts + 1 >= MAX_CONFIRM_ATTEMPTS {
            retire_replacement(&mut tx, &user_id).await?;
            return Ok((tx, Outcome::ConfirmRefused(replacement_expired())));
        }
        sqlx::query(
            "UPDATE two_factor_replacements SET attempts = attempts + 1 WHERE user_id = $1",
        )
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
        return Ok((tx, Outcome::ConfirmRefused(code_rejected())));
    };

    // The new factor verified: swap it in place. The pending ciphertext is
    // already in the stored layout and moves across unchanged.
    let backup_codes = generate_backup_codes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH);
    let codes_json = serde_json::to_string(&backup_codes).map_err(|_| unavailable())?;
    let encrypted_codes = encrypt(&codes_json, &state.session_secret).map_err(|_| unavailable())?;
    let swapped = sqlx::query(
        "UPDATE two_factor SET secret = $2, backup_codes = $3, last_totp_step = $4 WHERE user_id = $1",
    )
    .bind(&user_id)
    .bind(&pending_secret)
    .bind(&encrypted_codes)
    .bind(step)
    .execute(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if swapped.rows_affected() != 1 {
        return Err(unavailable());
    }
    retire_replacement(&mut tx, &user_id).await?;
    sqlx::query("DELETE FROM two_factor_tokens WHERE user_id = $1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| unavailable())?;
    let revoked: Vec<String> =
        sqlx::query_scalar("DELETE FROM sessions WHERE user_id = $1 RETURNING id")
            .bind(&user_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
    let signed_out_sessions = revoked.iter().filter(|id| **id != session.id).count() as i64;
    let (ip, ua) = request_info(headers);
    let created = create_session_in(&mut *tx, &user_id, &ip, &ua)
        .await
        .map_err(|_| unavailable())?;
    Ok((
        tx,
        Outcome::Replaced {
            user_id,
            email,
            backup_codes,
            signed_out_sessions,
            session_token: created.token,
        },
    ))
}

async fn retire_replacement(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM two_factor_replacements WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(|_| unavailable())?;
    Ok(())
}

async fn prepare_regenerate(
    state: &ReplacementState,
    headers: &HeaderMap,
    request: Result<Json<ProofRequest>, JsonRejection>,
) -> Result<Prepared, AppError> {
    exact_origin(headers, &state.frontend_url)?;
    let digest = cookie_digest(headers)?;
    let Json(request) = request.map_err(|_| malformed())?;
    validate_proof_request(&request)?;
    let (mut tx, proof) = fresh_proof(state, &digest, &request).await?;
    let account = match proof {
        Proof::Accepted(account) => account,
        failure => return Ok((tx, proof_failure(failure, "regenerate"))),
    };
    let backup_codes = generate_backup_codes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH);
    store_recovery_codes(&mut tx, state, &account.user_id, &backup_codes).await?;
    Ok((
        tx,
        Outcome::Regenerated {
            user_id: account.user_id,
            email: account.email,
            backup_codes,
            used_recovery_code: account.used_recovery_code,
        },
    ))
}

async fn start(
    State(state): State<ReplacementState>,
    headers: HeaderMap,
    request: Result<Json<ProofRequest>, JsonRejection>,
) -> Response {
    let prepared = tokio::time::timeout(REQUEST_BUDGET, prepare_start(&state, &headers, request));
    finish(&state, &headers, prepared.await).await
}

async fn confirm(
    State(state): State<ReplacementState>,
    headers: HeaderMap,
    request: Result<Json<ConfirmRequest>, JsonRejection>,
) -> Response {
    let prepared = tokio::time::timeout(REQUEST_BUDGET, prepare_confirm(&state, &headers, request));
    finish(&state, &headers, prepared.await).await
}

async fn regenerate(
    State(state): State<ReplacementState>,
    headers: HeaderMap,
    request: Result<Json<ProofRequest>, JsonRejection>,
) -> Response {
    let prepared = tokio::time::timeout(
        REQUEST_BUDGET,
        prepare_regenerate(&state, &headers, request),
    );
    finish(&state, &headers, prepared.await).await
}

/// The audit event a prepared outcome records. It carries no secret, code,
/// URI or password, and is written in the same transaction as the change.
fn audit_event(outcome: &Outcome) -> Option<(&str, &'static str, serde_json::Value, &'static str)> {
    match outcome {
        Outcome::ProofFailed {
            user_id,
            operation,
            reason,
            locked,
        } => Some((
            user_id,
            "user.2fa.proof_failed",
            json!({ "operation": operation, "reason": reason, "locked": locked }),
            "warn",
        )),
        Outcome::Started {
            user_id,
            replaced_pending,
            used_recovery_code,
            ..
        } => Some((
            user_id,
            "user.2fa.replace_started",
            json!({
                "replaced_pending": replaced_pending,
                "proof": proof_label(*used_recovery_code),
            }),
            "info",
        )),
        Outcome::ConfirmRefused(_) => None,
        Outcome::Replaced {
            user_id,
            signed_out_sessions,
            ..
        } => Some((
            user_id,
            "user.2fa.replaced",
            json!({ "signed_out_sessions": signed_out_sessions }),
            "info",
        )),
        Outcome::Regenerated {
            user_id,
            used_recovery_code,
            ..
        } => Some((
            user_id,
            "user.2fa.recovery_codes_regenerated",
            json!({ "proof": proof_label(*used_recovery_code) }),
            "info",
        )),
    }
}

fn notice(outcome: &Outcome) -> Option<(String, String, Notice)> {
    match outcome {
        Outcome::Replaced { user_id, email, .. } => {
            Some((user_id.clone(), email.clone(), Notice::Replaced))
        }
        Outcome::Regenerated { user_id, email, .. } => {
            Some((user_id.clone(), email.clone(), Notice::Regenerated))
        }
        _ => None,
    }
}

/// Write the audit row into the prepared transaction, then commit outside the
/// request budget: once every check has passed, a late timeout must not leave
/// a committed swap that the caller believes failed. The commit and the
/// post-commit notice run in their own task, so a client that disconnects
/// cannot cancel either one part-way.
async fn finish(
    state: &ReplacementState,
    headers: &HeaderMap,
    prepared: Result<Result<Prepared, AppError>, tokio::time::error::Elapsed>,
) -> Response {
    let (mut tx, outcome) = match prepared {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => return private(error),
        Err(_) => return private(unavailable()),
    };
    if let Some((user_id, action, metadata, severity)) = audit_event(&outcome) {
        let (ip, ua) = request_info(headers);
        if log_audit_in(&mut tx, action, user_id, &ip, &ua, metadata, severity)
            .await
            .is_err()
        {
            return private(unavailable());
        }
    }
    let notice = notice(&outcome);
    let task_state = state.clone();
    let committed = tokio::spawn(async move {
        let committed = tx.commit().await.is_ok();
        if committed && let Some((user_id, to, notice)) = notice {
            notify(&task_state, &user_id, to, notice);
        }
        committed
    })
    .await
    .unwrap_or(false);
    if !committed {
        return private(unavailable());
    }
    match outcome {
        Outcome::ProofFailed { locked, .. } => private(if locked {
            account_locked()
        } else {
            proof_rejected()
        }),
        Outcome::Started { response, .. } => private(Json(response)),
        Outcome::ConfirmRefused(error) => private(error),
        Outcome::Replaced {
            backup_codes,
            signed_out_sessions,
            session_token,
            ..
        } => {
            let mut response = private(Json(ConfirmResponse {
                backup_codes,
                signed_out_sessions,
            }));
            match HeaderValue::from_str(&session_cookie_string(&session_token, state.secure)) {
                Ok(cookie) => {
                    response.headers_mut().insert(header::SET_COOKIE, cookie);
                }
                Err(_) => return private(unavailable()),
            }
            response
        }
        Outcome::Regenerated { backup_codes, .. } => {
            private(Json(RegenerateResponse { backup_codes }))
        }
    }
}

fn proof_label(used_recovery_code: bool) -> &'static str {
    if used_recovery_code {
        "recovery_code"
    } else {
        "authenticator"
    }
}

#[derive(Clone, Copy)]
enum Notice {
    Replaced,
    Regenerated,
}

impl Notice {
    fn subject(self) -> &'static str {
        match self {
            Self::Replaced => "Your Codewire authenticator was replaced",
            Self::Regenerated => "New Codewire recovery codes were created",
        }
    }

    fn html(self, reset_url: &str) -> String {
        let (heading, body) = match self {
            Self::Replaced => (
                "Your authenticator was replaced",
                "The authenticator app for your Codewire account was replaced and new recovery codes were created. Your old authenticator and recovery codes no longer work, and your other browsers were signed out.",
            ),
            Self::Regenerated => (
                "New recovery codes were created",
                "New recovery codes were created for your Codewire account. Your previous recovery codes no longer work. Your authenticator app still works.",
            ),
        };
        format!(
            r#"<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
	<h2>{heading}</h2>
	<p>{body}</p>
	<p>If you didn't do this, <a href="{reset_url}">reset your password</a> now and contact support.</p>
</div>"#
        )
    }
}

/// Best-effort notice after commit. It runs in the background so a slow mail
/// provider can never turn a committed change into an apparent failure, and it
/// contains no code, secret or link that grants access.
fn notify(state: &ReplacementState, user_id: &str, to: String, notice: Notice) {
    if !state.email.is_configured() {
        return;
    }
    let email = state.email.clone();
    let user_id = user_id.to_owned();
    let reset_url = format!(
        "{}/forgot-password",
        state.frontend_url.trim_end_matches('/')
    );
    tokio::spawn(async move {
        if let Err(error) = email
            .send_html(&to, notice.subject(), &notice.html(&reset_url))
            .await
        {
            tracing::warn!(%error, user_id = %user_id, "failed to send two-factor change notice");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn app() -> Router {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://synthetic:synthetic@127.0.0.1:9/synthetic")
            .unwrap();
        // Closing the lazy pool makes storage failure deterministic without
        // networking.
        pool.close().await;
        replacement_router(
            pool,
            "synthetic-session-secret".into(),
            true,
            "https://app.codewire.test".into(),
            EmailClient::disabled(),
        )
    }

    async fn send(
        app: &Router,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        use tower::ServiceExt;
        let mut builder = axum::http::Request::builder().method("POST").uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = app
            .clone()
            .oneshot(
                builder
                    .body(axum::body::Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
    }

    const PATHS: [&str; 3] = [
        "/api/auth/two-factor/replace/start",
        "/api/auth/two-factor/replace/confirm",
        "/api/auth/two-factor/recovery-codes/regenerate",
    ];

    fn body_for(path: &str) -> &'static str {
        if path.ends_with("/confirm") {
            r#"{"account_id":"owner","replacement_id":"0123456789abcdef0123456789abcdef","code":"123456"}"#
        } else {
            r#"{"account_id":"owner","password":"synthetic-password","proof":"123456"}"#
        }
    }

    #[tokio::test]
    async fn every_route_requires_exact_origin_and_cookie_only_before_any_database_work() {
        // The lazy pool points at a closed port: reaching the database would
        // answer 503, so 403/401 prove the boundary is checked first.
        let app = app().await;
        for path in PATHS {
            let body = body_for(path);
            let cookie = ("cookie", "codewire.session_token=synthetic-cookie-canary");
            let json = ("content-type", "application/json");
            let origin = ("origin", "https://app.codewire.test");
            for (headers, expected) in [
                (vec![cookie, json], StatusCode::FORBIDDEN),
                (
                    vec![cookie, json, ("origin", "https://evil.codewire.test")],
                    StatusCode::FORBIDDEN,
                ),
                (
                    vec![
                        cookie,
                        json,
                        origin,
                        ("origin", "https://app.codewire.test"),
                    ],
                    StatusCode::FORBIDDEN,
                ),
                (vec![json, origin], StatusCode::UNAUTHORIZED),
                (
                    vec![
                        json,
                        origin,
                        ("authorization", "Bearer cw_synthetic_api_key"),
                    ],
                    StatusCode::UNAUTHORIZED,
                ),
                (
                    vec![
                        cookie,
                        json,
                        origin,
                        ("authorization", "Bearer synthetic-session"),
                    ],
                    StatusCode::UNAUTHORIZED,
                ),
            ] {
                let (status, response_headers, text) = send(&app, path, &headers, body).await;
                assert_eq!(status, expected, "{path} {headers:?}");
                assert_eq!(response_headers[header::CACHE_CONTROL], "no-store");
                assert!(!response_headers.contains_key(header::SET_COOKIE));
                assert!(!text.contains("synthetic-cookie-canary"));
            }
        }
    }

    #[tokio::test]
    async fn closed_bounded_bodies_and_unreachable_storage_are_private_failures() {
        let app = app().await;
        let headers = [
            ("cookie", "codewire.session_token=synthetic-cookie-canary"),
            ("content-type", "application/json"),
            ("origin", "https://app.codewire.test"),
        ];
        for path in PATHS {
            for body in [
                // Unknown fields are rejected, including smuggled secrets.
                body_for(path).replace('}', r#","secret":"JBSWY3DPEHPK3PXP"}"#),
                "{}".to_owned(),
                "not json".to_owned(),
                format!(
                    r#"{{"account_id":"owner","password":"{}","proof":"123456"}}"#,
                    "p".repeat(2_100)
                ),
            ] {
                let (status, response_headers, text) = send(&app, path, &headers, &body).await;
                assert!(
                    matches!(
                        status,
                        StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE
                    ),
                    "{path} {status} {body}"
                );
                assert_eq!(response_headers[header::CACHE_CONTROL], "no-store");
                assert!(!text.contains("JBSWY3DPEHPK3PXP"));
            }
            // A well-formed request that reaches storage fails closed, privately.
            let (status, response_headers, text) = send(&app, path, &headers, body_for(path)).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
            assert_eq!(response_headers[header::CACHE_CONTROL], "no-store");
            assert!(!response_headers.contains_key(header::SET_COOKIE));
            for forbidden in ["postgres://", "synthetic-password", "PoolTimedOut"] {
                assert!(!text.contains(forbidden), "{path}: {text}");
            }
        }
    }

    #[test]
    fn proofs_are_classified_without_guessing() {
        assert!(
            matches!(classify_proof(" 123 456 "), ProofKind::Authenticator(code) if code == "123456")
        );
        assert!(
            matches!(classify_proof("ABCDEF0123"), ProofKind::RecoveryCode(code) if code == "abcdef0123")
        );
        assert!(
            matches!(classify_proof("abcde-f0123"), ProofKind::RecoveryCode(code) if code == "abcdef0123")
        );
        assert!(matches!(classify_proof("1234567"), ProofKind::Unrecognized));
        assert!(matches!(classify_proof("12345a"), ProofKind::Unrecognized));
        assert!(matches!(
            classify_proof("ghijklmnop"),
            ProofKind::Unrecognized
        ));
        assert!(valid_replacement_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_replacement_id("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!valid_replacement_id("0123456789abcdef"));
    }

    #[test]
    fn notices_carry_no_codes_or_secrets() {
        for notice in [Notice::Replaced, Notice::Regenerated] {
            let html = notice.html("https://app.codewire.test/forgot-password");
            assert!(html.contains("https://app.codewire.test/forgot-password"));
            assert!(!html.contains("otpauth://"));
            assert!(!notice.subject().is_empty());
        }
    }
}
