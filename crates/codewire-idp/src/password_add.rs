//! Adding a password to an account that signs in only with GitHub or Google
//! (#4528; owner, 2026-11-13: "they should be able to add a password if they
//! want to"). It owns `POST /api/auth/password/add`.
//!
//! The route uses the account controls' boundary: the exact frontend Origin,
//! the session cookie only (an `Authorization` header is refused, so API keys
//! and OAuth tokens never reach it), an `account_id` echo, a closed body of at
//! most 2 KiB, a bounded transaction and `no-store` answers.
//!
//! An emailed reset link proves only that someone reads the mailbox, so it
//! never adds a password (#4549). Adding one needs the account itself: a
//! verified address, a browser session that signed in at most 10 minutes ago,
//! and, when a second factor is enrolled, a fresh code from it. The password
//! row and its audit entry commit together, and the account's address gets a
//! notice afterwards.

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use codewire_email::{Email, EmailClient};
use codewire_server_core::AppError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;

use crate::auth_session::{
    STATEMENT_CEILING, bounded_transaction_within, cookie_digest, exact_origin, hash_password,
    hex_id, lock_account_actor, log_audit_in, private, request_info, unavailable, valid_id,
    validate_password,
};
use crate::oauth::Provider;
use crate::two_factor::code;
use crate::two_factor::{record_failed_attempt, reset_failed_attempts};

const BODY_LIMIT_BYTES: usize = 2_048;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_CODE_BYTES: usize = 64;
/// How recently this browser session must have signed in.
const RECENT_SIGN_IN_SECS: i64 = 10 * 60;

/// The route's time bounds. Production uses the default: 5 s per request and
/// the shared 4 s statement ceiling. A test whose subject is neither adds
/// longer ones as a router `Extension`, as the other account controls do
/// (#3311). A client cannot set a request extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordAddBounds {
    pub request: Duration,
    pub statement: Duration,
}

impl Default for PasswordAddBounds {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(5),
            statement: STATEMENT_CEILING,
        }
    }
}

#[derive(Clone)]
struct PasswordAddState {
    pool: PgPool,
    session_secret: String,
    frontend_url: String,
    email: EmailClient,
}

/// Deliberately not `Debug`: the password and the code are secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddRequest {
    account_id: String,
    new_password: String,
    #[serde(default)]
    code: String,
}

#[derive(Serialize)]
struct AddResponse {
    added: bool,
}

pub fn password_add_router(
    pool: PgPool,
    session_secret: String,
    frontend_url: String,
    email: EmailClient,
) -> Router {
    Router::new()
        .route("/api/auth/password/add", post(add))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .with_state(PasswordAddState {
            pool,
            session_secret,
            frontend_url,
            email,
        })
}

fn malformed() -> AppError {
    AppError::BadRequest("Invalid password request".into())
}

fn refused(status: StatusCode, code: &'static str, detail: &'static str) -> AppError {
    AppError::Coded {
        status,
        code,
        detail: detail.into(),
    }
}

fn locked_refusal() -> AppError {
    refused(
        StatusCode::TOO_MANY_REQUESTS,
        "account_locked",
        "Too many attempts. Try again later.",
    )
}

fn unverified_refusal() -> AppError {
    refused(
        StatusCode::FORBIDDEN,
        "email_unverified",
        "Verify your email address first.",
    )
}

fn exists_refusal() -> AppError {
    refused(
        StatusCode::CONFLICT,
        "password_exists",
        "This account already has a password.",
    )
}

fn reauthentication_refusal() -> AppError {
    refused(
        StatusCode::FORBIDDEN,
        "reauthentication_required",
        "Sign in again before adding a password.",
    )
}

/// Unlocked preflight: an anonymous or foreign caller, and an account that
/// would be refused anyway, never reaches the password hash. The locked
/// checks in [`prepare`] remain the authority.
async fn preflight(
    state: &PasswordAddState,
    digest: &str,
    account_id: &str,
) -> Result<(), AppError> {
    let row: Option<(String, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT session.user_id, \
                COALESCE(owner.locked_until > clock_timestamp()::timestamp, false), \
                COALESCE(owner.email_verified, false), \
                EXISTS (SELECT 1 FROM accounts a WHERE a.user_id = owner.id \
                         AND a.provider_id = 'credential'), \
                session.created_at > (clock_timestamp() - make_interval(secs => $2))::timestamp \
         FROM sessions AS session \
         JOIN users AS owner ON owner.id = session.user_id \
         WHERE session.token_hash = $1 AND session.expires_at > clock_timestamp()",
    )
    .bind(digest)
    .bind(RECENT_SIGN_IN_SECS as f64)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| unavailable())?;
    let Some((owner, locked, verified, has_password, recent)) = row else {
        return Err(AppError::Unauthorized);
    };
    if owner != account_id {
        return Err(AppError::Forbidden);
    }
    if locked {
        return Err(locked_refusal());
    }
    if !verified {
        return Err(unverified_refusal());
    }
    if has_password {
        return Err(exists_refusal());
    }
    if !recent {
        return Err(reauthentication_refusal());
    }
    Ok(())
}

enum Outcome {
    Added {
        user_id: String,
        email: String,
        providers: Vec<&'static str>,
        proof: &'static str,
    },
    CodeRejected {
        user_id: String,
        now_locked: bool,
    },
}

async fn add(
    State(state): State<PasswordAddState>,
    bounds: Option<Extension<PasswordAddBounds>>,
    headers: HeaderMap,
    request: Result<Json<AddRequest>, JsonRejection>,
) -> Response {
    let bounds = bounds.map(|Extension(bounds)| bounds).unwrap_or_default();
    let prepared = tokio::time::timeout(
        bounds.request,
        prepare(&state, bounds.statement, &headers, request),
    )
    .await;
    let (mut tx, outcome) = match prepared {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => return private(error),
        Err(_) => return private(unavailable()),
    };
    let (ip, ua) = request_info(&headers);
    let (user_id, action, metadata, severity) = match &outcome {
        Outcome::Added { user_id, proof, .. } => (
            user_id.as_str(),
            "user.password.added",
            json!({ "proof": proof }),
            "info",
        ),
        Outcome::CodeRejected {
            user_id,
            now_locked,
        } => (
            user_id.as_str(),
            "user.password.add_refused",
            json!({ "reason": "code", "locked": now_locked }),
            "warn",
        ),
    };
    if log_audit_in(&mut tx, action, user_id, &ip, &ua, metadata, severity)
        .await
        .is_err()
    {
        return private(unavailable());
    }
    // Commit outside the request budget, in its own task, so neither a late
    // timeout nor a client that disconnects can leave a committed password
    // the caller believes failed, or cut off the notice.
    let task_state = state.clone();
    let committed = tokio::spawn(async move {
        if tx.commit().await.is_err() {
            return Err(outcome);
        }
        if let Outcome::Added {
            email, providers, ..
        } = &outcome
        {
            notify(&task_state, email, providers).await;
        }
        Ok(outcome)
    })
    .await;
    match committed {
        Ok(Ok(Outcome::Added { .. })) => {
            private((StatusCode::OK, Json(AddResponse { added: true })))
        }
        Ok(Ok(Outcome::CodeRejected { now_locked, .. })) => private(if now_locked {
            locked_refusal()
        } else {
            refused(
                StatusCode::UNPROCESSABLE_ENTITY,
                "code_rejected",
                "That code didn't match. Nothing changed.",
            )
        }),
        _ => private(unavailable()),
    }
}

async fn prepare(
    state: &PasswordAddState,
    statement: Duration,
    headers: &HeaderMap,
    request: Result<Json<AddRequest>, JsonRejection>,
) -> Result<(Transaction<'static, Postgres>, Outcome), AppError> {
    exact_origin(headers, &state.frontend_url)?;
    let digest = cookie_digest(headers)?;
    let Json(request) = request.map_err(|_| malformed())?;
    if !valid_id(&request.account_id)
        || request.new_password.len() > MAX_PASSWORD_BYTES
        || request.code.len() > MAX_CODE_BYTES
    {
        return Err(malformed());
    }
    preflight(state, &digest, &request.account_id).await?;
    validate_password(&request.new_password)
        .map_err(|message| AppError::BadRequest(message.into()))?;
    // Hash before any lock, so the slow work never holds the account.
    let new_password = request.new_password.clone();
    let hash = tokio::task::spawn_blocking(move || hash_password(&new_password))
        .await
        .map_err(|_| unavailable())??;

    let mut tx = state.pool.begin().await.map_err(|_| unavailable())?;
    bounded_transaction_within(&mut tx, statement).await?;
    // users FOR UPDATE, then this session FOR UPDATE: the account controls'
    // lock order. It also refuses a disabled account and one past neither
    // two-factor boundary.
    let (user_id, session) =
        lock_account_actor(&mut tx, &digest, &request.account_id, true).await?;
    let (email, verified, enrolled, locked, has_password, providers): (
        String,
        bool,
        bool,
        bool,
        bool,
        Vec<String>,
    ) = sqlx::query_as(
        "SELECT email, COALESCE(email_verified, false), COALESCE(two_factor_enabled, false), \
                COALESCE(locked_until > clock_timestamp()::timestamp, false), \
                EXISTS (SELECT 1 FROM accounts a WHERE a.user_id = u.id AND a.provider_id = 'credential'), \
                ARRAY(SELECT a.provider_id FROM accounts a WHERE a.user_id = u.id \
                       AND a.provider_id IN ('github', 'google') ORDER BY a.provider_id) \
         FROM users u WHERE u.id = $1",
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if locked {
        return Err(locked_refusal());
    }
    if !verified {
        return Err(unverified_refusal());
    }
    if has_password {
        return Err(exists_refusal());
    }
    let recent: bool = sqlx::query_scalar(
        "SELECT created_at > (clock_timestamp() - make_interval(secs => $2))::timestamp \
         FROM sessions WHERE id = $1",
    )
    .bind(&session.id)
    .bind(RECENT_SIGN_IN_SECS as f64)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    if !recent {
        return Err(reauthentication_refusal());
    }

    let mut proof = "session";
    if enrolled {
        let Some(factor) = code::lock_factor(&mut tx, &user_id, &state.session_secret).await?
        else {
            return Err(unavailable());
        };
        let checked = code::check(&factor, &request.code, &email, &state.session_secret);
        if !checked.accepted() {
            let now_locked = record_failed_attempt(&mut tx, &user_id).await?;
            return Ok((
                tx,
                Outcome::CodeRejected {
                    user_id,
                    now_locked,
                },
            ));
        }
        checked
            .record(&mut tx, &state.session_secret, &user_id)
            .await?;
        reset_failed_attempts(&mut tx, &user_id).await?;
        proof = if checked.used_recovery_code() {
            "recovery_code"
        } else {
            "authenticator"
        };
    }

    sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, account_id, password, created_at, updated_at) \
         VALUES ($1, $2, 'credential', $3, $4, NOW(), NOW())",
    )
    .bind(hex_id())
    .bind(&user_id)
    // As sign-up stores a password row: its account_id is the address.
    .bind(&email)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(|_| unavailable())?;
    let providers = providers
        .iter()
        .filter_map(|provider| Provider::parse(provider))
        .map(Provider::label)
        .collect();
    Ok((
        tx,
        Outcome::Added {
            user_id,
            email,
            providers,
            proof,
        },
    ))
}

/// Best effort, after the commit: the account's address learns a password was
/// added, in case it wasn't the account's owner.
async fn notify(state: &PasswordAddState, to: &str, providers: &[&'static str]) {
    if !state.email.is_configured() {
        return;
    }
    let settings_url = format!("{}/settings", state.frontend_url.trim_end_matches('/'));
    if let Err(error) = state
        .email
        .send(to, &password_added_email(providers, &settings_url))
        .await
    {
        tracing::error!(%error, "failed to send the password-added notice");
    }
}

/// The notice that a password was added. It carries no code, secret or link
/// that grants access.
pub(crate) fn password_added_email(providers: &[&'static str], settings_url: &str) -> Email {
    let also = if providers.is_empty() {
        String::new()
    } else {
        format!(", as well as with {}", providers.join(" or "))
    };
    Email::new(
        "A password was added to your Codewire account",
        "A password was added to your Codewire account",
    )
    .paragraph(format!(
        "A password was added to your account from Settings. You can now sign in with your email address and this password{also}."
    ))
    .paragraph("If this wasn't you, reset your password and review your account's sessions in Settings.")
    .button("Open Settings", settings_url)
    .reason("You got this email because a password was added to the Codewire account for this address.")
}
