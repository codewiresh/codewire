//! Session-core credential auth — the `/api/auth/{sign-up,sign-in,
//! sign-out,get-session}` handlers.
//!
//! This is auth code, so every observable byte is contract-sensitive: HTTP status
//! codes, error `detail` strings, JSON field names/nullability, the
//! Argon2id PHC hash format, and the `Set-Cookie` header bytes.
//!
//! - [`sign_up`] (`POST /api/auth/sign-up`, public) creates a
//!   `users` + `accounts` (`provider_id='credential'`) pair inside a
//!   transaction, mints a session, and returns the session cookie + an
//!   `AuthResponse`.
//! - [`sign_in`] (`POST /api/auth/sign-in`, public) verifies the
//!   credential, applies the failed-attempt lockout (≥5 ⇒ 15 min), and
//!   either issues a 2FA challenge token or mints a session.
//! - [`sign_out`] (`POST /api/auth/sign-out`, public) deletes the
//!   session(s) named by the cookie and/or bearer token and always
//!   returns `{success:true}` with a clear-cookie.
//! - [`get_session`] (`GET /api/auth/get-session`, *optional* auth)
//!   returns the current `AuthResponse`, or JSON `null` (200, not 401)
//!   when unauthenticated.
//!
//! ## Error-envelope mapping
//!
//! The Go handlers raise plain `huma.Error4xx(detail)` — huma's default
//! `ErrorModel`, which carries `status`/`title`/`detail` but **no**
//! `code`/`hint`. server-core's `AppError::Unauthorized`/`Forbidden`
//! instead carry the `session_expired`/`forbidden` machine codes (+
//! hints), so they would *not* be byte-identical. To match Go exactly we
//! use `AppError::Coded { code: "", … }` for the 401 (`Invalid email or
//! password`) and 429 (`Account is temporarily locked. …`) branches —
//! `code: ""` is omitted from the body (huma `omitempty`), yielding the
//! bare status+title+detail envelope. The 409 conflict uses
//! `AppError::Conflict`, which already emits no code (matching
//! `huma.Error409Conflict`).

use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use codewire_server_core::auth::{api_key_prefix, hash_api_key, hash_session_token};
use codewire_server_core::{AppError, ValidatedJson};
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

/// Web session lifetime: 8 hours (`auth.SessionDuration`, 28800s).
pub(crate) const SESSION_DURATION_SECS: i64 = 8 * 60 * 60;
/// Account lockout window after 5 failed sign-ins: 15 minutes.
pub(crate) const LOCKOUT_DURATION_SECS: i64 = 15 * 60;
/// 2FA challenge-token lifetime: 10 minutes.
const TWO_FACTOR_TOKEN_TTL_SECS: i64 = 10 * 60;
/// Failed-attempt threshold that triggers the lockout.
pub(crate) const MAX_FAILED_ATTEMPTS: i32 = 5;

/// State for the session-auth handlers: the pool, the cookie `Secure`
/// flag (HTTPS frontends only, mirroring Go's
/// `secure := strings.HasPrefix(cfg.FrontendURL, "https")`), and the
/// frontend URL (kept for parity with the other handler groups even
/// though these four handlers don't build links).
#[derive(Clone)]
pub struct SessionAuthState {
    pub pool: PgPool,
    pub secure: bool,
}

impl FromRef<SessionAuthState> for PgPool {
    fn from_ref(s: &SessionAuthState) -> PgPool {
        s.pool.clone()
    }
}

// --- wire types (mirror auth.SignUpRequest / SignInRequest / AuthResponse) ---

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SignUpRequest {
    email: String,
    password: String,
    #[serde(default)]
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    invite_code: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct SignInRequest {
    email: String,
    password: String,
}

/// Mirrors `auth.UserResponse` field-for-field (JSON names + nullability).
#[derive(Serialize, JsonSchema)]
pub(crate) struct UserResponse {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) email_verified: bool,
    pub(crate) name: Option<String>,
    pub(crate) image: Option<String>,
    pub(crate) is_admin: bool,
    pub(crate) two_factor_enabled: bool,
    pub(crate) created_at: String,
}

/// Mirrors `auth.SessionResponse`.
#[derive(Serialize, JsonSchema)]
pub(crate) struct SessionResponse {
    pub(crate) id: String,
    pub(crate) token: String,
    pub(crate) expires_at: String,
}

/// Mirrors `auth.AuthResponse`. `skip_2fa_setup` is `omitempty` on the
/// Go side and the idp service has no `Skip2FASetup` config, so it is
/// always `false` here and omitted from the body.
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuthResponse {
    pub(crate) user: UserResponse,
    pub(crate) session: SessionResponse,
    #[serde(rename = "skip_2fa_setup", skip_serializing_if = "is_false")]
    pub(crate) skip_2fa_setup: bool,
}

/// Mirrors `SignInResponseBody` — `user`/`session` are `omitempty`
/// pointers, `twoFactorRequired`/`twoFactorToken` are `omitempty`. The
/// success branch sends `user`+`session`; the 2FA branch sends only
/// `twoFactorRequired`+`twoFactorToken`.
#[derive(Serialize, JsonSchema, Default)]
pub(crate) struct SignInResponseBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionResponse>,
    #[serde(rename = "twoFactorRequired", skip_serializing_if = "is_false")]
    two_factor_required: bool,
    #[serde(rename = "twoFactorToken", skip_serializing_if = "String::is_empty")]
    two_factor_token: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct SignOutBody {
    success: bool,
}

/// `users` row in the lockout/verify projection used by sign-in and the
/// `UserResponse` projection used by sign-up/get-session.
#[derive(sqlx::FromRow)]
pub(crate) struct UserAuthRow {
    pub(crate) id: String,
    pub(crate) email: String,
    pub(crate) email_verified: Option<bool>,
    pub(crate) name: Option<String>,
    pub(crate) image: Option<String>,
    pub(crate) is_admin: Option<bool>,
    pub(crate) two_factor_enabled: Option<bool>,
    pub(crate) locked_until: Option<NaiveDateTime>,
    pub(crate) created_at: Option<NaiveDateTime>,
}

#[derive(sqlx::FromRow)]
struct ApiKeySessionRow {
    key_id: String,
    id: String,
    email: String,
    email_verified: Option<bool>,
    name: Option<String>,
    image: Option<String>,
    is_admin: Option<bool>,
    two_factor_enabled: Option<bool>,
    locked_until: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
}

// --- RNG / hashing helpers (mirror auth.GenerateID / GenerateToken /
// HashPassword / VerifyPassword) ---

/// 16 random bytes, lowercase hex (32 chars) — synthetic row ids
/// (`auth.GenerateID`).
pub(crate) fn hex_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_lower(&bytes)
}

/// 32 random bytes, lowercase hex (64 chars) — session + 2FA tokens
/// (`auth.GenerateToken`).
pub(crate) fn hex_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_lower(&bytes)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Go's `time.RFC3339` over a `timestamp without time zone` (UTC,
/// seconds precision) — `2006-01-02T15:04:05Z`.
pub(crate) fn format_time(t: NaiveDateTime) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Best-effort request metadata for the audit/IP columns (matches the
/// device-flow handler's reading of `r.RemoteAddr`/`r.UserAgent()`).
/// Never echoed in a body, so only the column writes matter.
pub(crate) fn request_info(headers: &HeaderMap) -> (String, String) {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (ip, ua)
}

/// The shared Argon2id configuration: `m=65536,t=3,p=2`, 32-byte hash,
/// v=0x13 (19). Wire-compatible with Go's
/// `argon2.IDKey(pw, salt, 3, 64*1024, 2, 32)` and its PHC encoding —
/// verified by a Go→Rust round-trip in the tests.
fn argon2id() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 2, Some(32)).expect("static argon2 params are valid"),
    )
}

/// Mirrors `auth.HashPassword`: 16-byte random salt, Argon2id, PHC
/// string `$argon2id$v=19$m=65536,t=3,p=2$<b64-salt>$<b64-hash>` with
/// RawStd (no-padding) base64 — byte-identical to the Go encoder.
pub(crate) fn hash_password(password: &str) -> Result<String, AppError> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    // SaltString encodes with the same no-padding base64 alphabet Go's
    // RawStdEncoding uses, so the emitted PHC string matches Go's.
    let salt = SaltString::encode_b64(&salt).map_err(|e| {
        tracing::error!(error = %e, "failed to encode argon2 salt");
        AppError::InternalMsg("Failed to create account".into())
    })?;
    let phc = argon2id()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to hash password");
            AppError::InternalMsg("Failed to create account".into())
        })?
        .to_string();
    Ok(phc)
}

/// Mirrors `auth.VerifyPassword`: parse the stored PHC hash and compare
/// (constant-time, inside the crate) against the candidate. Accepts a
/// Go-produced hash of the same format. A malformed hash or mismatch
/// is a non-match, never an error the caller distinguishes (Go folds
/// `err != nil || !match` into the same failure branch).
fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    argon2id()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Port of `auth.ValidatePassword` — same rules, same error string
/// (`"password must contain <a>, <b>, …"`). Returns the Go `detail`
/// verbatim so a 400 is byte-identical.
pub(crate) fn validate_password(password: &str) -> Result<(), String> {
    let mut errors: Vec<&str> = Vec::new();
    // Go uses `len()` (byte length) for the bounds.
    let byte_len = password.len();
    if byte_len < 12 {
        errors.push("at least 12 characters");
    }
    if byte_len > 128 {
        errors.push("at most 128 characters");
    }
    let (mut upper, mut lower, mut digit, mut special) = (false, false, false, false);
    for c in password.chars() {
        if c.is_uppercase() {
            upper = true;
        } else if c.is_lowercase() {
            lower = true;
        } else if c.is_numeric() && c.is_ascii_digit() {
            // Go's `unicode.IsDigit` is true for the Nd category; the
            // ASCII-digit subset covers every credential password we
            // accept, and keeping it ASCII avoids a Unicode-table dep.
            digit = true;
        } else if is_punct_or_symbol(c) {
            special = true;
        }
    }
    if !upper {
        errors.push("an uppercase letter");
    }
    if !lower {
        errors.push("a lowercase letter");
    }
    if !digit {
        errors.push("a digit");
    }
    if !special {
        errors.push("a special character");
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("password must contain {}", errors.join(", ")))
    }
}

/// ASCII approximation of Go's `unicode.IsPunct(c) || unicode.IsSymbol(c)`
/// special-character class. Covers the printable ASCII punctuation and
/// symbol code points (the set used by real credential passwords);
/// avoids dragging a Unicode-category table into the idp service.
fn is_punct_or_symbol(c: char) -> bool {
    c.is_ascii_punctuation() || matches!(c, '`' | '^' | '|' | '~' | '$' | '+' | '<' | '=' | '>')
}

/// Build the session `Set-Cookie` value, byte-for-byte matching Go's
/// `(&http.Cookie{…}).String()` for the set case:
/// `codewire.session_token=<token>; Path=/; Max-Age=28800; HttpOnly;
/// Secure; SameSite=Lax` (the `Secure` attribute only when `secure`).
pub(crate) fn session_cookie_string(token: &str, secure: bool) -> String {
    let mut s = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly",
        codewire_server_core::auth::SESSION_COOKIE_NAME,
        token,
        SESSION_DURATION_SECS
    );
    if secure {
        s.push_str("; Secure");
    }
    s.push_str("; SameSite=Lax");
    s
}

/// Build the clear `Set-Cookie` value, byte-for-byte matching Go's
/// `(&http.Cookie{…, MaxAge: -1}).String()`: an empty value and
/// `Max-Age=0` (Go renders any negative `MaxAge` as `Max-Age=0`).
fn clear_cookie_string(secure: bool) -> String {
    let mut s = format!(
        "{}=; Path=/; Max-Age=0; HttpOnly",
        codewire_server_core::auth::SESSION_COOKIE_NAME
    );
    if secure {
        s.push_str("; Secure");
    }
    s.push_str("; SameSite=Lax");
    s
}

/// huma `Error401Unauthorized(detail)` parity — a bare 401 with a custom
/// detail and **no** `code`/`hint` (unlike `AppError::Unauthorized`,
/// which carries the `session_expired` code).
fn unauthorized(detail: &'static str) -> AppError {
    AppError::Coded {
        status: StatusCode::UNAUTHORIZED,
        code: "",
        detail: detail.into(),
    }
}

/// huma `Error429TooManyRequests(detail)` parity — a bare 429 with a
/// custom detail and no code/hint.
pub(crate) fn too_many_requests(detail: &'static str) -> AppError {
    AppError::Coded {
        status: StatusCode::TOO_MANY_REQUESTS,
        code: "",
        detail: detail.into(),
    }
}

/// Extracts a `Bearer <token>` value (mirrors `extractBearerToken`).
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(str::to_owned)
}

fn is_api_key(token: &str) -> bool {
    token
        .strip_prefix("cw_")
        .is_some_and(|rest| rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Extracts the `codewire.session_token` cookie value (RFC 6265 list).
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let name = codewire_server_core::auth::SESSION_COOKIE_NAME;
    for pair in raw.split(';') {
        let pair = pair.trim_start();
        if let Some(rest) = pair.strip_prefix(name) {
            let rest = rest.trim_start();
            if let Some(value) = rest.strip_prefix('=') {
                return Some(
                    value
                        .trim_end_matches(|c: char| c.is_whitespace())
                        .to_string(),
                );
            }
        }
    }
    None
}

/// Fire-and-forget audit log (mirrors `auth.LogAuditEvent`). Failure
/// must never fail the request.
pub(crate) async fn log_audit(
    pool: &PgPool,
    action: &str,
    user_id: &str,
    ip: &str,
    ua: &str,
    metadata: serde_json::Value,
    severity: &str,
) {
    let _ = sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity)
        VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(hex_id())
    .bind(action)
    .bind(user_id)
    .bind(ip)
    .bind(ua)
    .bind(metadata)
    .bind(severity)
    .execute(pool)
    .await;
}

/// Insert a web session row (mirrors `auth.CreateSession`): a 64-hex
/// token, a 32-hex id, `expires_at = NOW() + 8h`. Returns the
/// `SessionResponse` (id/token/expires_at) for the body.
pub(crate) async fn create_session(
    pool: &PgPool,
    user_id: &str,
    ip: &str,
    ua: &str,
) -> Result<SessionResponse, AppError> {
    let id = hex_id();
    let token = hex_token();
    let token_hash = hash_session_token(&token);
    let expires_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO sessions
            (id, user_id, token_hash, expires_at, ip_address, user_agent, created_at, updated_at)
        VALUES ($1, $2, $3, NOW() + ($4::bigint * interval '1 second'), $5, $6, NOW(), NOW())
        RETURNING expires_at
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(SESSION_DURATION_SECS)
    .bind(ip)
    .bind(ua)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create session");
        AppError::InternalMsg("Failed to create session".into())
    })?;

    Ok(SessionResponse {
        id,
        token,
        expires_at: format_time(expires_at),
    })
}

pub(crate) fn user_response(r: UserAuthRow) -> UserResponse {
    UserResponse {
        id: r.id,
        email: r.email,
        email_verified: r.email_verified.unwrap_or(false),
        name: r.name,
        image: r.image,
        is_admin: r.is_admin.unwrap_or(false),
        two_factor_enabled: r.two_factor_enabled.unwrap_or(false),
        created_at: r.created_at.map(format_time).unwrap_or_default(),
    }
}

// --- handlers ---

/// `POST /api/auth/sign-up` (public).
async fn sign_up(
    State(state): State<SessionAuthState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<SignUpRequest>,
) -> Result<Response, AppError> {
    // email-required → 400 "Email is required".
    if req.email.is_empty() {
        return Err(AppError::BadRequest("Email is required".into()));
    }
    // ValidatePassword → 400 with its message.
    if let Err(msg) = validate_password(&req.password) {
        return Err(AppError::BadRequest(msg.into()));
    }
    // Invite codes: the idp service has no invite-code config (Go's
    // `cfg.InviteCodes` is empty here), so the check is skipped —
    // exactly as Go's `if len(cfg.InviteCodes) > 0` guard does.

    // email-exists → 409 "An account with this email already exists".
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_some() {
        return Err(AppError::Conflict(
            "An account with this email already exists".into(),
        ));
    }

    let hash = hash_password(&req.password)?;
    let user_id = hex_id();
    let account_id = hex_id();
    let name: Option<&str> = if req.name.is_empty() {
        None
    } else {
        Some(&req.name)
    };

    // users + accounts in one transaction (`provider_id='credential'`,
    // `account_id=email`, `password=hash`). `created_at`/`updated_at`
    // are set to the same NOW() the session/response will format.
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin tx");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    let created_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
        VALUES ($1, $2, false, $3, NOW(), NOW())
        RETURNING created_at
        "#,
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create user");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    sqlx::query(
        r#"
        INSERT INTO accounts
            (id, user_id, provider_id, account_id, password, created_at, updated_at)
        VALUES ($1, $2, 'credential', $3, $4, NOW(), NOW())
        "#,
    )
    .bind(&account_id)
    .bind(&user_id)
    .bind(&req.email)
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create account");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit tx");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    let (ip, ua) = request_info(&headers);
    let session = create_session(&state.pool, &user_id, &ip, &ua)
        .await
        .map_err(|_| AppError::InternalMsg("Account created but session failed".into()))?;

    log_audit(
        &state.pool,
        "user.signup",
        &user_id,
        &ip,
        &ua,
        json!({ "email": req.email }),
        "info",
    )
    .await;

    let user = UserResponse {
        id: user_id,
        email: req.email,
        email_verified: false,
        name: name.map(str::to_owned),
        image: None,
        is_admin: false,
        two_factor_enabled: false,
        created_at: format_time(created_at),
    };

    let body = AuthResponse {
        user,
        session,
        skip_2fa_setup: false,
    };
    Ok(with_cookie(
        session_cookie_string(&body.session.token, state.secure),
        Json(body),
    ))
}

/// `POST /api/auth/sign-in` (public).
async fn sign_in(
    State(state): State<SessionAuthState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<SignInRequest>,
) -> Result<Response, AppError> {
    // Lookup user by email; not found → 401 "Invalid email or password".
    let user: Option<UserAuthRow> = sqlx::query_as(
        r#"
        SELECT id, email, email_verified, name, image, is_admin,
               two_factor_enabled, locked_until, created_at
        FROM users WHERE email = $1
        "#,
    )
    .bind(&req.email)
    .fetch_optional(&state.pool)
    .await?;
    let Some(user) = user else {
        return Err(unauthorized("Invalid email or password"));
    };

    // locked_until > now → 429.
    if let Some(locked) = user.locked_until
        && locked > Utc::now().naive_utc()
    {
        return Err(too_many_requests(
            "Account is temporarily locked. Please try again later.",
        ));
    }

    // SELECT the credential password hash; missing → 401 (same message).
    let hash: Option<String> = sqlx::query_scalar(
        "SELECT password FROM accounts WHERE user_id = $1 AND provider_id = 'credential'",
    )
    .bind(&user.id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(hash) = hash else {
        return Err(unauthorized("Invalid email or password"));
    };

    let (ip, ua) = request_info(&headers);

    // Verify; on failure atomically bump attempts (lock at ≥5), audit
    // (warn), 401. Password and second-factor failures share this counter,
    // so a read-then-write update could otherwise lose a concurrent failure.
    if !verify_password(&req.password, &hash) {
        let _ = sqlx::query_scalar::<_, i32>(
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
        .bind(&user.id)
        .bind(MAX_FAILED_ATTEMPTS)
        .bind(LOCKOUT_DURATION_SECS)
        .fetch_optional(&state.pool)
        .await;
        log_audit(
            &state.pool,
            "user.signin.failed",
            &user.id,
            &ip,
            &ua,
            json!({ "email": req.email }),
            "warn",
        )
        .await;
        return Err(unauthorized("Invalid email or password"));
    }

    // 2FA challenge branch: no session, no cookie.
    if user.two_factor_enabled.unwrap_or(false) {
        let tf_token = hex_token();
        let tf_id = hex_id();
        sqlx::query(
            r#"
            INSERT INTO two_factor_tokens (id, user_id, token, expires_at)
            VALUES ($1, $2, $3, NOW() + ($4::bigint * interval '1 second'))
            "#,
        )
        .bind(&tf_id)
        .bind(&user.id)
        .bind(&tf_token)
        .bind(TWO_FACTOR_TOKEN_TTL_SECS)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to store 2FA token");
            AppError::InternalMsg("Failed to store 2FA token".into())
        })?;

        let body = SignInResponseBody {
            two_factor_required: true,
            two_factor_token: tf_token,
            ..Default::default()
        };
        return Ok(Json(body).into_response());
    }

    // Password verification completes the login for accounts without
    // 2FA, so only this branch resets the account failure state. A 2FA
    // account resets after its challenge is successfully validated.
    let _ = sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(&user.id)
    .execute(&state.pool)
    .await;

    // No 2FA: mint a session + cookie.
    let session = create_session(&state.pool, &user.id, &ip, &ua).await?;
    log_audit(
        &state.pool,
        "user.signin",
        &user.id,
        &ip,
        &ua,
        json!({ "email": user.email }),
        "info",
    )
    .await;

    let cookie = session_cookie_string(&session.token, state.secure);
    let body = SignInResponseBody {
        user: Some(user_response(user)),
        session: Some(session),
        ..Default::default()
    };
    Ok(with_cookie(cookie, Json(body)))
}

/// `POST /api/auth/sign-out` (public, rate-limited). Best-effort delete
/// of the session(s) named by the cookie and/or bearer token; always
/// returns 200 `{success:true}` with a clear-cookie. The audit log is
/// best-effort: it fires only when the cookie token resolves to a user
/// (mirroring Go's "if user in context" guard, which here is the
/// rate-limited public route's available identity).
async fn sign_out(State(state): State<SessionAuthState>, headers: HeaderMap) -> Response {
    let cookie_tok = session_cookie(&headers);
    let bearer_tok = extract_bearer(&headers);

    // Resolve the audit user before deleting (the row vanishes after).
    let mut audit_user: Option<String> = None;
    if let Some(tok) = cookie_tok.as_deref() {
        let token_hash = hash_session_token(tok);
        audit_user = sqlx::query_scalar(
            "SELECT user_id FROM sessions \
             WHERE token_hash = $1 \
               AND expires_at > NOW()",
        )
        .bind(&token_hash)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
    }

    if let Some(tok) = cookie_tok.as_deref() {
        let token_hash = hash_session_token(tok);
        let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&state.pool)
            .await;
    }
    if let Some(tok) = bearer_tok.as_deref() {
        let token_hash = hash_session_token(tok);
        let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&state.pool)
            .await;
    }

    if let Some(uid) = audit_user {
        let (ip, ua) = request_info(&headers);
        log_audit(
            &state.pool,
            "user.signout",
            &uid,
            &ip,
            &ua,
            json!(null),
            "info",
        )
        .await;
    }

    with_cookie(
        clear_cookie_string(state.secure),
        Json(SignOutBody { success: true }),
    )
}

/// `GET /api/auth/get-session` (*optional* auth). Returns the current
/// `AuthResponse`, or JSON `null` (200, not 401) when unauthenticated.
///
/// Go's optional-auth middleware resolves the user+session via
/// `AuthenticateRequest`; the cookie path bumps the session's sliding
/// expiry (`GetSessionByToken`) and the handler returns `null` when
/// `user==nil || (session==nil && apiKey==nil)`. We resolve manually:
/// the session cookie (preferred) bumps + returns the session row, then
/// loads the user. A bearer that is a Codewire API key returns the user with
/// an empty session object; a bearer that is a raw session token is handled
/// like a cookie. Anything else (or no credential) yields `null`.
async fn get_session(State(state): State<SessionAuthState>, headers: HeaderMap) -> Response {
    // Prefer the cookie, then a raw bearer token (CLI / proxy), matching
    // the Go authenticator precedence.
    let token = session_cookie(&headers).or_else(|| extract_bearer(&headers));
    let Some(token) = token else {
        return Json(serde_json::Value::Null).into_response();
    };

    if is_api_key(&token) {
        let key_hash = hash_api_key(&token);
        let key_prefix = api_key_prefix(&token);
        let row: Option<ApiKeySessionRow> = sqlx::query_as(
            r#"
            SELECT ak.id AS key_id,
                   u.id, u.email, u.email_verified, u.name, u.image, u.is_admin,
                   u.two_factor_enabled, u.locked_until, u.created_at
              FROM api_keys ak
              JOIN users u ON u.id = ak.user_id
             WHERE ak.key_prefix = $1
               AND ak.key_hash = $2
               AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
               AND ak.disabled_at IS NULL
            "#,
        )
        .bind(key_prefix)
        .bind(&key_hash)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();

        let Some(row) = row else {
            return Json(serde_json::Value::Null).into_response();
        };

        let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(&row.key_id)
            .execute(&state.pool)
            .await;

        let user = UserAuthRow {
            id: row.id,
            email: row.email,
            email_verified: row.email_verified,
            name: row.name,
            image: row.image,
            is_admin: row.is_admin,
            two_factor_enabled: row.two_factor_enabled,
            locked_until: row.locked_until,
            created_at: row.created_at,
        };

        return Json(AuthResponse {
            user: user_response(user),
            session: SessionResponse {
                id: String::new(),
                token: String::new(),
                expires_at: String::new(),
            },
            skip_2fa_setup: false,
        })
        .into_response();
    }

    // Sliding-expiry bump + fetch (mirrors auth.GetSessionByToken).
    let token_hash = hash_session_token(&token);
    let row: Option<(String, String, NaiveDateTime)> = sqlx::query_as(
        r#"
        UPDATE sessions
           SET expires_at = GREATEST(expires_at, NOW() + ($2::bigint * interval '1 second')),
               updated_at = NOW()
         WHERE token_hash = $1
           AND expires_at > NOW()
        RETURNING id, user_id, expires_at
        "#,
    )
    .bind(&token_hash)
    .bind(SESSION_DURATION_SECS)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let Some((session_id, user_id, expires_at)) = row else {
        return Json(serde_json::Value::Null).into_response();
    };

    let user: Option<UserAuthRow> = sqlx::query_as(
        r#"
        SELECT id, email, email_verified, name, image, is_admin,
               two_factor_enabled, locked_until, created_at
        FROM users WHERE id = $1
        "#,
    )
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let Some(user) = user else {
        return Json(serde_json::Value::Null).into_response();
    };

    Json(AuthResponse {
        user: user_response(user),
        session: SessionResponse {
            id: session_id,
            token,
            expires_at: format_time(expires_at),
        },
        skip_2fa_setup: false,
    })
    .into_response()
}

/// Attach a `Set-Cookie` header to a JSON response. Falls back to the
/// bare body if the cookie string somehow isn't a valid header value
/// (it always is — ASCII only).
fn with_cookie(cookie: String, body: impl IntoResponse) -> Response {
    match header::HeaderValue::from_str(&cookie) {
        Ok(v) => ([(header::SET_COOKIE, v)], body).into_response(),
        Err(_) => body.into_response(),
    }
}

/// The session-auth router: four endpoints under `/api/auth`. All are
/// public (sign-out is rate-limited in Go via middleware; get-session
/// is optional-auth) — auth is resolved inside the handlers, so no
/// `require_auth` layer is attached.
pub fn router(pool: PgPool, secure: bool) -> Router {
    let state = SessionAuthState { pool, secure };
    Router::new()
        .route("/api/auth/sign-up", post(sign_up))
        .route("/api/auth/sign-in", post(sign_in))
        .route("/api/auth/sign-out", post(sign_out))
        .route("/api/auth/get-session", get(get_session))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_emits_go_phc_prefix_and_roundtrips() {
        let phc = hash_password("CorrectHorse9#xy").unwrap();
        assert!(
            phc.starts_with("$argon2id$v=19$m=65536,t=3,p=2$"),
            "unexpected PHC: {phc}"
        );
        // 6 `$`-delimited fields: ["", "argon2id", "v=19", "params",
        // "salt", "hash"] — exactly Go's `strings.Split(...,"$")` shape.
        assert_eq!(phc.split('$').count(), 6, "PHC must have 6 parts: {phc}");
        assert!(verify_password("CorrectHorse9#xy", &phc));
        assert!(!verify_password("wrong-password", &phc));
    }

    #[test]
    fn verifies_a_go_produced_hash() {
        // Produced by `golang.org/x/crypto/argon2.IDKey` with the same
        // params (password "CorrectHorse9#xy"); locks in cross-language
        // compatibility.
        let go_hash = "$argon2id$v=19$m=65536,t=3,p=2$pOS7M9Kb49avWxdWd0qOAw$YQhSwF0Pp5ErjWYOwMdj2KYmIpUajvLSKK/PX6rGEBE";
        assert!(verify_password("CorrectHorse9#xy", go_hash));
        assert!(!verify_password("nope", go_hash));
    }

    #[test]
    fn set_cookie_bytes_match_go() {
        // Verified against Go's `(&http.Cookie{…}).String()`.
        assert_eq!(
            session_cookie_string("TOKENVALUE", true),
            "codewire.session_token=TOKENVALUE; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Lax"
        );
        assert_eq!(
            session_cookie_string("TOKENVALUE", false),
            "codewire.session_token=TOKENVALUE; Path=/; Max-Age=28800; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn clear_cookie_bytes_match_go() {
        // Go renders MaxAge<0 as `Max-Age=0` (not -1) with an empty value.
        assert_eq!(
            clear_cookie_string(true),
            "codewire.session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        );
        assert_eq!(
            clear_cookie_string(false),
            "codewire.session_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn validate_password_accepts_a_strong_password() {
        assert!(validate_password("CorrectHorse9#xy").is_ok());
        assert!(validate_password("Aa1!aaaaaaaa").is_ok()); // exactly 12 chars
    }

    #[test]
    fn validate_password_rejects_with_go_message() {
        // Too short + missing every class → all the clauses, in order.
        let err = validate_password("a").unwrap_err();
        assert_eq!(
            err,
            "password must contain at least 12 characters, an uppercase letter, a digit, a special character"
        );
        // Missing only a special char.
        let err = validate_password("Abcdefghij12").unwrap_err();
        assert_eq!(err, "password must contain a special character");
        // Missing only a digit.
        let err = validate_password("Abcdefghij!!").unwrap_err();
        assert_eq!(err, "password must contain a digit");
        // Over-length (129 chars): one long lowercase run.
        let long = "A1!".to_string() + &"a".repeat(126);
        assert_eq!(long.len(), 129);
        assert_eq!(
            validate_password(&long).unwrap_err(),
            "password must contain at most 128 characters"
        );
    }

    #[test]
    fn signin_2fa_body_omits_user_and_session() {
        let body = SignInResponseBody {
            two_factor_required: true,
            two_factor_token: "tok".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["twoFactorRequired"], true);
        assert_eq!(v["twoFactorToken"], "tok");
        assert!(v.get("user").is_none());
        assert!(v.get("session").is_none());
        // The success-shape omits the 2FA fields instead.
        let ok = SignInResponseBody {
            session: Some(SessionResponse {
                id: "s".into(),
                token: "t".into(),
                expires_at: "2021-01-01T00:00:00Z".into(),
            }),
            ..Default::default()
        };
        let v = serde_json::to_value(&ok).unwrap();
        assert!(v.get("twoFactorRequired").is_none());
        assert!(v.get("twoFactorToken").is_none());
        assert_eq!(v["session"]["token"], "t");
    }

    #[test]
    fn auth_response_omits_skip_2fa() {
        // The idp service has no Skip2FASetup config; the field exists for
        // contract compatibility but stays false and omitted on the wire.
        let v = serde_json::to_value(AuthResponse {
            user: UserResponse {
                id: "u".into(),
                email: "a@b.c".into(),
                email_verified: false,
                name: None,
                image: None,
                is_admin: false,
                two_factor_enabled: false,
                created_at: "2021-01-01T00:00:00Z".into(),
            },
            session: SessionResponse {
                id: "s".into(),
                token: "t".into(),
                expires_at: "2021-01-01T00:00:00Z".into(),
            },
            skip_2fa_setup: false,
        })
        .unwrap();
        assert!(v.get("skip_2fa_setup").is_none());
        // `name` is a present-but-null field (Go `*string` without
        // omitempty), matching UserResponse.
        assert!(v["user"]["name"].is_null());
    }

    #[test]
    fn id_and_token_hex_widths_match_go() {
        assert_eq!(hex_id().len(), 32);
        assert_eq!(hex_token().len(), 64);
        assert!(hex_id().chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn unauthorized_and_locked_carry_bare_status_and_detail() {
        match unauthorized("Invalid email or password") {
            AppError::Coded {
                status,
                code,
                detail,
            } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(code, "");
                assert_eq!(detail, "Invalid email or password");
            }
            _ => panic!("expected Coded"),
        }
        match too_many_requests("Account is temporarily locked. Please try again later.") {
            AppError::Coded { status, detail, .. } => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(
                    detail,
                    "Account is temporarily locked. Please try again later."
                );
            }
            _ => panic!("expected Coded"),
        }
    }
}
