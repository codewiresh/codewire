//! Session-core credential auth — the `/api/auth/{sign-up,sign-in,
//! sign-out,get-session}` handlers.
//!
//! This is auth code, so every observable byte is contract-sensitive: HTTP status
//! codes, error `detail` strings, JSON field names/nullability, the
//! Argon2id PHC hash format, and the `Set-Cookie` header bytes.
//!
//! - `sign_up` (`POST /api/auth/sign-up`, public) creates a
//!   `users` + `accounts` (`provider_id='credential'`) pair inside a
//!   transaction, mints a session, and returns the session cookie + an
//!   `AuthResponse`.
//! - `sign_in` (`POST /api/auth/sign-in`, public) verifies the
//!   credential, applies the failed-attempt lockout (≥5 ⇒ 15 min), and
//!   either issues a 2FA challenge token or mints a session.
//! - `sign_out` (`POST /api/auth/sign-out`, public) deletes the
//!   session(s) named by the cookie and/or bearer token and always
//!   returns `{success:true}` with a clear-cookie.
//! - `get_session` (`GET /api/auth/get-session`, *optional* auth)
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
use chrono::{Duration, NaiveDateTime, Utc};
use codewire_email::EmailClient;
use codewire_server_core::auth::{
    api_key_prefix, hash_api_key, hash_session_token, touch_api_key_last_used_best_effort,
};
use codewire_server_core::{AppError, ValidatedJson};
use rand::RngCore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::fmt;
use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};

use crate::email_password::{
    VerificationPurpose, create_verification_in_transaction, send_verification_email,
};

mod session_inventory;

// The cookie-only account controls share one boundary: exact Origin, the
// session cookie and never a bearer, an owner-first lock order and a bounded,
// private transaction. Two-factor replacement reuses it unchanged.
pub(crate) use session_inventory::{
    actor as lock_account_actor, bounded_transaction, cookie_digest, exact_origin, private,
    unavailable, valid_id,
};

/// Web session lifetime: 8 hours (`auth.SessionDuration`, 28800s).
pub(crate) const SESSION_DURATION_SECS: i64 = 8 * 60 * 60;
/// Account lockout window after 5 failed sign-ins: 15 minutes.
pub(crate) const LOCKOUT_DURATION_SECS: i64 = 15 * 60;
/// 2FA challenge-token lifetime: 10 minutes.
const TWO_FACTOR_TOKEN_TTL_SECS: i64 = 10 * 60;
/// Failed-attempt threshold that triggers the lockout.
pub(crate) const MAX_FAILED_ATTEMPTS: i32 = 5;

const SIGNUP_INVITE_CODE_HASHES_ENV: &str = "IDP_SIGNUP_INVITE_CODE_HASHES";
const SHA256_DIGEST_BYTES: usize = 32;
const SHA256_HEX_CHARS: usize = SHA256_DIGEST_BYTES * 2;
const MAX_ACCESS_REASON_CHARS: usize = 2_000;
const MAX_TURNSTILE_TOKEN_BYTES: usize = 2_048;
const TURNSTILE_SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Configuration-owned signup invite policy.
///
/// Runtime configuration sends signups through access review when the hash
/// list is empty. Trusted tests can opt into the explicit open-signup policy.
/// A configured policy stores only fixed-size SHA-256 digests; plaintext
/// invite codes are never retained.
#[derive(Clone, Default)]
pub struct SignupInvitePolicy {
    accepted_hashes: Arc<[[u8; SHA256_DIGEST_BYTES]]>,
    open_signup: bool,
}

impl fmt::Debug for SignupInvitePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignupInvitePolicy")
            .field("configured", &self.is_configured())
            .field("open_signup", &self.open_signup)
            .field("accepted_hash_count", &self.accepted_hashes.len())
            .finish()
    }
}

impl SignupInvitePolicy {
    /// Construct the explicit open-signup policy used by trusted tests.
    pub fn open() -> Self {
        Self {
            accepted_hashes: Arc::default(),
            open_signup: true,
        }
    }

    /// Parse an optional comma-separated list of lowercase SHA-256 hex
    /// digests. Absent or whitespace-only input selects access review.
    pub fn from_sha256_hashes(value: Option<&str>) -> anyhow::Result<Self> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(Self::default());
        };

        let mut accepted_hashes = Vec::new();
        for encoded in value.split(',').map(str::trim) {
            let digest = decode_sha256_digest(encoded)?;
            if accepted_hashes.contains(&digest) {
                anyhow::bail!("{SIGNUP_INVITE_CODE_HASHES_ENV} contains a duplicate digest");
            }
            accepted_hashes.push(digest);
        }

        Ok(Self {
            accepted_hashes: accepted_hashes.into(),
            open_signup: false,
        })
    }

    /// Whether signup requires one of the configured invite codes.
    pub fn is_configured(&self) -> bool {
        !self.accepted_hashes.is_empty()
    }

    fn accepts(&self, invite_code: &str) -> bool {
        if self.open_signup {
            return true;
        }
        if !self.is_configured() || invite_code.is_empty() {
            return false;
        }

        let candidate: [u8; SHA256_DIGEST_BYTES] = Sha256::digest(invite_code.as_bytes()).into();
        let mut accepted = 0u8;
        for expected in self.accepted_hashes.iter() {
            accepted |= constant_time_digest_eq(&candidate, expected);
        }
        accepted == 1
    }
}

fn decode_sha256_digest(encoded: &str) -> anyhow::Result<[u8; SHA256_DIGEST_BYTES]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != SHA256_HEX_CHARS
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        anyhow::bail!(
            "{SIGNUP_INVITE_CODE_HASHES_ENV} entries must be {SHA256_HEX_CHARS}-character lowercase SHA-256 hex digests"
        );
    }

    let mut digest = [0u8; SHA256_DIGEST_BYTES];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("digest syntax is validated before decoding"),
    }
}

fn constant_time_digest_eq(
    left: &[u8; SHA256_DIGEST_BYTES],
    right: &[u8; SHA256_DIGEST_BYTES],
) -> u8 {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    u8::from(difference == 0)
}

#[derive(Clone)]
enum HumanVerification {
    /// `router` is retained as a trusted in-process test entrypoint.
    TrustedTest,
    /// Production configuration intentionally fails closed until its
    /// Turnstile secret is delivered.
    Unavailable,
    Configured {
        secret: String,
        hostname: String,
    },
}

/// State for the session-auth handlers: the pool, cookie policy, and signup
/// delivery/verification configuration.
#[derive(Clone)]
pub struct SessionAuthState {
    pub pool: PgPool,
    pub secure: bool,
    signup_invite_policy: SignupInvitePolicy,
    frontend_url: String,
    email: EmailClient,
    human_verification: HumanVerification,
    turnstile_bypass_email: String,
    http: reqwest::Client,
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
    #[serde(default)]
    invite_code: String,
    #[serde(default)]
    reason: String,
    #[serde(default, rename = "turnstile_token", alias = "cf-turnstile-response")]
    turnstile_token: String,
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

/// Browser-visible session metadata. The bearer capability is delivered only
/// through the HttpOnly session cookie and is never serialized into JSON.
#[derive(Serialize, JsonSchema)]
pub(crate) struct SessionResponse {
    pub(crate) id: String,
    pub(crate) expires_at: String,
}

/// A newly minted session and its one-time raw cookie capability.
pub(crate) struct CreatedSession {
    pub(crate) response: SessionResponse,
    pub(crate) token: String,
}

impl fmt::Debug for CreatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedSession")
            .field("session_id", &self.response.id)
            .field("expires_at", &self.response.expires_at)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Mirrors `auth.AuthResponse`. `skip_2fa_setup` is omitted unless the
/// current browser session skipped two-factor setup and the account has no
/// enabled factor.
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

/// Signup returns the normal session-shaped response for an immediately
/// admitted invite, or an accepted pending-access response with no session.
#[derive(Serialize, JsonSchema)]
pub(crate) struct SignUpResponseBody {
    user: UserResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<SessionResponse>,
    #[serde(rename = "accessPending", skip_serializing_if = "is_false")]
    access_pending: bool,
}

#[derive(Serialize)]
struct TurnstileValidationRequest<'a> {
    secret: &'a str,
    response: &'a str,
}

#[derive(Clone, Deserialize)]
struct TurnstileValidationResponse {
    success: bool,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    action: String,
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
    pub(crate) enabled: bool,
    pub(crate) locked_until: Option<NaiveDateTime>,
    pub(crate) created_at: Option<NaiveDateTime>,
}

/// A disabled, unverified account that is waiting for an administrator to
/// review an access request. This projection is deliberately separate from
/// the sign-in row so the retry path can lock and re-check every state that
/// makes an email reissue safe.
#[derive(sqlx::FromRow)]
struct PendingAccessSignupRow {
    id: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    image: Option<String>,
    is_admin: bool,
    two_factor_enabled: bool,
    enabled: bool,
    access_reason: Option<String>,
    created_at: NaiveDateTime,
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
    enabled: bool,
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
pub(crate) fn verify_password(password: &str, encoded_hash: &str) -> bool {
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

pub(crate) fn account_disabled() -> AppError {
    AppError::Coded {
        status: StatusCode::FORBIDDEN,
        code: "account_disabled",
        detail: "Account access is disabled".into(),
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
/// browser-safe session metadata plus the raw token for `Set-Cookie`.
pub(crate) async fn create_session(
    pool: &PgPool,
    user_id: &str,
    ip: &str,
    ua: &str,
) -> Result<CreatedSession, AppError> {
    create_session_in(pool, user_id, ip, ua).await
}

/// [`create_session`] on any executor, so a caller can issue the session in
/// the same transaction that revokes the account's other sessions.
pub(crate) async fn create_session_in<'e, E>(
    executor: E,
    user_id: &str,
    ip: &str,
    ua: &str,
) -> Result<CreatedSession, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let id = hex_id();
    let token = hex_token();
    let token_hash = hash_session_token(&token);
    let expires_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO sessions
            (id, user_id, token_hash, expires_at, ip_address, user_agent, created_at, updated_at)
        SELECT $1, user_account.id, $3, NOW() + ($4::bigint * interval '1 second'),
               $5, $6, NOW(), NOW()
          FROM users AS user_account
         WHERE user_account.id = $2
           AND user_account.enabled
        RETURNING expires_at
        "#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(SESSION_DURATION_SECS)
    .bind(ip)
    .bind(ua)
    .fetch_optional(executor)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create session");
        AppError::InternalMsg("Failed to create session".into())
    })?
    .ok_or_else(account_disabled)?;

    Ok(CreatedSession {
        token,
        response: SessionResponse {
            id,
            expires_at: format_time(expires_at),
        },
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

async fn validate_turnstile(
    state: &SessionAuthState,
    email: &str,
    token: &str,
) -> Result<(), AppError> {
    if turnstile_bypassed_for_email(&state.turnstile_bypass_email, email) {
        return Ok(());
    }
    let HumanVerification::Configured { secret, hostname } = &state.human_verification else {
        return match &state.human_verification {
            HumanVerification::TrustedTest => Ok(()),
            HumanVerification::Unavailable => Err(AppError::ServiceUnavailable(
                "Human verification is temporarily unavailable".into(),
            )),
            HumanVerification::Configured { .. } => unreachable!("matched above"),
        };
    };

    if token.is_empty()
        || token.len() > MAX_TURNSTILE_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(AppError::BadRequest(
            "Complete the human verification challenge".into(),
        ));
    }

    let response = state
        .http
        .post(TURNSTILE_SITEVERIFY_URL)
        .form(&TurnstileValidationRequest {
            secret,
            response: token,
        })
        .send()
        .await
        .map_err(|error| {
            tracing::error!(%error, "turnstile validation request failed");
            AppError::ServiceUnavailable("Human verification is temporarily unavailable".into())
        })?;
    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "turnstile validation returned an error");
        return Err(AppError::ServiceUnavailable(
            "Human verification is temporarily unavailable".into(),
        ));
    }
    let validation = response
        .json::<TurnstileValidationResponse>()
        .await
        .map_err(|error| {
            tracing::error!(%error, "turnstile validation response was invalid");
            AppError::ServiceUnavailable("Human verification is temporarily unavailable".into())
        })?;
    if !turnstile_validation_matches(&validation, hostname) {
        return Err(AppError::BadRequest(
            "Complete the human verification challenge".into(),
        ));
    }
    Ok(())
}

fn turnstile_bypassed_for_email(configured_email: &str, requested_email: &str) -> bool {
    !configured_email.is_empty() && configured_email == requested_email
}

fn turnstile_validation_matches(
    validation: &TurnstileValidationResponse,
    expected_hostname: &str,
) -> bool {
    validation.success
        && validation.action == "signup"
        && !expected_hostname.is_empty()
        && validation.hostname == expected_hostname
}

fn pending_access_user_response(row: &PendingAccessSignupRow) -> UserResponse {
    UserResponse {
        id: row.id.clone(),
        email: row.email.clone(),
        email_verified: row.email_verified,
        name: row.name.clone(),
        image: row.image.clone(),
        is_admin: row.is_admin,
        two_factor_enabled: row.two_factor_enabled,
        created_at: format_time(row.created_at),
    }
}

async fn deliver_pending_signup_verification(
    state: &SessionAuthState,
    user: UserResponse,
    token: String,
) -> Result<Response, AppError> {
    let verify_url = format!(
        "{}/verify-email?token={token}",
        state.frontend_url.trim_end_matches('/')
    );
    if let Err(error) = send_verification_email(&state.email, &user.email, &verify_url).await {
        tracing::error!(%error, user_id = %user.id, "failed to send signup verification email");
        return Err(AppError::ServiceUnavailable(
            "Your access request was saved, but email delivery is temporarily unavailable. Try again shortly."
                .into(),
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(SignUpResponseBody {
            user,
            session: None,
            access_pending: true,
        }),
    )
        .into_response())
}

async fn retry_pending_signup(
    state: &SessionAuthState,
    headers: &HeaderMap,
    email: &str,
) -> Result<Option<Response>, AppError> {
    let mut tx = state.pool.begin().await.map_err(|error| {
        tracing::error!(%error, "failed to begin pending signup retry");
        AppError::InternalMsg("Failed to create account".into())
    })?;
    let user = sqlx::query_as::<_, PendingAccessSignupRow>(
        r#"SELECT id,
                  email,
                  COALESCE(email_verified, false) AS email_verified,
                  name,
                  image,
                  COALESCE(is_admin, false) AS is_admin,
                  COALESCE(two_factor_enabled, false) AS two_factor_enabled,
                  enabled,
                  access_reason,
                  COALESCE(created_at, NOW()::timestamp) AS created_at
           FROM users
           WHERE email = $1
           FOR UPDATE"#,
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| {
        tracing::error!(%error, "failed to load pending signup retry");
        AppError::InternalMsg("Failed to create account".into())
    })?;
    let Some(user) = user else {
        tx.commit().await.map_err(|error| {
            tracing::error!(%error, "failed to complete pending signup retry lookup");
            AppError::InternalMsg("Failed to create account".into())
        })?;
        return Ok(None);
    };
    if user.enabled || user.email_verified || user.access_reason.is_none() {
        return Err(AppError::Conflict(
            "An account with this email already exists".into(),
        ));
    }
    let token = create_verification_in_transaction(
        &mut tx,
        &user.email,
        VerificationPurpose::EmailVerification,
        Duration::hours(24),
    )
    .await?;
    tx.commit().await.map_err(|error| {
        tracing::error!(%error, "failed to commit pending signup retry");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    let (ip, ua) = request_info(headers);
    log_audit(
        &state.pool,
        "user.signup.access_requested.retry",
        &user.id,
        &ip,
        &ua,
        json!({ "email": &user.email }),
        "info",
    )
    .await;
    deliver_pending_signup_verification(state, pending_access_user_response(&user), token)
        .await
        .map(Some)
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
    validate_turnstile(&state, &req.email, &req.turnstile_token).await?;

    let enabled = state.signup_invite_policy.accepts(&req.invite_code);
    let access_reason = req.reason.trim();
    if !enabled
        && (access_reason.is_empty() || access_reason.chars().count() > MAX_ACCESS_REASON_CHARS)
    {
        return Err(AppError::BadRequest(
            "Tell us why you want to use Codewire".into(),
        ));
    }
    if !enabled && !state.email.is_configured() {
        return Err(AppError::ServiceUnavailable(
            "Email verification is temporarily unavailable".into(),
        ));
    }

    // A repeated request for an unverified pending account only reissues its
    // verification email. This makes the post-commit delivery failure
    // recoverable without changing a password or allowing a disabled account
    // to sign in.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_some() {
        if let Some(response) = retry_pending_signup(&state, &headers, &req.email).await? {
            return Ok(response);
        }
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
    let stored_access_reason = (!enabled).then_some(access_reason);

    // users + accounts in one transaction (`provider_id='credential'`,
    // `account_id=email`, `password=hash`). `created_at`/`updated_at`
    // are set to the same NOW() the session/response will format.
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!(error = %e, "failed to begin tx");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    let created_at: NaiveDateTime = sqlx::query_scalar(
        r#"
        INSERT INTO users
            (id, email, email_verified, name, enabled, access_reason, created_at, updated_at)
        VALUES ($1, $2, false, $3, $4, $5, NOW(), NOW())
        RETURNING created_at
        "#,
    )
    .bind(&user_id)
    .bind(&req.email)
    .bind(name)
    .bind(enabled)
    .bind(stored_access_reason)
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

    let verification_token = if enabled {
        None
    } else {
        Some(
            create_verification_in_transaction(
                &mut tx,
                &req.email,
                VerificationPurpose::EmailVerification,
                Duration::hours(24),
            )
            .await?,
        )
    };

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "failed to commit tx");
        AppError::InternalMsg("Failed to create account".into())
    })?;

    let (ip, ua) = request_info(&headers);
    log_audit(
        &state.pool,
        if enabled {
            "user.signup"
        } else {
            "user.signup.access_requested"
        },
        &user_id,
        &ip,
        &ua,
        json!({ "email": req.email, "enabled": enabled }),
        "info",
    )
    .await;

    let user = UserResponse {
        id: user_id.clone(),
        email: req.email.clone(),
        email_verified: false,
        name: name.map(str::to_owned),
        image: None,
        is_admin: false,
        two_factor_enabled: false,
        created_at: format_time(created_at),
    };

    if !enabled {
        let token = verification_token.expect("pending signups create a verification token");
        return deliver_pending_signup_verification(&state, user, token).await;
    }

    let created_session = create_session(&state.pool, &user_id, &ip, &ua)
        .await
        .map_err(|_| AppError::InternalMsg("Account created but session failed".into()))?;
    let body = SignUpResponseBody {
        user,
        session: Some(created_session.response),
        access_pending: false,
    };
    Ok(with_cookie(
        session_cookie_string(&created_session.token, state.secure),
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
               two_factor_enabled, enabled, locked_until, created_at
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

    if !user.enabled {
        return Err(account_disabled());
    }

    // 2FA challenge branch: no session, no cookie.
    if user.two_factor_enabled.unwrap_or(false) {
        let tf_token = hex_token();
        let tf_token_hash = hash_session_token(&tf_token);
        let tf_id = hex_id();
        sqlx::query(
            r#"
            INSERT INTO two_factor_tokens (id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, NOW() + ($4::bigint * interval '1 second'))
            "#,
        )
        .bind(&tf_id)
        .bind(&user.id)
        .bind(&tf_token_hash)
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
    let created_session = create_session(&state.pool, &user.id, &ip, &ua).await?;
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

    let cookie = session_cookie_string(&created_session.token, state.secure);
    let body = SignInResponseBody {
        user: Some(user_response(user)),
        session: Some(created_session.response),
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
        let row: Option<ApiKeySessionRow> = match sqlx::query_as(
            r#"
            SELECT ak.id AS key_id,
                   u.id, u.email, u.email_verified, u.name, u.image, u.is_admin,
                   u.two_factor_enabled, u.enabled, u.locked_until, u.created_at
              FROM api_keys ak
              JOIN users u ON u.id = ak.user_id
             WHERE ak.key_prefix = $1
               AND ak.key_hash = $2
               AND (ak.expires_at IS NULL OR ak.expires_at > NOW())
               AND ak.disabled_at IS NULL
               AND u.enabled
            "#,
        )
        .bind(key_prefix)
        .bind(&key_hash)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(row) => row,
            Err(error) => {
                tracing::error!(error = %error, "failed to resolve API-key optional session");
                return AppError::InternalMsg("Failed to resolve session".into()).into_response();
            }
        };

        let Some(row) = row else {
            return Json(serde_json::Value::Null).into_response();
        };

        touch_api_key_last_used_best_effort(&state.pool, &row.key_id);

        let user = UserAuthRow {
            id: row.id,
            email: row.email,
            email_verified: row.email_verified,
            name: row.name,
            image: row.image,
            is_admin: row.is_admin,
            two_factor_enabled: row.two_factor_enabled,
            enabled: row.enabled,
            locked_until: row.locked_until,
            created_at: row.created_at,
        };

        return Json(AuthResponse {
            user: user_response(user),
            session: SessionResponse {
                id: String::new(),
                expires_at: String::new(),
            },
            skip_2fa_setup: false,
        })
        .into_response();
    }

    // Sliding-expiry bump + fetch (mirrors auth.GetSessionByToken).
    let token_hash = hash_session_token(&token);
    let row: Option<(String, String, NaiveDateTime, bool)> = match sqlx::query_as(
        r#"
        UPDATE sessions AS session
           SET expires_at = GREATEST(session.expires_at, NOW() + ($2::bigint * interval '1 second')),
               updated_at = NOW()
          FROM users AS user_account
         WHERE session.token_hash = $1
           AND session.expires_at > NOW()
           AND session.user_id = user_account.id
           AND user_account.enabled
        RETURNING session.id, session.user_id, session.expires_at,
                  session.two_factor_setup_skipped_at IS NOT NULL
        "#,
    )
    .bind(&token_hash)
    .bind(SESSION_DURATION_SECS)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(error) => {
            tracing::error!(error = %error, "failed to resolve optional browser session");
            return AppError::InternalMsg("Failed to resolve session".into()).into_response();
        }
    };

    let Some((session_id, user_id, expires_at, setup_skipped)) = row else {
        return Json(serde_json::Value::Null).into_response();
    };

    let user: Option<UserAuthRow> = match sqlx::query_as(
        r#"
        SELECT id, email, email_verified, name, image, is_admin,
               two_factor_enabled, enabled, locked_until, created_at
        FROM users WHERE id = $1 AND enabled
        "#,
    )
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(user) => user,
        Err(error) => {
            tracing::error!(error = %error, "failed to load user for optional session");
            return AppError::InternalMsg("Failed to resolve session".into()).into_response();
        }
    };

    let Some(user) = user else {
        return Json(serde_json::Value::Null).into_response();
    };
    // Skipping setup applies only to this session and never to an account
    // with an enabled factor.
    let skip_2fa_setup = setup_skipped && !user.two_factor_enabled.unwrap_or(false);

    Json(AuthResponse {
        user: user_response(user),
        session: SessionResponse {
            id: session_id,
            expires_at: format_time(expires_at),
        },
        skip_2fa_setup,
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
pub fn router(pool: PgPool, secure: bool, signup_invite_policy: SignupInvitePolicy) -> Router {
    router_with_state(
        pool,
        secure,
        signup_invite_policy,
        String::new(),
        EmailClient::disabled(),
        HumanVerification::TrustedTest,
        String::new(),
    )
}

pub fn router_with_signup_delivery(
    pool: PgPool,
    secure: bool,
    signup_invite_policy: SignupInvitePolicy,
    frontend_url: String,
    email: EmailClient,
    turnstile_secret_key: String,
    turnstile_bypass_email: String,
) -> Router {
    let hostname = reqwest::Url::parse(&frontend_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned));
    let human_verification = match (turnstile_secret_key.trim().is_empty(), hostname) {
        (false, Some(hostname)) if !hostname.is_empty() => HumanVerification::Configured {
            secret: turnstile_secret_key,
            hostname,
        },
        _ => HumanVerification::Unavailable,
    };
    router_with_state(
        pool,
        secure,
        signup_invite_policy,
        frontend_url,
        email,
        human_verification,
        turnstile_bypass_email,
    )
}

fn router_with_state(
    pool: PgPool,
    secure: bool,
    signup_invite_policy: SignupInvitePolicy,
    frontend_url: String,
    email: EmailClient,
    human_verification: HumanVerification,
    turnstile_bypass_email: String,
) -> Router {
    let state = SessionAuthState {
        pool,
        secure,
        signup_invite_policy,
        frontend_url,
        email,
        human_verification,
        turnstile_bypass_email,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("static signup HTTP client configuration"),
    };
    Router::new()
        .route("/api/auth/sign-up", post(sign_up))
        .route("/api/auth/sign-in", post(sign_in))
        .route("/api/auth/sign-out", post(sign_out))
        .route("/api/auth/get-session", get(get_session))
        .merge(session_inventory::router())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite_digest(invite_code: &str) -> String {
        format!("{:x}", Sha256::digest(invite_code.as_bytes()))
    }

    #[test]
    fn signup_invite_policy_requires_review_without_hashes() {
        for value in [None, Some(""), Some("   ")] {
            let policy = SignupInvitePolicy::from_sha256_hashes(value).unwrap();
            assert!(!policy.is_configured());
            assert!(!policy.accepts(""));
            assert!(!policy.accepts("any-value"));
        }

        let open = SignupInvitePolicy::open();
        assert!(open.accepts(""));
        assert!(open.accepts("any-value"));
    }

    #[test]
    fn configured_signup_invite_policy_accepts_only_matching_values() {
        let first = invite_digest("synthetic-invite-one");
        let second = invite_digest("synthetic-invite-two");
        let configured = format!("{first}, {second}");
        let policy = SignupInvitePolicy::from_sha256_hashes(Some(&configured)).unwrap();

        assert!(policy.is_configured());
        assert!(policy.accepts("synthetic-invite-one"));
        assert!(policy.accepts("synthetic-invite-two"));
        assert!(!policy.accepts(""));
        assert!(!policy.accepts("synthetic-invite-three"));

        let debug = format!("{policy:?}");
        assert!(!debug.contains(&first));
        assert!(!debug.contains("synthetic-invite"));
    }

    #[test]
    fn signup_invite_policy_rejects_invalid_hash_configuration() {
        let digest = invite_digest("synthetic-invite");
        for value in [
            "abc".to_owned(),
            "A".repeat(SHA256_HEX_CHARS),
            "g".repeat(SHA256_HEX_CHARS),
            format!("{digest},"),
            format!("{digest},{digest}"),
        ] {
            let error = SignupInvitePolicy::from_sha256_hashes(Some(&value)).unwrap_err();
            assert!(error.to_string().contains(SIGNUP_INVITE_CODE_HASHES_ENV));
            assert!(!error.to_string().contains("synthetic-invite"));
        }
    }

    #[test]
    fn turnstile_validation_binds_success_to_action_and_hostname() {
        let valid = TurnstileValidationResponse {
            success: true,
            hostname: "codewire.sh".into(),
            action: "signup".into(),
        };
        assert!(turnstile_validation_matches(&valid, "codewire.sh"));

        for candidate in [
            TurnstileValidationResponse {
                success: false,
                ..valid.clone()
            },
            TurnstileValidationResponse {
                action: "login".into(),
                ..valid.clone()
            },
            TurnstileValidationResponse {
                hostname: "example.test".into(),
                ..valid.clone()
            },
        ] {
            assert!(!turnstile_validation_matches(&candidate, "codewire.sh"));
        }
        assert!(!turnstile_validation_matches(&valid, ""));
    }

    #[test]
    fn turnstile_bypass_is_exactly_one_configured_email() {
        assert!(turnstile_bypassed_for_email(
            "codewire-e2e@example.test",
            "codewire-e2e@example.test"
        ));
        assert!(!turnstile_bypassed_for_email(
            "codewire-e2e@example.test",
            "other@example.test"
        ));
        assert!(!turnstile_bypassed_for_email("", ""));
        assert!(!turnstile_bypassed_for_email("", "other@example.test"));
    }

    #[tokio::test]
    async fn configured_e2e_email_bypasses_only_turnstile() {
        let pool = PgPool::connect_lazy("postgres://localhost/none").unwrap();
        let state = SessionAuthState {
            pool,
            secure: false,
            signup_invite_policy: SignupInvitePolicy::open(),
            frontend_url: String::new(),
            email: EmailClient::disabled(),
            human_verification: HumanVerification::Unavailable,
            turnstile_bypass_email: "codewire-e2e@example.test".into(),
            http: reqwest::Client::new(),
        };

        assert!(
            validate_turnstile(&state, "codewire-e2e@example.test", "")
                .await
                .is_ok()
        );
        assert!(matches!(
            validate_turnstile(&state, "other@example.test", "").await,
            Err(AppError::ServiceUnavailable(_))
        ));
    }

    #[test]
    fn pending_access_response_preserves_review_account_identity() {
        let row = PendingAccessSignupRow {
            id: "pending-user".into(),
            email: "pending@example.test".into(),
            email_verified: false,
            name: Some("Pending Person".into()),
            image: None,
            is_admin: false,
            two_factor_enabled: false,
            enabled: false,
            access_reason: Some("Evaluate Codewire".into()),
            created_at: NaiveDateTime::parse_from_str("2026-09-09 17:00:00", "%Y-%m-%d %H:%M:%S")
                .expect("parse fixed timestamp"),
        };

        let response = pending_access_user_response(&row);
        assert_eq!(response.id, row.id);
        assert_eq!(response.email, row.email);
        assert!(!response.email_verified);
        assert_eq!(response.name.as_deref(), Some("Pending Person"));
        assert_eq!(response.created_at, "2026-09-09T17:00:00Z");
    }

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
                expires_at: "2021-01-01T00:00:00Z".into(),
            }),
            ..Default::default()
        };
        let v = serde_json::to_value(&ok).unwrap();
        assert!(v.get("twoFactorRequired").is_none());
        assert!(v.get("twoFactorToken").is_none());
        assert!(v["session"].get("token").is_none());
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
    fn created_session_debug_redacts_cookie_capability() {
        let session = CreatedSession {
            response: SessionResponse {
                id: "session-id".into(),
                expires_at: "2021-01-01T00:00:00Z".into(),
            },
            token: "session-token-marker".into(),
        };

        let diagnostic = format!("{session:?}");
        assert!(!diagnostic.contains("session-token-marker"));
        assert!(diagnostic.contains("session-id"));
        assert!(diagnostic.contains("[REDACTED]"));
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

    #[tokio::test]
    async fn optional_session_database_failure_is_not_reported_as_signed_out() {
        let pool = PgPool::connect_lazy("postgres://localhost/none").unwrap();
        pool.close().await;
        let state = SessionAuthState {
            pool,
            secure: false,
            signup_invite_policy: SignupInvitePolicy::open(),
            frontend_url: String::new(),
            email: EmailClient::disabled(),
            human_verification: HumanVerification::TrustedTest,
            turnstile_bypass_email: String::new(),
            http: reqwest::Client::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "codewire.session_token=synthetic-session".parse().unwrap(),
        );

        let response = get_session(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
