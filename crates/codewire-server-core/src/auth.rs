//! Authentication for Codewire backend services.
//!
//! Three user-credential kinds are accepted, all validated by direct
//! database lookup (`codewire/plans:connect-rpc/15-auth-policy.md`):
//!
//! 1. **Session cookie** (`codewire.session_token`) — the dominant flow for
//!    browser callers (dashboard). Validated against the `sessions` table
//!    with a sliding-expiry `UPDATE … RETURNING`, then the `users` row is
//!    loaded to populate `is_admin`.
//! 2. **`cw_`-prefixed API keys** — SHA-256 hashed and looked up in
//!    `api_keys`.
//! 3. **OIDC-issued opaque access tokens** — minted by `codewire-idp`,
//!    SHA-256 hashed and looked up in `oidc_access_tokens` joined to
//!    `users` and `oidc_clients` (see
//!    `authenticate_oidc_access_token`). Access tokens keep the fixed
//!    expiry the idp issued: presenting one never reads or writes
//!    `sessions`, and no shared secret is involved. Product APIs additionally
//!    require the exact `codewire.api` scope; identity-only tokens remain
//!    valid for OIDC UserInfo but receive `403` at product boundaries.
//!
//! Handlers consume the principal and delegated authority through axum's
//! extractor system as [`AuthUser`] and [`CredentialContext`], populated by
//! [`require_auth`] middleware. Admin-only handlers add [`require_admin`]
//! after it. Browser-owned account-security routes instead use
//! [`require_session_auth`] and never accept bearer credentials.
//! Isolated services can instead mount
//! [`ConnectAuthLayer::oauth_bearer_only`](crate::connect::ConnectAuthLayer::oauth_bearer_only):
//! cookies never supply identity and API keys never enter their lookup or
//! usage-bookkeeping paths. Credential mutation uses its own narrower
//! session-or-OAuth mount with an exact browser-Origin requirement; it does not
//! broaden OAuth-only delegation.

use axum::extract::{FromRequestParts, State};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::Duration;

use crate::error::AppError;

mod oauth_authority;
pub use oauth_authority::{OAuthBearerAuthority, OAuthBearerAuthorityError};
mod session_mutation_authority;
pub use session_mutation_authority::{
    CredentialMutationAuthority, CredentialMutationAuthorityError,
};

/// Published browser session cookie name.
pub const SESSION_COOKIE_NAME: &str = "codewire.session_token";

/// Baseline OAuth capability required when an OIDC access token calls a
/// Codewire product API. Identity-only scopes remain valid at OIDC/UserInfo
/// endpoints but confer no product authority.
pub const PRODUCT_API_SCOPE: &str = "codewire.api";

/// Sliding-expiry window applied on every session-cookie validation.
/// Sliding browser-session duration.
pub const SESSION_DURATION: chrono::Duration = chrono::Duration::hours(8);

/// Best-effort usage bookkeeping must never extend credential resolution.
/// A short background bound also prevents a locked key row from accumulating
/// detached database work.
const API_KEY_LAST_USED_TOUCH_TIMEOUT: Duration = Duration::from_millis(250);

/// Identity attached to a request once auth succeeds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthUser {
    /// `users.id` from the Codewire schema. Stored as text in Postgres
    /// (UUID-formatted), so the Rust type is `String` rather than `Uuid`
    /// to avoid lossy round-tripping.
    pub user_id: String,
    /// Org context, if the credential carries one (`api_keys.org_id`).
    /// Cookie sessions don't carry an org — the handler picks it from
    /// the path or from a separate membership lookup.
    pub org_id: Option<String>,
    /// Mirrors `users.is_admin` — used by `require_admin` and by
    /// in-handler filters like the billing-plans `is_admin_only` mask.
    pub is_admin: bool,
    /// `true` for `cw_` API keys; `false` for session-cookie or OIDC
    /// bearer auth. Used in audit logs and rate limiters that care which
    /// credential kind was used.
    pub via_api_key: bool,
}

impl AuthUser {
    /// Convenience: returns the org ID or rejects with `forbidden`.
    pub fn require_org(&self) -> Result<&str, AppError> {
        self.org_id.as_deref().ok_or(AppError::Forbidden)
    }

    /// Rejects org-scoped machine credentials at account-global boundaries.
    /// API keys act only inside their single bound organization; they cannot
    /// mutate the owning user's account, join/create organizations, mint
    /// user tickets, or inherit global administrator authority.
    pub fn require_account_credential(&self) -> Result<(), AppError> {
        if self.via_api_key {
            return Err(api_key_scope_violation());
        }
        Ok(())
    }

    /// Requires a user credential belonging to a global administrator.
    /// Organization API keys never inherit this authority from their owner.
    pub fn require_global_admin(&self) -> Result<(), AppError> {
        self.require_account_credential()?;
        if !self.is_admin {
            return Err(AppError::Forbidden);
        }
        Ok(())
    }

    /// Whether this credential can act inside `org_id`. User credentials can
    /// use normal membership checks; API keys are confined to their one
    /// non-empty bound organization before any user-level shortcut applies.
    pub fn permits_organization(&self, org_id: &str) -> bool {
        !self.via_api_key
            || self
                .org_id
                .as_deref()
                .is_some_and(|key_org| !key_org.is_empty() && key_org == org_id)
    }
}

/// Which credential kind validated a request.
///
/// One variant per accepted user-credential flavor
/// (`codewire/plans:connect-rpc/15-auth-policy.md`). The Connect per-RPC log event
/// (`codewire/plans:connect-rpc/03-connect-server-infrastructure.md` D7) reports
/// [`CredentialKind::as_str`] as its `credential` field — the evidence
/// substrate for the migration's rollout observation — so the strings are
/// load-bearing once dashboards key on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// `codewire.session_token` cookie (flavor 1, browsers).
    SessionCookie,
    /// `cw_`-prefixed API key (flavor 3, machines).
    ApiKey,
    /// OIDC-issued opaque access token presented as a bearer (flavor 2).
    OidcAccessToken,
}

impl CredentialKind {
    /// Stable log/wire spelling of the credential kind.
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::SessionCookie => "session",
            CredentialKind::ApiKey => "api_key",
            CredentialKind::OidcAccessToken => "oidc",
        }
    }
}

/// Credential-specific authority attached alongside [`AuthUser`].
///
/// OAuth scopes describe the authority delegated to one token/client, not a
/// property of the user. Keeping this context separate avoids making session
/// cookies and org-scoped API keys pretend to have OAuth semantics while
/// preserving the evidence future service-specific checks need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialContext {
    SessionCookie,
    ApiKey {
        key_id: String,
        /// Reserved API-key labels. They are intentionally not interpreted as
        /// OAuth scopes; key authority remains its exactly-one `org_id`.
        scopes: Vec<String>,
    },
    OidcAccessToken {
        /// OAuth client to which the token was issued, not a resource
        /// audience.
        client_id: String,
        scopes: Vec<String>,
    },
}

impl CredentialContext {
    /// Stable telemetry kind derived from the resolved credential.
    pub fn kind(&self) -> CredentialKind {
        match self {
            CredentialContext::SessionCookie => CredentialKind::SessionCookie,
            CredentialContext::ApiKey { .. } => CredentialKind::ApiKey,
            CredentialContext::OidcAccessToken { .. } => CredentialKind::OidcAccessToken,
        }
    }
}

/// Resolved product authentication: resource principal plus the authority of
/// the credential that was presented.
#[derive(Debug, Clone)]
pub struct Authentication {
    /// User/resource principal.
    pub user: AuthUser,
    /// Credential-specific delegated authority.
    pub credential: CredentialContext,
    pub(crate) oauth_bearer_authority: Option<OAuthBearerAuthority>,
}

impl Authentication {
    /// The original OAuth token's publication authority, never a raw bearer.
    /// Session and API-key authentication deliberately have no such authority.
    pub fn oauth_bearer_authority(&self) -> Option<&OAuthBearerAuthority> {
        self.oauth_bearer_authority.as_ref()
    }
}

/// Application state expected by [`require_auth`].
#[derive(Clone)]
pub struct AuthState {
    pub pool: PgPool,
}

/// Axum middleware that requires a valid credential. Inserts an
/// [`AuthUser`] into request extensions on success.
pub async fn require_auth(
    State(state): State<AuthState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, AppError> {
    // Pull the credentials out of the headers before the first await:
    // holding `&Request` across an await would make this future !Send
    // (axum's Body is !Sync), and axum middleware futures must be Send.
    let auth = authenticate_headers_with_context(&state, req.headers()).await?;
    if let Some(authority) = auth.oauth_bearer_authority {
        req.extensions_mut().insert(authority);
    }
    req.extensions_mut().insert(auth.credential);
    req.extensions_mut().insert(auth.user);
    Ok(next.run(req).await)
}

/// Axum middleware for browser-owned identity operations that require a live
/// session cookie specifically.
///
/// Unlike [`require_auth`], this deliberately does not inspect an
/// `Authorization` bearer. OIDC access tokens and API keys authorize product
/// API calls; neither credential is authority to approve a login or mutate
/// the account's authentication factors.
pub async fn require_session_auth(
    State(state): State<AuthState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = session_cookie(req.headers())
        .map(str::to_owned)
        .ok_or(AppError::Unauthorized)?;
    let user = authenticate_session_cookie(&state.pool, &token).await?;
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

/// Authenticate the standard Codewire credential set directly from HTTP
/// headers. Self-authenticating Connect handlers use this instead of the
/// axum middleware so they can dispatch distinct machine credentials first
/// while preserving the exact user-credential precedence used by REST.
pub async fn authenticate_headers(
    state: &AuthState,
    headers: &HeaderMap,
) -> Result<AuthUser, AppError> {
    Ok(authenticate_headers_with_context(state, headers)
        .await?
        .user)
}

/// Authenticate and authorize the standard product credential set while
/// preserving credential-specific context for service-level checks.
pub async fn authenticate_headers_with_context(
    state: &AuthState,
    headers: &HeaderMap,
) -> Result<Authentication, AppError> {
    let session_token = session_cookie(headers).map(str::to_owned);
    let bearer = bearer_token(headers).map(str::to_owned);
    authenticate_product(state, session_token.as_deref(), bearer.as_deref()).await
}

/// Resolves one credential already isolated by a trusted internal adapter.
///
/// Public HTTP/Connect paths continue to use
/// [`authenticate_headers_with_context`], which owns normal header
/// precedence. This entry point exists for the private Mesh authorization
/// hop only after its HMAC boundary has authenticated the calling service and
/// removed the raw forwarded metadata before generated-service dispatch.
pub async fn authenticate_product_credential(
    state: &AuthState,
    session_token: Option<&str>,
    bearer: Option<&str>,
) -> Result<Authentication, AppError> {
    authenticate_product(state, session_token, bearer).await
}

/// Axum middleware that rejects non-admin callers. Must be chained
/// after [`require_auth`].
pub async fn require_admin(req: axum::extract::Request, next: Next) -> Result<Response, AppError> {
    let user = req
        .extensions()
        .get::<AuthUser>()
        .ok_or(AppError::Unauthorized)?;
    user.require_global_admin()?;
    Ok(next.run(req).await)
}

/// Axum middleware for account-global user operations. Must run after
/// [`require_auth`]; org-scoped API keys are rejected even when their owner is
/// a global administrator.
pub async fn require_account_auth(
    req: axum::extract::Request,
    next: Next,
) -> Result<Response, AppError> {
    let user = req
        .extensions()
        .get::<AuthUser>()
        .ok_or(AppError::Unauthorized)?;
    user.require_account_credential()?;
    Ok(next.run(req).await)
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

impl<S> FromRequestParts<S> for CredentialContext
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CredentialContext>()
            .cloned()
            .ok_or(AppError::Unauthorized)
    }
}

/// Direct authentication entry point for raw (non-middleware) handlers that
/// need a custom rejection body.
pub async fn authenticate(
    state: &AuthState,
    session_token: Option<&str>,
    bearer: Option<&str>,
) -> Result<AuthUser, AppError> {
    Ok(authenticate_product(state, session_token, bearer)
        .await?
        .user)
}

/// [`authenticate`], additionally reporting which credential flavor
/// validated. This is retained for callers that need the stable telemetry
/// spelling; it applies the same product-scope policy before returning.
pub async fn authenticate_with_kind(
    state: &AuthState,
    session_token: Option<&str>,
    bearer: Option<&str>,
) -> Result<(AuthUser, CredentialKind), AppError> {
    let auth = authenticate_product(state, session_token, bearer).await?;
    let kind = auth.credential.kind();
    Ok((auth.user, kind))
}

async fn authenticate_product(
    state: &AuthState,
    session_token: Option<&str>,
    bearer: Option<&str>,
) -> Result<Authentication, AppError> {
    let auth = resolve_authentication(state, session_token, bearer).await?;
    require_product_access(&auth)?;
    Ok(auth)
}

/// Resolves a credential without assigning it product authority. Crate-private
/// so every external caller goes through the shared product policy.
pub(crate) async fn resolve_authentication(
    state: &AuthState,
    session_token: Option<&str>,
    bearer: Option<&str>,
) -> Result<Authentication, AppError> {
    // Credential precedence is session cookie first, then Authorization.
    if let Some(token) = session_token
        && let Ok(user) = authenticate_session_cookie(&state.pool, token).await
    {
        return Ok(Authentication {
            user,
            credential: CredentialContext::SessionCookie,
            oauth_bearer_authority: None,
        });
    }
    // Fall through: a stale cookie shouldn't deny a valid bearer.

    if let Some(token) = bearer {
        if is_api_key(token) {
            // Format matched but auth failed — don't fall through to the
            // other bearer kinds, mirroring auth.AuthenticateRequest in Go.
            return authenticate_api_key(&state.pool, token).await;
        }
        // Flavor 2: opaque OIDC access token, resolved by hashed lookup
        // against the idp's token store. Fixed expiry by design — this
        // path never touches `sessions`.
        if let Some(auth) = authenticate_oidc_access_token(&state.pool, token).await? {
            return Ok(auth);
        }
    }

    Err(AppError::Unauthorized)
}

/// Resolve only an opaque OAuth bearer. Scope authorization remains the shared
/// `require_product_access` step, so Connect retains validated principal
/// evidence even when an identity-only token lacks product authority.
///
/// This path has no session/API-key fallback and requires only the existing
/// identity SELECT columns in `oidc_access_tokens`, `users` and `oidc_clients`.
/// In particular, an irrelevant cookie never triggers a session lookup/write.
pub(crate) async fn resolve_oauth_bearer_authentication(
    state: &AuthState,
    headers: &HeaderMap,
) -> Result<Authentication, AppError> {
    let token = oauth_bearer_token(headers).ok_or(AppError::Unauthorized)?;
    authenticate_oidc_access_token(&state.pool, token)
        .await
        // The isolated boundary does not retain database errors or their source
        // chains: neither presented credentials nor database details can escape
        // through Debug, Display, Connect rendering or error telemetry.
        .map_err(|_| AppError::ServiceUnavailable("OAuth credential lookup unavailable".into()))?
        .ok_or(AppError::Unauthorized)
}

/// Resolve the only two original authorities admitted by
/// `CredentialMutationService`. A presented session must come from the exact
/// configured browser origin; API keys never enter their lookup path.
pub(crate) async fn resolve_credential_mutation_authentication(
    state: &AuthState,
    headers: &HeaderMap,
    session_origin: &http::HeaderValue,
) -> Result<(Authentication, CredentialMutationAuthority), AppError> {
    if let Some(token) = credential_mutation_session_cookie(headers)? {
        // A browser session and an Authorization credential are distinct
        // original authorities. Never choose one by precedence at this mount.
        if headers.contains_key(AUTHORIZATION) {
            return Err(AppError::Unauthorized);
        }
        let mut origins = headers.get_all(http::header::ORIGIN).iter();
        if origins.next() != Some(session_origin) || origins.next().is_some() {
            return Err(AppError::Forbidden);
        }
        let captured_monotonic = std::time::Instant::now();
        let captured_wall = chrono::Utc::now();
        let digest = hash_session_token(token);
        let row: Option<(String, String, bool, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT session_id,user_id,is_admin,expires_at FROM public.codewire_authenticate_credential_session($1::text)",
        )
        .bind(&digest)
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| AppError::ServiceUnavailable("session credential lookup unavailable".into()))?;
        let (session_id, user_id, is_admin, expires_at) = row.ok_or(AppError::Unauthorized)?;
        let authority = session_mutation_authority::SessionCredentialMutationAuthority::new(
            session_id,
            digest,
            user_id.clone(),
            expires_at,
            captured_monotonic,
            captured_wall,
        )
        .ok_or(AppError::Unauthorized)?;
        return Ok((
            Authentication {
                user: AuthUser {
                    user_id,
                    org_id: None,
                    is_admin,
                    via_api_key: false,
                },
                credential: CredentialContext::SessionCookie,
                oauth_bearer_authority: None,
            },
            CredentialMutationAuthority::from_session(authority),
        ));
    }

    let auth = resolve_oauth_bearer_authentication(state, headers).await?;
    let authority = auth
        .oauth_bearer_authority()
        .cloned()
        .ok_or(AppError::Unauthorized)?;
    Ok((auth, CredentialMutationAuthority::from(authority)))
}

/// Extract exactly one browser-session cookie for credential mutation.
///
/// General product authentication retains its established cookie precedence.
/// This isolated mutation mount rejects duplicate Cookie fields or duplicate
/// session-cookie pairs so an intermediary cannot influence which original
/// authority is selected by field or pair ordering.
fn credential_mutation_session_cookie(headers: &HeaderMap) -> Result<Option<&str>, AppError> {
    let mut fields = headers.get_all(COOKIE).iter();
    let Some(raw) = fields.next() else {
        return Ok(None);
    };
    if fields.next().is_some() {
        return Err(AppError::Unauthorized);
    }
    let raw = raw.to_str().map_err(|_| AppError::Unauthorized)?;
    let mut token = None;
    for pair in raw.split(';') {
        let Some((name, value)) = pair.trim_start().split_once('=') else {
            continue;
        };
        if name.trim_end() != SESSION_COOKIE_NAME {
            continue;
        }
        let value = value.trim_end_matches(|character: char| character.is_whitespace());
        if value.is_empty() || token.replace(value).is_some() {
            return Err(AppError::Unauthorized);
        }
    }
    Ok(token)
}

fn oauth_bearer_token(headers: &HeaderMap) -> Option<&str> {
    // Reject ambiguous duplicate credentials rather than choosing an identity
    // according to header ordering. Cookies are deliberately not consulted.
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || is_api_key(token) {
        return None;
    }
    // RFC 6750 bearer syntax, with padding only at the end. This validates
    // framing, not token authority: even a syntactically valid session token
    // can authenticate only if its digest is in the live OAuth token store.
    // Do not reserve every `cw_` prefix: a genuine randomly minted base64url
    // OAuth token can begin with those bytes without being an API key.
    let unpadded = token.trim_end_matches('=');
    if unpadded.is_empty()
        || !unpadded.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
    {
        return None;
    }
    Some(token)
}

/// Applies the shared baseline product policy after credential resolution.
/// A valid identity-only OAuth token is forbidden, not unauthenticated.
pub(crate) fn require_product_access(auth: &Authentication) -> Result<(), AppError> {
    if let CredentialContext::OidcAccessToken { scopes, .. } = &auth.credential
        && !scopes.iter().any(|scope| scope == PRODUCT_API_SCOPE)
    {
        return Err(insufficient_scope());
    }
    Ok(())
}

fn insufficient_scope() -> AppError {
    AppError::Coded {
        status: axum::http::StatusCode::FORBIDDEN,
        code: "insufficient_scope",
        detail: format!("OIDC access token lacks required {PRODUCT_API_SCOPE} scope").into(),
    }
}

fn api_key_scope_violation() -> AppError {
    AppError::Coded {
        status: axum::http::StatusCode::FORBIDDEN,
        code: "api_key_scope_violation",
        detail: "organization-scoped API key cannot perform account-global operations".into(),
    }
}

/// Mirrors `auth.IsAPIKey`: `cw_` followed by exactly 64 hex chars.
fn is_api_key(token: &str) -> bool {
    token
        .strip_prefix("cw_")
        .is_some_and(|rest| rest.len() == 64)
}

/// Generates a fresh `cw_`-prefixed API key — `cw_` + 64 lowercase hex
/// chars (32 random bytes) — matching `auth.GenerateAPIKey` on the Go
/// side. Entropy comes from two v4 UUIDs (getrandom-backed); only the
/// format and length matter for cross-language compatibility, since the
/// stored hash is computed over the full string.
pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    format!("cw_{}", hex_lower(&bytes))
}

/// Mirrors `auth.HashAPIKey`: the SHA-256 hex digest of the full raw key
/// string (including the `cw_` prefix), as stored in
/// `api_keys.key_hash`.
pub fn hash_api_key(raw: &str) -> String {
    sha256_hex(raw)
}

/// The at-rest representation of an opaque OAuth token (access or
/// refresh): the SHA-256 hex digest of the raw token, as stored in
/// `oidc_access_tokens.token_hash` / `oidc_refresh_tokens.token_hash`.
/// Raw token values exist only in memory and in the one-time token
/// response; verification hashes the presented bearer and looks up the
/// digest — the same pattern `cw_` API keys use.
pub fn hash_oauth_token(raw: &str) -> String {
    sha256_hex(raw)
}

/// The at-rest representation of a browser or legacy CLI session token.
/// Hash-only writers persist this lowercase SHA-256 digest and never the raw
/// token; the nullable legacy column is removed by the later scrub work item.
pub fn hash_session_token(raw: &str) -> String {
    sha256_hex(raw)
}

fn sha256_hex(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex_lower(&hasher.finalize())
}

/// Mirrors `auth.PrefixFromKey`: the 8 hex chars immediately after the
/// `cw_` prefix, stored in `api_keys.key_prefix` for the indexed lookup.
/// Empty for malformed keys.
pub fn api_key_prefix(raw: &str) -> &str {
    raw.get("cw_".len().."cw_".len() + 8).unwrap_or("")
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

/// Extracts the value of the `codewire.session_token` cookie from the
/// request's `Cookie` header. RFC 6265 cookie strings are
/// `name=value; name2=value2; …` with no quoting for our purposes
/// (the service emits a hex-encoded 32-byte token), so a hand-rolled
/// parser avoids dragging in `axum-extra` for one field.
pub fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim_start();
        if let Some(value) = pair.strip_prefix(SESSION_COOKIE_NAME) {
            // Allow whitespace around the `=` even though the Go writer
            // never produces it, to match browser quirks observed in
            // the wild.
            let value = value.trim_start();
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.trim_end_matches(|c: char| c.is_whitespace()));
            }
        }
    }
    None
}

async fn authenticate_session_cookie(pool: &PgPool, token: &str) -> Result<AuthUser, AppError> {
    // Sliding expiry: mirrors `auth.GetSessionByToken` exactly for an enabled
    // account. Disabled users do not refresh their session expiry and cannot
    // reach a product or identity operation through an existing cookie.
    let token_hash = hash_session_token(token);
    let user: (String, bool) = sqlx::query_as(
        r#"
        UPDATE sessions AS session
           SET expires_at = GREATEST(session.expires_at, NOW() + $2::interval),
               updated_at = NOW()
          FROM users AS user_account
         WHERE session.token_hash = $1
           AND session.expires_at > NOW()
           AND session.user_id = user_account.id
           AND user_account.enabled
         RETURNING session.user_id, user_account.is_admin
        "#,
    )
    .bind(&token_hash)
    .bind(format!("{} seconds", SESSION_DURATION.num_seconds()))
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?
    .ok_or(AppError::Unauthorized)?;
    let (user_id, is_admin) = user;

    Ok(AuthUser {
        user_id,
        org_id: None,
        is_admin,
        via_api_key: false,
    })
}

#[derive(sqlx::FromRow)]
struct ApiKeyAuthRow {
    id: String,
    user_id: String,
    org_id: String,
    scopes: Vec<String>,
}

async fn authenticate_api_key(pool: &PgPool, full_token: &str) -> Result<Authentication, AppError> {
    // Hash the raw token with SHA-256 and store its hexadecimal digest.
    let mut hasher = Sha256::new();
    hasher.update(full_token.as_bytes());
    let hex = hex_lower(&hasher.finalize());

    // Use the indexed prefix plus full hash. `disabled_at` is a timestamp,
    // not a boolean, and only null values authenticate.
    let prefix = &full_token["cw_".len().."cw_".len() + 8];
    let row: Option<ApiKeyAuthRow> = sqlx::query_as(
        r#"
        SELECT a.id,
               a.user_id,
               a.org_id,
               a.scopes
          FROM api_keys a
          JOIN users u ON u.id = a.user_id
         WHERE a.key_prefix = $1
           AND a.key_hash = $2
           AND (a.expires_at IS NULL OR a.expires_at > NOW())
           AND a.disabled_at IS NULL
           AND u.enabled
        "#,
    )
    .bind(prefix)
    .bind(&hex)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;

    let row = row.ok_or(AppError::Unauthorized)?;

    touch_api_key_last_used_best_effort(pool, &row.id);

    Ok(Authentication {
        user: AuthUser {
            user_id: row.user_id,
            org_id: Some(row.org_id),
            // An org-scoped API key never inherits the owning user's global
            // administrator authority.
            is_admin: false,
            via_api_key: true,
        },
        credential: CredentialContext::ApiKey {
            key_id: row.id,
            scopes: row.scopes,
        },
        oauth_bearer_authority: None,
    })
}

/// Schedule approximate API-key usage bookkeeping outside authentication.
///
/// Authorization is decided by the preceding indexed read. `last_used_at` is
/// operational metadata, so a row lock, pool stall, or write failure must not
/// reject an otherwise valid credential. Coalescing keeps normal request
/// volume from producing one row update per RPC; the timeout bounds detached
/// work when the row or database is unavailable.
pub fn touch_api_key_last_used_best_effort(pool: &PgPool, key_id: &str) {
    let pool = pool.clone();
    let key_id = key_id.to_owned();
    std::mem::drop(tokio::spawn(async move {
        let update = sqlx::query(
            r#"WITH eligible AS (
                    SELECT key.id
                    FROM api_keys AS key
                    JOIN users AS user_account ON user_account.id = key.user_id
                    WHERE key.id = $1
                      AND user_account.enabled
                      AND (key.last_used_at IS NULL
                           OR key.last_used_at < NOW() - interval '1 minute')
                    FOR UPDATE OF key SKIP LOCKED
                )
                UPDATE api_keys AS key
                   SET last_used_at = NOW()
                  FROM eligible
                 WHERE key.id = eligible.id"#,
        )
        .bind(key_id)
        .execute(&pool);
        let _ = tokio::time::timeout(API_KEY_LAST_USED_TOUCH_TIMEOUT, update).await;
    }));
}

type OidcAccessTokenRow = (
    String,
    bool,
    String,
    Vec<String>,
    chrono::DateTime<chrono::Utc>,
);

/// Validates an opaque OIDC access token (auth-policy flavor 2) by direct
/// lookup against the idp's token store: hash the presented token, join
/// the subject and issuing client, and reject expired tokens and disabled
/// clients. Deliberately *not* a session lookup — access tokens keep the
/// fixed expiry the idp issued (no sliding window, no `sessions` write),
/// and validation never involves `SESSION_SECRET`.
async fn authenticate_oidc_access_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<Authentication>, AppError> {
    // Pin both clocks before awaiting identity lookup. A wall-clock rewind
    // during lookup or a later publication cannot renew elapsed authority.
    let captured_monotonic = std::time::Instant::now();
    let captured_wall = chrono::Utc::now();
    let digest = hash_oauth_token(token);
    let row: Option<OidcAccessTokenRow> = sqlx::query_as(
        r#"
        SELECT t.user_id,
               u.is_admin,
               t.client_id,
               t.scopes,
               t.expires_at
          FROM oidc_access_tokens t
          JOIN users u ON u.id = t.user_id
          JOIN oidc_clients c ON c.id = t.client_id
         WHERE t.token_hash = $1
           AND t.expires_at > NOW()
           AND NOT c.disabled
           AND u.enabled
        "#,
    )
    .bind(&digest)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;

    Ok(
        row.and_then(|(user_id, is_admin, client_id, scopes, expires_at)| {
            let authority = OAuthBearerAuthority::new(
                digest,
                user_id.clone(),
                client_id.clone(),
                expires_at,
                captured_monotonic,
                captured_wall,
            )?;
            Some(Authentication {
                oauth_bearer_authority: Some(authority),
                user: AuthUser {
                    user_id,
                    org_id: None,
                    is_admin,
                    via_api_key: false,
                },
                credential: CredentialContext::OidcAccessToken { client_id, scopes },
            })
        }),
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(header: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        h
    }

    fn auth_with(credential: CredentialContext) -> Authentication {
        Authentication {
            user: AuthUser {
                user_id: "user-1".into(),
                org_id: None,
                is_admin: true,
                via_api_key: false,
            },
            credential,
            oauth_bearer_authority: None,
        }
    }

    #[test]
    fn oidc_product_scope_is_exact_and_admin_independent() {
        let allowed = auth_with(CredentialContext::OidcAccessToken {
            client_id: "native-client".into(),
            scopes: vec!["openid".into(), PRODUCT_API_SCOPE.into()],
        });
        assert!(require_product_access(&allowed).is_ok());

        for lookalike in ["codewire.api.read", "Codewire.api", "codewire.ap"] {
            let denied = auth_with(CredentialContext::OidcAccessToken {
                client_id: "identity-client".into(),
                scopes: vec!["openid".into(), lookalike.into()],
            });
            assert!(matches!(
                require_product_access(&denied),
                Err(AppError::Coded {
                    status: axum::http::StatusCode::FORBIDDEN,
                    code: "insufficient_scope",
                    ..
                })
            ));
        }
    }

    #[test]
    fn account_credentials_require_global_admin_authorization() {
        for credential in [
            CredentialContext::SessionCookie,
            CredentialContext::OidcAccessToken {
                client_id: "native-client".into(),
                scopes: vec![PRODUCT_API_SCOPE.into()],
            },
        ] {
            let mut user = auth_with(credential).user;
            user.is_admin = false;
            assert!(matches!(
                user.require_global_admin(),
                Err(AppError::Forbidden)
            ));
            user.is_admin = true;
            assert!(user.require_global_admin().is_ok());
        }
    }

    #[test]
    fn org_scoped_api_key_cannot_become_account_or_global_admin_credential() {
        let mut user = auth_with(CredentialContext::ApiKey {
            key_id: "key-1".into(),
            scopes: Vec::new(),
        })
        .user;
        user.org_id = Some("org-1".into());
        user.via_api_key = true;
        user.is_admin = true;

        assert!(matches!(
            user.require_account_credential(),
            Err(AppError::Coded {
                status: axum::http::StatusCode::FORBIDDEN,
                code: "api_key_scope_violation",
                ..
            })
        ));
        assert!(matches!(
            user.require_global_admin(),
            Err(AppError::Coded {
                status: axum::http::StatusCode::FORBIDDEN,
                code: "api_key_scope_violation",
                ..
            })
        ));
        assert!(user.permits_organization("org-1"));
        assert!(!user.permits_organization("org-2"));
        user.org_id = None;
        assert!(!user.permits_organization("org-1"));
    }

    #[test]
    fn api_key_labels_are_not_oauth_scope_requirements() {
        for scopes in [vec![], vec!["future.label".into()]] {
            let auth = auth_with(CredentialContext::ApiKey {
                key_id: "key-1".into(),
                scopes,
            });
            assert!(require_product_access(&auth).is_ok());
        }
    }

    #[test]
    fn extracts_bearer_prefix_case_insensitively() {
        for header in ["Bearer cw_abc", "bearer cw_abc"] {
            let h = headers_with("authorization", header);
            assert_eq!(bearer_token(&h), Some("cw_abc"));
        }
    }

    #[test]
    fn rejects_requests_without_authorization_header() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn oauth_only_errors_do_not_retain_input_or_database_sources() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        pool.close().await;
        for value in ["Basic synthetic-invalid", "Bearer synthetic-opaque"] {
            let headers = headers_with("authorization", value);
            let error =
                resolve_oauth_bearer_authentication(&AuthState { pool: pool.clone() }, &headers)
                    .await
                    .unwrap_err();
            let rendered = format!("{error} {error:?}");
            for forbidden in ["synthetic", "PoolClosed", "postgres", "127.0.0.1"] {
                assert!(!rendered.contains(forbidden));
            }
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[tokio::test]
    async fn credential_mutation_rejects_invalid_session_authority_before_database_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic")
            .unwrap();
        let state = AuthState { pool };
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}=session-canary")
                .parse()
                .unwrap(),
        );
        headers.insert(
            http::header::ORIGIN,
            "https://attacker.example".parse().unwrap(),
        );
        let result = resolve_credential_mutation_authentication(
            &state,
            &headers,
            &http::HeaderValue::from_static("https://codewire.example"),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden)));

        let valid_origin = http::HeaderValue::from_static("https://codewire.example");
        let mut duplicate_fields = HeaderMap::new();
        duplicate_fields.append(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}=first-canary")
                .parse()
                .unwrap(),
        );
        duplicate_fields.append(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}=second-canary")
                .parse()
                .unwrap(),
        );
        duplicate_fields.insert(http::header::ORIGIN, valid_origin.clone());

        let mut duplicate_pairs = HeaderMap::new();
        duplicate_pairs.insert(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}=first-canary; {SESSION_COOKIE_NAME}=second-canary")
                .parse()
                .unwrap(),
        );
        duplicate_pairs.insert(http::header::ORIGIN, valid_origin.clone());

        let mut mixed = HeaderMap::new();
        mixed.insert(
            COOKIE,
            format!("{SESSION_COOKIE_NAME}=session-canary")
                .parse()
                .unwrap(),
        );
        mixed.insert(AUTHORIZATION, "Bearer oauth-canary".parse().unwrap());
        mixed.insert(http::header::ORIGIN, valid_origin.clone());

        for ambiguous in [&duplicate_fields, &duplicate_pairs, &mixed] {
            let result =
                resolve_credential_mutation_authentication(&state, ambiguous, &valid_origin).await;
            assert!(matches!(result, Err(AppError::Unauthorized)));
        }
    }

    #[test]
    fn extracts_session_cookie_from_singleton() {
        let h = headers_with("cookie", "codewire.session_token=deadbeef");
        assert_eq!(session_cookie(&h), Some("deadbeef"));
    }

    #[test]
    fn extracts_session_cookie_among_others() {
        let h = headers_with(
            "cookie",
            "other=1; codewire.session_token=abc123; trailing=2",
        );
        assert_eq!(session_cookie(&h), Some("abc123"));
    }

    #[test]
    fn extracts_session_cookie_with_whitespace_padding() {
        // Browsers and proxies are inconsistent about whitespace after
        // the `;` — assert we handle either form.
        let h = headers_with("cookie", "x=1;codewire.session_token=tok");
        assert_eq!(session_cookie(&h), Some("tok"));
    }

    #[test]
    fn ignores_partial_cookie_name_match() {
        // A different cookie that shares a prefix must not be picked up.
        let h = headers_with("cookie", "codewire.session_token_other=nope");
        assert_eq!(session_cookie(&h), None);
    }

    #[test]
    fn returns_none_when_session_cookie_absent() {
        let h = headers_with("cookie", "other=1; another=2");
        assert_eq!(session_cookie(&h), None);
    }

    #[test]
    fn api_key_format_requires_cw_prefix_and_64_hex_chars() {
        // Mirrors auth.IsAPIKey — a short or long token must NOT take the
        // API-key path (it falls through to the OIDC decrypt instead).
        assert!(is_api_key(&format!("cw_{}", "a".repeat(64))));
        assert!(!is_api_key(&format!("cw_{}", "a".repeat(63))));
        assert!(!is_api_key(&format!("cw_{}", "a".repeat(65))));
        assert!(!is_api_key(&"a".repeat(67)));
        assert!(!is_api_key("cw_"));
    }

    #[test]
    fn generated_api_key_is_well_formed_and_self_consistent() {
        let raw = generate_api_key();
        // Same format the middleware's is_api_key gate accepts.
        assert!(is_api_key(&raw), "generated key {raw} is not cw_+64hex");
        // The stored prefix is the 8 hex chars after cw_, exactly what the
        // authenticate_api_key lookup indexes on.
        assert_eq!(api_key_prefix(&raw), &raw["cw_".len().."cw_".len() + 8]);
        // The stored hash is sha256(full raw), the value the lookup matches.
        let mut h = Sha256::new();
        h.update(raw.as_bytes());
        assert_eq!(hash_api_key(&raw), hex_lower(&h.finalize()));
        // Two calls don't collide.
        assert_ne!(generate_api_key(), generate_api_key());
    }

    #[test]
    fn hex_lower_is_lowercase_hex() {
        let mut h = Sha256::new();
        h.update(b"cw_abc");
        let s = hex_lower(&h.finalize());
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        // Round-trip against the stdlib's format to lock in the encoding.
        let mut h = Sha256::new();
        h.update(b"cw_abc");
        let formatted: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(s, formatted);
    }

    #[test]
    fn oauth_token_hash_is_sha256_hex_of_raw() {
        // The at-rest digest the idp writes and authenticate_oidc_access_token
        // looks up: SHA-256 over the raw opaque token, lowercase hex.
        let raw = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let mut h = Sha256::new();
        h.update(raw.as_bytes());
        let expected: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hash_oauth_token(raw), expected);
        assert_eq!(hash_oauth_token(raw).len(), 64);
        assert_ne!(hash_oauth_token(raw), hash_oauth_token("other-token"));
    }

    #[test]
    fn session_token_hash_matches_fixed_sha256_vector() {
        assert_eq!(
            hash_session_token("contract-user-session-token"),
            "3408b549139c3c2e41b288c0366e894314250a6ef57582e77c14ff2a72bb6efb"
        );
        assert_eq!(hash_session_token(""), hash_oauth_token(""));
        assert!(
            hash_session_token("token")
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        );
    }
}
