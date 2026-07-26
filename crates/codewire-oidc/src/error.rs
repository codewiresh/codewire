//! OAuth 2.0 / OIDC error taxonomy.
//!
//! These map to the `error` codes defined by RFC 6749 §4.1.2.1 / §5.2 and
//! OpenID Connect Core. Authorization-endpoint errors are returned as a
//! redirect (`?error=…&error_description=…&state=…`); token/userinfo/etc.
//! errors are returned as `application/json` problem bodies. The provider
//! never reflects internal detail into `error_description`.

use std::fmt;

/// A protocol-level error with a stable OAuth `error` code.
///
/// The `description` is safe, caller-facing text (never internal detail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    /// The stable machine-readable code (e.g. `invalid_request`).
    pub code: ErrorCode,
    /// Human-readable, non-sensitive description.
    pub description: String,
}

impl OAuthError {
    /// Build an error with a code and description.
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }

    /// `invalid_request` — malformed/missing parameter.
    pub fn invalid_request(d: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, d)
    }
    /// `invalid_client` — client auth failed / unknown / disabled.
    pub fn invalid_client(d: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidClient, d)
    }
    /// `invalid_grant` — bad/expired/replayed code or refresh token.
    pub fn invalid_grant(d: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidGrant, d)
    }
    /// `access_denied` — the resource owner or policy denied the request.
    pub fn access_denied(d: impl Into<String>) -> Self {
        Self::new(ErrorCode::AccessDenied, d)
    }
    /// `server_error` — an unexpected provider-side failure.
    pub fn server_error(d: impl Into<String>) -> Self {
        Self::new(ErrorCode::ServerError, d)
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.description)
    }
}

impl std::error::Error for OAuthError {}

/// The RFC 6749 / OIDC Core `error` codes this provider emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `invalid_request`
    InvalidRequest,
    /// `invalid_client`
    InvalidClient,
    /// `invalid_grant`
    InvalidGrant,
    /// `invalid_token` (RFC 6750 — a bad/expired access token at a protected
    /// resource such as the userinfo endpoint)
    InvalidToken,
    /// `unauthorized_client`
    UnauthorizedClient,
    /// `unsupported_grant_type`
    UnsupportedGrantType,
    /// `unsupported_response_type`
    UnsupportedResponseType,
    /// `invalid_scope`
    InvalidScope,
    /// `access_denied`
    AccessDenied,
    /// `authorization_pending` (RFC 8628 — device flow, user hasn't approved yet)
    AuthorizationPending,
    /// `slow_down` (RFC 8628 — device flow, client is polling too fast)
    SlowDown,
    /// `expired_token` (RFC 8628 — device flow, the device_code expired)
    ExpiredToken,
    /// `login_required` (OIDC; e.g. `prompt=none` with no session)
    LoginRequired,
    /// `interaction_required` (OIDC)
    InteractionRequired,
    /// `server_error`
    ServerError,
    /// `temporarily_unavailable`
    TemporarilyUnavailable,
}

impl ErrorCode {
    /// The wire string for this code.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InvalidClient => "invalid_client",
            ErrorCode::InvalidGrant => "invalid_grant",
            ErrorCode::InvalidToken => "invalid_token",
            ErrorCode::UnauthorizedClient => "unauthorized_client",
            ErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            ErrorCode::UnsupportedResponseType => "unsupported_response_type",
            ErrorCode::InvalidScope => "invalid_scope",
            ErrorCode::AccessDenied => "access_denied",
            ErrorCode::AuthorizationPending => "authorization_pending",
            ErrorCode::SlowDown => "slow_down",
            ErrorCode::ExpiredToken => "expired_token",
            ErrorCode::LoginRequired => "login_required",
            ErrorCode::InteractionRequired => "interaction_required",
            ErrorCode::ServerError => "server_error",
            ErrorCode::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Errors a [`crate::store`] implementation can return. Kept opaque to the
/// library (it never inspects the cause) so the host's storage layer —
/// sqlx, in-memory, anything — stays behind the trait boundary.
#[derive(Debug, thiserror::Error)]
#[error("store error: {0}")]
pub struct StoreError(pub String);

impl StoreError {
    /// Wrap any displayable cause as a store error.
    pub fn new(cause: impl fmt::Display) -> Self {
        Self(cause.to_string())
    }
}

/// Convenience alias for store results.
pub type StoreResult<T> = Result<T, StoreError>;
