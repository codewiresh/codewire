//! Core protocol types — unbranded, named for OIDC/OAuth, not for any
//! particular deployment.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The provider's issuer identifier (an `https://` URL, or `http://` only
/// in explicitly-insecure dev mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer(pub String);

impl Issuer {
    /// The issuer as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A subject identifier (`sub`) — stable per end-user. This provider uses
/// **public** subjects (the same `sub` for every client), matching the Go
/// implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject(pub String);

/// An opaque identifier for an in-flight authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthRequestId(pub String);

/// A space-delimited OAuth scope set, kept order-preserving.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scopes(pub Vec<String>);

impl Scopes {
    /// Parse a space-delimited scope string (RFC 6749 §3.3).
    pub fn parse(s: &str) -> Self {
        Self(s.split_whitespace().map(str::to_owned).collect())
    }
    /// Whether `scope` is present.
    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|s| s == scope)
    }
    /// Render back to the space-delimited wire form.
    pub fn to_space_delimited(&self) -> String {
        self.0.join(" ")
    }
}

/// OAuth client application type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    /// Server-side web app (confidential).
    Web,
    /// Native/desktop app (public; PKCE required).
    Native,
    /// Browser/SPA (public).
    UserAgent,
}

/// Token-endpoint client authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// HTTP Basic (`client_secret_basic`).
    ClientSecretBasic,
    /// Form post (`client_secret_post`).
    ClientSecretPost,
    /// Public client, no secret (`none`) — PKCE required.
    None,
}

/// OAuth grant type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    /// `authorization_code`
    AuthorizationCode,
    /// `refresh_token`
    RefreshToken,
    /// `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628)
    DeviceCode,
}

/// OAuth response type. This provider supports `code` only (no implicit
/// or hybrid flows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// `code`
    Code,
}

/// A registered relying party, carrying the full `oidc_clients` capability
/// set the provider needs (the store maps its persistence to this).
#[derive(Debug, Clone)]
pub struct Client {
    /// `client_id`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Application type (drives the public/PKCE policy).
    pub application_type: ApplicationType,
    /// Token-endpoint auth method.
    pub auth_method: AuthMethod,
    /// Exact-match redirect URI allowlist.
    pub redirect_uris: Vec<String>,
    /// Exact-match post-logout redirect URI allowlist (end_session).
    pub post_logout_redirect_uris: Vec<String>,
    /// Allowed grant types.
    pub grant_types: Vec<GrantType>,
    /// Allowed response types (`code` only here).
    pub response_types: Vec<ResponseType>,
    /// Allowed scopes.
    pub scopes: Scopes,
    /// Whether the consent screen is skipped (true for all current clients).
    pub skip_consent: bool,
    /// Access-token lifetime (seconds).
    pub access_token_lifetime_secs: u64,
    /// ID-token lifetime (seconds).
    pub id_token_lifetime_secs: u64,
    /// Refresh-token lifetime (seconds); `None` = no refresh tokens.
    pub refresh_token_lifetime_secs: Option<u64>,
    /// Allowed clock skew for token validation (seconds).
    pub clock_skew_secs: u64,
    /// A disabled client is rejected at every endpoint.
    pub disabled: bool,
}

impl Client {
    /// Whether this is a public client (no secret; PKCE required).
    pub fn is_public(&self) -> bool {
        matches!(self.auth_method, AuthMethod::None)
    }
    /// Exact-match redirect URI validation (no substring/prefix/port
    /// wildcards — see threat T1).
    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }
    /// Exact-match post-logout redirect validation.
    pub fn allows_post_logout_redirect_uri(&self, uri: &str) -> bool {
        self.post_logout_redirect_uris.iter().any(|u| u == uri)
    }
}

/// Token/userinfo claims: the standard set plus order-stable extras
/// (e.g. `org_id`, `org_role`, `org_assignments`). Serialized flat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier.
    pub sub: String,
    /// `email` (email scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// `email_verified` (email scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// `name` (profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `picture` (profile scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Additional, deployment-specific claims (kept ordered for stable
    /// JSON), populated by the host's claim customizer.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// A parsed `/authorize` request (after syntactic validation).
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// `client_id`.
    pub client_id: String,
    /// `redirect_uri`.
    pub redirect_uri: String,
    /// `response_type` (only `code` supported).
    pub response_type: ResponseType,
    /// Requested scopes.
    pub scopes: Scopes,
    /// Opaque `state` round-tripped to the RP.
    pub state: Option<String>,
    /// `nonce` echoed into the id_token.
    pub nonce: Option<String>,
    /// PKCE `code_challenge`.
    pub code_challenge: Option<String>,
    /// PKCE `code_challenge_method` (`S256` only).
    pub code_challenge_method: Option<String>,
    /// OIDC `prompt`.
    pub prompt: Option<String>,
    /// OIDC `max_age` (seconds).
    pub max_age: Option<u64>,
}

/// A stored authorization request, once persisted by the store.
#[derive(Debug, Clone)]
pub struct StoredAuthRequest {
    /// The opaque id.
    pub id: AuthRequestId,
    /// The original request.
    pub request: AuthorizationRequest,
    /// The bound subject, once login completes.
    pub subject: Option<Subject>,
}

/// The grant captured when an authorization code is issued; consumed once
/// at the token endpoint.
#[derive(Debug, Clone)]
pub struct AuthCodeGrant {
    /// The client the code was issued to.
    pub client_id: String,
    /// The redirect URI the code is bound to.
    pub redirect_uri: String,
    /// The authenticated subject.
    pub subject: Subject,
    /// Granted scopes.
    pub scopes: Scopes,
    /// PKCE challenge to verify against the verifier at exchange.
    pub code_challenge: Option<String>,
    /// `nonce` to embed in the id_token.
    pub nonce: Option<String>,
    /// When the end-user authenticated (Unix seconds), carried into the
    /// id_token `auth_time` claim.
    pub auth_time: Option<i64>,
}

/// An issued opaque access token's backing record.
#[derive(Debug, Clone)]
pub struct AccessGrant {
    /// The subject the token authenticates.
    pub subject: Subject,
    /// The client the token was issued to.
    pub client_id: String,
    /// Token scopes.
    pub scopes: Scopes,
}

/// An issued refresh token's backing record (rotated on use).
#[derive(Debug, Clone)]
pub struct RefreshGrant {
    /// The subject.
    pub subject: Subject,
    /// The client.
    pub client_id: String,
    /// Scopes (may be down-scoped on refresh).
    pub scopes: Scopes,
}

/// The state of a device-authorization grant (RFC 8628).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    /// Awaiting the end-user's approval at the verification URI.
    Pending,
    /// The end-user approved; the device may now exchange its code.
    Approved {
        /// The authenticated subject.
        subject: Subject,
        /// When the user authenticated (for the id_token `auth_time`).
        auth_time: Option<i64>,
    },
    /// The end-user explicitly denied the request.
    Denied,
}

/// A stored device-authorization grant (RFC 8628). The `device_code` is the
/// secret the device polls with; the `user_code` is the short human-entered
/// code shown at the verification URI.
#[derive(Clone)]
pub struct DeviceAuthorization {
    /// The opaque device code (polled at the token endpoint).
    pub device_code: String,
    /// The short, human-friendly user code.
    pub user_code: String,
    /// The client that started the flow.
    pub client_id: String,
    /// Requested scopes.
    pub scopes: Scopes,
    /// Current status.
    pub status: DeviceStatus,
}

impl fmt::Debug for DeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("status", &self.status)
            .finish()
    }
}

/// Ambient request context the host supplies to [`crate::store::UserAuthenticator`]
/// (e.g. session cookie, headers) — opaque to the library.
#[derive(Default, Clone)]
pub struct RequestContext {
    /// Raw cookie header, if any (the host interprets it).
    pub cookie: Option<String>,
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestContext")
            .field("cookie", &self.cookie.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[cfg(test)]
mod secret_debug_tests {
    use super::*;

    #[test]
    fn device_authorization_debug_redacts_capabilities() {
        let value = DeviceAuthorization {
            device_code: "device-capability-marker".into(),
            user_code: "user-capability-marker".into(),
            client_id: "client".into(),
            scopes: Scopes(vec!["openid".into()]),
            status: DeviceStatus::Pending,
        };

        let diagnostic = format!("{value:?}");
        assert!(!diagnostic.contains("device-capability-marker"));
        assert!(!diagnostic.contains("user-capability-marker"));
        assert!(diagnostic.contains("[REDACTED]"));
        assert!(diagnostic.contains("client"));
    }

    #[test]
    fn request_context_debug_redacts_cookie() {
        let context = RequestContext {
            cookie: Some("session-cookie-marker".into()),
        };

        let diagnostic = format!("{context:?}");
        assert!(!diagnostic.contains("session-cookie-marker"));
        assert!(diagnostic.contains("[REDACTED]"));
    }
}

/// Outcome of resolving the end-user for an authorization request.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// The user is authenticated; proceed to issue a code for this subject.
    Authenticated {
        /// The resolved end-user.
        subject: Subject,
        /// When the end-user authenticated (Unix seconds), for the id_token
        /// `auth_time` claim. `None` if the host doesn't track it.
        auth_time: Option<i64>,
    },
    /// No live session — redirect the user agent to this login URL.
    NeedsLogin(String),
    /// Policy denied (e.g. not a member of the resource's org).
    Denied(String),
}
