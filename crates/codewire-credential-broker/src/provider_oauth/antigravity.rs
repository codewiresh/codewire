//! Antigravity's own Google OAuth sign-in, run by Codewire as Antigravity's
//! public Google Desktop OAuth client (#6555).
//!
//! The flow is authorization code with PKCE S256 and Antigravity's manual
//! redirect (`https://antigravity.google/oauth-callback`): the person signs in
//! in their browser and pastes the raw authorization code Google shows, a
//! callback URL, or `code#state`.
//! [`AntigravitySignIn::start`] creates the PKCE verifier and state and builds
//! the authorize URL; [`AntigravitySignIn::complete`] checks state when
//! supplied, exchanges the code at `POST https://oauth2.googleapis.com/token`
//! (form-encoded with `client_id`, `client_secret`, and `code_verifier`),
//! validates granted scopes and `id_token` `iss`/`aud`, and returns the
//! canonical import.
//!
//! Per Google's installed-application OAuth specification and the owner's
//! 2026-11-25 decision on #6555, Desktop OAuth `client_id` and `client_secret`
//! are built-in public client identifiers (zero OpenBao dependency for `--cloud`
//! and `--local`). The runtime still keeps `client_secret` zeroized/redacted
//! in logs and errors, and sends it strictly to `POST https://oauth2.googleapis.com/token`
//! (never to `/revoke` or any other host/path).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use rand::RngCore as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use super::{ProviderRevocation, RevocationFailure, Secret, call, decode_json, revoke_request};
use crate::BrokerUpstreamTransport;
use crate::antigravity_oauth::{
    ANTIGRAVITY_ALLOWED_SCOPES, AntigravityIssuedTokens, AntigravityOAuthCredential,
    AntigravityOAuthImport, import_antigravity_tokens,
};

/// Antigravity's public Google Desktop OAuth client ID.
pub(crate) const ANTIGRAVITY_OAUTH_CLIENT_ID: &str =
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
/// Antigravity's public Google Desktop OAuth client secret (installed-app
/// public identifier; sent only to `POST https://oauth2.googleapis.com/token`).
pub(crate) const ANTIGRAVITY_OAUTH_CLIENT_SECRET: &str = "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";

pub(crate) const GOOGLE_OAUTH_HOST: &str = "oauth2.googleapis.com";
pub(crate) const GOOGLE_TOKEN_PATH: &str = "/token";
pub(crate) const GOOGLE_REVOKE_PATH: &str = "/revoke";
pub(crate) const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) const GOOGLE_REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";
pub const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/auth";
pub(crate) const ANTIGRAVITY_MANUAL_REDIRECT_URL: &str =
    "https://antigravity.google/oauth-callback";

/// How long a started sign-in may be completed.
pub const ANTIGRAVITY_SIGN_IN_LIFETIME: Duration = Duration::from_secs(15 * 60);
const MAX_HANDLE_CLOCK_SKEW_SECONDS: u64 = 60;
const HANDLE_VERSION: &str = "cwag1";
const RANDOM_BYTES: usize = 32;
const RANDOM_TEXT_BYTES: usize = 43;
const MAX_CODE_BYTES: usize = 1024;
const MAX_PASTE_BYTES: usize = 4096;

pub const ANTIGRAVITY_SIGN_IN_CODE_INVALID: &str = "the pasted URL or code is not from this Antigravity sign-in; paste the callback URL or code shown after signing in, or start again";
pub const ANTIGRAVITY_SIGN_IN_EXPIRED: &str = "the Antigravity sign-in expired; start a new one";

/// Typed sign-in outcomes. None carries provider text, the code, or a token.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AntigravitySignInError {
    #[error("the pasted URL or code is not from this Antigravity sign-in")]
    InvalidCode,
    #[error("the Antigravity sign-in expired before it was completed")]
    Expired,
    #[error("Google refused the Antigravity sign-in code")]
    Denied,
    #[error("Google is unavailable")]
    Unavailable,
    #[error("Google's response is invalid")]
    InvalidResponse,
}

/// Runs Antigravity Google sign-ins over one provider transport admitting only
/// `POST https://oauth2.googleapis.com/token`.
pub struct AntigravitySignIn {
    upstream: Arc<dyn BrokerUpstreamTransport>,
}

pub struct StartedAntigravitySignIn {
    authorize_url: String,
    handle: Zeroizing<String>,
    expires_at_unix: u64,
}

impl StartedAntigravitySignIn {
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn into_handle(self) -> Zeroizing<String> {
        self.handle
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl std::fmt::Debug for StartedAntigravitySignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedAntigravitySignIn")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

struct Handle {
    state: Secret,
    verifier: Secret,
    issued_at_unix: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Secret,
    #[serde(default)]
    refresh_token: Option<Secret>,
    #[serde(default)]
    id_token: Option<Secret>,
    expires_in: u64,
    #[serde(default)]
    scope: Option<String>,
}

impl TokenResponse {
    fn into_tokens(self) -> AntigravityIssuedTokens {
        AntigravityIssuedTokens {
            access_token: self.access_token.into_inner(),
            refresh_token: self
                .refresh_token
                .filter(|token| !token.expose().is_empty())
                .map(Secret::into_inner),
            id_token: self
                .id_token
                .filter(|token| !token.expose().is_empty())
                .map(Secret::into_inner),
            expires_in: self.expires_in,
            scope: self.scope,
        }
    }
}

impl AntigravitySignIn {
    pub fn new(upstream: Arc<dyn BrokerUpstreamTransport>) -> Self {
        Self { upstream }
    }

    /// Create this sign-in's PKCE verifier, state, and Google authorize URL.
    pub fn start(&self) -> Result<StartedAntigravitySignIn, AntigravitySignInError> {
        start_at(now_unix()?)
    }

    /// Validate the pasted raw authorization code, callback URL, or
    /// `code#state` against `handle` (verifying `state` in constant time when
    /// supplied), exchange the code at `POST https://oauth2.googleapis.com/token`
    /// with the PKCE verifier, and return the canonical import.
    pub async fn complete(
        &self,
        handle: &str,
        pasted: &str,
    ) -> Result<AntigravityOAuthImport, AntigravitySignInError> {
        let handle = parse_handle(handle)?;
        let now = now_unix()?;
        if handle.issued_at_unix > now.saturating_add(MAX_HANDLE_CLOCK_SKEW_SECONDS) {
            return Err(AntigravitySignInError::InvalidCode);
        }
        if now
            >= handle
                .issued_at_unix
                .saturating_add(ANTIGRAVITY_SIGN_IN_LIFETIME.as_secs())
        {
            return Err(AntigravitySignInError::Expired);
        }
        let code = parse_pasted_code(pasted, handle.state.expose())?;
        let tokens = self.exchange(&code, &handle).await?;
        import_antigravity_tokens(tokens.into_tokens())
            .map_err(|_| AntigravitySignInError::InvalidResponse)
    }

    async fn exchange(
        &self,
        code: &Secret,
        handle: &Handle,
    ) -> Result<TokenResponse, AntigravitySignInError> {
        let body = Zeroizing::new({
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code");
            form.append_pair("code", code.expose());
            form.append_pair("redirect_uri", ANTIGRAVITY_MANUAL_REDIRECT_URL);
            form.append_pair("client_id", ANTIGRAVITY_OAUTH_CLIENT_ID);
            form.append_pair("client_secret", ANTIGRAVITY_OAUTH_CLIENT_SECRET);
            form.append_pair("code_verifier", handle.verifier.expose());
            form.finish().into_bytes()
        });
        let (status, body) = call(
            &self.upstream,
            Method::POST,
            GOOGLE_TOKEN_URL,
            form_headers(),
            body,
        )
        .await
        .map_err(transport_error)?;
        if matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED) {
            return Err(AntigravitySignInError::Denied);
        }
        check_status(status)?;
        decode_json(&body).map_err(|_| AntigravitySignInError::InvalidResponse)
    }
}

/// Form-encoded refresh request body and pinned target URL for
/// `POST https://oauth2.googleapis.com/token`.
pub(crate) fn refresh_request(
    refresh_token: &str,
) -> Result<(Url, Zeroizing<Vec<u8>>), AntigravitySignInError> {
    let target =
        Url::parse(GOOGLE_TOKEN_URL).map_err(|_| AntigravitySignInError::InvalidResponse)?;
    let body = Zeroizing::new({
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "refresh_token");
        form.append_pair("refresh_token", refresh_token);
        form.append_pair("client_id", ANTIGRAVITY_OAUTH_CLIENT_ID);
        form.append_pair("client_secret", ANTIGRAVITY_OAUTH_CLIENT_SECRET);
        form.finish().into_bytes()
    });
    Ok((target, body))
}

/// Parse the JSON token response from `POST https://oauth2.googleapis.com/token`
/// during a refresh exchange.
pub(crate) fn parse_refresh_response(
    body: &[u8],
) -> Result<AntigravityIssuedTokens, AntigravitySignInError> {
    let response: TokenResponse =
        decode_json(body).map_err(|_| AntigravitySignInError::InvalidResponse)?;
    Ok(response.into_tokens())
}

/// Whether `material` is a canonical stored Antigravity OAuth envelope.
/// Secret-free predicate used by the confined local revocation executor.
pub fn is_stored_bundle(material: &[u8]) -> bool {
    AntigravityOAuthCredential::parse(material).is_ok()
}

/// Revoke a stored Antigravity Google OAuth credential via RFC 7009
/// `POST https://oauth2.googleapis.com/revoke` (body-only `token`,
/// `query().is_none()`, and NO `client_secret`, #6555).
pub async fn revoke_stored(
    upstream: &Arc<dyn BrokerUpstreamTransport>,
    material: &[u8],
) -> ProviderRevocation {
    match AntigravityOAuthCredential::parse(material) {
        Ok(credential) => revoke_refresh_token(upstream, credential.refresh_token()).await,
        Err(_) => ProviderRevocation::Failed(RevocationFailure::Unreadable),
    }
}

pub(crate) async fn revoke_refresh_token(
    upstream: &Arc<dyn BrokerUpstreamTransport>,
    refresh_token: &str,
) -> ProviderRevocation {
    let body = Zeroizing::new({
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("token", refresh_token);
        form.finish().into_bytes()
    });
    revoke_request(
        upstream,
        Method::POST,
        GOOGLE_REVOKE_URL,
        form_headers(),
        body,
        StatusCode::OK,
    )
    .await
}

fn form_headers() -> HeaderMap {
    HeaderMap::from_iter([
        (header::ACCEPT, HeaderValue::from_static("application/json")),
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ),
    ])
}

fn start_at(now_unix: u64) -> Result<StartedAntigravitySignIn, AntigravitySignInError> {
    let mut raw_verifier = Zeroizing::new([0_u8; RANDOM_BYTES]);
    let mut raw_state = Zeroizing::new([0_u8; RANDOM_BYTES]);
    rand::rngs::OsRng.fill_bytes(&mut *raw_verifier);
    rand::rngs::OsRng.fill_bytes(&mut *raw_state);
    let verifier =
        Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*raw_verifier));
    let state = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*raw_state));
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let mut url =
        Url::parse(GOOGLE_AUTHORIZE_URL).map_err(|_| AntigravitySignInError::InvalidResponse)?;
    url.query_pairs_mut()
        .append_pair("client_id", ANTIGRAVITY_OAUTH_CLIENT_ID)
        .append_pair("redirect_uri", ANTIGRAVITY_MANUAL_REDIRECT_URL)
        .append_pair("response_type", "code")
        .append_pair("scope", &ANTIGRAVITY_ALLOWED_SCOPES.join(" "))
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state);
    let handle = Zeroizing::new(format!(
        "{HANDLE_VERSION}:{now_unix}:{}:{}",
        state.as_str(),
        verifier.as_str()
    ));
    let expires_at_unix = now_unix.saturating_add(ANTIGRAVITY_SIGN_IN_LIFETIME.as_secs());
    Ok(StartedAntigravitySignIn {
        authorize_url: url.into(),
        handle,
        expires_at_unix,
    })
}

fn parse_handle(raw: &str) -> Result<Handle, AntigravitySignInError> {
    let mut parts = raw.split(':');
    let (Some(version), Some(issued), Some(state), Some(verifier), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(AntigravitySignInError::InvalidCode);
    };
    if version != HANDLE_VERSION
        || state.len() != RANDOM_TEXT_BYTES
        || verifier.len() != RANDOM_TEXT_BYTES
        || !is_base64url(state)
        || !is_base64url(verifier)
    {
        return Err(AntigravitySignInError::InvalidCode);
    }
    let issued_at_unix = issued
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(AntigravitySignInError::InvalidCode)?;
    Ok(Handle {
        state: Secret::new(state.to_owned()),
        verifier: Secret::new(verifier.to_owned()),
        issued_at_unix,
    })
}

/// Parse a pasted callback URL (`https://antigravity.google/oauth-callback?code=...`),
/// `code#state`, or raw Google authorization code (as copied from
/// `antigravity.google/oauth-callback`, which strips query parameters from the
/// address bar and copies only `code`). When `state` is supplied it must match
/// the started sign-in in constant time; PKCE `code_verifier` in the sealed
/// handle authenticates the exchange with Google's `/token` endpoint.
fn parse_pasted_code(pasted: &str, expected_state: &str) -> Result<Secret, AntigravitySignInError> {
    let trimmed = pasted.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PASTE_BYTES {
        return Err(AntigravitySignInError::InvalidCode);
    }
    let (code, state) = if is_http_url(trimmed) {
        let parsed = Url::parse(trimmed).map_err(|_| AntigravitySignInError::InvalidCode)?;
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        for (name, value) in parsed.query_pairs() {
            if name == "code" {
                if code.is_some() {
                    return Err(AntigravitySignInError::InvalidCode);
                }
                code = Some(value.into_owned());
            } else if name == "state" {
                if state.is_some() {
                    return Err(AntigravitySignInError::InvalidCode);
                }
                state = Some(value.into_owned());
            }
        }
        (code.ok_or(AntigravitySignInError::InvalidCode)?, state)
    } else if let Some((code, state)) = trimmed.split_once('#') {
        (code.to_owned(), Some(state.to_owned()))
    } else {
        if looks_like_malformed_url(trimmed) {
            return Err(AntigravitySignInError::InvalidCode);
        }
        (trimmed.to_owned(), None)
    };
    if code.is_empty()
        || code.len() > MAX_CODE_BYTES
        || !code.bytes().all(|byte| byte.is_ascii_graphic())
        || state
            .as_deref()
            .is_some_and(|value| !ct_eq(value.as_bytes(), expected_state.as_bytes()))
    {
        return Err(AntigravitySignInError::InvalidCode);
    }
    Ok(Secret::new(code))
}

fn is_http_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
        || bytes
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
}

fn looks_like_malformed_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.contains("://")
        || value.contains('?')
        || bytes
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http:"))
        || bytes
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https:"))
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&a, &b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn now_unix() -> Result<u64, AntigravitySignInError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AntigravitySignInError::Unavailable)
}

fn transport_error(error: super::DeviceLoginError) -> AntigravitySignInError {
    match error {
        super::DeviceLoginError::Unavailable => AntigravitySignInError::Unavailable,
        _ => AntigravitySignInError::InvalidResponse,
    }
}

#[cfg(test)]
#[path = "antigravity_tests.rs"]
mod tests;

fn check_status(status: StatusCode) -> Result<(), AntigravitySignInError> {
    if status.is_success() {
        Ok(())
    } else if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        Err(AntigravitySignInError::Unavailable)
    } else {
        Err(AntigravitySignInError::InvalidResponse)
    }
}
