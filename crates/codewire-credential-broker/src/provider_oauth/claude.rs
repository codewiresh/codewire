//! Claude Code's own claude.ai sign-in, run by Codewire as Claude Code's
//! public OAuth client.
//!
//! The flow is the authorization code with PKCE and Claude's manual redirect:
//! a platform service cannot receive Claude Code's `localhost` callback, so the
//! person signs in in their browser and pastes the `code#state` Claude shows.
//! [`ClaudeSignIn::start`] creates the PKCE verifier and state and builds the
//! authorize URL; [`ClaudeSignIn::complete`] checks the pasted state, exchanges
//! the code, reads the plan from Claude's OAuth profile and returns the
//! canonical import. The same token endpoint refreshes a stored sign-in
//! ([`refresh_request`]); that is the broker's job, never the Sandbox's.
//!
//! The request shapes follow the pinned Claude Code 2.1.308: JSON bodies, the
//! `state` in the code exchange, the granted `scope` on refresh, and the
//! previous refresh token kept when a refresh returns none. Codewire asks for
//! Claude Code's claude.ai scopes without `org:create_api_key`.
//!
//! Portions derived from pi, Copyright (c) 2025 Mario Zechner, MIT License
//! (PKCE, the state, the authorize URL, parsing the pasted code, and the
//! exchange and refresh request and response handling):
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to
//! deal in the Software without restriction, including without limitation the
//! rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
//! sell copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in
//! all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//! FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
//! IN THE SOFTWARE.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use super::{Secret, call, decode_json};
use crate::BrokerUpstreamTransport;
use crate::claude_oauth::{
    ClaudeIssuedTokens, ClaudeOAuthImport, ClaudeProfile, ClaudeSubscriptionType,
    import_claude_tokens,
};

/// The public OAuth client of Claude Code. Codewire signs in and refreshes as
/// this client, so the tokens are the ones Claude Code itself uses.
pub(crate) const CLAUDE_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// Claude's token endpoint, for both the code exchange and refresh.
pub(crate) const CLAUDE_TOKEN_HOST: &str = "platform.claude.com";
pub(crate) const CLAUDE_TOKEN_PATH: &str = "/v1/oauth/token";
const CLAUDE_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
/// Claude's OAuth profile, read once with a new sign-in for its plan.
pub(crate) const CLAUDE_PROFILE_PATH: &str = "/api/oauth/profile";
const CLAUDE_PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
/// The claude.ai subscription sign-in, not the Console's API-key login.
const CLAUDE_AUTHORIZE_URL: &str = "https://claude.com/cai/oauth/authorize";
/// The page that shows `code#state` for the person to paste.
const CLAUDE_MANUAL_REDIRECT_URL: &str = "https://platform.claude.com/oauth/code/callback";
/// Claude Code's claude.ai scopes in the pinned 2.1.308, never
/// `org:create_api_key`. `user:profile` enables `/usage` and the plan.
pub const CLAUDE_SIGN_IN_SCOPES: [&str; 6] = [
    "user:profile",
    "user:inference",
    "user:sessions:claude_code",
    "user:mcp_servers",
    "user:file_upload",
    "user:plugins",
];
/// How long a started sign-in may be completed.
pub const CLAUDE_SIGN_IN_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// A handle dated this far in the future is refused: a clock fault, not a login.
const MAX_HANDLE_CLOCK_SKEW_SECONDS: u64 = 60;
const HANDLE_VERSION: &str = "cwcs1";
const RANDOM_BYTES: usize = 32;
/// 32 random bytes in unpadded base64url.
const RANDOM_TEXT_BYTES: usize = 43;
const MAX_CODE_BYTES: usize = 1024;
const MAX_PASTE_BYTES: usize = 4096;
const MAX_PROFILE_TEXT_BYTES: usize = 256;

/// Typed sign-in outcomes. None carries provider text, the code or a token.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClaudeSignInError {
    /// The pasted value is not `code#state` from this sign-in.
    #[error("the pasted code is not from this Claude sign-in")]
    InvalidCode,
    /// The sign-in was started too long ago.
    #[error("the Claude sign-in expired before it was completed")]
    Expired,
    /// Claude refused the code, for example because it was already used.
    #[error("Claude refused the sign-in code")]
    Denied,
    /// Claude could not be reached or answered with a server error.
    #[error("Claude is unavailable")]
    Unavailable,
    /// Claude answered outside the documented protocol.
    #[error("Claude's response is invalid")]
    InvalidResponse,
}

/// Runs Claude sign-ins over one provider transport, which must admit only
/// Claude's token endpoint and the OAuth profile read.
pub struct ClaudeSignIn {
    upstream: Arc<dyn BrokerUpstreamTransport>,
}

/// A started sign-in: the authorize URL to open, and the handle that only
/// [`ClaudeSignIn::complete`] reads. The handle carries this sign-in's PKCE
/// verifier and state; the client that started the sign-in keeps it private
/// and returns it unchanged. It grants nothing alone: the provider redeems the
/// verifier only with the code it issued to the person who signed in.
pub struct StartedClaudeSignIn {
    authorize_url: String,
    handle: Zeroizing<String>,
    expires_at_unix: u64,
}

impl StartedClaudeSignIn {
    /// Claude's fixed authorize page with this sign-in's challenge and state.
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

impl std::fmt::Debug for StartedClaudeSignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedClaudeSignIn")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish_non_exhaustive()
    }
}

struct Handle {
    state: Secret,
    verifier: Secret,
    issued_at_unix: u64,
}

#[derive(Serialize)]
struct CodeExchange<'a> {
    grant_type: &'static str,
    code: &'a str,
    redirect_uri: &'static str,
    client_id: &'static str,
    code_verifier: &'a str,
    state: &'a str,
}

#[derive(Serialize)]
struct RefreshExchange<'a> {
    grant_type: &'static str,
    refresh_token: &'a str,
    client_id: &'static str,
    scope: String,
}

/// The token endpoint's JSON. Unknown fields (the account and organization
/// summaries, `token_type`) are ignored.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: Secret,
    #[serde(default)]
    refresh_token: Option<Secret>,
    expires_in: u64,
    #[serde(default)]
    refresh_token_expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

impl TokenResponse {
    fn into_tokens(self) -> ClaudeIssuedTokens {
        ClaudeIssuedTokens {
            access_token: self.access_token.into_inner(),
            refresh_token: self
                .refresh_token
                .filter(|token| !token.expose().is_empty())
                .map(Secret::into_inner),
            expires_in: self.expires_in,
            refresh_token_expires_in: self.refresh_token_expires_in,
            scope: self.scope,
        }
    }
}

#[derive(Default, Deserialize)]
struct ProfileResponse {
    #[serde(default)]
    account: Option<ProfileAccount>,
    #[serde(default)]
    organization: Option<ProfileOrganization>,
}

#[derive(Default, Deserialize)]
struct ProfileAccount {
    #[serde(default)]
    email: Option<String>,
}

#[derive(Default, Deserialize)]
struct ProfileOrganization {
    #[serde(default)]
    organization_type: Option<String>,
    #[serde(default)]
    rate_limit_tier: Option<String>,
}

impl ClaudeSignIn {
    pub fn new(upstream: Arc<dyn BrokerUpstreamTransport>) -> Self {
        Self { upstream }
    }

    /// Create this sign-in's PKCE verifier and state and the authorize URL.
    /// Nothing is sent and nothing is stored.
    pub fn start(&self) -> Result<StartedClaudeSignIn, ClaudeSignInError> {
        start_at(now_unix()?)
    }

    /// Check the pasted `code#state` against the handle, exchange the code,
    /// read the plan and return the canonical import. Every failure drops the
    /// tokens from memory; nothing revokes them at Claude.
    pub async fn complete(
        &self,
        handle: &str,
        pasted: &str,
    ) -> Result<ClaudeOAuthImport, ClaudeSignInError> {
        let handle = parse_handle(handle)?;
        let now = now_unix()?;
        if handle.issued_at_unix > now.saturating_add(MAX_HANDLE_CLOCK_SKEW_SECONDS) {
            return Err(ClaudeSignInError::InvalidCode);
        }
        if now
            >= handle
                .issued_at_unix
                .saturating_add(CLAUDE_SIGN_IN_LIFETIME.as_secs())
        {
            return Err(ClaudeSignInError::Expired);
        }
        let code = parse_pasted_code(pasted, handle.state.expose())?;
        let tokens = self.exchange(&code, &handle).await?;
        let profile = self.profile(tokens.access_token.expose()).await?;
        import_claude_tokens(tokens.into_tokens(), profile)
            .map_err(|_| ClaudeSignInError::InvalidResponse)
    }

    async fn exchange(
        &self,
        code: &Secret,
        handle: &Handle,
    ) -> Result<TokenResponse, ClaudeSignInError> {
        let body = Zeroizing::new(
            serde_json::to_vec(&CodeExchange {
                grant_type: "authorization_code",
                code: code.expose(),
                redirect_uri: CLAUDE_MANUAL_REDIRECT_URL,
                client_id: CLAUDE_OAUTH_CLIENT_ID,
                code_verifier: handle.verifier.expose(),
                state: handle.state.expose(),
            })
            .map_err(|_| ClaudeSignInError::InvalidResponse)?,
        );
        let (status, body) = call(
            &self.upstream,
            Method::POST,
            CLAUDE_TOKEN_URL,
            json_headers(),
            body,
        )
        .await
        .map_err(transport_error)?;
        if matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED) {
            return Err(ClaudeSignInError::Denied);
        }
        check_status(status)?;
        decode_json(&body).map_err(|_| ClaudeSignInError::InvalidResponse)
    }

    async fn profile(&self, access_token: &str) -> Result<ClaudeProfile, ClaudeSignInError> {
        let mut bearer = Zeroizing::new(String::with_capacity(7 + access_token.len()));
        bearer.push_str("Bearer ");
        bearer.push_str(access_token);
        let mut authorization =
            HeaderValue::from_str(&bearer).map_err(|_| ClaudeSignInError::InvalidResponse)?;
        authorization.set_sensitive(true);
        let mut headers = json_headers();
        headers.insert(header::AUTHORIZATION, authorization);
        let (status, body) = call(
            &self.upstream,
            Method::GET,
            CLAUDE_PROFILE_URL,
            headers,
            Zeroizing::new(Vec::new()),
        )
        .await
        .map_err(transport_error)?;
        check_status(status)?;
        let profile: ProfileResponse =
            decode_json(&body).map_err(|_| ClaudeSignInError::InvalidResponse)?;
        let organization = profile.organization.unwrap_or_default();
        Ok(ClaudeProfile {
            email: profile
                .account
                .and_then(|account| account.email)
                .filter(|email| email.len() <= MAX_PROFILE_TEXT_BYTES),
            subscription_type: organization
                .organization_type
                .as_deref()
                .and_then(ClaudeSubscriptionType::from_organization_type),
            rate_limit_tier: organization
                .rate_limit_tier
                .filter(|tier| tier.len() <= MAX_PROFILE_TEXT_BYTES),
        })
    }
}

/// The JSON body and target of one refresh of a stored sign-in, asking again
/// for exactly the scopes it was granted, as Claude Code does.
pub(crate) fn refresh_request(
    refresh_token: &str,
    scopes: &[String],
) -> Result<(Url, Zeroizing<Vec<u8>>), ClaudeSignInError> {
    let body = Zeroizing::new(
        serde_json::to_vec(&RefreshExchange {
            grant_type: "refresh_token",
            refresh_token,
            client_id: CLAUDE_OAUTH_CLIENT_ID,
            scope: scopes.join(" "),
        })
        .map_err(|_| ClaudeSignInError::InvalidResponse)?,
    );
    let target = Url::parse(CLAUDE_TOKEN_URL).map_err(|_| ClaudeSignInError::InvalidResponse)?;
    Ok((target, body))
}

/// Parse a successful refresh answer. An absent refresh token means the
/// previous one stays.
pub(crate) fn parse_refresh_response(body: &[u8]) -> Result<ClaudeIssuedTokens, ClaudeSignInError> {
    let response: TokenResponse =
        serde_json::from_slice(body).map_err(|_| ClaudeSignInError::InvalidResponse)?;
    if response.access_token.expose().is_empty() {
        return Err(ClaudeSignInError::InvalidResponse);
    }
    Ok(response.into_tokens())
}

fn start_at(now: u64) -> Result<StartedClaudeSignIn, ClaudeSignInError> {
    let verifier = random_text();
    let state = random_text();
    let challenge = s256_challenge(&verifier);
    let authorize_url = authorize_url(&challenge, &state)?;
    let handle = Zeroizing::new(format!(
        "{HANDLE_VERSION}.{}.{}.{now}",
        state.as_str(),
        verifier.as_str()
    ));
    Ok(StartedClaudeSignIn {
        authorize_url,
        handle,
        expires_at_unix: now.saturating_add(CLAUDE_SIGN_IN_LIFETIME.as_secs()),
    })
}

/// Claude Code's claude.ai authorize request: `code=true`, the public client,
/// the manual redirect, the scopes, the S256 challenge and the state.
fn authorize_url(challenge: &str, state: &str) -> Result<String, ClaudeSignInError> {
    let mut url = Url::parse(CLAUDE_AUTHORIZE_URL).map_err(|_| ClaudeSignInError::Unavailable)?;
    url.query_pairs_mut()
        .append_pair("code", "true")
        .append_pair("client_id", CLAUDE_OAUTH_CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", CLAUDE_MANUAL_REDIRECT_URL)
        .append_pair("scope", &CLAUDE_SIGN_IN_SCOPES.join(" "))
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state);
    Ok(url.into())
}

/// RFC 7636 S256: the unpadded base64url SHA-256 of the verifier.
fn s256_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_text() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0_u8; RANDOM_BYTES]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*bytes))
}

fn random_text_shape(value: &str) -> bool {
    value.len() == RANDOM_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn parse_handle(value: &str) -> Result<Handle, ClaudeSignInError> {
    let mut parts = value.split('.');
    let (Some(HANDLE_VERSION), Some(state), Some(verifier), Some(issued), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(ClaudeSignInError::InvalidCode);
    };
    if !random_text_shape(state)
        || !random_text_shape(verifier)
        || issued.is_empty()
        || issued.len() > 20
        || !issued.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ClaudeSignInError::InvalidCode);
    }
    Ok(Handle {
        state: Secret::new(state.to_owned()),
        verifier: Secret::new(verifier.to_owned()),
        issued_at_unix: issued.parse().map_err(|_| ClaudeSignInError::InvalidCode)?,
    })
}

/// Claude's manual redirect page shows `code#state`. The state must be this
/// sign-in's, so a code from another sign-in, or another person's, is refused
/// before anything is sent.
fn parse_pasted_code(pasted: &str, expected_state: &str) -> Result<Secret, ClaudeSignInError> {
    if pasted.len() > MAX_PASTE_BYTES {
        return Err(ClaudeSignInError::InvalidCode);
    }
    let (code, state) = pasted
        .trim()
        .split_once('#')
        .ok_or(ClaudeSignInError::InvalidCode)?;
    let valid_code = !code.is_empty()
        && code.len() <= MAX_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'));
    if !valid_code || !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return Err(ClaudeSignInError::InvalidCode);
    }
    Ok(Secret::new(code.to_owned()))
}

/// Constant-time comparison of two equal-length values; unequal lengths are
/// unequal without comparing contents.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn transport_error(error: super::DeviceLoginError) -> ClaudeSignInError {
    match error {
        super::DeviceLoginError::InvalidResponse => ClaudeSignInError::InvalidResponse,
        _ => ClaudeSignInError::Unavailable,
    }
}

fn json_headers() -> HeaderMap {
    HeaderMap::from_iter([
        (header::ACCEPT, HeaderValue::from_static("application/json")),
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ),
    ])
}

fn check_status(status: StatusCode) -> Result<(), ClaudeSignInError> {
    if status.is_success() {
        Ok(())
    } else if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        Err(ClaudeSignInError::Unavailable)
    } else {
        Err(ClaudeSignInError::InvalidResponse)
    }
}

fn now_unix() -> Result<u64, ClaudeSignInError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ClaudeSignInError::Unavailable)
}

#[cfg(test)]
#[path = "claude_tests.rs"]
mod tests;
