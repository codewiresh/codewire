//! Codewire's own OAuth device logins for provider credential enrollment.
//!
//! Each flow runs over a [`BrokerUpstreamTransport`]: production uses the
//! pinned, allowlisted provider HTTPS transport, and the Kind fixture an
//! in-process synthetic provider. No provider CLI, subprocess or file is
//! involved on any placement. A completed flow returns the same canonical
//! import as the placement's other enrollment paths, so storage is unchanged.
//! Provider material exists only in zeroizing memory until the caller moves it
//! into its protected store.

pub mod codex;
pub mod github;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use http::{HeaderMap, Method, StatusCode};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

use crate::{BrokerUpstreamRequest, BrokerUpstreamTransport};

/// OpenAI's issuer for ChatGPT (Codex) OAuth.
pub(crate) const OPENAI_AUTH_HOST: &str = "auth.openai.com";
/// The public OAuth client of the Codex CLI. Codewire enrolls and refreshes
/// Codex logins as this client, so they are the tokens Codex itself uses.
pub(crate) const CODEX_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// Token endpoint for both the device-code exchange and refresh.
pub(crate) const OPENAI_TOKEN_PATH: &str = "/oauth/token";
pub(crate) const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub(crate) const CODEX_DEVICE_USERCODE_PATH: &str = "/api/accounts/deviceauth/usercode";
pub(crate) const CODEX_DEVICE_TOKEN_PATH: &str = "/api/accounts/deviceauth/token";
/// Where the user approves a Codex device login.
const CODEX_DEVICE_VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";
const CODEX_DEVICE_REDIRECT_URL: &str = "https://auth.openai.com/deviceauth/callback";

const GITHUB_HOST: &str = "github.com";
pub(crate) const GITHUB_DEVICE_CODE_PATH: &str = "/login/device/code";
pub(crate) const GITHUB_ACCESS_TOKEN_PATH: &str = "/login/oauth/access_token";
/// Where the user approves a GitHub device login.
const GITHUB_DEVICE_VERIFICATION_URL: &str = "https://github.com/login/device";

/// RFC 8628 section 3.2: the interval when the provider names none.
pub(crate) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// RFC 8628 section 3.5: each `slow_down` adds five seconds to the interval.
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// One request and its whole response; login endpoints answer at once.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_USER_CODE_BYTES: usize = 32;

/// Typed device-login outcomes. None carries provider text or material.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeviceLoginError {
    /// The provider does not offer device-code login for this client or
    /// account (for ChatGPT, see "Enable device code authorization").
    #[error("device code login is not enabled for this account")]
    DeviceLoginDisabled,
    /// The code expired before it was approved.
    #[error("the device code expired before it was approved")]
    Expired,
    /// The user or the provider refused the login.
    #[error("the device login was denied")]
    AccessDenied,
    /// The approved GitHub account has no installation of this App.
    #[error("the GitHub App is not installed for this account")]
    InstallationRequired,
    /// The provider could not be reached or answered with a server error.
    #[error("the provider is unavailable")]
    Unavailable,
    /// The provider answered outside the documented protocol.
    #[error("the provider response is invalid")]
    InvalidResponse,
}

/// The one-time code a user enters at a fixed provider verification page.
/// It is not a credential, but `Debug` still redacts it.
pub struct DeviceChallenge {
    verification_url: &'static str,
    user_code: Zeroizing<String>,
    expires_at_unix: u64,
}

impl DeviceChallenge {
    fn new(
        verification_url: &'static str,
        user_code: String,
        lifetime: Duration,
    ) -> Result<Self, DeviceLoginError> {
        let user_code = Zeroizing::new(user_code);
        if user_code.is_empty()
            || user_code.len() > MAX_USER_CODE_BYTES
            || !user_code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(DeviceLoginError::InvalidResponse);
        }
        let expires_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| DeviceLoginError::InvalidResponse)?
            .as_secs()
            .saturating_add(lifetime.as_secs());
        Ok(Self {
            verification_url,
            user_code,
            expires_at_unix,
        })
    }

    /// A fixed provider page, never a URL taken from a response.
    pub fn verification_url(&self) -> &'static str {
        self.verification_url
    }

    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl std::fmt::Debug for DeviceChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceChallenge")
            .field("verification_url", &self.verification_url)
            .field("user_code", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// A provider value Codewire must hold but never print: tokens, device codes
/// and PKCE verifiers. It has no `Clone`, and `Debug` and `Display` redact.
pub(crate) struct Secret(Zeroizing<String>);

impl Secret {
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub(crate) fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// One poll's result. `SlowDown` carries the provider's new interval when it
/// names one; otherwise the current interval grows by [`SLOW_DOWN_STEP`].
pub(crate) enum PollStep<T> {
    Done(T),
    Pending,
    SlowDown(Option<Duration>),
}

/// Wait one interval before each poll, as RFC 8628 requires, until the poll
/// completes, fails, or the code's lifetime ends. The interval never shrinks,
/// and the code's lifetime, not an interval cap, bounds the whole login,
/// including a poll still in flight.
pub(crate) async fn poll_until_done<T, F, Fut>(
    interval: Duration,
    deadline: tokio::time::Instant,
    mut poll: F,
) -> Result<T, DeviceLoginError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<PollStep<T>, DeviceLoginError>>,
{
    let mut interval = interval.max(MIN_POLL_INTERVAL);
    loop {
        if tokio::time::Instant::now() + interval >= deadline {
            return Err(DeviceLoginError::Expired);
        }
        tokio::time::sleep(interval).await;
        let step = tokio::time::timeout_at(deadline, poll())
            .await
            .map_err(|_| DeviceLoginError::Expired)??;
        match step {
            PollStep::Done(value) => return Ok(value),
            PollStep::Pending => {}
            PollStep::SlowDown(next) => {
                interval = next
                    .unwrap_or_else(|| interval.saturating_add(SLOW_DOWN_STEP))
                    .max(interval);
            }
        }
    }
}

/// Send one request to an exact provider URL and read its status and a body
/// of at most [`MAX_RESPONSE_BYTES`] into zeroizing memory, all within
/// [`REQUEST_TIMEOUT`].
pub(crate) async fn call(
    upstream: &Arc<dyn BrokerUpstreamTransport>,
    method: Method,
    target: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<(StatusCode, Zeroizing<Vec<u8>>), DeviceLoginError> {
    let target = Url::parse(target).map_err(|_| DeviceLoginError::InvalidResponse)?;
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let response = upstream
            .execute(BrokerUpstreamRequest::new(method, target, headers, body))
            .await
            .map_err(|_| DeviceLoginError::Unavailable)?;
        let (status, _headers, mut body) = response.into_parts();
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|_| DeviceLoginError::Unavailable)?;
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(DeviceLoginError::InvalidResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    })
    .await
    .map_err(|_| DeviceLoginError::Unavailable)?
}

/// Decode a bounded JSON body; parse errors never echo provider text.
pub(crate) fn decode_json<T: serde::de::DeserializeOwned>(
    body: &[u8],
) -> Result<T, DeviceLoginError> {
    serde_json::from_slice(body).map_err(|_| DeviceLoginError::InvalidResponse)
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
