//! Codex (ChatGPT) device login as OpenAI's Codex client.
//!
//! The protocol is the one the Codex CLI uses: request a user code, poll until
//! the user approves it at [`CODEX_DEVICE_VERIFICATION_URL`], then exchange
//! the issued authorization code and PKCE verifier at the token endpoint the
//! broker already uses for refresh. These endpoints are not a documented
//! public API; this module is their one owner, and the synthetic-provider
//! contract tests pin the shapes it accepts.

use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    CODEX_DEVICE_REDIRECT_URL, CODEX_DEVICE_TOKEN_PATH, CODEX_DEVICE_USERCODE_PATH,
    CODEX_DEVICE_VERIFICATION_URL, CODEX_OAUTH_CLIENT_ID, DEFAULT_POLL_INTERVAL, DeviceChallenge,
    DeviceLoginError, OPENAI_AUTH_HOST, OPENAI_TOKEN_URL, PollStep, Secret, call, decode_json,
    poll_until_done,
};
use crate::BrokerUpstreamTransport;
use crate::codex_oauth::{CodexOAuthImport, import_codex_tokens};

/// The Codex CLI gives up after fifteen minutes; OpenAI names no other bound.
const CODE_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Starts and completes Codex device logins over one provider transport,
/// which must admit only the Codex device-enrollment destinations.
pub struct CodexDeviceLogin {
    upstream: Arc<dyn BrokerUpstreamTransport>,
}

/// A started login: the challenge to show, and the provider handle that only
/// [`CodexDeviceLogin::complete`] uses.
pub struct PendingCodexDeviceLogin {
    challenge: DeviceChallenge,
    device_auth_id: Secret,
    interval: Duration,
    deadline: tokio::time::Instant,
}

impl PendingCodexDeviceLogin {
    pub fn challenge(&self) -> &DeviceChallenge {
        &self.challenge
    }
}

impl std::fmt::Debug for PendingCodexDeviceLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingCodexDeviceLogin")
            .field("challenge", &self.challenge)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct UserCodeRequest {
    client_id: &'static str,
}

#[derive(Deserialize)]
struct UserCodeResponse {
    device_auth_id: Secret,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(default)]
    interval: Option<Interval>,
}

/// OpenAI sends the interval as a decimal string; a number is accepted too.
#[derive(Deserialize)]
#[serde(untagged)]
enum Interval {
    Text(String),
    Seconds(u64),
}

impl Interval {
    fn seconds(&self) -> Result<u64, DeviceLoginError> {
        match self {
            Self::Text(text) => text
                .trim()
                .parse()
                .map_err(|_| DeviceLoginError::InvalidResponse),
            Self::Seconds(seconds) => Ok(*seconds),
        }
    }
}

#[derive(Serialize)]
struct PollRequest<'a> {
    device_auth_id: &'a str,
    user_code: &'a str,
}

#[derive(Deserialize)]
struct ApprovedCode {
    authorization_code: Secret,
    code_verifier: Secret,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Secret,
    access_token: Secret,
    refresh_token: Secret,
}

impl CodexDeviceLogin {
    pub fn new(upstream: Arc<dyn BrokerUpstreamTransport>) -> Self {
        Self { upstream }
    }

    /// Ask OpenAI for a user code. Nothing is stored and nothing needs
    /// cleanup if the caller never completes the login.
    pub async fn start(&self) -> Result<PendingCodexDeviceLogin, DeviceLoginError> {
        let body = serde_json::to_vec(&UserCodeRequest {
            client_id: CODEX_OAUTH_CLIENT_ID,
        })
        .map_err(|_| DeviceLoginError::InvalidResponse)?;
        let (status, body) = call(
            &self.upstream,
            Method::POST,
            &endpoint(CODEX_DEVICE_USERCODE_PATH),
            json_headers(),
            body,
        )
        .await?;
        if status == StatusCode::NOT_FOUND {
            return Err(DeviceLoginError::DeviceLoginDisabled);
        }
        check_status(status)?;
        let response: UserCodeResponse = decode_json(&body)?;
        let interval = match &response.interval {
            Some(interval) => Duration::from_secs(interval.seconds()?),
            None => DEFAULT_POLL_INTERVAL,
        };
        if response.device_auth_id.expose().is_empty() {
            return Err(DeviceLoginError::InvalidResponse);
        }
        Ok(PendingCodexDeviceLogin {
            challenge: DeviceChallenge::new(
                CODEX_DEVICE_VERIFICATION_URL,
                response.user_code,
                CODE_LIFETIME,
            )?,
            device_auth_id: response.device_auth_id,
            interval,
            deadline: tokio::time::Instant::now() + CODE_LIFETIME,
        })
    }

    /// Wait for approval, exchange the authorization code, and return the
    /// canonical Codex import. Dropping the future abandons the login.
    pub async fn complete(
        &self,
        pending: PendingCodexDeviceLogin,
    ) -> Result<CodexOAuthImport, DeviceLoginError> {
        let approved =
            poll_until_done(pending.interval, pending.deadline, || self.poll(&pending)).await?;
        let tokens = self.exchange(approved).await?;
        import_codex_tokens(
            tokens.id_token.into_inner(),
            tokens.access_token.into_inner(),
            tokens.refresh_token.into_inner(),
        )
        .map_err(|_| DeviceLoginError::InvalidResponse)
    }

    async fn poll(
        &self,
        pending: &PendingCodexDeviceLogin,
    ) -> Result<PollStep<ApprovedCode>, DeviceLoginError> {
        let mut body = Zeroizing::new(
            serde_json::to_vec(&PollRequest {
                device_auth_id: pending.device_auth_id.expose(),
                user_code: pending.challenge.user_code(),
            })
            .map_err(|_| DeviceLoginError::InvalidResponse)?,
        );
        let (status, body) = call(
            &self.upstream,
            Method::POST,
            &endpoint(CODEX_DEVICE_TOKEN_PATH),
            json_headers(),
            std::mem::take(&mut *body),
        )
        .await?;
        // OpenAI answers 403 or 404 until the user approves the code.
        if matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
            return Ok(PollStep::Pending);
        }
        check_status(status)?;
        decode_json(&body).map(PollStep::Done)
    }

    async fn exchange(&self, approved: ApprovedCode) -> Result<TokenResponse, DeviceLoginError> {
        let mut body = Zeroizing::new({
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code");
            form.append_pair("code", approved.authorization_code.expose());
            form.append_pair("redirect_uri", CODEX_DEVICE_REDIRECT_URL);
            form.append_pair("client_id", CODEX_OAUTH_CLIENT_ID);
            form.append_pair("code_verifier", approved.code_verifier.expose());
            form.finish().into_bytes()
        });
        let (status, body) = call(
            &self.upstream,
            Method::POST,
            OPENAI_TOKEN_URL,
            HeaderMap::from_iter([
                (header::ACCEPT, HeaderValue::from_static("application/json")),
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                ),
            ]),
            std::mem::take(&mut *body),
        )
        .await?;
        if matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED) {
            return Err(DeviceLoginError::AccessDenied);
        }
        check_status(status)?;
        decode_json(&body)
    }
}

fn endpoint(path: &str) -> String {
    format!("https://{OPENAI_AUTH_HOST}{path}")
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

fn check_status(status: StatusCode) -> Result<(), DeviceLoginError> {
    if status.is_success() {
        Ok(())
    } else if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        Err(DeviceLoginError::Unavailable)
    } else {
        Err(DeviceLoginError::InvalidResponse)
    }
}
