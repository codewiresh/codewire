//! GitHub App device login (RFC 8628) for clients that hold no App secret.
//!
//! A public client knows only the App's client ID and slug. The issued user
//! token passes the same user and installation checks as the dashboard's
//! browser authorization and becomes the same canonical import.

use std::sync::Arc;
use std::time::Duration;

use http::{HeaderMap, HeaderValue, Method, header};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    DEFAULT_POLL_INTERVAL, DeviceChallenge, DeviceLoginError, GITHUB_ACCESS_TOKEN_PATH,
    GITHUB_DEVICE_CODE_PATH, GITHUB_DEVICE_VERIFICATION_URL, GITHUB_HOST, PollStep, Secret, call,
    decode_json, poll_until_done,
};
use crate::BrokerUpstreamTransport;
use crate::github_app::{
    GitHubAppAuthorizationError, GitHubAppAuthorizationImport, TokenResponse,
    import_initial_authorization, valid_app_slug, valid_client_value,
};

const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const USER_AGENT: &str = "Codewire";
/// GitHub issues fifteen-minute codes; a longer answer is not trusted.
const MAX_CODE_LIFETIME: Duration = Duration::from_secs(30 * 60);
const MIN_CODE_LIFETIME: Duration = Duration::from_secs(60);

/// The Codewire GitHub App (Codewire.sh, App ID 2837346, owned by the
/// codewiresh organization): its public identity, shared by every placement
/// and by the Dev and Production platforms. A client ID and an App slug are
/// not secrets: GitHub shows both on its authorization and installation pages.
pub(crate) const CODEWIRE_GITHUB_APP_CLIENT_ID: &str = "Iv23lif1VpZftJWtcQCL";
pub(crate) const CODEWIRE_GITHUB_APP_SLUG: &str = "codewire-sh";

/// GitHub's page for installing the Codewire App on a personal account or an
/// organization and choosing its repositories.
pub fn codewire_github_app_install_url() -> String {
    format!("https://github.com/apps/{CODEWIRE_GITHUB_APP_SLUG}/installations/new")
}

/// The Codewire GitHub App, for a client that holds no App secret.
pub fn codewire_github_app() -> GitHubDeviceLoginConfig {
    GitHubDeviceLoginConfig {
        client_id: CODEWIRE_GITHUB_APP_CLIENT_ID.to_owned(),
        app_slug: CODEWIRE_GITHUB_APP_SLUG.to_owned(),
    }
}

/// The public identity of one Codewire GitHub App. It deliberately has no
/// client secret: device login never needs one.
pub struct GitHubDeviceLoginConfig {
    client_id: String,
    app_slug: String,
}

impl GitHubDeviceLoginConfig {
    pub fn new(client_id: String, app_slug: String) -> Result<Self, GitHubAppAuthorizationError> {
        if !valid_client_value(&client_id) || !valid_app_slug(&app_slug) {
            return Err(GitHubAppAuthorizationError::Configuration);
        }
        Ok(Self {
            client_id,
            app_slug,
        })
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn app_slug(&self) -> &str {
        &self.app_slug
    }
}

/// Starts and completes GitHub App device logins over one provider transport,
/// which must admit only the GitHub App authorization destinations.
pub struct GitHubDeviceLogin {
    config: GitHubDeviceLoginConfig,
    upstream: Arc<dyn BrokerUpstreamTransport>,
}

/// A started login: the challenge to show, and the device code that only
/// [`GitHubDeviceLogin::complete`] uses.
pub struct PendingGitHubDeviceLogin {
    challenge: DeviceChallenge,
    device_code: Secret,
    interval: Duration,
    deadline: tokio::time::Instant,
}

impl PendingGitHubDeviceLogin {
    pub fn challenge(&self) -> &DeviceChallenge {
        &self.challenge
    }
}

impl std::fmt::Debug for PendingGitHubDeviceLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingGitHubDeviceLogin")
            .field("challenge", &self.challenge)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: Secret,
    user_code: String,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

/// GitHub reports device-flow outcomes as an `error` code, with HTTP 200.
#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(default)]
    interval: Option<u64>,
}

impl GitHubDeviceLogin {
    pub fn new(
        config: GitHubDeviceLoginConfig,
        upstream: Arc<dyn BrokerUpstreamTransport>,
    ) -> Self {
        Self { config, upstream }
    }

    /// Ask GitHub for a user code. Nothing is stored and nothing needs
    /// cleanup if the caller never completes the login.
    pub async fn start(&self) -> Result<PendingGitHubDeviceLogin, DeviceLoginError> {
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("client_id", &self.config.client_id);
            form.finish().into_bytes()
        };
        let response: DeviceCodeResponse = self
            .post(GITHUB_DEVICE_CODE_PATH, body)
            .await?
            .map_err(|error| error.outcome())?;
        let lifetime = Duration::from_secs(response.expires_in);
        if !(MIN_CODE_LIFETIME..=MAX_CODE_LIFETIME).contains(&lifetime)
            || response.device_code.expose().is_empty()
        {
            return Err(DeviceLoginError::InvalidResponse);
        }
        Ok(PendingGitHubDeviceLogin {
            challenge: DeviceChallenge::new(
                GITHUB_DEVICE_VERIFICATION_URL,
                response.user_code,
                lifetime,
            )?,
            device_code: response.device_code,
            interval: response
                .interval
                .map_or(DEFAULT_POLL_INTERVAL, Duration::from_secs),
            deadline: tokio::time::Instant::now() + lifetime,
        })
    }

    /// Wait for approval, then verify the GitHub user and this App's
    /// installation exactly as the browser authorization does. Dropping the
    /// future abandons the login.
    pub async fn complete(
        &self,
        pending: PendingGitHubDeviceLogin,
    ) -> Result<GitHubAppAuthorizationImport, DeviceLoginError> {
        let response =
            poll_until_done(pending.interval, pending.deadline, || self.poll(&pending)).await?;
        import_initial_authorization(self.upstream.as_ref(), &self.config.app_slug, response)
            .await
            .map_err(device_error)
    }

    async fn poll(
        &self,
        pending: &PendingGitHubDeviceLogin,
    ) -> Result<PollStep<TokenResponse>, DeviceLoginError> {
        let mut body = Zeroizing::new({
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("client_id", &self.config.client_id);
            form.append_pair("device_code", pending.device_code.expose());
            form.append_pair("grant_type", DEVICE_CODE_GRANT);
            form.finish().into_bytes()
        });
        match self
            .post::<TokenResponse>(GITHUB_ACCESS_TOKEN_PATH, std::mem::take(&mut *body))
            .await?
        {
            Ok(response) if response.is_user_token() => Ok(PollStep::Done(response)),
            Ok(_) => Err(DeviceLoginError::InvalidResponse),
            Err(error) => match error.error.as_str() {
                "authorization_pending" => Ok(PollStep::Pending),
                "slow_down" => Ok(PollStep::SlowDown(error.interval.map(Duration::from_secs))),
                _ => Err(error.outcome()),
            },
        }
    }

    /// POST a form to a fixed GitHub login endpoint. The answer is either the
    /// expected document or GitHub's `error` document.
    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Result<T, ErrorResponse>, DeviceLoginError> {
        let (status, body) = call(
            &self.upstream,
            Method::POST,
            &format!("https://{GITHUB_HOST}{path}"),
            HeaderMap::from_iter([
                (header::ACCEPT, HeaderValue::from_static("application/json")),
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                ),
                (header::USER_AGENT, HeaderValue::from_static(USER_AGENT)),
            ]),
            Zeroizing::new(body),
        )
        .await?;
        if let Ok(error) = decode_json::<ErrorResponse>(&body) {
            return Ok(Err(error));
        }
        if status.is_server_error() || status == http::StatusCode::TOO_MANY_REQUESTS {
            return Err(DeviceLoginError::Unavailable);
        }
        if !status.is_success() {
            return Err(DeviceLoginError::InvalidResponse);
        }
        decode_json(&body).map(Ok)
    }
}

impl ErrorResponse {
    fn outcome(&self) -> DeviceLoginError {
        match self.error.as_str() {
            "expired_token" => DeviceLoginError::Expired,
            "access_denied" => DeviceLoginError::AccessDenied,
            "device_flow_disabled" => DeviceLoginError::DeviceLoginDisabled,
            _ => DeviceLoginError::InvalidResponse,
        }
    }
}

fn device_error(error: GitHubAppAuthorizationError) -> DeviceLoginError {
    match error {
        GitHubAppAuthorizationError::Denied => DeviceLoginError::AccessDenied,
        GitHubAppAuthorizationError::InstallationRequired => DeviceLoginError::InstallationRequired,
        GitHubAppAuthorizationError::Unavailable => DeviceLoginError::Unavailable,
        GitHubAppAuthorizationError::Configuration
        | GitHubAppAuthorizationError::InvalidAuthorizationCode
        | GitHubAppAuthorizationError::InvalidResponse => DeviceLoginError::InvalidResponse,
    }
}
