//! GitHub App user-to-server authorization inside the isolated credential
//! authority.
//!
//! This is intentionally separate from `github_enrollment`: that module owns
//! the GitHub CLI device flow used by `cw`.  A browser callback carries an
//! OAuth authorization code from a GitHub App installation, which this owner
//! exchanges only from the credential authority that holds the App client
//! secret.  The resulting user token never reaches the dashboard or a
//! Sandbox.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{BrokerUpstreamRequest, BrokerUpstreamTransport};

const TOKEN_EXCHANGE_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const INSTALLATIONS_URL: &str = "https://api.github.com/user/installations";
const MAX_AUTHORIZATION_CODE_BYTES: usize = 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_TOKEN_BYTES: usize = 4096;
const MAX_ACCOUNT_BYTES: usize = 39;
const MAX_INSTALLATION_PAGES: u32 = 10;
const GITHUB_APP_BUNDLE_PREFIX: &[u8] = b"codewire-github-app-user-v1:";
const GITHUB_APP_BUNDLE_VERSION: u8 = 1;
const ACCESS_TOKEN_RENEWAL_SKEW_SECONDS: u64 = 5 * 60;
const MIN_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAX_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const MIN_REFRESH_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAX_REFRESH_TOKEN_LIFETIME_SECONDS: u64 = 366 * 24 * 60 * 60;

/// Deliberately non-Debug configuration for one registered GitHub App.
/// `client_secret` is only ever used to build the fixed token-exchange body.
pub struct GitHubAppAuthorizationConfig {
    client_id: String,
    client_secret: Zeroizing<String>,
    app_slug: String,
    callback_url: String,
}

impl GitHubAppAuthorizationConfig {
    pub fn new(
        client_id: String,
        client_secret: Zeroizing<String>,
        app_slug: String,
        callback_url: String,
    ) -> Result<Self, GitHubAppAuthorizationError> {
        if !valid_client_value(&client_id)
            || !valid_client_value(&client_secret)
            || !valid_app_slug(&app_slug)
            || !valid_callback_url(&callback_url)
        {
            return Err(GitHubAppAuthorizationError::Configuration);
        }
        Ok(Self {
            client_id,
            client_secret,
            app_slug,
            callback_url,
        })
    }
}

/// Canonical protected material for a rotating GitHub App user-to-server
/// credential. The versioned envelope is deliberately distinct from legacy raw
/// GitHub CLI token bytes. It has no Debug, Clone, or serialization surface.
pub struct GitHubAppUserOAuthBundle {
    bytes: Zeroizing<Vec<u8>>,
}

impl GitHubAppUserOAuthBundle {
    /// Whether material claims to use the versioned GitHub App form. Callers
    /// use this only to choose the closed App refresh path; they must parse it
    /// successfully before treating it as a credential.
    pub fn is_tagged(bytes: &[u8]) -> bool {
        bytes.starts_with(GITHUB_APP_BUNDLE_PREFIX)
    }

    /// Decode only the tagged canonical form. Callers must never fall back to a
    /// raw token when bytes claim to be a GitHub App bundle but fail validation.
    pub fn parse(bytes: &[u8]) -> Result<Self, GitHubAppAuthorizationError> {
        let payload = parse_bundle_payload(bytes)?;
        Self::from_payload(payload)
    }

    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.bytes))
    }

    pub(crate) fn access_token(&self) -> Result<Zeroizing<String>, GitHubAppAuthorizationError> {
        Ok(parse_bundle_payload(&self.bytes)?.access_token)
    }

    pub fn should_refresh(&self, now_unix: u64) -> Result<bool, GitHubAppAuthorizationError> {
        let payload = parse_bundle_payload(&self.bytes)?;
        if payload.refresh_expires_at_unix <= now_unix {
            return Err(GitHubAppAuthorizationError::Denied);
        }
        Ok(payload.access_expires_at_unix
            <= now_unix.saturating_add(ACCESS_TOKEN_RENEWAL_SKEW_SECONDS))
    }

    pub(crate) fn redaction_components(
        &self,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, GitHubAppAuthorizationError> {
        let payload = parse_bundle_payload(&self.bytes)?;
        Ok(vec![
            Zeroizing::new(payload.access_token.as_bytes().to_vec()),
            Zeroizing::new(payload.refresh_token.as_bytes().to_vec()),
        ])
    }

    fn from_initial_response(
        response: TokenResponse,
        now_unix: u64,
        user_id: u64,
        app_slug: String,
        installation_id: u64,
    ) -> Result<GitHubAppAuthorizationMaterial, GitHubAppAuthorizationError> {
        response.into_initial_material(now_unix, user_id, app_slug, installation_id)
    }

    fn from_refresh_response(
        response: TokenResponse,
        now_unix: u64,
        expected: GitHubAppRefreshExpectation,
    ) -> Result<Self, GitHubAppAuthorizationError> {
        response.into_refresh_bundle(now_unix, expected)
    }

    fn refresh_expectation(
        &self,
    ) -> Result<(Zeroizing<String>, GitHubAppRefreshExpectation), GitHubAppAuthorizationError> {
        let payload = parse_bundle_payload(&self.bytes)?;
        Ok((
            payload.refresh_token,
            GitHubAppRefreshExpectation {
                user_id: payload.user_id,
                app_slug: payload.app_slug,
                installation_id: payload.installation_id,
            },
        ))
    }

    fn from_payload(
        payload: GitHubAppUserOAuthPayload,
    ) -> Result<Self, GitHubAppAuthorizationError> {
        validate_bundle_payload(&payload)?;
        let mut json = Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|_| GitHubAppAuthorizationError::InvalidResponse)?,
        );
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            GITHUB_APP_BUNDLE_PREFIX
                .len()
                .checked_add(json.len())
                .ok_or(GitHubAppAuthorizationError::InvalidResponse)?,
        ));
        bytes.extend_from_slice(GITHUB_APP_BUNDLE_PREFIX);
        bytes.extend_from_slice(&json);
        json.zeroize();
        Ok(Self { bytes })
    }
}

/// Closed GitHub credential material accepted by the fixed GitHub proxy. Raw
/// material remains for the CLI device flow and existing non-expiring user
/// tokens. A malformed tagged App bundle is never interpreted as raw bytes.
pub(crate) enum GitHubOAuthCredential {
    Raw(Zeroizing<Vec<u8>>),
    App(GitHubAppUserOAuthBundle),
}

impl GitHubOAuthCredential {
    pub(crate) fn parse(material: &[u8]) -> Result<Self, GitHubAppAuthorizationError> {
        if GitHubAppUserOAuthBundle::is_tagged(material) {
            return GitHubAppUserOAuthBundle::parse(material).map(Self::App);
        }
        if material.is_empty()
            || material.len() > MAX_TOKEN_BYTES
            || !material.iter().all(|byte| byte.is_ascii_graphic())
        {
            return Err(GitHubAppAuthorizationError::InvalidResponse);
        }
        Ok(Self::Raw(Zeroizing::new(material.to_vec())))
    }

    pub(crate) fn access_token(&self) -> Result<Zeroizing<String>, GitHubAppAuthorizationError> {
        match self {
            Self::Raw(token) => String::from_utf8(token.to_vec())
                .map(Zeroizing::new)
                .map_err(|_| GitHubAppAuthorizationError::InvalidResponse),
            Self::App(bundle) => bundle.access_token(),
        }
    }

    pub(crate) fn should_refresh(
        &self,
        now_unix: u64,
    ) -> Result<bool, GitHubAppAuthorizationError> {
        match self {
            Self::Raw(_) => Ok(false),
            Self::App(bundle) => bundle.should_refresh(now_unix),
        }
    }

    pub(crate) fn into_app(self) -> Option<GitHubAppUserOAuthBundle> {
        match self {
            Self::Raw(_) => None,
            Self::App(bundle) => Some(bundle),
        }
    }

    pub(crate) fn is_app(&self) -> bool {
        matches!(self, Self::App(_))
    }

    pub(crate) fn redaction_components(
        &self,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, GitHubAppAuthorizationError> {
        match self {
            Self::Raw(token) => Ok(vec![Zeroizing::new(token.to_vec())]),
            Self::App(bundle) => bundle.redaction_components(),
        }
    }
}

enum GitHubAppAuthorizationMaterial {
    Raw(Zeroizing<Vec<u8>>),
    Bundle(GitHubAppUserOAuthBundle),
}

impl GitHubAppAuthorizationMaterial {
    fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Raw(bytes) => bytes,
            Self::Bundle(bundle) => bundle.into_bytes(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GitHubAppUserOAuthPayload {
    version: u8,
    access_token: Zeroizing<String>,
    access_expires_at_unix: u64,
    refresh_token: Zeroizing<String>,
    refresh_expires_at_unix: u64,
    user_id: u64,
    app_slug: String,
    installation_id: u64,
}

struct GitHubAppRefreshExpectation {
    user_id: u64,
    app_slug: String,
    installation_id: u64,
}

/// A protected GitHub user token plus the verified GitHub login.  This type
/// intentionally has no Debug/Clone/serialization implementation.
pub struct GitHubAppAuthorizationImport {
    material: Zeroizing<Vec<u8>>,
    account_hint: String,
}

impl GitHubAppAuthorizationImport {
    /// The verified GitHub login is public credential metadata, not provider
    /// material. It lets the authority keep a reconnect bound to the identity
    /// that existing profiles already reference.
    pub fn account_hint(&self) -> &str {
        &self.account_hint
    }

    pub fn take_import(
        &mut self,
    ) -> Result<(Zeroizing<Vec<u8>>, Option<String>), GitHubAppAuthorizationError> {
        if self.material.is_empty() || self.account_hint.is_empty() {
            return Err(GitHubAppAuthorizationError::InvalidResponse);
        }
        Ok((
            Zeroizing::new(std::mem::take(&mut *self.material)),
            Some(std::mem::take(&mut self.account_hint)),
        ))
    }
}

/// The only owner permitted to exchange browser callback codes for the
/// configured App.  Its upstream transport must be resolved with the separate
/// GitHub App authorization destination family, never the Sandbox bridge
/// transport.
pub struct GitHubAppAuthorizationOwner {
    config: GitHubAppAuthorizationConfig,
    upstream: Arc<dyn BrokerUpstreamTransport>,
}

impl GitHubAppAuthorizationOwner {
    pub fn new(
        config: GitHubAppAuthorizationConfig,
        upstream: Arc<dyn BrokerUpstreamTransport>,
    ) -> Self {
        Self { config, upstream }
    }

    /// Exchange one browser callback code, verify its GitHub user identity,
    /// and prove the user has an installation of this exact App.  The caller
    /// owns browser-state validation and durable publication fences.
    pub async fn complete(
        &self,
        mut authorization_code: Zeroizing<Vec<u8>>,
    ) -> Result<GitHubAppAuthorizationImport, GitHubAppAuthorizationError> {
        if !valid_authorization_code(&authorization_code) {
            authorization_code.zeroize();
            return Err(GitHubAppAuthorizationError::InvalidAuthorizationCode);
        }
        let response = self.exchange_authorization_code(&authorization_code).await;
        authorization_code.zeroize();
        let response = response?;
        let user = self.user(&response.access_token).await?;
        let installation_id = self
            .verify_installation(&response.access_token, None)
            .await?;
        let material = GitHubAppUserOAuthBundle::from_initial_response(
            response,
            unix_now()?,
            user.id,
            self.config.app_slug.clone(),
            installation_id,
        )
        .map(GitHubAppAuthorizationMaterial::into_bytes)?;
        Ok(GitHubAppAuthorizationImport {
            material,
            account_hint: user.login,
        })
    }

    /// Rotate an already-validated expiring GitHub App user credential. This
    /// owner is configured only inside credential-service, which is the sole
    /// holder of the App client secret and the private finite provider route.
    /// Durable reservation, promotion, and current-caller admission stay with
    /// the surrounding authority; this method never publishes material.
    pub async fn refresh(
        &self,
        bundle: GitHubAppUserOAuthBundle,
    ) -> Result<GitHubAppUserOAuthBundle, GitHubAppRefreshError> {
        let (refresh_token, expected) = bundle
            .refresh_expectation()
            .map_err(GitHubAppRefreshError::permanent)?;
        let response = self.exchange_refresh(&refresh_token).await?;
        let user = self
            .user(&response.access_token)
            .await
            .map_err(GitHubAppRefreshError::from_authorization)?;
        if user.id != expected.user_id {
            return Err(GitHubAppRefreshError::Permanent);
        }
        let installation_id = self
            .verify_installation(&response.access_token, Some(expected.installation_id))
            .await
            .map_err(GitHubAppRefreshError::from_authorization)?;
        if installation_id != expected.installation_id || expected.app_slug != self.config.app_slug
        {
            return Err(GitHubAppRefreshError::Permanent);
        }
        GitHubAppUserOAuthBundle::from_refresh_response(response, unix_now_refresh()?, expected)
            .map_err(GitHubAppRefreshError::permanent)
    }

    async fn exchange_authorization_code(
        &self,
        authorization_code: &[u8],
    ) -> Result<TokenResponse, GitHubAppAuthorizationError> {
        let code = std::str::from_utf8(authorization_code)
            .map_err(|_| GitHubAppAuthorizationError::InvalidAuthorizationCode)?;
        let mut body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("client_id", &self.config.client_id);
            serializer.append_pair("client_secret", &self.config.client_secret);
            serializer.append_pair("code", code);
            serializer.append_pair("redirect_uri", &self.config.callback_url);
            Zeroizing::new(serializer.finish().into_bytes())
        };
        let response = self
            .request(
                Method::POST,
                TOKEN_EXCHANGE_URL,
                HeaderMap::from_iter([
                    (header::ACCEPT, HeaderValue::from_static("application/json")),
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-www-form-urlencoded"),
                    ),
                    (
                        header::USER_AGENT,
                        HeaderValue::from_static("Codewire-Credential-Service"),
                    ),
                ]),
                std::mem::take(&mut *body),
            )
            .await?;
        let response: TokenResponse = response_json(response).await?;
        if !response.token_type.eq_ignore_ascii_case("bearer")
            || !valid_user_token(&response.access_token)
        {
            return Err(GitHubAppAuthorizationError::InvalidResponse);
        }
        Ok(response)
    }

    async fn exchange_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse, GitHubAppRefreshError> {
        if !valid_refresh_token(refresh_token) {
            return Err(GitHubAppRefreshError::Permanent);
        }
        let mut body = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("client_id", &self.config.client_id);
            serializer.append_pair("client_secret", &self.config.client_secret);
            serializer.append_pair("grant_type", "refresh_token");
            serializer.append_pair("refresh_token", refresh_token);
            Zeroizing::new(serializer.finish().into_bytes())
        };
        let response = self
            .request(
                Method::POST,
                TOKEN_EXCHANGE_URL,
                HeaderMap::from_iter([
                    (header::ACCEPT, HeaderValue::from_static("application/json")),
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/x-www-form-urlencoded"),
                    ),
                    (
                        header::USER_AGENT,
                        HeaderValue::from_static("Codewire-Credential-Service"),
                    ),
                ]),
                std::mem::take(&mut *body),
            )
            .await
            .map_err(GitHubAppRefreshError::from_authorization)?;
        let response: TokenResponse = response_json(response)
            .await
            .map_err(GitHubAppRefreshError::from_authorization)?;
        if !response.token_type.eq_ignore_ascii_case("bearer")
            || !valid_user_token(&response.access_token)
        {
            return Err(GitHubAppRefreshError::Permanent);
        }
        Ok(response)
    }

    async fn user(&self, token: &str) -> Result<VerifiedUser, GitHubAppAuthorizationError> {
        let response = self
            .request(
                Method::GET,
                USER_URL,
                authorization_headers(token)?,
                Vec::new(),
            )
            .await?;
        let response: UserResponse = response_json(response).await?;
        if response.id == 0 || !valid_login(&response.login) {
            return Err(GitHubAppAuthorizationError::InvalidResponse);
        }
        Ok(VerifiedUser {
            id: response.id,
            login: response.login,
        })
    }

    async fn verify_installation(
        &self,
        token: &str,
        expected_installation_id: Option<u64>,
    ) -> Result<u64, GitHubAppAuthorizationError> {
        for page in 1..=MAX_INSTALLATION_PAGES {
            let target = format!("{INSTALLATIONS_URL}?per_page=100&page={page}");
            let response = self
                .request(
                    Method::GET,
                    &target,
                    authorization_headers(token)?,
                    Vec::new(),
                )
                .await?;
            let response: InstallationsResponse = response_json(response).await?;
            if let Some(installation) = response.installations.iter().find(|installation| {
                installation.id > 0
                    && installation.app_slug == self.config.app_slug
                    && expected_installation_id.is_none_or(|expected| expected == installation.id)
            }) {
                return Ok(installation.id);
            }
            if response.installations.len() < 100 {
                return Err(GitHubAppAuthorizationError::InstallationRequired);
            }
        }
        // Exhausting the bounded listing is not proof that the App is absent.
        Err(GitHubAppAuthorizationError::Unavailable)
    }

    async fn request(
        &self,
        method: Method,
        target: &str,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<crate::BrokerUpstreamResponse, GitHubAppAuthorizationError> {
        let target = Url::parse(target).map_err(|_| GitHubAppAuthorizationError::Configuration)?;
        self.upstream
            .execute(BrokerUpstreamRequest::new(method, target, headers, body))
            .await
            .map_err(|_| GitHubAppAuthorizationError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum GitHubAppAuthorizationError {
    #[error("GitHub App authorization configuration is invalid")]
    Configuration,
    #[error("GitHub App callback code is invalid")]
    InvalidAuthorizationCode,
    #[error("GitHub App authorization was denied")]
    Denied,
    #[error("GitHub App repository access is not installed for this account")]
    InstallationRequired,
    #[error("GitHub App authorization is unavailable")]
    Unavailable,
    #[error("GitHub App authorization response is invalid")]
    InvalidResponse,
}

/// Refresh outcome classification used only by the credential authority after
/// durable Start. It contains no provider response, material, or retry permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitHubAppRefreshError {
    Permanent,
    Uncertain,
}

impl GitHubAppRefreshError {
    fn permanent(_: GitHubAppAuthorizationError) -> Self {
        Self::Permanent
    }

    fn from_authorization(error: GitHubAppAuthorizationError) -> Self {
        match error {
            GitHubAppAuthorizationError::Unavailable => Self::Uncertain,
            GitHubAppAuthorizationError::Configuration
            | GitHubAppAuthorizationError::InvalidAuthorizationCode
            | GitHubAppAuthorizationError::Denied
            | GitHubAppAuthorizationError::InstallationRequired
            | GitHubAppAuthorizationError::InvalidResponse => Self::Permanent,
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Zeroizing<String>,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<Zeroizing<String>>,
    refresh_token_expires_in: Option<u64>,
}

impl TokenResponse {
    fn into_initial_material(
        self,
        now_unix: u64,
        user_id: u64,
        app_slug: String,
        installation_id: u64,
    ) -> Result<GitHubAppAuthorizationMaterial, GitHubAppAuthorizationError> {
        match (
            self.expires_in,
            self.refresh_token,
            self.refresh_token_expires_in,
        ) {
            (None, None, None) => Ok(GitHubAppAuthorizationMaterial::Raw(Zeroizing::new(
                self.access_token.as_bytes().to_vec(),
            ))),
            (Some(access_lifetime), Some(refresh_token), Some(refresh_lifetime)) => {
                let bundle = bundle_from_expiring_tokens(
                    self.access_token,
                    access_lifetime,
                    refresh_token,
                    refresh_lifetime,
                    now_unix,
                    GitHubAppRefreshExpectation {
                        user_id,
                        app_slug,
                        installation_id,
                    },
                )?;
                Ok(GitHubAppAuthorizationMaterial::Bundle(bundle))
            }
            _ => Err(GitHubAppAuthorizationError::InvalidResponse),
        }
    }

    fn into_refresh_bundle(
        self,
        now_unix: u64,
        expected: GitHubAppRefreshExpectation,
    ) -> Result<GitHubAppUserOAuthBundle, GitHubAppAuthorizationError> {
        let (Some(access_lifetime), Some(refresh_token), Some(refresh_lifetime)) = (
            self.expires_in,
            self.refresh_token,
            self.refresh_token_expires_in,
        ) else {
            return Err(GitHubAppAuthorizationError::InvalidResponse);
        };
        bundle_from_expiring_tokens(
            self.access_token,
            access_lifetime,
            refresh_token,
            refresh_lifetime,
            now_unix,
            expected,
        )
    }
}

#[derive(Deserialize)]
struct UserResponse {
    id: u64,
    login: String,
}

struct VerifiedUser {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct InstallationsResponse {
    installations: Vec<Installation>,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
    app_slug: String,
}

fn bundle_from_expiring_tokens(
    access_token: Zeroizing<String>,
    access_lifetime: u64,
    refresh_token: Zeroizing<String>,
    refresh_lifetime: u64,
    now_unix: u64,
    expected: GitHubAppRefreshExpectation,
) -> Result<GitHubAppUserOAuthBundle, GitHubAppAuthorizationError> {
    if !valid_user_token(&access_token)
        || !valid_refresh_token(&refresh_token)
        || !(MIN_ACCESS_TOKEN_LIFETIME_SECONDS..=MAX_ACCESS_TOKEN_LIFETIME_SECONDS)
            .contains(&access_lifetime)
        || !(MIN_REFRESH_TOKEN_LIFETIME_SECONDS..=MAX_REFRESH_TOKEN_LIFETIME_SECONDS)
            .contains(&refresh_lifetime)
        || refresh_lifetime <= access_lifetime
    {
        return Err(GitHubAppAuthorizationError::InvalidResponse);
    }
    let access_expires_at_unix = now_unix
        .checked_add(access_lifetime)
        .filter(|expiry| *expiry > now_unix)
        .ok_or(GitHubAppAuthorizationError::InvalidResponse)?;
    let refresh_expires_at_unix = now_unix
        .checked_add(refresh_lifetime)
        .filter(|expiry| *expiry > access_expires_at_unix)
        .ok_or(GitHubAppAuthorizationError::InvalidResponse)?;
    GitHubAppUserOAuthBundle::from_payload(GitHubAppUserOAuthPayload {
        version: GITHUB_APP_BUNDLE_VERSION,
        access_token,
        access_expires_at_unix,
        refresh_token,
        refresh_expires_at_unix,
        user_id: expected.user_id,
        app_slug: expected.app_slug,
        installation_id: expected.installation_id,
    })
}

fn parse_bundle_payload(
    bytes: &[u8],
) -> Result<GitHubAppUserOAuthPayload, GitHubAppAuthorizationError> {
    let json = bytes
        .strip_prefix(GITHUB_APP_BUNDLE_PREFIX)
        .ok_or(GitHubAppAuthorizationError::InvalidResponse)?;
    if json.is_empty() || json.len() > MAX_RESPONSE_BYTES {
        return Err(GitHubAppAuthorizationError::InvalidResponse);
    }
    let payload: GitHubAppUserOAuthPayload =
        serde_json::from_slice(json).map_err(|_| GitHubAppAuthorizationError::InvalidResponse)?;
    validate_bundle_payload(&payload)?;
    Ok(payload)
}

fn validate_bundle_payload(
    payload: &GitHubAppUserOAuthPayload,
) -> Result<(), GitHubAppAuthorizationError> {
    if payload.version != GITHUB_APP_BUNDLE_VERSION
        || !valid_user_token(&payload.access_token)
        || !valid_refresh_token(&payload.refresh_token)
        || payload.access_expires_at_unix == 0
        || payload.refresh_expires_at_unix <= payload.access_expires_at_unix
        || payload.user_id == 0
        || !valid_app_slug(&payload.app_slug)
        || payload.installation_id == 0
    {
        return Err(GitHubAppAuthorizationError::InvalidResponse);
    }
    Ok(())
}

fn unix_now() -> Result<u64, GitHubAppAuthorizationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| GitHubAppAuthorizationError::Unavailable)
}

fn unix_now_refresh() -> Result<u64, GitHubAppRefreshError> {
    unix_now().map_err(GitHubAppRefreshError::from_authorization)
}

async fn response_json<T>(
    response: crate::BrokerUpstreamResponse,
) -> Result<T, GitHubAppAuthorizationError>
where
    T: serde::de::DeserializeOwned,
{
    let (status, headers, mut body) = response.into_parts();
    if !status.is_success() {
        return Err(
            if matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                GitHubAppAuthorizationError::Denied
            } else {
                GitHubAppAuthorizationError::Unavailable
            },
        );
    }
    if !headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(GitHubAppAuthorizationError::InvalidResponse);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| GitHubAppAuthorizationError::Unavailable)?;
        let next = bytes
            .len()
            .checked_add(chunk.len())
            .filter(|size| *size <= MAX_RESPONSE_BYTES)
            .ok_or(GitHubAppAuthorizationError::InvalidResponse)?;
        let additional_capacity = next.saturating_sub(bytes.len());
        bytes
            .try_reserve(additional_capacity)
            .map_err(|_| GitHubAppAuthorizationError::InvalidResponse)?;
        bytes.extend_from_slice(&chunk);
    }
    let parsed =
        serde_json::from_slice(&bytes).map_err(|_| GitHubAppAuthorizationError::InvalidResponse);
    bytes.zeroize();
    parsed
}

fn authorization_headers(token: &str) -> Result<HeaderMap, GitHubAppAuthorizationError> {
    let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| GitHubAppAuthorizationError::InvalidResponse)?;
    Ok(HeaderMap::from_iter([
        (header::AUTHORIZATION, authorization),
        (
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        ),
        (
            header::USER_AGENT,
            HeaderValue::from_static("Codewire-Credential-Service"),
        ),
    ]))
}

fn valid_client_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_app_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_callback_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/api/v1/github/oauth/callback"
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn valid_authorization_code(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUTHORIZATION_CODE_BYTES
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_user_token(value: &str) -> bool {
    value.starts_with("ghu_")
        && value.len() > 4
        && value.len() <= MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_refresh_token(value: &str) -> bool {
    value.starts_with("ghr_")
        && value.len() > 4
        && value.len() <= MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCOUNT_BYTES
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use async_trait::async_trait;
    use bytes::Bytes;
    use http::StatusCode;

    use super::*;
    use crate::{BrokerUpstreamError, BrokerUpstreamResponse};

    type RecordedRequest = (Method, String, HeaderMap, Vec<u8>);

    #[derive(Default)]
    struct Provider {
        requests: Mutex<Vec<RecordedRequest>>,
        missing_installation: AtomicBool,
        full_installation_pages: bool,
    }

    #[async_trait]
    impl BrokerUpstreamTransport for Provider {
        async fn execute(
            &self,
            request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            let (method, target, headers, body) = request.into_parts();
            let index = self.requests.lock().unwrap().len();
            self.requests
                .lock()
                .unwrap()
                .push((method, target.as_str().to_owned(), headers, body));
            let value = match index {
                0 => serde_json::json!({
                    "access_token": "ghu_synthetic_user_token_1234567890",
                    "token_type": "bearer"
                }),
                1 => serde_json::json!({"id": 73, "login": "octo-user", "private": "ignored"}),
                2.. if self.missing_installation.load(Ordering::SeqCst) => serde_json::json!({
                    "installations": if self.full_installation_pages {
                        vec![serde_json::json!({"id": 42, "app_slug": "another-app"}); 100]
                    } else {
                        Vec::new()
                    }
                }),
                2 => serde_json::json!({
                    "installations": [{"id": 41, "app_slug": "codewire"}]
                }),
                _ => return Err(BrokerUpstreamError::Protocol),
            };
            Ok(BrokerUpstreamResponse::new(
                StatusCode::OK,
                HeaderMap::from_iter([(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json; charset=utf-8"),
                )]),
                Box::pin(futures::stream::once(async move {
                    Ok(Bytes::from(serde_json::to_vec(&value).unwrap()))
                })),
            ))
        }
    }

    #[tokio::test]
    async fn missing_installation_returns_no_import_and_allows_a_fresh_attempt() {
        let provider = Arc::new(Provider {
            missing_installation: AtomicBool::new(true),
            ..Default::default()
        });
        let owner = GitHubAppAuthorizationOwner::new(config(), provider.clone());
        assert!(matches!(
            owner.complete(Zeroizing::new(b"first-code".to_vec())).await,
            Err(GitHubAppAuthorizationError::InstallationRequired)
        ));
        assert_eq!(provider.requests.lock().unwrap().len(), 3);
        // Installation is a separate provider action. A fresh authorization
        // code must pass the complete exchange and identity checks again.
        provider.missing_installation.store(false, Ordering::SeqCst);
        provider.requests.lock().unwrap().clear();
        assert!(
            owner
                .complete(Zeroizing::new(b"fresh-code".to_vec()))
                .await
                .is_ok()
        );
        assert_eq!(provider.requests.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn bounded_installation_listing_does_not_claim_absence() {
        let provider = Arc::new(Provider {
            missing_installation: AtomicBool::new(true),
            full_installation_pages: true,
            ..Default::default()
        });
        let owner = GitHubAppAuthorizationOwner::new(config(), provider.clone());
        assert!(matches!(
            owner
                .complete(Zeroizing::new(b"synthetic-code".to_vec()))
                .await,
            Err(GitHubAppAuthorizationError::Unavailable)
        ));
        assert_eq!(
            provider.requests.lock().unwrap().len(),
            2 + MAX_INSTALLATION_PAGES as usize
        );
    }

    struct ExpiringProvider {
        requests: Mutex<Vec<RecordedRequest>>,
        refreshed_user_id: u64,
        refreshed_installation_id: u64,
        refreshed_app_slug: &'static str,
    }

    impl Default for ExpiringProvider {
        fn default() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                refreshed_user_id: 73,
                refreshed_installation_id: 41,
                refreshed_app_slug: "codewire",
            }
        }
    }

    #[async_trait]
    impl BrokerUpstreamTransport for ExpiringProvider {
        async fn execute(
            &self,
            request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            let (method, target, headers, body) = request.into_parts();
            let index = self.requests.lock().unwrap().len();
            self.requests
                .lock()
                .unwrap()
                .push((method, target.as_str().to_owned(), headers, body));
            let value = match index {
                0 => serde_json::json!({
                    "access_token": "ghu_synthetic_user_token_1234567890",
                    "token_type": "bearer",
                    "expires_in": 28_800,
                    "refresh_token": "ghr_synthetic_refresh_token_1234567890",
                    "refresh_token_expires_in": 15_897_600
                }),
                1 => serde_json::json!({"id": 73, "login": "octo-user"}),
                2 => serde_json::json!({
                    "installations": [{"id": 41, "app_slug": "codewire"}]
                }),
                3 => serde_json::json!({
                    "access_token": "ghu_rotated_user_token_1234567890",
                    "token_type": "bearer",
                    "expires_in": 28_800,
                    "refresh_token": "ghr_rotated_refresh_token_1234567890",
                    "refresh_token_expires_in": 15_897_600
                }),
                4 => {
                    serde_json::json!({"id": self.refreshed_user_id, "login": "renamed-octo-user"})
                }
                5 => serde_json::json!({
                    "installations": [{"id": self.refreshed_installation_id, "app_slug": self.refreshed_app_slug}]
                }),
                _ => return Err(BrokerUpstreamError::Protocol),
            };
            Ok(BrokerUpstreamResponse::new(
                StatusCode::OK,
                HeaderMap::from_iter([(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )]),
                Box::pin(futures::stream::once(async move {
                    Ok(Bytes::from(serde_json::to_vec(&value).unwrap()))
                })),
            ))
        }
    }

    fn config() -> GitHubAppAuthorizationConfig {
        GitHubAppAuthorizationConfig::new(
            "Iv1.syntheticclient".into(),
            Zeroizing::new("synthetic-client-secret".into()),
            "codewire".into(),
            "https://codewire.example/api/v1/github/oauth/callback".into(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn exchanges_browser_code_and_verifies_the_exact_app_installation() {
        let provider = Arc::new(Provider::default());
        let owner = GitHubAppAuthorizationOwner::new(config(), provider.clone());
        let mut imported = owner
            .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
            .await
            .unwrap();
        let (material, account) = imported.take_import().unwrap();
        assert_eq!(account.as_deref(), Some("octo-user"));
        assert_eq!(material.as_slice(), b"ghu_synthetic_user_token_1234567890");
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, Method::POST);
        assert_eq!(requests[0].1, TOKEN_EXCHANGE_URL);
        assert_eq!(
            std::str::from_utf8(&requests[0].3).unwrap(),
            "client_id=Iv1.syntheticclient&client_secret=synthetic-client-secret&code=synthetic-code-123&redirect_uri=https%3A%2F%2Fcodewire.example%2Fapi%2Fv1%2Fgithub%2Foauth%2Fcallback"
        );
        assert_eq!(requests[1].1, USER_URL);
        assert_eq!(
            requests[1].2.get(header::AUTHORIZATION).unwrap(),
            "Bearer ghu_synthetic_user_token_1234567890"
        );
        assert_eq!(
            requests[2].1,
            "https://api.github.com/user/installations?per_page=100&page=1"
        );
    }

    #[tokio::test]
    async fn expiring_user_tokens_use_a_canonical_bundle_and_rotate_on_the_fixed_route() {
        let provider = Arc::new(ExpiringProvider::default());
        let owner = GitHubAppAuthorizationOwner::new(config(), provider.clone());
        let mut imported = owner
            .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
            .await
            .unwrap();
        let (material, account) = imported.take_import().unwrap();
        assert_eq!(account.as_deref(), Some("octo-user"));
        let bundle = GitHubAppUserOAuthBundle::parse(&material).unwrap();
        assert_eq!(
            bundle.access_token().unwrap().as_str(),
            "ghu_synthetic_user_token_1234567890"
        );
        assert!(!bundle.should_refresh(unix_now().unwrap()).unwrap());
        let rotated = owner.refresh(bundle).await.unwrap();
        assert_eq!(
            rotated.access_token().unwrap().as_str(),
            "ghu_rotated_user_token_1234567890"
        );
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 6);
        assert_eq!(requests[3].0, Method::POST);
        assert_eq!(requests[3].1, TOKEN_EXCHANGE_URL);
        assert_eq!(
            std::str::from_utf8(&requests[3].3).unwrap(),
            "client_id=Iv1.syntheticclient&client_secret=synthetic-client-secret&grant_type=refresh_token&refresh_token=ghr_synthetic_refresh_token_1234567890"
        );
        assert_eq!(
            requests[5].1,
            "https://api.github.com/user/installations?per_page=100&page=1"
        );
    }

    #[tokio::test]
    async fn refresh_rejects_a_different_github_user_or_app_installation() {
        for (user_id, installation_id, app_slug) in [
            (74, 41, "codewire"),
            (73, 42, "codewire"),
            (73, 41, "other-app"),
        ] {
            let provider = Arc::new(ExpiringProvider {
                requests: Mutex::new(Vec::new()),
                refreshed_user_id: user_id,
                refreshed_installation_id: installation_id,
                refreshed_app_slug: app_slug,
            });
            let owner = GitHubAppAuthorizationOwner::new(config(), provider);
            let mut imported = owner
                .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
                .await
                .unwrap();
            let (material, _) = imported.take_import().unwrap();
            let bundle = GitHubAppUserOAuthBundle::parse(&material).unwrap();
            assert!(matches!(
                owner.refresh(bundle).await,
                Err(GitHubAppRefreshError::Permanent)
            ));
        }
    }

    #[test]
    fn malformed_tagged_bundles_never_fall_back_to_raw_cli_material() {
        assert!(matches!(
            GitHubOAuthCredential::parse(b"codewire-github-app-user-v1:not-json"),
            Err(GitHubAppAuthorizationError::InvalidResponse)
        ));
        let response = TokenResponse {
            access_token: Zeroizing::new("ghu_synthetic_user_token".into()),
            token_type: "bearer".into(),
            expires_in: Some(28_800),
            refresh_token: None,
            refresh_token_expires_in: Some(15_897_600),
        };
        assert!(matches!(
            response.into_initial_material(1, 73, "codewire".into(), 41,),
            Err(GitHubAppAuthorizationError::InvalidResponse)
        ));
    }

    #[test]
    fn configuration_and_callback_inputs_are_closed() {
        assert!(valid_callback_url(
            "https://codewire.example/api/v1/github/oauth/callback"
        ));
        assert!(valid_callback_url(
            "http://127.0.0.1:5173/api/v1/github/oauth/callback"
        ));
        for value in [
            "https://codewire.example/settings/credentials/github/callback",
            "https://codewire.example/api/v1/github/oauth/callback?next=bad",
            "https://user@example.test/api/v1/github/oauth/callback",
            "https://codewire.example/other",
            "file:///api/v1/github/oauth/callback",
        ] {
            assert!(!valid_callback_url(value), "accepted {value}");
        }
        assert!(valid_authorization_code(b"code_123-abc.~"));
        assert!(!valid_authorization_code(b"code&injected"));
        assert!(!valid_user_token("gho_device_token"));
        assert!(valid_user_token("ghu_user_token_123"));
        assert!(valid_refresh_token("ghr_refresh_token_123"));
        assert!(!valid_refresh_token("ghu_user_token_123"));
    }
}
