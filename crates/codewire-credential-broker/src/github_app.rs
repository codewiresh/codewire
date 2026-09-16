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

use futures::StreamExt as _;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::Deserialize;
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
        let token = self.exchange(&authorization_code).await;
        authorization_code.zeroize();
        let mut token = token?;
        let account_hint = self.user(&token).await?;
        self.verify_installation(&token).await?;
        let material = Zeroizing::new(std::mem::take(&mut *token).into_bytes());
        Ok(GitHubAppAuthorizationImport {
            material,
            account_hint,
        })
    }

    async fn exchange(
        &self,
        authorization_code: &[u8],
    ) -> Result<Zeroizing<String>, GitHubAppAuthorizationError> {
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
            // GitHub App user-token rotation needs the credential broker's
            // durable refresh authority. Until that provider-specific refresh
            // path exists, refuse an expiring bundle rather than retaining an
            // access token which would later fail without a safe renewal.
            || response.expires_in.is_some()
            || response.refresh_token.is_some()
            || response.refresh_token_expires_in.is_some()
        {
            return Err(
                if response.expires_in.is_some()
                    || response.refresh_token.is_some()
                    || response.refresh_token_expires_in.is_some()
                {
                    GitHubAppAuthorizationError::ExpiringTokensUnsupported
                } else {
                    GitHubAppAuthorizationError::InvalidResponse
                },
            );
        }
        Ok(response.access_token)
    }

    async fn user(&self, token: &str) -> Result<String, GitHubAppAuthorizationError> {
        let response = self
            .request(
                Method::GET,
                USER_URL,
                authorization_headers(token)?,
                Vec::new(),
            )
            .await?;
        let response: UserResponse = response_json(response).await?;
        if !valid_login(&response.login) {
            return Err(GitHubAppAuthorizationError::InvalidResponse);
        }
        Ok(response.login)
    }

    async fn verify_installation(&self, token: &str) -> Result<(), GitHubAppAuthorizationError> {
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
            if response.installations.iter().any(|installation| {
                installation.id > 0 && installation.app_slug == self.config.app_slug
            }) {
                return Ok(());
            }
            if response.installations.len() < 100 {
                break;
            }
        }
        Err(GitHubAppAuthorizationError::Denied)
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
    #[error("GitHub App authorization is unavailable")]
    Unavailable,
    #[error("GitHub App authorization response is invalid")]
    InvalidResponse,
    #[error("GitHub App expiring user tokens are not yet supported")]
    ExpiringTokensUnsupported,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Zeroizing<String>,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<Zeroizing<String>>,
    refresh_token_expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct UserResponse {
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
            && url.path() == "/settings/credentials/github/callback"
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
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use bytes::Bytes;
    use http::StatusCode;

    use super::*;
    use crate::{BrokerUpstreamError, BrokerUpstreamResponse};

    type RecordedRequest = (Method, String, HeaderMap, Vec<u8>);

    #[derive(Default)]
    struct Provider {
        requests: Mutex<Vec<RecordedRequest>>,
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
                1 => serde_json::json!({"login": "octo-user", "private": "ignored"}),
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

    struct ExpiringProvider;

    #[async_trait]
    impl BrokerUpstreamTransport for ExpiringProvider {
        async fn execute(
            &self,
            request: BrokerUpstreamRequest,
        ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
            let (method, target, _, _) = request.into_parts();
            if method != Method::POST || target.as_str() != TOKEN_EXCHANGE_URL {
                return Err(BrokerUpstreamError::Protocol);
            }
            let value = serde_json::json!({
                "access_token": "ghu_synthetic_user_token_1234567890",
                "token_type": "bearer",
                "expires_in": 28_800,
                "refresh_token": "ghr_synthetic_refresh_token_1234567890",
                "refresh_token_expires_in": 15_897_600
            });
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
            "https://codewire.example/settings/credentials/github/callback".into(),
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
            "client_id=Iv1.syntheticclient&client_secret=synthetic-client-secret&code=synthetic-code-123&redirect_uri=https%3A%2F%2Fcodewire.example%2Fsettings%2Fcredentials%2Fgithub%2Fcallback"
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
    async fn rejects_expiring_user_tokens_until_the_durable_refresh_path_exists() {
        let owner = GitHubAppAuthorizationOwner::new(config(), Arc::new(ExpiringProvider));
        assert!(matches!(
            owner
                .complete(Zeroizing::new(b"synthetic-code-123".to_vec()))
                .await,
            Err(GitHubAppAuthorizationError::ExpiringTokensUnsupported)
        ));
    }

    #[test]
    fn configuration_and_callback_inputs_are_closed() {
        assert!(valid_callback_url(
            "https://codewire.example/settings/credentials/github/callback"
        ));
        for value in [
            "https://codewire.example/settings/credentials/github/callback?next=bad",
            "https://user@example.test/settings/credentials/github/callback",
            "https://codewire.example/other",
            "file:///settings/credentials/github/callback",
        ] {
            assert!(!valid_callback_url(value), "accepted {value}");
        }
        assert!(valid_authorization_code(b"code_123-abc.~"));
        assert!(!valid_authorization_code(b"code&injected"));
        assert!(!valid_user_token("gho_device_token"));
        assert!(valid_user_token("ghu_user_token_123"));
    }
}
