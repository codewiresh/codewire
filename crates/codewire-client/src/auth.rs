use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "desktop-pkce-loopback")]
use std::sync::atomic::AtomicBool;
#[cfg(feature = "desktop-pkce-loopback")]
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine as _;
use connectrpc::ErrorCode;
use http::HeaderValue;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use url::Url;

use crate::{ClientConfig, ClientError};

/// A validated bearer credential.
///
/// Debug output is always redacted. Callers that must authenticate a
/// non-Connect transport, such as the permanent terminal WebSocket, can use
/// [`expose_secret`](Self::expose_secret) deliberately.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken(String);

impl BearerToken {
    pub fn new(token: impl Into<String>) -> Result<Self, ClientError> {
        let token = token.into();
        if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(ClientError::new(
                ErrorCode::InvalidArgument,
                "bearer token must not be empty or contain whitespace",
            ));
        }
        HeaderValue::try_from(format!("Bearer {token}")).map_err(|_| {
            ClientError::new(
                ErrorCode::InvalidArgument,
                "bearer token contains invalid header characters",
            )
        })?;
        Ok(Self(token))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub(crate) fn authorization_header(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

/// Supplies the current bearer credential for each RPC.
///
/// The provider is asynchronous so the later OAuth convergence can refresh
/// and atomically persist a token pair behind this same seam. API keys and
/// OAuth access tokens both use this interface; the server remains the
/// authority for their distinct semantics.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn token(&self) -> Result<BearerToken, ClientError>;
}

/// A non-refreshing provider for an already-resolved token or `cw_` API key.
#[derive(Clone, Debug)]
pub struct StaticTokenProvider {
    token: BearerToken,
}

impl StaticTokenProvider {
    pub fn new(token: impl Into<String>) -> Result<Self, ClientError> {
        Ok(Self {
            token: BearerToken::new(token)?,
        })
    }

    /// Move an already validated credential into a static provider without
    /// manufacturing another plaintext copy.
    pub fn from_token(token: BearerToken) -> Self {
        Self { token }
    }
}

#[async_trait]
impl TokenProvider for StaticTokenProvider {
    async fn token(&self) -> Result<BearerToken, ClientError> {
        Ok(self.token.clone())
    }
}

/// The standard OAuth client registration used by the public Codewire CLI.
pub const CODEWIRE_CLI_OAUTH_CLIENT_ID: &str = "codewire-cli";
/// The exact scopes granted to the public Codewire CLI device flow.
pub const CODEWIRE_CLI_OAUTH_SCOPES: &str = "openid profile email offline_access codewire.api";
/// The fixed native public client used by the replacement desktop application.
pub const CODEWIRE_DESKTOP_OAUTH_CLIENT_ID: &str = "codewire-desktop";
/// The fixed loopback callback registered for the replacement desktop client.
pub const CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI: &str = "http://localhost:9876/callback";
/// The desktop needs the same product capability as every other native client.
pub const CODEWIRE_DESKTOP_OAUTH_SCOPES: &str = CODEWIRE_CLI_OAUTH_SCOPES;

/// OIDC metadata needed by the public CLI. Endpoint URLs are validated against
/// the configured issuer before a credential can be sent to them.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct OAuthDiscovery {
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub revocation_endpoint: String,
    pub device_authorization_endpoint: Option<String>,
}

/// The opaque state required to complete one authorization-code PKCE login.
/// It is intentionally not serializable or debuggable because the verifier is
/// a one-time credential.
pub struct OAuthPkceAuthorization {
    authorization_url: Url,
    state: String,
    code_verifier: String,
    client_id: String,
    redirect_uri: String,
}

impl OAuthPkceAuthorization {
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }
}

impl fmt::Debug for OAuthPkceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthPkceAuthorization")
            .field("authorization_url", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("code_verifier", &"[REDACTED]")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// One pre-bound desktop OAuth login attempt.
///
/// The loopback listener is created before the browser is opened, so a fast
/// redirect cannot race listener startup. The authorization URL remains in
/// memory and is deliberately omitted from `Debug` output.
#[cfg(feature = "desktop-pkce-loopback")]
pub struct DesktopOAuthLogin {
    authorization: OAuthPkceAuthorization,
    callback_server: tiny_http::Server,
    cancellation: DesktopOAuthCancellation,
}

#[cfg(feature = "desktop-pkce-loopback")]
impl DesktopOAuthLogin {
    pub fn authorization_url(&self) -> &Url {
        self.authorization.authorization_url()
    }

    pub fn cancellation(&self) -> DesktopOAuthCancellation {
        self.cancellation.clone()
    }
}

/// Cancellation handle for one desktop OAuth login attempt.
#[cfg(feature = "desktop-pkce-loopback")]
#[derive(Clone, Default)]
pub struct DesktopOAuthCancellation {
    cancelled: Arc<AtomicBool>,
}

#[cfg(feature = "desktop-pkce-loopback")]
impl DesktopOAuthCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// One atomic credential entry in the operating-system keyring. The complete
/// rotating OAuth pair is serialized into one keyring value, so readers never
/// observe an access token and refresh token from different generations.
#[cfg(feature = "desktop-keyring")]
#[derive(Clone, Debug)]
pub struct KeyringCredentialStore {
    service: String,
    account: String,
}

#[cfg(feature = "desktop-keyring")]
impl KeyringCredentialStore {
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    pub fn desktop() -> Self {
        Self::new("codewire-desktop", "oauth")
    }

    fn entry(&self) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(&self.service, &self.account)
            .map_err(|_| credential_error("open OAuth keyring entry"))
    }
}

#[cfg(feature = "desktop-keyring")]
impl CredentialStore for KeyringCredentialStore {
    fn load(&self) -> Result<Option<OAuthCredentials>, ClientError> {
        match self.entry()?.get_password() {
            Ok(serialized) => decode_keyring_credentials(&serialized).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(credential_error("read OAuth keyring credentials")),
        }
    }

    fn save(&self, credentials: &OAuthCredentials) -> Result<(), ClientError> {
        let serialized = encode_keyring_credentials(credentials)?;
        self.entry()?
            .set_password(&serialized)
            .map_err(|_| credential_error("write OAuth keyring credentials"))
    }

    fn delete(&self) -> Result<(), ClientError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(credential_error("delete OAuth keyring credentials")),
        }
    }
}

/// RFC 8628 device-authorization response. The CLI deliberately presents the
/// base verification URI and user code, so the existing browser page remains
/// the sole password/2FA/passkey owner during dual serving.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct OAuthDeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
    pub interval: u64,
}

impl fmt::Debug for OAuthDeviceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthDeviceAuthorization")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("verification_uri_complete", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// UserInfo claims used by `cw whoami`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthUserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

/// A successful OAuth token response. It intentionally does not implement
/// `Debug`, because all but the expiry and scope are credential material.
#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: String,
}

impl OAuthTokenResponse {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

impl fmt::Debug for OAuthTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

/// OAuth credentials persisted by a [`CredentialStore`]. The token pair is
/// opaque and its `Debug` representation is deliberately redacted.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct OAuthCredentials {
    issuer: String,
    client_id: String,
    access_token: String,
    refresh_token: String,
    expires_at_unix: u64,
    scope: String,
}

impl OAuthCredentials {
    /// Build an opaque native credential pair for a known issuer. Callers
    /// normally obtain this from [`OAuthClient::credentials_from_device_token`]
    /// rather than handling token response fields directly.
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        expires_at_unix: u64,
        scope: impl Into<String>,
    ) -> Result<Self, ClientError> {
        let issuer = issuer.into();
        Url::parse(&issuer).map_err(|_| {
            ClientError::new(
                ErrorCode::InvalidArgument,
                "OAuth issuer must be a valid URL",
            )
        })?;
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(ClientError::new(
                ErrorCode::InvalidArgument,
                "OAuth client id must not be empty",
            ));
        }
        let access_token = BearerToken::new(access_token)?.0;
        let refresh_token = BearerToken::new(refresh_token)?.0;
        Ok(Self {
            issuer,
            client_id,
            access_token,
            refresh_token,
            expires_at_unix,
            scope: scope.into(),
        })
    }

    fn from_token_response(
        issuer: String,
        client_id: String,
        response: OAuthTokenResponse,
        previous_refresh_token: Option<&str>,
    ) -> Result<Self, ClientError> {
        if !response.token_type.eq_ignore_ascii_case("bearer") {
            return Err(ClientError::new(
                ErrorCode::Unauthenticated,
                "OAuth token response did not use Bearer authentication",
            ));
        }
        let access_token = BearerToken::new(response.access_token)?.0;
        let refresh_token = response
            .refresh_token
            .or_else(|| previous_refresh_token.map(ToOwned::to_owned))
            .ok_or_else(|| {
                ClientError::new(
                    ErrorCode::Unauthenticated,
                    "OAuth token response did not include a refresh token",
                )
            })?;
        BearerToken::new(&refresh_token)?;
        let expires_at_unix = now_unix()
            .checked_add(response.expires_in)
            .ok_or_else(|| ClientError::new(ErrorCode::Internal, "OAuth expiry is invalid"))?;
        Self::new(
            issuer,
            client_id,
            access_token,
            refresh_token,
            expires_at_unix,
            response.scope,
        )
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn bearer_token(&self) -> Result<BearerToken, ClientError> {
        BearerToken::new(self.access_token.clone())
    }

    fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    fn is_fresh(&self) -> bool {
        self.expires_at_unix > now_unix().saturating_add(60)
    }
}

impl fmt::Debug for OAuthCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthCredentials")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Atomic persistence boundary for a native OAuth token pair.
pub trait CredentialStore: Send + Sync {
    fn load(&self) -> Result<Option<OAuthCredentials>, ClientError>;
    fn save(&self, credentials: &OAuthCredentials) -> Result<(), ClientError>;
    fn delete(&self) -> Result<(), ClientError>;
}

/// File-backed native OAuth credential store. Writes are staged in the target
/// directory, synced, and atomically renamed, so refresh rotation never leaves
/// a half-written credential pair.
#[derive(Clone, Debug)]
pub struct FileCredentialStore {
    path: PathBuf,
}

impl FileCredentialStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        Self::at(config_dir.as_ref().join("credentials.json"))
    }

    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CredentialStore for FileCredentialStore {
    fn load(&self) -> Result<Option<OAuthCredentials>, ClientError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(credential_error("read OAuth credentials")),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| credential_error("parse OAuth credentials"))
    }

    fn save(&self, credentials: &OAuthCredentials) -> Result<(), ClientError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| credential_error("resolve OAuth credential directory"))?;
        fs::create_dir_all(parent)
            .map_err(|_| credential_error("create OAuth credential directory"))?;
        harden_credential_dir(parent)?;

        let mut payload = serde_json::to_vec_pretty(credentials)
            .map_err(|_| credential_error("serialize OAuth credentials"))?;
        payload.push(b'\n');

        let temporary = credential_temp_path(&self.path);
        let write_result = (|| -> Result<(), ClientError> {
            let mut file = credential_temp_file(&temporary)?;
            file.write_all(&payload)
                .map_err(|_| credential_error("write OAuth credentials"))?;
            file.sync_all()
                .map_err(|_| credential_error("sync OAuth credentials"))?;
            fs::rename(&temporary, &self.path)
                .map_err(|_| credential_error("replace OAuth credentials"))?;
            sync_credential_dir(parent)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    fn delete(&self) -> Result<(), ClientError> {
        match fs::remove_file(&self.path) {
            Ok(()) => {
                if let Some(parent) = self.path.parent() {
                    sync_credential_dir(parent)?;
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(credential_error("delete OAuth credentials")),
        }
    }
}

/// Standard OAuth/OIDC raw-HTTP client. It belongs in the shared Rust core,
/// because identity-plane endpoints are a permanent raw-HTTP exception while
/// product APIs remain generated Connect clients.
#[derive(Clone)]
pub struct OAuthClient {
    discovery: OAuthDiscovery,
    authorization_endpoint: Option<Url>,
    token_endpoint: Url,
    userinfo_endpoint: Url,
    revocation_endpoint: Url,
    device_authorization_endpoint: Url,
    http: reqwest::Client,
    json_timeout: Duration,
}

impl OAuthClient {
    pub async fn discover(server_url: impl AsRef<str>) -> Result<Self, AuthClientError> {
        Self::discover_with_http(server_url, reqwest::Client::new()).await
    }

    pub async fn discover_with_http(
        server_url: impl AsRef<str>,
        http: reqwest::Client,
    ) -> Result<Self, AuthClientError> {
        let config = ClientConfig::new(server_url)?;
        let discovery_url = endpoint_from_config(&config, ".well-known/openid-configuration");
        let response = http
            .get(discovery_url)
            .timeout(AUTH_JSON_TIMEOUT)
            .send()
            .await?;
        let response = check_response(response).await?;
        let discovery = response.json::<OAuthDiscovery>().await?;
        Self::from_discovery(config.server_url(), discovery, http)
    }

    /// Build the Codewire-standard endpoint set for a saved credential. Fresh
    /// logins always use discovery; this constructor avoids a second network
    /// round-trip before a provider can refresh an expired token on restart.
    pub fn for_server_url(server_url: impl AsRef<str>) -> Result<Self, ClientError> {
        Self::for_server_url_with_http(server_url, reqwest::Client::new())
    }

    /// Build the standard endpoint set with an explicitly confined transport.
    /// Credential-owning processes use this to disable ambient proxies and
    /// redirects before a refresh token can enter an outbound request.
    pub fn for_server_url_with_http(
        server_url: impl AsRef<str>,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        let config = ClientConfig::new(server_url)?;
        let issuer = config
            .server_url()
            .as_str()
            .trim_end_matches('/')
            .to_string();
        let discovery = OAuthDiscovery {
            issuer,
            authorization_endpoint: Some(
                endpoint_from_config(&config, "api/oauth/authorize").to_string(),
            ),
            token_endpoint: endpoint_from_config(&config, "api/oauth/token").to_string(),
            userinfo_endpoint: endpoint_from_config(&config, "api/oauth/userinfo").to_string(),
            revocation_endpoint: endpoint_from_config(&config, "api/oauth/revoke").to_string(),
            device_authorization_endpoint: Some(
                endpoint_from_config(&config, "api/oauth/device_authorization").to_string(),
            ),
        };
        Self::from_discovery(config.server_url(), discovery, http)
            .map_err(AuthClientError::into_client_error)
    }

    fn from_discovery(
        configured_server: &Url,
        discovery: OAuthDiscovery,
        http: reqwest::Client,
    ) -> Result<Self, AuthClientError> {
        let issuer = validated_oauth_endpoint(configured_server, &discovery.issuer, "issuer")?;
        let token_endpoint =
            validated_oauth_endpoint(&issuer, &discovery.token_endpoint, "token endpoint")?;
        let authorization_endpoint = discovery
            .authorization_endpoint
            .as_deref()
            .map(|endpoint| validated_oauth_endpoint(&issuer, endpoint, "authorization endpoint"))
            .transpose()?;
        let userinfo_endpoint =
            validated_oauth_endpoint(&issuer, &discovery.userinfo_endpoint, "userinfo endpoint")?;
        let revocation_endpoint = validated_oauth_endpoint(
            &issuer,
            &discovery.revocation_endpoint,
            "revocation endpoint",
        )?;
        let device_authorization_endpoint = discovery
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| AuthClientError::Response {
                message: "issuer does not advertise OAuth device authorization".to_string(),
            })
            .and_then(|endpoint| {
                validated_oauth_endpoint(&issuer, endpoint, "device authorization endpoint")
            })?;
        Ok(Self {
            discovery,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            revocation_endpoint,
            device_authorization_endpoint,
            http,
            json_timeout: AUTH_JSON_TIMEOUT,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.discovery.issuer
    }

    /// Start a standard authorization-code flow with RFC 7636 S256 PKCE.
    /// The returned value is intentionally opaque; callers only open its URL
    /// and hand the final loopback callback back to this client.
    pub fn begin_pkce_authorization(
        &self,
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scopes: impl AsRef<str>,
    ) -> Result<OAuthPkceAuthorization, AuthClientError> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(AuthClientError::Response {
                message: "OAuth client id must not be empty".into(),
            });
        }
        let redirect_uri = redirect_uri.into();
        let callback = Url::parse(&redirect_uri).map_err(|_| AuthClientError::Response {
            message: "OAuth redirect URI is not a valid URL".into(),
        })?;
        if callback.scheme() != "http"
            || !matches!(
                callback.host_str(),
                Some("localhost") | Some("127.0.0.1") | Some("::1")
            )
            || callback.port().is_none()
        {
            return Err(AuthClientError::Response {
                message: "native OAuth redirect URI must be an explicit loopback HTTP URL".into(),
            });
        }
        let authorization_endpoint =
            self.authorization_endpoint
                .clone()
                .ok_or_else(|| AuthClientError::Response {
                    message: "issuer does not advertise OAuth authorization".into(),
                })?;
        let code_verifier = random_urlsafe(48);
        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(code_verifier.as_bytes()));
        let state = random_urlsafe(32);
        let mut authorization_url = authorization_endpoint;
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", scopes.as_ref())
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(OAuthPkceAuthorization {
            authorization_url,
            state,
            code_verifier,
            client_id,
            redirect_uri,
        })
    }

    /// Complete a PKCE login from the complete loopback callback URL. The
    /// callback's origin and path must exactly match the registered redirect,
    /// and its state must match the one-time request before any token request
    /// is sent.
    pub async fn complete_pkce_authorization(
        &self,
        authorization: OAuthPkceAuthorization,
        callback_url: &str,
    ) -> Result<OAuthCredentials, AuthClientError> {
        let callback = Url::parse(callback_url).map_err(|_| AuthClientError::Response {
            message: "OAuth callback is not a valid URL".into(),
        })?;
        let expected =
            Url::parse(&authorization.redirect_uri).map_err(|_| AuthClientError::Response {
                message: "OAuth redirect URI is not a valid URL".into(),
            })?;
        if callback.scheme() != expected.scheme()
            || callback.host_str() != expected.host_str()
            || callback.port_or_known_default() != expected.port_or_known_default()
            || callback.path() != expected.path()
        {
            return Err(AuthClientError::Response {
                message: "OAuth callback did not match the registered redirect URI".into(),
            });
        }
        let mut state = None;
        let mut code = None;
        let mut oauth_error = None;
        let mut error_description = None;
        for (key, value) in callback.query_pairs() {
            let value = value.into_owned();
            let duplicate = match key.as_ref() {
                "state" => state.replace(value).is_some(),
                "code" => code.replace(value).is_some(),
                "error" => oauth_error.replace(value).is_some(),
                "error_description" => error_description.replace(value).is_some(),
                _ => false,
            };
            if duplicate {
                let message = match key.as_ref() {
                    "state" => "OAuth callback contained duplicate state values",
                    "code" => "OAuth callback contained duplicate authorization codes",
                    "error" => "OAuth callback contained duplicate error codes",
                    "error_description" => "OAuth callback contained duplicate error descriptions",
                    _ => unreachable!("only handled callback parameters can be duplicates"),
                };
                return Err(AuthClientError::Response {
                    message: message.into(),
                });
            }
        }
        if state.as_deref() != Some(authorization.state.as_str()) {
            return Err(AuthClientError::Response {
                message: "OAuth callback state did not match the authorization request".into(),
            });
        }
        if let Some(oauth_error) = oauth_error {
            if oauth_error.trim().is_empty() {
                return Err(AuthClientError::Response {
                    message: "OAuth callback contained an empty error code".into(),
                });
            }
            if code.as_deref().is_some_and(|code| !code.is_empty()) {
                return Err(AuthClientError::Response {
                    message: "OAuth callback contained both a code and an error".into(),
                });
            }
            let description = error_description
                .filter(|description| !description.trim().is_empty())
                .map(|description| format!(": {description}"))
                .unwrap_or_default();
            return Err(AuthClientError::OAuth {
                code: oauth_error,
                description,
            });
        }
        if error_description.is_some() {
            return Err(AuthClientError::Response {
                message: "OAuth callback contained an error description without an error code"
                    .into(),
            });
        }
        let code = code
            .as_deref()
            .filter(|code| !code.is_empty())
            .ok_or_else(|| AuthClientError::Response {
                message: "OAuth callback did not contain an authorization code".into(),
            })?;
        let response = self
            .token_request(&[
                ("client_id", authorization.client_id.as_str()),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", authorization.redirect_uri.as_str()),
                ("code_verifier", authorization.code_verifier.as_str()),
            ])
            .await?;
        OAuthCredentials::from_token_response(
            self.discovery.issuer.clone(),
            authorization.client_id,
            response,
            None,
        )
        .map_err(AuthClientError::Client)
    }

    /// Prepare the fixed desktop PKCE flow and bind its registered loopback
    /// callback before returning the system-browser URL to the caller.
    #[cfg(feature = "desktop-pkce-loopback")]
    pub fn begin_desktop_pkce_login(&self) -> Result<DesktopOAuthLogin, AuthClientError> {
        let authorization = self.begin_pkce_authorization(
            CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
            CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI,
            CODEWIRE_DESKTOP_OAUTH_SCOPES,
        )?;
        let callback_server =
            tiny_http::Server::http("localhost:9876").map_err(|_| AuthClientError::Response {
                message: "unable to bind the desktop OAuth loopback callback".into(),
            })?;
        Ok(DesktopOAuthLogin {
            authorization,
            callback_server,
            cancellation: DesktopOAuthCancellation::default(),
        })
    }

    /// Wait for and exchange one prepared desktop PKCE callback.
    #[cfg(feature = "desktop-pkce-loopback")]
    pub async fn complete_desktop_pkce_login(
        &self,
        login: DesktopOAuthLogin,
    ) -> Result<OAuthCredentials, AuthClientError> {
        let DesktopOAuthLogin {
            authorization,
            callback_server,
            cancellation,
        } = login;
        let callback = receive_desktop_loopback_callback(
            callback_server,
            cancellation.clone(),
            Duration::from_secs(300),
        )
        .await?;
        if cancellation.is_cancelled() {
            return Err(desktop_oauth_cancelled_error());
        }
        let credentials = self
            .complete_pkce_authorization(authorization, &callback)
            .await?;
        if cancellation.is_cancelled() {
            return Err(desktop_oauth_cancelled_error());
        }
        Ok(credentials)
    }

    /// Complete the fixed desktop PKCE flow through the system browser and its
    /// registered loopback callback. UI applications should use
    /// [`begin_desktop_pkce_login`](Self::begin_desktop_pkce_login), open the
    /// returned URL through their native application framework, and then call
    /// [`complete_desktop_pkce_login`](Self::complete_desktop_pkce_login).
    #[cfg(feature = "desktop-pkce-loopback")]
    pub async fn login_desktop_pkce(&self) -> Result<OAuthCredentials, AuthClientError> {
        let login = self.begin_desktop_pkce_login()?;
        open::that(login.authorization_url().as_str()).map_err(|_| AuthClientError::Response {
            message: "unable to open the system browser for OAuth login".into(),
        })?;
        self.complete_desktop_pkce_login(login).await
    }

    pub async fn authorize_device(&self) -> Result<OAuthDeviceAuthorization, AuthClientError> {
        self.form_request(
            self.http
                .post(self.device_authorization_endpoint.clone())
                .form(&[
                    ("client_id", CODEWIRE_CLI_OAUTH_CLIENT_ID),
                    ("scope", CODEWIRE_CLI_OAUTH_SCOPES),
                ]),
        )
        .await
    }

    pub async fn exchange_device_code(
        &self,
        device_code: &str,
    ) -> Result<OAuthTokenResponse, AuthClientError> {
        self.token_request(&[
            ("client_id", CODEWIRE_CLI_OAUTH_CLIENT_ID),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
        ])
        .await
    }

    pub async fn refresh(
        &self,
        credentials: &OAuthCredentials,
    ) -> Result<OAuthCredentials, AuthClientError> {
        if credentials.issuer != self.discovery.issuer {
            return Err(AuthClientError::Response {
                message: "OAuth credentials are not for this Codewire server".to_string(),
            });
        }
        let response = self
            .token_request(&[
                ("client_id", credentials.client_id()),
                ("grant_type", "refresh_token"),
                ("refresh_token", credentials.refresh_token()),
            ])
            .await?;
        OAuthCredentials::from_token_response(
            self.discovery.issuer.clone(),
            credentials.client_id().to_string(),
            response,
            Some(credentials.refresh_token()),
        )
        .map_err(AuthClientError::Client)
    }

    pub fn credentials_from_device_token(
        &self,
        response: OAuthTokenResponse,
    ) -> Result<OAuthCredentials, ClientError> {
        OAuthCredentials::from_token_response(
            self.discovery.issuer.clone(),
            CODEWIRE_CLI_OAUTH_CLIENT_ID.to_string(),
            response,
            None,
        )
    }

    pub async fn userinfo(&self, token: &BearerToken) -> Result<OAuthUserInfo, AuthClientError> {
        let response = self
            .json_request(
                self.http
                    .get(self.userinfo_endpoint.clone())
                    .bearer_auth(token.expose_secret()),
            )
            .send()
            .await?;
        let response = check_response(response).await?;
        Ok(response.json::<OAuthUserInfo>().await?)
    }

    pub async fn revoke(&self, token: &str) -> Result<(), AuthClientError> {
        self.revoke_token(token, "refresh_token").await
    }

    async fn revoke_token(&self, token: &str, hint: &str) -> Result<(), AuthClientError> {
        let response = self
            .json_request(self.http.post(self.revocation_endpoint.clone()).form(&[
                ("client_id", CODEWIRE_CLI_OAUTH_CLIENT_ID),
                ("token", token),
                ("token_type_hint", hint),
            ]))
            .send()
            .await?;
        check_response(response).await?;
        Ok(())
    }

    /// Revoke a persisted sign-in without exposing its tokens to the caller.
    /// The server revokes exactly the token it is given, so the refresh token
    /// and the access token are each revoked; the sign-in has ended only when
    /// both succeed (#4016).
    pub async fn revoke_credentials(
        &self,
        credentials: &OAuthCredentials,
    ) -> Result<(), AuthClientError> {
        if credentials.issuer != self.discovery.issuer {
            return Err(AuthClientError::Response {
                message: "OAuth credentials are not for this Codewire server".to_string(),
            });
        }
        self.revoke_token(credentials.refresh_token(), "refresh_token")
            .await?;
        self.revoke_token(&credentials.access_token, "access_token")
            .await
    }

    async fn token_request(
        &self,
        form: &[(&str, &str)],
    ) -> Result<OAuthTokenResponse, AuthClientError> {
        self.form_request(self.http.post(self.token_endpoint.clone()).form(form))
            .await
    }

    async fn form_request<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, AuthClientError> {
        let response = self.json_request(request).send().await?;
        let response = check_oauth_response(response).await?;
        Ok(response.json::<T>().await?)
    }

    fn json_request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.timeout(self.json_timeout)
    }
}

/// A refresh-on-demand provider backed by an atomic credential store. The
/// mutex coalesces concurrent RPC refreshes so a rotated refresh token is not
/// replayed by another local request.
pub struct RefreshingTokenProvider<S = FileCredentialStore> {
    client: OAuthClient,
    store: S,
    credentials: Mutex<OAuthCredentials>,
}

impl<S: CredentialStore> RefreshingTokenProvider<S> {
    pub fn from_store(client: OAuthClient, store: S) -> Result<Self, ClientError> {
        let credentials = store.load()?.ok_or_else(|| {
            ClientError::new(ErrorCode::Unauthenticated, "OAuth credentials unavailable")
        })?;
        if credentials.issuer != client.discovery.issuer {
            return Err(ClientError::new(
                ErrorCode::Unauthenticated,
                "OAuth credentials are not for this Codewire server",
            ));
        }
        Ok(Self {
            client,
            store,
            credentials: Mutex::new(credentials),
        })
    }

    pub fn new(
        client: OAuthClient,
        store: S,
        credentials: OAuthCredentials,
    ) -> Result<Self, ClientError> {
        if credentials.issuer != client.discovery.issuer {
            return Err(ClientError::new(
                ErrorCode::Unauthenticated,
                "OAuth credentials are not for this Codewire server",
            ));
        }
        Ok(Self {
            client,
            store,
            credentials: Mutex::new(credentials),
        })
    }
}

#[async_trait]
impl<S: CredentialStore> TokenProvider for RefreshingTokenProvider<S> {
    async fn token(&self) -> Result<BearerToken, ClientError> {
        let mut credentials = self.credentials.lock().await;
        if credentials.is_fresh() {
            return credentials.bearer_token();
        }
        let refreshed = self
            .client
            .refresh(&credentials)
            .await
            .map_err(AuthClientError::into_client_error)?;
        self.store.save(&refreshed)?;
        *credentials = refreshed;
        credentials.bearer_token()
    }
}

/// The identity-plane user shape used for CLI rendering while the CLI finishes
/// its OAuth convergence. This is raw HTTP by design: the IdP implements
/// standard HTTP/OIDC protocols rather than a control-plane RPC.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    #[serde(default, deserialize_with = "null_string_as_default")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, deserialize_with = "null_string_as_default")]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub image: String,
    pub is_admin: bool,
    pub two_factor_enabled: bool,
    pub created_at: String,
}

fn null_string_as_default<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AuthSession {
    pub id: String,
    pub token: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AuthResponse {
    pub user: Option<AuthUser>,
    pub session: Option<AuthSession>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthClientError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("session expired or invalid")]
    Unauthenticated,
    #[error("{message}")]
    Response { message: String },
    #[error("OAuth {code}{description}")]
    OAuth { code: String, description: String },
}

impl AuthClientError {
    /// The RFC/OIDC code is useful to a device-flow poller without making a
    /// product client branch on free-form error text.
    pub fn oauth_code(&self) -> Option<&str> {
        match self {
            Self::OAuth { code, .. } => Some(code),
            _ => None,
        }
    }

    fn into_client_error(self) -> ClientError {
        match self {
            Self::Client(error) => error,
            Self::Unauthenticated => ClientError::new(
                ErrorCode::Unauthenticated,
                "OAuth credentials expired or invalid",
            ),
            Self::OAuth { code, .. }
                if matches!(
                    code.as_str(),
                    "invalid_grant" | "invalid_token" | "expired_token" | "access_denied"
                ) =>
            {
                ClientError::new(
                    ErrorCode::Unauthenticated,
                    "OAuth credentials expired or invalid",
                )
            }
            Self::Request(_) => ClientError::new(ErrorCode::Unavailable, "OAuth request failed"),
            Self::Response { .. } | Self::OAuth { .. } => {
                ClientError::new(ErrorCode::Internal, "OAuth response was invalid")
            }
        }
    }
}

/// Raw IdP client kept inside the shared Rust core. Its paths are a permanent
/// raw-HTTP exception, not an alternate control-plane client.
#[derive(Clone)]
pub struct AuthClient {
    config: ClientConfig,
    token_provider: Option<Arc<dyn TokenProvider>>,
    http: reqwest::Client,
    json_timeout: Duration,
}

const AUTH_JSON_TIMEOUT: Duration = Duration::from_secs(30);

impl AuthClient {
    pub fn unauthenticated(server_url: impl AsRef<str>) -> Result<Self, ClientError> {
        Self::unauthenticated_with_http(server_url, reqwest::Client::new())
    }

    pub fn unauthenticated_with_http(
        server_url: impl AsRef<str>,
        http: reqwest::Client,
    ) -> Result<Self, ClientError> {
        Ok(Self {
            config: ClientConfig::new(server_url)?,
            token_provider: None,
            http,
            json_timeout: AUTH_JSON_TIMEOUT,
        })
    }

    pub(crate) fn authenticated(
        config: ClientConfig,
        token_provider: Arc<dyn TokenProvider>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            config,
            token_provider: Some(token_provider),
            http,
            json_timeout: AUTH_JSON_TIMEOUT,
        }
    }

    pub fn server_url(&self) -> &Url {
        self.config.server_url()
    }

    pub async fn get_session(&self) -> Result<AuthResponse, AuthClientError> {
        let response = self
            .authenticated_json_request(self.http.get(self.endpoint("api/auth/get-session")))
            .await?
            .send()
            .await?;
        let response = check_response(response).await?;
        Ok(response.json::<AuthResponse>().await?)
    }

    pub async fn logout(&self) -> Result<(), AuthClientError> {
        let response = self
            .authenticated_json_request(self.http.post(self.endpoint("api/auth/sign-out")))
            .await?
            .send()
            .await?;
        check_response(response).await?;
        Ok(())
    }

    fn json_request(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.timeout(self.json_timeout)
    }

    async fn authenticated_json_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, AuthClientError> {
        let token = self
            .token_provider
            .as_ref()
            .ok_or_else(|| {
                ClientError::new(ErrorCode::Unauthenticated, "bearer token unavailable")
            })?
            .token()
            .await?;
        Ok(self.json_request(request.bearer_auth(token.expose_secret())))
    }

    fn endpoint(&self, path: &str) -> Url {
        let mut url = self.config.server_url().clone();
        let base_path = url.path().trim_end_matches('/');
        let path = path.trim_start_matches('/');
        let joined = if base_path.is_empty() {
            format!("/{path}")
        } else {
            format!("{base_path}/{path}")
        };
        url.set_path(&joined);
        url.set_query(None);
        url
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ApiError {
    title: String,
    detail: String,
}

async fn check_response(response: reqwest::Response) -> Result<reqwest::Response, AuthClientError> {
    if response.status().is_success() {
        return Ok(response);
    }
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AuthClientError::Unauthenticated);
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if let Ok(api_error) = serde_json::from_str::<ApiError>(&body)
        && !api_error.title.trim().is_empty()
    {
        return Err(AuthClientError::Response {
            message: if api_error.detail.trim().is_empty() {
                api_error.title
            } else {
                api_error.detail
            },
        });
    }

    let body = body.trim();
    Err(AuthClientError::Response {
        message: if body.is_empty() {
            format!("HTTP {status}")
        } else {
            format!("HTTP {status}: {body}")
        },
    })
}

async fn check_oauth_response(
    response: reqwest::Response,
) -> Result<reqwest::Response, AuthClientError> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if let Ok(error) = serde_json::from_str::<OAuthErrorResponse>(&body)
        && !error.error.trim().is_empty()
    {
        let description = error
            .error_description
            .filter(|description| !description.trim().is_empty())
            .map(|description| format!(": {description}"))
            .unwrap_or_default();
        return Err(AuthClientError::OAuth {
            code: error.error,
            description,
        });
    }
    Err(AuthClientError::Response {
        message: format!("OAuth endpoint returned HTTP {status}"),
    })
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

fn endpoint_from_config(config: &ClientConfig, path: &str) -> Url {
    let mut url = config.server_url().clone();
    let base_path = url.path().trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let joined = if base_path.is_empty() {
        format!("/{path}")
    } else {
        format!("{base_path}/{path}")
    };
    url.set_path(&joined);
    url.set_query(None);
    url
}

fn validated_oauth_endpoint(
    expected_origin: &Url,
    endpoint: &str,
    label: &str,
) -> Result<Url, AuthClientError> {
    let url = Url::parse(endpoint).map_err(|_| AuthClientError::Response {
        message: format!("OAuth {label} is not a valid URL"),
    })?;
    if !matches!(url.scheme(), "https" | "http") || url.origin() != expected_origin.origin() {
        return Err(AuthClientError::Response {
            message: format!("OAuth {label} is outside the configured issuer"),
        });
    }
    Ok(url)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_urlsafe(bytes: usize) -> String {
    use rand::RngCore as _;

    let mut value = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

#[cfg(feature = "desktop-pkce-loopback")]
async fn receive_desktop_loopback_callback(
    server: tiny_http::Server,
    cancellation: DesktopOAuthCancellation,
    timeout: Duration,
) -> Result<String, AuthClientError> {
    tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + timeout;
        let request = loop {
            if cancellation.is_cancelled() {
                return Err(desktop_oauth_cancelled_error());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(AuthClientError::Response {
                    message: "desktop OAuth login timed out".into(),
                });
            }
            match server
                .recv_timeout(remaining.min(Duration::from_millis(100)))
                .map_err(|_| AuthClientError::Response {
                    message: "desktop OAuth loopback callback failed".into(),
                })? {
                Some(request) => break request,
                None => continue,
            }
        };
        if cancellation.is_cancelled() {
            return Err(desktop_oauth_cancelled_error());
        }
        let path_and_query = request.url().to_string();
        let callback_url = Url::parse(&format!("http://localhost:9876{path_and_query}"));
        let valid_path = callback_url
            .as_ref()
            .is_ok_and(|callback| callback.path() == "/callback");
        let callback_succeeded = callback_url.as_ref().is_ok_and(|callback| {
            let mut has_code = false;
            let mut has_error = false;
            for (key, value) in callback.query_pairs() {
                match key.as_ref() {
                    "code" if !value.is_empty() => has_code = true,
                    "error" if !value.is_empty() => has_error = true,
                    _ => {}
                }
            }
            valid_path && has_code && !has_error
        });
        let body = if callback_succeeded {
            "<html><body><h1>Authentication complete</h1><p>You can return to Codewire.</p></body></html>"
        } else {
            "<html><body><h1>Authentication failed</h1><p>You can return to Codewire.</p></body></html>"
        };
        let status = if callback_succeeded { 200 } else { 400 };
        let _ = request.respond(
            tiny_http::Response::from_string(body)
                .with_status_code(status)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                        .expect("static content-type header"),
                ),
        );
        if !valid_path {
            return Err(AuthClientError::Response {
                message: "desktop OAuth callback used an unexpected path".into(),
            });
        }
        Ok(format!("http://localhost:9876{path_and_query}"))
    })
    .await
    .map_err(|_| AuthClientError::Response {
        message: "desktop OAuth callback task failed".into(),
    })?
}

#[cfg(feature = "desktop-pkce-loopback")]
fn desktop_oauth_cancelled_error() -> AuthClientError {
    AuthClientError::Response {
        message: "desktop OAuth login cancelled".into(),
    }
}

fn credential_error(action: &str) -> ClientError {
    ClientError::new(ErrorCode::Internal, format!("unable to {action}"))
}

#[cfg(feature = "desktop-keyring")]
fn encode_keyring_credentials(credentials: &OAuthCredentials) -> Result<String, ClientError> {
    serde_json::to_string(credentials)
        .map_err(|_| credential_error("serialize OAuth keyring credentials"))
}

#[cfg(feature = "desktop-keyring")]
fn decode_keyring_credentials(serialized: &str) -> Result<OAuthCredentials, ClientError> {
    serde_json::from_str(serialized)
        .map_err(|_| credential_error("parse OAuth keyring credentials"))
}

fn credential_temp_path(path: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("credentials.json");
    path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ))
}

fn credential_temp_file(path: &Path) -> Result<fs::File, ClientError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| credential_error("create temporary OAuth credentials"))
}

#[cfg(unix)]
fn harden_credential_dir(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| credential_error("secure OAuth credential directory"))
}

#[cfg(not(unix))]
fn harden_credential_dir(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn sync_credential_dir(path: &Path) -> Result<(), ClientError> {
    fs::File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| credential_error("sync OAuth credential directory"))
}

#[cfg(not(unix))]
fn sync_credential_dir(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    #[test]
    fn bearer_tokens_are_validated_without_echoing_the_value() {
        assert!(BearerToken::new("").is_err());
        assert!(BearerToken::new("token with whitespace").is_err());
        assert!(BearerToken::new("token\r\ninjected: true").is_err());

        let token = BearerToken::new("secret-value").expect("valid token");
        assert_eq!(format!("{token:?}"), "BearerToken([REDACTED])");
        assert!(!format!("{token:?}").contains("secret-value"));
        assert_eq!(token.expose_secret(), "secret-value");
    }

    #[test]
    fn device_authorization_debug_preserves_user_instructions_but_redacts_capabilities() {
        const DEVICE_MARKER: &str = "synthetic-device-code-capability";
        const COMPLETE_URI_MARKER: &str = "synthetic-complete-uri-capability";
        let authorization = OAuthDeviceAuthorization {
            device_code: DEVICE_MARKER.to_owned(),
            user_code: "BCDF-GHJK".to_owned(),
            verification_uri: "https://identity.example.test/device".to_owned(),
            verification_uri_complete: format!(
                "https://identity.example.test/device?capability={COMPLETE_URI_MARKER}"
            ),
            expires_in: 600,
            interval: 5,
        };

        let debug = format!("{authorization:?}");
        assert!(debug.contains("BCDF-GHJK"));
        assert!(debug.contains("https://identity.example.test/device"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(DEVICE_MARKER));
        assert!(!debug.contains(COMPLETE_URI_MARKER));
    }

    #[tokio::test]
    async fn discovery_device_grant_and_userinfo_use_standard_oauth_wires() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "token_endpoint": format!("{}/api/oauth/token", server.uri()),
                "userinfo_endpoint": format!("{}/api/oauth/userinfo", server.uri()),
                "revocation_endpoint": format!("{}/api/oauth/revoke", server.uri()),
                "device_authorization_endpoint": format!(
                    "{}/api/oauth/device_authorization", server.uri()
                )
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/device_authorization"))
            .and(matchers::body_string_contains("client_id=codewire-cli"))
            .and(matchers::body_string_contains("codewire.api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code": "device-code",
                "user_code": "BCDF-GHJK",
                "verification_uri": format!("{}/device", server.uri()),
                "verification_uri_complete": format!("{}/device?user_code=BCDF-GHJK", server.uri()),
                "expires_in": 600,
                "interval": 5
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/token"))
            .and(matchers::body_string_contains(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
            ))
            .and(matchers::body_string_contains("device_code=device-code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-token",
                "scope": CODEWIRE_CLI_OAUTH_SCOPES
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/oauth/userinfo"))
            .and(matchers::header("authorization", "Bearer access-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "user_123", "email": "noel@example.com", "email_verified": true,
                "name": "Noel"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = OAuthClient::discover(server.uri()).await.expect("discover");
        let device = client.authorize_device().await.expect("device authorize");
        assert_eq!(device.user_code, "BCDF-GHJK");
        assert!(device.verification_uri_complete.contains("user_code="));
        let credentials = client
            .credentials_from_device_token(
                client
                    .exchange_device_code(&device.device_code)
                    .await
                    .expect("device exchange"),
            )
            .expect("credentials");
        let user = client
            .userinfo(&credentials.bearer_token().expect("access token"))
            .await
            .expect("userinfo");
        assert_eq!(user.sub, "user_123");
        assert_eq!(user.name.as_deref(), Some("Noel"));
    }

    #[tokio::test]
    async fn pkce_authorization_code_flow_binds_loopback_state_and_product_scope() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": server.uri(),
                "authorization_endpoint": format!("{}/api/oauth/authorize", server.uri()),
                "token_endpoint": format!("{}/api/oauth/token", server.uri()),
                "userinfo_endpoint": format!("{}/api/oauth/userinfo", server.uri()),
                "revocation_endpoint": format!("{}/api/oauth/revoke", server.uri()),
                "device_authorization_endpoint": format!("{}/api/oauth/device_authorization", server.uri())
            })))
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/token"))
            .and(matchers::body_string_contains(
                "grant_type=authorization_code",
            ))
            .and(matchers::body_string_contains("client_id=codewire-desktop"))
            .and(matchers::body_string_contains(
                "redirect_uri=http%3A%2F%2Flocalhost%3A9876%2Fcallback",
            ))
            .and(matchers::body_string_contains("code_verifier="))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "desktop-access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "desktop-refresh",
                "scope": CODEWIRE_DESKTOP_OAUTH_SCOPES
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = OAuthClient::discover(server.uri()).await.expect("discover");
        let authorization = client
            .begin_pkce_authorization(
                CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
                CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI,
                CODEWIRE_DESKTOP_OAUTH_SCOPES,
            )
            .expect("start pkce");
        let query = authorization
            .authorization_url()
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            query.get("response_type").map(|value| value.as_ref()),
            Some("code")
        );
        assert_eq!(
            query
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert_eq!(
            query.get("scope").map(|value| value.as_ref()),
            Some(CODEWIRE_DESKTOP_OAUTH_SCOPES)
        );
        assert_ne!(query.get("state").map(|value| value.as_ref()), Some(""));
        let callback = format!(
            "{}?code=desktop-code&state={}",
            CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI, authorization.state
        );
        let credentials = client
            .complete_pkce_authorization(authorization, &callback)
            .await
            .expect("exchange pkce code");
        assert_eq!(credentials.client_id(), CODEWIRE_DESKTOP_OAUTH_CLIENT_ID);
        assert_eq!(
            credentials.bearer_token().expect("token").expose_secret(),
            "desktop-access"
        );
    }

    #[tokio::test]
    async fn pkce_callback_rejects_duplicate_or_untrusted_parameters_before_exchange() {
        let client = OAuthClient::for_server_url("https://codewire.test").expect("OAuth client");
        let authorization = client
            .begin_pkce_authorization(
                CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
                CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI,
                CODEWIRE_DESKTOP_OAUTH_SCOPES,
            )
            .expect("start pkce");
        let duplicate_code = format!(
            "{}?code=first&code=second&state={}",
            CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI, authorization.state
        );
        let error = client
            .complete_pkce_authorization(authorization, &duplicate_code)
            .await
            .expect_err("duplicate code must be rejected before token exchange");
        assert!(matches!(
            error,
            AuthClientError::Response { ref message }
                if message == "OAuth callback contained duplicate authorization codes"
        ));

        let error = client
            .begin_pkce_authorization(
                CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
                "http://example.test:9876/callback",
                CODEWIRE_DESKTOP_OAUTH_SCOPES,
            )
            .expect_err("non-loopback redirect must be rejected");
        assert!(matches!(error, AuthClientError::Response { .. }));
    }

    #[tokio::test]
    async fn pkce_callback_preserves_oauth_error_after_state_validation() {
        let client = OAuthClient::for_server_url("https://codewire.test").expect("OAuth client");
        let authorization = client
            .begin_pkce_authorization(
                CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
                CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI,
                CODEWIRE_DESKTOP_OAUTH_SCOPES,
            )
            .expect("start pkce");
        let callback = format!(
            "{}?error=invalid_scope&error_description=scope%20not%20allowed&state={}",
            CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI, authorization.state
        );
        let error = client
            .complete_pkce_authorization(authorization, &callback)
            .await
            .expect_err("OAuth error callback must not reach token exchange");
        assert!(matches!(
            error,
            AuthClientError::OAuth {
                ref code,
                ref description,
            } if code == "invalid_scope" && description == ": scope not allowed"
        ));

        let authorization = client
            .begin_pkce_authorization(
                CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
                CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI,
                CODEWIRE_DESKTOP_OAUTH_SCOPES,
            )
            .expect("start pkce");
        let callback = format!(
            "{}?error=invalid_scope&error_description=sensitive&state=wrong-state",
            CODEWIRE_DESKTOP_OAUTH_REDIRECT_URI
        );
        let error = client
            .complete_pkce_authorization(authorization, &callback)
            .await
            .expect_err("untrusted OAuth error must fail state validation first");
        assert!(matches!(
            error,
            AuthClientError::Response { ref message }
                if message == "OAuth callback state did not match the authorization request"
        ));
    }

    #[cfg(feature = "desktop-pkce-loopback")]
    #[tokio::test]
    async fn desktop_loopback_cancellation_stops_waiting_and_releases_listener() {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind loopback listener");
        let address = server
            .server_addr()
            .to_ip()
            .expect("loopback listener has an IP address");
        let cancellation = DesktopOAuthCancellation::default();
        let cancel_from_ui = cancellation.clone();
        let waiter = tokio::spawn(async move {
            receive_desktop_loopback_callback(server, cancellation, Duration::from_secs(5)).await
        });

        tokio::task::yield_now().await;
        cancel_from_ui.cancel();

        let error = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("cancelled listener stops promptly")
            .expect("callback task joins")
            .expect_err("cancelled listener does not produce a callback");
        assert!(matches!(
            error,
            AuthClientError::Response { ref message }
                if message == "desktop OAuth login cancelled"
        ));
        std::net::TcpListener::bind(address).expect("cancelled listener releases its port");
    }

    #[tokio::test]
    async fn refresh_provider_replaces_the_pair_atomically() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/oauth/token"))
            .and(matchers::body_string_contains("grant_type=refresh_token"))
            .and(matchers::body_string_contains("refresh_token=old-refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh",
                "scope": CODEWIRE_CLI_OAUTH_SCOPES
            })))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().expect("credential directory");
        let store = FileCredentialStore::new(directory.path());
        let credentials = OAuthCredentials::new(
            server.uri(),
            CODEWIRE_CLI_OAUTH_CLIENT_ID,
            "old-access",
            "old-refresh",
            0,
            CODEWIRE_CLI_OAUTH_SCOPES,
        )
        .expect("expired credentials");
        store.save(&credentials).expect("save credentials");
        let provider = RefreshingTokenProvider::from_store(
            OAuthClient::for_server_url(server.uri()).expect("oauth client"),
            store.clone(),
        )
        .expect("refresh provider");

        let token = provider.token().await.expect("refresh token");
        assert_eq!(token.expose_secret(), "new-access");
        assert_eq!(
            store
                .load()
                .expect("load credentials")
                .expect("credentials")
                .bearer_token()
                .expect("stored access")
                .expose_secret(),
            "new-access"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("credential directory")
                .all(|entry| !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
    }

    #[cfg(feature = "desktop-keyring")]
    #[test]
    fn desktop_keyring_payload_is_one_complete_rotating_credential_pair() {
        let store = KeyringCredentialStore::desktop();
        assert_eq!(store.service, "codewire-desktop");
        assert_eq!(store.account, "oauth");

        let credentials = OAuthCredentials::new(
            "https://codewire.test",
            CODEWIRE_DESKTOP_OAUTH_CLIENT_ID,
            "desktop-access",
            "desktop-refresh",
            4_102_444_800,
            CODEWIRE_DESKTOP_OAUTH_SCOPES,
        )
        .expect("valid desktop credentials");
        let serialized = encode_keyring_credentials(&credentials).expect("serialize one entry");
        assert!(serialized.contains("desktop-access"));
        assert!(serialized.contains("desktop-refresh"));
        assert_eq!(
            decode_keyring_credentials(&serialized).expect("decode one entry"),
            credentials
        );
    }

    #[test]
    fn idp_user_shape_preserves_the_cli_json_contract() {
        let user: AuthUser = serde_json::from_value(serde_json::json!({
            "id": "user_123",
            "email": "noel@example.com",
            "email_verified": true,
            "name": null,
            "image": null,
            "is_admin": false,
            "two_factor_enabled": true,
            "created_at": "2026-07-04T00:00:00Z"
        }))
        .expect("decode user");
        assert_eq!(user.name, "");
        assert_eq!(user.image, "");
    }

    #[tokio::test]
    async fn retained_raw_idp_session_requests_keep_their_wires() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/api/auth/get-session"))
            .and(matchers::header("authorization", "Bearer session-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user": {"id": "user_123"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/auth/sign-out"))
            .and(matchers::header("authorization", "Bearer session-token"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let authenticated = AuthClient::authenticated(
            ClientConfig::new(server.uri()).expect("config"),
            Arc::new(StaticTokenProvider::new("session-token").expect("token")),
            reqwest::Client::new(),
        );
        assert_eq!(
            authenticated
                .get_session()
                .await
                .expect("get session")
                .user
                .expect("user")
                .id,
            "user_123"
        );
        authenticated.logout().await.expect("logout");
        server.verify().await;
    }

    #[tokio::test]
    async fn raw_idp_paths_keep_the_configured_server_base_path() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("GET"))
            .and(matchers::path("/control/api/auth/get-session"))
            .and(matchers::header("authorization", "Bearer session-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "user": {"id": "user_123"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        AuthClient::authenticated(
            ClientConfig::new(format!("{}/control", server.uri())).expect("config"),
            Arc::new(StaticTokenProvider::new("session-token").expect("token")),
            reqwest::Client::new(),
        )
        .get_session()
        .await
        .expect("get session");
        server.verify().await;
    }
}
