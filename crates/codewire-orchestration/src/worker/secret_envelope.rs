//! Authenticated envelopes and KEK providers for tenant secrets.
//!
//! Secret values are encrypted locally under one 256-bit DEK per tenant
//! scope. OpenBao Transit wraps each DEK. Provider responses carry the
//! observed key version beside the wrapped DEK, so callers never race a
//! separate "active version" query.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

pub const SECRET_FORMAT_V1: i16 = 1;
pub const WRAPPED_DEK_FORMAT_V1: i16 = 1;
pub const DEK_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const SECRET_AAD_DOMAIN_V1: &[u8] = b"codewire/tenant-secret/v1\0";
const DEK_CONTEXT_DOMAIN_V1: &[u8] = b"codewire/tenant-dek-context/v1\0";
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/codewire-tenant-bao/token";
const DEFAULT_AUTH_MOUNT: &str = "kubernetes-codewire";
const DEFAULT_TRANSIT_MOUNT: &str = "transit";
const DEFAULT_TRANSIT_KEY: &str = "tenant-dek";
const MAX_BAO_RESPONSE_BYTES: usize = 64 * 1024;

/// A value-blind error. It deliberately retains no path, tenant identifier,
/// secret key, plaintext, ciphertext, token, endpoint, or response body.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecretEnvelopeError {
    class: &'static str,
    scope: Option<TenantSecretScope>,
    provider: Option<KekProviderKind>,
    key_version: Option<u32>,
    format: Option<i16>,
}

impl SecretEnvelopeError {
    fn envelope(class: &'static str, context: &DekContext, format: i16) -> Self {
        Self {
            class,
            scope: Some(context.scope),
            provider: None,
            key_version: None,
            format: Some(format),
        }
    }

    pub(crate) fn provider(
        class: &'static str,
        provider: KekProviderKind,
        key_version: Option<u32>,
        format: Option<i16>,
    ) -> Self {
        Self {
            class,
            scope: None,
            provider: Some(provider),
            key_version,
            format,
        }
    }

    fn configuration(class: &'static str, provider: KekProviderKind) -> Self {
        Self::provider(class, provider, None, None)
    }

    pub fn failure_class(&self) -> &'static str {
        self.class
    }
}

impl fmt::Display for SecretEnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tenant-secret-envelope failure_class={}", self.class)?;
        if let Some(scope) = self.scope {
            write!(f, " scope={}", scope.as_str())?;
        }
        if let Some(provider) = self.provider {
            write!(f, " provider={}", provider.as_str())?;
        }
        if let Some(key_version) = self.key_version {
            write!(f, " key_version={key_version}")?;
        }
        if let Some(format) = self.format {
            write!(f, " format={format}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SecretEnvelopeError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TenantSecretScope {
    Organization,
    User,
    Canary,
}

impl TenantSecretScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Organization => "org",
            Self::User => "user",
            Self::Canary => "canary",
        }
    }
}

/// The DEK scope derived from one exact product secret path.
#[derive(Clone, Eq, PartialEq)]
pub struct DekContext {
    pub scope: TenantSecretScope,
    pub scope_id: String,
}

impl fmt::Debug for DekContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DekContext")
            .field("scope", &self.scope)
            .field("scope_id", &"[redacted]")
            .finish()
    }
}

impl DekContext {
    /// Fixed provider context for the persisted KEK readiness canary. It is
    /// not derivable from a product secret path and cannot collide with an
    /// organization or user DEK scope.
    pub fn canary() -> Self {
        Self {
            scope: TenantSecretScope::Canary,
            scope_id: "tenant-secret".to_owned(),
        }
    }

    pub fn from_secret_path(path: &str) -> Result<Self, SecretEnvelopeError> {
        let invalid = || SecretEnvelopeError {
            class: "unrecognized-secret-path",
            scope: None,
            provider: None,
            key_version: None,
            format: None,
        };
        if path.len() > 1024 || !path.starts_with('/') || path.ends_with('/') {
            return Err(invalid());
        }
        let segments: Vec<_> = path[1..].split('/').collect();
        let (scope, scope_id) = match segments.as_slice() {
            ["org-secrets", org_id] if valid_scope_id(org_id) => {
                (TenantSecretScope::Organization, *org_id)
            }
            ["projects", org_id, project_id]
                if valid_scope_id(org_id) && valid_scope_id(project_id) =>
            {
                (TenantSecretScope::Organization, *org_id)
            }
            ["users", user_id] if valid_scope_id(user_id) => (TenantSecretScope::User, *user_id),
            _ => return Err(invalid()),
        };
        Ok(Self {
            scope,
            scope_id: scope_id.to_owned(),
        })
    }

    fn transit_context(&self) -> String {
        STANDARD.encode(length_prefixed(
            DEK_CONTEXT_DOMAIN_V1,
            &[self.scope.as_str().as_bytes(), self.scope_id.as_bytes()],
        ))
    }
}

fn valid_scope_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub struct SecretCoordinates<'a> {
    pub context: &'a DekContext,
    pub path: &'a str,
    pub key: &'a str,
}

/// One persisted tenant-secret envelope. Debug output is intentionally
/// metadata-only.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedTenantSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub format: i16,
}

impl fmt::Debug for EncryptedTenantSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedTenantSecret")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce_len", &self.nonce.len())
            .field("format", &self.format)
            .finish()
    }
}

pub fn encrypt_secret(
    dek: &[u8; DEK_BYTES],
    coordinates: &SecretCoordinates<'_>,
    plaintext: &[u8],
) -> Result<EncryptedTenantSecret, SecretEnvelopeError> {
    let format = SECRET_FORMAT_V1;
    let error = |class| SecretEnvelopeError::envelope(class, coordinates.context, format);
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|_| error("invalid-dek-length"))?;
    let mut nonce = [0_u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let aad = secret_aad_v1(coordinates);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| error("encryption-failed"))?;
    Ok(EncryptedTenantSecret {
        ciphertext,
        nonce: nonce.to_vec(),
        format,
    })
}

pub fn decrypt_secret(
    dek: &[u8; DEK_BYTES],
    coordinates: &SecretCoordinates<'_>,
    envelope: &EncryptedTenantSecret,
) -> Result<Zeroizing<Vec<u8>>, SecretEnvelopeError> {
    let error = |class| SecretEnvelopeError::envelope(class, coordinates.context, envelope.format);
    if envelope.format != SECRET_FORMAT_V1 {
        return Err(error("unknown-secret-format"));
    }
    let nonce: [u8; NONCE_BYTES] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| error("invalid-secret-nonce-length"))?;
    if envelope.ciphertext.len() < TAG_BYTES {
        return Err(error("invalid-secret-ciphertext-length"));
    }
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|_| error("invalid-dek-length"))?;
    let aad = secret_aad_v1(coordinates);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| error("authentication-failed"))?;
    Ok(Zeroizing::new(plaintext))
}

fn secret_aad_v1(coordinates: &SecretCoordinates<'_>) -> Vec<u8> {
    length_prefixed(
        SECRET_AAD_DOMAIN_V1,
        &[
            coordinates.context.scope.as_str().as_bytes(),
            coordinates.context.scope_id.as_bytes(),
            coordinates.path.as_bytes(),
            coordinates.key.as_bytes(),
        ],
    )
}

fn length_prefixed(domain: &[u8], values: &[&[u8]]) -> Vec<u8> {
    let capacity = domain.len()
        + values
            .iter()
            .map(|value| 8_usize.saturating_add(value.len()))
            .sum::<usize>();
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(domain);
    for value in values {
        encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
        encoded.extend_from_slice(value);
    }
    encoded
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KekProviderKind {
    OpenBaoTransit,
}

impl KekProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenBaoTransit => "openbao-transit",
        }
    }

    pub fn from_persisted(value: &str) -> Option<Self> {
        match value {
            "openbao-transit" => Some(Self::OpenBaoTransit),
            _ => None,
        }
    }
}

/// Provider-owned persisted DEK envelope. Debug output never includes the
/// wrapped bytes or nonce.
#[derive(Clone, Eq, PartialEq)]
pub struct WrappedDek {
    pub provider: KekProviderKind,
    pub key_name: String,
    pub key_version: u32,
    pub ciphertext: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    pub format: i16,
}

impl fmt::Debug for WrappedDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedDek")
            .field("provider", &self.provider)
            .field("key_name", &self.key_name)
            .field("key_version", &self.key_version)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce_len", &self.nonce.as_ref().map(Vec::len))
            .field("format", &self.format)
            .finish()
    }
}

pub struct GeneratedDek {
    pub plaintext: Zeroizing<[u8; DEK_BYTES]>,
    pub wrapped: WrappedDek,
}

#[async_trait]
pub trait KekProvider: Send + Sync {
    fn kind(&self) -> KekProviderKind;

    async fn generate(&self, context: &DekContext) -> Result<GeneratedDek, SecretEnvelopeError>;

    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError>;

    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<WrappedDek, SecretEnvelopeError>;

    /// Return the provider authority identity. Keyring providers have no
    /// external authority and return `None`; OpenBao validates and returns its
    /// configured cluster id.
    async fn authority_id(&self) -> Result<Option<String>, SecretEnvelopeError>;
}

/// In-memory provider used only by tests which need the encrypted PostgreSQL
/// store without a live OpenBao service. It persists the same OpenBao-shaped
/// envelope fields so schema tests exercise the production contract.
#[cfg(any(test, feature = "kind-e2e"))]
pub(crate) struct TestKekProvider;

#[cfg(any(test, feature = "kind-e2e"))]
#[async_trait]
impl KekProvider for TestKekProvider {
    fn kind(&self) -> KekProviderKind {
        KekProviderKind::OpenBaoTransit
    }

    async fn generate(&self, _context: &DekContext) -> Result<GeneratedDek, SecretEnvelopeError> {
        let mut plaintext = Zeroizing::new([0_u8; DEK_BYTES]);
        rand::rngs::OsRng.fill_bytes(&mut *plaintext);
        let ciphertext = format!("vault:v1:{}", STANDARD.encode(*plaintext)).into_bytes();
        Ok(GeneratedDek {
            plaintext,
            wrapped: WrappedDek {
                provider: KekProviderKind::OpenBaoTransit,
                key_name: DEFAULT_TRANSIT_KEY.into(),
                key_version: 1,
                ciphertext,
                nonce: None,
                format: WRAPPED_DEK_FORMAT_V1,
            },
        })
    }

    async fn unwrap(
        &self,
        _context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        let error = || {
            SecretEnvelopeError::provider(
                "test-provider-envelope-invalid",
                KekProviderKind::OpenBaoTransit,
                Some(wrapped.key_version),
                Some(wrapped.format),
            )
        };
        let encoded = std::str::from_utf8(&wrapped.ciphertext)
            .ok()
            .and_then(|value| value.strip_prefix("vault:v1:"))
            .ok_or_else(error)?;
        let decoded = STANDARD.decode(encoded).map_err(|_| error())?;
        let dek = decoded.as_slice().try_into().map_err(|_| error())?;
        Ok(Zeroizing::new(dek))
    }

    async fn rewrap(
        &self,
        _context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<WrappedDek, SecretEnvelopeError> {
        Ok(wrapped.clone())
    }

    async fn authority_id(&self) -> Result<Option<String>, SecretEnvelopeError> {
        Ok(Some("test-openbao".into()))
    }
}

fn parse_version(value: &str) -> Option<u32> {
    let version = value.strip_prefix('v')?;
    if !matches!(version.as_bytes().first(), Some(b'1'..=b'9'))
        || !version.as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    version.parse().ok()
}

#[derive(Clone)]
pub struct OpenBaoTransitConfig {
    address: Url,
    auth_mount: String,
    role: String,
    token_path: PathBuf,
    transit_mount: String,
    key_name: String,
    expected_cluster_id: String,
}

impl OpenBaoTransitConfig {
    pub fn from_env() -> Result<Self, SecretEnvelopeError> {
        let provider = KekProviderKind::OpenBaoTransit;
        let required = |name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    SecretEnvelopeError::configuration("missing-openbao-configuration", provider)
                })
        };
        let address = required("BAO_ADDR")?
            .parse()
            .map_err(|_| SecretEnvelopeError::configuration("invalid-openbao-origin", provider))?;
        Self::new(
            address,
            std::env::var("TENANT_SECRET_BAO_AUTH_MOUNT")
                .unwrap_or_else(|_| DEFAULT_AUTH_MOUNT.to_owned()),
            required("TENANT_SECRET_BAO_ROLE")?,
            std::env::var_os("TENANT_SECRET_BAO_SA_TOKEN_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_TOKEN_PATH)),
            std::env::var("TENANT_SECRET_BAO_TRANSIT_MOUNT")
                .unwrap_or_else(|_| DEFAULT_TRANSIT_MOUNT.to_owned()),
            std::env::var("TENANT_SECRET_BAO_TRANSIT_KEY")
                .unwrap_or_else(|_| DEFAULT_TRANSIT_KEY.to_owned()),
            required("TENANT_SECRET_BAO_EXPECTED_CLUSTER_ID")?,
        )
    }

    pub fn new(
        mut address: Url,
        auth_mount: String,
        role: String,
        token_path: PathBuf,
        transit_mount: String,
        key_name: String,
        expected_cluster_id: String,
    ) -> Result<Self, SecretEnvelopeError> {
        let provider = KekProviderKind::OpenBaoTransit;
        let internal_http = address.scheme() == "http"
            && address
                .host_str()
                .is_some_and(|host| host == "127.0.0.1" || host.ends_with(".svc.cluster.local"));
        if address.host_str().is_none()
            || (address.scheme() != "https" && !internal_http)
            || !address.username().is_empty()
            || address.password().is_some()
            || address.path() != "/"
            || address.query().is_some()
            || address.fragment().is_some()
        {
            return Err(SecretEnvelopeError::configuration(
                "invalid-openbao-origin",
                provider,
            ));
        }
        if !valid_bao_segment(&auth_mount)
            || !valid_bao_segment(&transit_mount)
            || key_name != DEFAULT_TRANSIT_KEY
            || !valid_bao_role(&role)
            || !valid_authority_id(&expected_cluster_id)
        {
            return Err(SecretEnvelopeError::configuration(
                "invalid-openbao-configuration",
                provider,
            ));
        }
        address.set_query(None);
        address.set_fragment(None);
        Ok(Self {
            address,
            auth_mount,
            role,
            token_path,
            transit_mount,
            key_name,
            expected_cluster_id,
        })
    }
}

fn valid_bao_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_bao_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn valid_authority_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

struct CachedBaoToken {
    value: Zeroizing<String>,
    expires_at: Instant,
}

pub struct OpenBaoTransitProvider {
    config: OpenBaoTransitConfig,
    http: reqwest::Client,
    token: Mutex<Option<CachedBaoToken>>,
}

#[derive(Serialize)]
struct BaoAuthRequest<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Deserialize)]
struct BaoAuthResponse {
    auth: BaoAuth,
}

#[derive(Deserialize)]
struct BaoAuth {
    client_token: Zeroizing<String>,
    #[serde(default)]
    lease_duration: u64,
}

#[derive(Serialize)]
struct BaoContextRequest<'a> {
    context: &'a str,
}

#[derive(Serialize)]
struct BaoCiphertextRequest<'a> {
    ciphertext: &'a str,
    context: &'a str,
}

#[derive(Deserialize)]
struct BaoDataResponse<T> {
    data: T,
}

#[derive(Deserialize)]
struct BaoDatakeyData {
    plaintext: Zeroizing<String>,
    ciphertext: String,
}

#[derive(Deserialize)]
struct BaoPlaintextData {
    plaintext: Zeroizing<String>,
}

#[derive(Deserialize)]
struct BaoCiphertextData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct BaoHealthResponse {
    cluster_id: String,
}

impl OpenBaoTransitProvider {
    pub fn new(config: OpenBaoTransitConfig) -> Result<Self, SecretEnvelopeError> {
        let https_only = config.address.scheme() == "https";
        let http = reqwest::Client::builder()
            .https_only(https_only)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| {
                SecretEnvelopeError::configuration(
                    "openbao-client-construction-failed",
                    KekProviderKind::OpenBaoTransit,
                )
            })?;
        Ok(Self {
            config,
            http,
            token: Mutex::new(None),
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, SecretEnvelopeError> {
        let mut url = self.config.address.clone();
        let mut path = url.path_segments_mut().map_err(|_| {
            SecretEnvelopeError::configuration(
                "openbao-url-construction-failed",
                KekProviderKind::OpenBaoTransit,
            )
        })?;
        path.pop_if_empty().extend(segments);
        drop(path);
        Ok(url)
    }

    async fn authenticate(&self) -> Result<Zeroizing<String>, SecretEnvelopeError> {
        let provider = KekProviderKind::OpenBaoTransit;
        let mut cached = self.token.lock().await;
        if let Some(token) = cached.as_ref()
            && token.expires_at > Instant::now()
        {
            return Ok(Zeroizing::new(token.value.to_string()));
        }
        let jwt = Zeroizing::new(
            tokio::fs::read_to_string(&self.config.token_path)
                .await
                .map_err(|_| {
                    SecretEnvelopeError::configuration(
                        "openbao-service-account-token-unreadable",
                        provider,
                    )
                })?,
        );
        let url = self.endpoint(&["v1", "auth", &self.config.auth_mount, "login"])?;
        let response = self
            .http
            .post(url)
            .json(&BaoAuthRequest {
                role: &self.config.role,
                jwt: jwt.trim(),
            })
            .send()
            .await
            .map_err(|_| {
                SecretEnvelopeError::provider("openbao-auth-unavailable", provider, None, None)
            })?;
        if !response.status().is_success() {
            return Err(SecretEnvelopeError::provider(
                "openbao-auth-rejected",
                provider,
                None,
                None,
            ));
        }
        let response: BaoAuthResponse =
            decode_bao_response(response, "openbao-auth-response-invalid").await?;
        if response.auth.client_token.is_empty() {
            return Err(SecretEnvelopeError::provider(
                "openbao-auth-response-invalid",
                provider,
                None,
                None,
            ));
        }
        let refresh_after = response.auth.lease_duration.saturating_sub(60).min(60 * 60);
        let expires_at = Instant::now() + Duration::from_secs(refresh_after);
        let result = Zeroizing::new(response.auth.client_token.to_string());
        *cached = Some(CachedBaoToken {
            value: response.auth.client_token,
            expires_at,
        });
        Ok(result)
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        segments: &[&str],
        body: &impl Serialize,
        class: &'static str,
    ) -> Result<T, SecretEnvelopeError> {
        let provider = KekProviderKind::OpenBaoTransit;
        let token = self.authenticate().await?;
        let response = self
            .http
            .post(self.endpoint(segments)?)
            .header("X-Vault-Token", token.as_str())
            .json(body)
            .send()
            .await
            .map_err(|_| SecretEnvelopeError::provider(class, provider, None, None))?;
        if !response.status().is_success() {
            return Err(SecretEnvelopeError::provider(class, provider, None, None));
        }
        decode_bao_response(response, class).await
    }

    fn validate_transit_wrapped<'a>(
        &self,
        wrapped: &'a WrappedDek,
    ) -> Result<&'a str, SecretEnvelopeError> {
        let error = |class| {
            SecretEnvelopeError::provider(
                class,
                KekProviderKind::OpenBaoTransit,
                Some(wrapped.key_version),
                Some(wrapped.format),
            )
        };
        if wrapped.provider != KekProviderKind::OpenBaoTransit
            || wrapped.key_name != self.config.key_name
            || wrapped.key_version == 0
            || wrapped.format != WRAPPED_DEK_FORMAT_V1
            || wrapped.nonce.is_some()
        {
            return Err(error("invalid-openbao-envelope"));
        }
        let ciphertext = std::str::from_utf8(&wrapped.ciphertext)
            .map_err(|_| error("invalid-openbao-envelope"))?;
        let observed =
            parse_transit_version(ciphertext).ok_or_else(|| error("invalid-openbao-envelope"))?;
        if observed != wrapped.key_version {
            return Err(error("openbao-version-mismatch"));
        }
        Ok(ciphertext)
    }

    fn wrapped_from_transit_ciphertext(
        &self,
        ciphertext: String,
    ) -> Result<WrappedDek, SecretEnvelopeError> {
        let version = parse_transit_version(&ciphertext).ok_or_else(|| {
            SecretEnvelopeError::provider(
                "invalid-openbao-ciphertext",
                KekProviderKind::OpenBaoTransit,
                None,
                Some(WRAPPED_DEK_FORMAT_V1),
            )
        })?;
        Ok(WrappedDek {
            provider: KekProviderKind::OpenBaoTransit,
            key_name: self.config.key_name.clone(),
            key_version: version,
            ciphertext: ciphertext.into_bytes(),
            nonce: None,
            format: WRAPPED_DEK_FORMAT_V1,
        })
    }
}

#[async_trait]
impl KekProvider for OpenBaoTransitProvider {
    fn kind(&self) -> KekProviderKind {
        KekProviderKind::OpenBaoTransit
    }

    async fn generate(&self, context: &DekContext) -> Result<GeneratedDek, SecretEnvelopeError> {
        let context = context.transit_context();
        let response: BaoDataResponse<BaoDatakeyData> = self
            .post(
                &[
                    "v1",
                    &self.config.transit_mount,
                    "datakey",
                    "plaintext",
                    &self.config.key_name,
                ],
                &BaoContextRequest { context: &context },
                "openbao-datakey-failed",
            )
            .await?;
        let plaintext = decode_dek(&response.data.plaintext, "openbao-datakey-invalid")?;
        let wrapped = self.wrapped_from_transit_ciphertext(response.data.ciphertext)?;
        Ok(GeneratedDek { plaintext, wrapped })
    }

    async fn unwrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
        let ciphertext = self.validate_transit_wrapped(wrapped)?;
        let context = context.transit_context();
        let response: BaoDataResponse<BaoPlaintextData> = self
            .post(
                &[
                    "v1",
                    &self.config.transit_mount,
                    "decrypt",
                    &self.config.key_name,
                ],
                &BaoCiphertextRequest {
                    ciphertext,
                    context: &context,
                },
                "openbao-decrypt-failed",
            )
            .await?;
        decode_dek(&response.data.plaintext, "openbao-decrypt-invalid")
    }

    async fn rewrap(
        &self,
        context: &DekContext,
        wrapped: &WrappedDek,
    ) -> Result<WrappedDek, SecretEnvelopeError> {
        let ciphertext = self.validate_transit_wrapped(wrapped)?;
        let context = context.transit_context();
        let response: BaoDataResponse<BaoCiphertextData> = self
            .post(
                &[
                    "v1",
                    &self.config.transit_mount,
                    "rewrap",
                    &self.config.key_name,
                ],
                &BaoCiphertextRequest {
                    ciphertext,
                    context: &context,
                },
                "openbao-rewrap-failed",
            )
            .await?;
        self.wrapped_from_transit_ciphertext(response.data.ciphertext)
    }

    async fn authority_id(&self) -> Result<Option<String>, SecretEnvelopeError> {
        let provider = KekProviderKind::OpenBaoTransit;
        let mut health_url = self.endpoint(&["v1", "sys", "health"])?;
        health_url
            .query_pairs_mut()
            .append_pair("standbyok", "true")
            .append_pair("perfstandbyok", "true");
        let response = self.http.get(health_url).send().await.map_err(|_| {
            SecretEnvelopeError::provider("openbao-authority-unavailable", provider, None, None)
        })?;
        if !response.status().is_success() {
            return Err(SecretEnvelopeError::provider(
                "openbao-authority-unavailable",
                provider,
                None,
                None,
            ));
        }
        let response: BaoHealthResponse =
            decode_bao_response(response, "openbao-authority-response-invalid").await?;
        if response.cluster_id != self.config.expected_cluster_id {
            return Err(SecretEnvelopeError::provider(
                "openbao-authority-mismatch",
                provider,
                None,
                None,
            ));
        }
        Ok(Some(response.cluster_id))
    }
}

async fn decode_bao_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    class: &'static str,
) -> Result<T, SecretEnvelopeError> {
    let provider = KekProviderKind::OpenBaoTransit;
    let mut body = Zeroizing::new(Vec::new());
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|_| SecretEnvelopeError::provider(class, provider, None, None))?;
        if chunk.len() > MAX_BAO_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(SecretEnvelopeError::provider(class, provider, None, None));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| SecretEnvelopeError::provider(class, provider, None, None))
}

fn decode_dek(
    encoded: &str,
    class: &'static str,
) -> Result<Zeroizing<[u8; DEK_BYTES]>, SecretEnvelopeError> {
    let decoded = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| {
        SecretEnvelopeError::provider(class, KekProviderKind::OpenBaoTransit, None, None)
    })?);
    let dek: [u8; DEK_BYTES] = decoded.as_slice().try_into().map_err(|_| {
        SecretEnvelopeError::provider(class, KekProviderKind::OpenBaoTransit, None, None)
    })?;
    Ok(Zeroizing::new(dek))
}

fn parse_transit_version(ciphertext: &str) -> Option<u32> {
    let mut fields = ciphertext.splitn(3, ':');
    if fields.next()? != "vault" {
        return None;
    }
    let version = parse_version(fields.next()?)?;
    if fields.next()?.is_empty() {
        return None;
    }
    Some(version)
}

pub fn dek_fingerprint(dek: &[u8; DEK_BYTES]) -> [u8; 32] {
    Sha256::digest(dek).into()
}

pub fn verify_dek_fingerprint(
    dek: &[u8; DEK_BYTES],
    expected: &[u8],
    provider: KekProviderKind,
) -> Result<(), SecretEnvelopeError> {
    let actual = dek_fingerprint(dek);
    if expected.len() != actual.len() || actual.as_slice() != expected {
        return Err(SecretEnvelopeError::provider(
            "canary-fingerprint-mismatch",
            provider,
            None,
            None,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::Router;
    use axum::extract::{Json, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use serde_json::Value;

    use super::*;

    fn context(path: &str) -> DekContext {
        DekContext::from_secret_path(path).unwrap()
    }

    #[test]
    fn derives_only_exact_product_scopes() {
        let canary = DekContext::canary();
        assert_eq!(canary.scope, TenantSecretScope::Canary);
        assert_eq!(canary.scope_id, "tenant-secret");
        assert_eq!(
            context("/org-secrets/org_1").scope,
            TenantSecretScope::Organization
        );
        let project = context("/projects/org_1/project_1");
        assert_eq!(project.scope, TenantSecretScope::Organization);
        assert_eq!(project.scope_id, "org_1");
        assert_eq!(context("/users/user_1").scope, TenantSecretScope::User);
        for invalid in [
            "/",
            "users/user_1",
            "/users/user_1/",
            "/projects/org_1",
            "/projects/org_1/project_1/extra",
            "/other/org_1",
            "/users/not allowed",
        ] {
            assert!(DekContext::from_secret_path(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn secret_envelope_binds_scope_path_and_key_without_rendering_them() {
        let dek = [0x42; DEK_BYTES];
        let original_context = context("/projects/org_private/project_private");
        let coordinates = SecretCoordinates {
            context: &original_context,
            path: "/projects/org_private/project_private",
            key: "PRIVATE_KEY_NAME",
        };
        let plaintext = b"private-value-must-never-render";
        let envelope = encrypt_secret(&dek, &coordinates, plaintext).unwrap();
        assert_eq!(
            decrypt_secret(&dek, &coordinates, &envelope)
                .unwrap()
                .as_slice(),
            plaintext
        );

        let moved_path = SecretCoordinates {
            context: &original_context,
            path: "/projects/org_private/other_project",
            key: coordinates.key,
        };
        let moved_key = SecretCoordinates {
            context: &original_context,
            path: coordinates.path,
            key: "OTHER_KEY",
        };
        let other_context = context("/projects/other_org/project_private");
        let moved_scope = SecretCoordinates {
            context: &other_context,
            path: coordinates.path,
            key: coordinates.key,
        };
        for rejected in [&moved_path, &moved_key, &moved_scope] {
            let error = decrypt_secret(&dek, rejected, &envelope).unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains("failure_class=authentication-failed"));
            for forbidden in [
                "org_private",
                "project_private",
                "PRIVATE_KEY_NAME",
                "private-value-must-never-render",
            ] {
                assert!(!rendered.contains(forbidden));
            }
        }

        let mut truncated = envelope;
        truncated.ciphertext.truncate(TAG_BYTES - 1);
        assert!(
            decrypt_secret(&dek, &coordinates, &truncated)
                .unwrap_err()
                .to_string()
                .contains("failure_class=invalid-secret-ciphertext-length")
        );
    }

    #[derive(Default)]
    struct FakeBaoState {
        contexts: Mutex<Vec<String>>,
        oversized_next_datakey: AtomicBool,
    }

    #[derive(Deserialize)]
    struct FakeAuthRequest {
        role: String,
        jwt: String,
    }

    #[derive(Deserialize)]
    struct FakeDatakeyRequest {
        context: String,
    }

    #[derive(Deserialize)]
    struct FakeCiphertextRequest {
        context: String,
        ciphertext: String,
    }

    async fn fake_auth(Json(body): Json<FakeAuthRequest>) -> (StatusCode, Json<Value>) {
        if body.role != "tenant-role" || body.jwt != "projected-jwt" {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
        }
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "auth": {"client_token": "bao-token", "lease_duration": 300}
            })),
        )
    }

    fn authenticated(headers: &HeaderMap) -> bool {
        headers
            .get("X-Vault-Token")
            .is_some_and(|value| value == "bao-token")
    }

    async fn fake_datakey(
        State(state): State<Arc<FakeBaoState>>,
        headers: HeaderMap,
        Json(body): Json<FakeDatakeyRequest>,
    ) -> (StatusCode, Json<Value>) {
        if !authenticated(&headers) {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({})));
        }
        if state.oversized_next_datakey.swap(false, Ordering::SeqCst) {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "data": {"plaintext": "x".repeat(MAX_BAO_RESPONSE_BYTES + 1)}
                })),
            );
        }
        state.contexts.lock().await.push(body.context);
        (
            StatusCode::OK,
            Json(serde_json::json!({"data": {
                "plaintext": STANDARD.encode([0x5a; DEK_BYTES]),
                "ciphertext": "vault:v3:generated"
            }})),
        )
    }

    async fn fake_decrypt(
        State(state): State<Arc<FakeBaoState>>,
        headers: HeaderMap,
        Json(body): Json<FakeCiphertextRequest>,
    ) -> (StatusCode, Json<Value>) {
        let expected = state.contexts.lock().await.first().cloned();
        if !authenticated(&headers)
            || body.ciphertext != "vault:v3:generated"
            || expected.as_deref() != Some(body.context.as_str())
        {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
        }
        (
            StatusCode::OK,
            Json(serde_json::json!({"data": {
                "plaintext": STANDARD.encode([0x5a; DEK_BYTES])
            }})),
        )
    }

    async fn fake_rewrap(
        headers: HeaderMap,
        Json(body): Json<FakeCiphertextRequest>,
    ) -> (StatusCode, Json<Value>) {
        if !authenticated(&headers)
            || body.ciphertext != "vault:v3:generated"
            || body.context.is_empty()
        {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({})));
        }
        (
            StatusCode::OK,
            Json(serde_json::json!({"data": {
                "ciphertext": "vault:v4:rewrapped"
            }})),
        )
    }

    async fn fake_health() -> Json<Value> {
        Json(serde_json::json!({"cluster_id": "cluster-test-1"}))
    }

    async fn fake_bao() -> (Url, Arc<FakeBaoState>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(FakeBaoState::default());
        let app = Router::new()
            .route("/v1/auth/kubernetes/login", post(fake_auth))
            .route(
                "/v1/transit/datakey/plaintext/tenant-dek",
                post(fake_datakey),
            )
            .route("/v1/transit/decrypt/tenant-dek", post(fake_decrypt))
            .route("/v1/transit/rewrap/tenant-dek", post(fake_rewrap))
            .route("/v1/sys/health", get(fake_health))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}").parse().unwrap(), state, task)
    }

    #[tokio::test]
    async fn openbao_provider_uses_atomic_response_versions_and_expected_authority() {
        let (address, state, server) = fake_bao().await;
        let token_path =
            std::env::temp_dir().join(format!("codewire-tenant-bao-token-{}", std::process::id()));
        fs::write(&token_path, "projected-jwt\n").unwrap();
        let config = OpenBaoTransitConfig::new(
            address,
            "kubernetes".into(),
            "tenant-role".into(),
            token_path.clone(),
            "transit".into(),
            "tenant-dek".into(),
            "cluster-test-1".into(),
        )
        .unwrap();
        let provider = OpenBaoTransitProvider::new(config).unwrap();
        let original_context = context("/users/user_1");
        let other_context = context("/users/user_2");

        assert_eq!(
            provider.authority_id().await.unwrap().as_deref(),
            Some("cluster-test-1")
        );
        let generated = provider.generate(&original_context).await.unwrap();
        assert_eq!(generated.wrapped.key_version, 3);
        assert_eq!(generated.plaintext.as_ref(), &[0x5a; DEK_BYTES]);
        assert_eq!(
            provider
                .unwrap(&original_context, &generated.wrapped)
                .await
                .unwrap()
                .as_ref(),
            &[0x5a; DEK_BYTES]
        );
        assert!(
            provider
                .unwrap(&other_context, &generated.wrapped)
                .await
                .unwrap_err()
                .to_string()
                .contains("failure_class=openbao-decrypt-failed")
        );
        let rewrapped = provider
            .rewrap(&original_context, &generated.wrapped)
            .await
            .unwrap();
        assert_eq!(rewrapped.key_version, 4);
        assert_eq!(rewrapped.ciphertext, b"vault:v4:rewrapped");
        state.oversized_next_datakey.store(true, Ordering::SeqCst);
        let oversized = match provider.generate(&original_context).await {
            Ok(_) => panic!("oversized OpenBao response was accepted"),
            Err(error) => error,
        };
        assert_eq!(oversized.failure_class(), "openbao-datakey-failed");

        fs::remove_file(token_path).unwrap();
        server.abort();
    }

    #[test]
    fn transit_ciphertext_and_debug_surfaces_are_redacted() {
        for invalid in ["", "vault", "vault:v0:value", "vault:v1:", "other:v1:x"] {
            assert_eq!(parse_transit_version(invalid), None, "{invalid}");
        }
        assert_eq!(parse_transit_version("vault:v27:value"), Some(27));
        let wrapped = WrappedDek {
            provider: KekProviderKind::OpenBaoTransit,
            key_name: "tenant-dek".into(),
            key_version: 27,
            ciphertext: b"vault:v27:private-ciphertext".to_vec(),
            nonce: None,
            format: WRAPPED_DEK_FORMAT_V1,
        };
        let rendered = format!("{wrapped:?}");
        assert!(!rendered.contains("private-ciphertext"));
        assert!(rendered.contains("ciphertext_len"));
    }
}
