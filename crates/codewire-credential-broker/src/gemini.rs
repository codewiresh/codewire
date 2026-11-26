//! Gemini API adapter: a front-door-only transparent route to
//! `generativelanguage.googleapis.com` (#6555).
//!
//! Any CRUD request `agy`, `@google/gemini-cli`, or Google GenAI SDKs send to
//! `generativelanguage.googleapis.com` with this environment's `cwp1_`
//! placeholder in `x-goog-api-key` reaches Google with the leased API key
//! injected in `x-goog-api-key` (never in a URL query parameter) and responses
//! redacted through AV `RedactionSet`. No loopback route and no WebSockets.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig, RedactionSet,
    StreamingRedactor, prepare_credentials, validate_proxy_route,
};
use codewire_access::{CredentialAuthKind, CredentialStatus};
use http::{HeaderMap, Method};
use url::Url;

use crate::transparent::TransparentRequest;
use crate::{BrokerCredentialLease, CredentialBrokerError};

const PROVIDER: &str = "google";
const SLOT: &str = "gemini";
pub(crate) const ROUTE: &str = "gemini-api";
pub(crate) const OPERATION: &str = "generate";
pub(crate) const BASE_URL: &str = "https://generativelanguage.googleapis.com";
const CREDENTIAL_KEY: &str = "GEMINI_API_KEY";
const MAX_KEY_BYTES: usize = 1024;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Immutable Gemini API-key policy; it never accepts a caller-selected destination.
pub struct GeminiApiKeyAdapter {
    route: ProxyRouteConfig,
}

impl GeminiApiKeyAdapter {
    pub fn new() -> Result<Self, CredentialBrokerError> {
        let route = route();
        validate_proxy_route(ROUTE, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Run before requesting a lease or reading protected storage.
    pub fn validate_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedGeminiRequest, CredentialBrokerError> {
        Ok(ValidatedGeminiRequest(TransparentRequest::admit(
            method,
            path,
            query,
            headers,
            body,
            MAX_REQUEST_BYTES,
        )?))
    }

    /// Consume one exact operation lease and inject the API key in
    /// `x-goog-api-key`.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedGeminiRequest,
    ) -> Result<PreparedGeminiRequest, CredentialBrokerError> {
        validate_lease(&lease)?;
        let target = request.0.target(BASE_URL)?;
        let mut headers = request.0.outbound_headers(&[]);
        lease.with_material(|material| {
            let value = std::str::from_utf8(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            if value.is_empty()
                || value.len() > MAX_KEY_BYTES
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(CredentialBrokerError::InvalidCredentialMaterial);
            }
            let prepared = prepare_credentials(
                &self.route,
                &Material {
                    key: CREDENTIAL_KEY,
                    value,
                },
                &request.0.body,
            )
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            headers.insert(
                prepared.injection_name().clone(),
                prepared.injection_value().clone(),
            );
            let (body, redaction) = prepared.into_body_and_redaction();
            Ok(PreparedGeminiRequest {
                method: request.0.method,
                target,
                headers,
                body,
                response: PreparedGeminiResponse {
                    redaction,
                    max_body_bytes: MAX_RESPONSE_BYTES,
                },
            })
        })
    }
}

impl Default for GeminiApiKeyAdapter {
    fn default() -> Self {
        Self::new().expect("built-in Gemini policy must be valid")
    }
}

/// Credential-free validated request; its private field prevents route
/// changes between validation and lease consumption.
#[derive(Clone)]
pub struct ValidatedGeminiRequest(TransparentRequest);

impl ValidatedGeminiRequest {
    /// The request as the environment sent it, aimed at the pinned origin:
    /// for a front-door request carrying no placeholder, forwarded only when
    /// the untouched-forward rule admits it.
    pub(crate) fn into_forwarded(
        self,
    ) -> Result<(Method, Url, HeaderMap, Vec<u8>), CredentialBrokerError> {
        let target = self.0.target(BASE_URL)?;
        let TransparentRequest {
            method,
            headers,
            body,
            ..
        } = self.0;
        Ok((method, target, headers, body))
    }
}

/// Secret-bearing broker-only plan. No Debug, Clone, or serialization.
pub struct PreparedGeminiRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
    response: PreparedGeminiResponse,
}

impl PreparedGeminiRequest {
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, PreparedGeminiResponse) {
        (
            self.method,
            self.target,
            self.headers,
            self.body,
            self.response,
        )
    }
}

/// One response's AV redaction state. Call `begin` before any child-visible
/// headers or body bytes; content-coding rejection comes first.
pub struct PreparedGeminiResponse {
    redaction: RedactionSet,
    max_body_bytes: usize,
}

impl PreparedGeminiResponse {
    pub fn begin(
        self,
        upstream: &HeaderMap,
    ) -> Result<(HeaderMap, GeminiStreamingResponse), CredentialBrokerError> {
        let headers = crate::transparent::response_headers(upstream, &self.redaction)?;
        Ok((
            headers,
            GeminiStreamingResponse {
                redactor: self.redaction.into_streaming(),
                max_body_bytes: self.max_body_bytes,
                received_body_bytes: 0,
                terminal_error: None,
            },
        ))
    }
}

/// Byte-bounded redaction without parsing or rewriting SSE event framing.
pub struct GeminiStreamingResponse {
    redactor: StreamingRedactor,
    max_body_bytes: usize,
    received_body_bytes: usize,
    terminal_error: Option<CredentialBrokerError>,
}

impl GeminiStreamingResponse {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CredentialBrokerError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        let Some(total) = self
            .received_body_bytes
            .checked_add(chunk.len())
            .filter(|total| *total <= self.max_body_bytes)
        else {
            self.terminal_error = Some(CredentialBrokerError::ResponseTooLarge);
            return Err(CredentialBrokerError::ResponseTooLarge);
        };
        self.received_body_bytes = total;
        Ok(self.redactor.push(chunk))
    }

    pub fn finish(mut self) -> Result<Vec<u8>, CredentialBrokerError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        Ok(self.redactor.finish())
    }
}

struct Material<'a> {
    key: &'static str,
    value: &'a str,
}

impl CredentialSource for Material<'_> {
    fn credential(&self, key: &str) -> Option<&str> {
        (key == self.key).then_some(self.value)
    }
}

fn validate_lease(lease: &impl BrokerCredentialLease) -> Result<(), CredentialBrokerError> {
    let metadata = lease.credential_metadata();
    let grant = lease.grant();
    let permission = lease.permission();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CredentialBrokerError::UnsupportedLease)?
        .as_secs();
    if metadata.provider.as_str() != PROVIDER
        || metadata.authentication_kind != CredentialAuthKind::ApiKey
        || metadata.status != CredentialStatus::Active
        || metadata.revocation_generation == 0
        || metadata.revocation_generation != grant.credential_revocation_generation
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.capability_slot.as_str() != SLOT
        || grant.credential_id != metadata.id
        || grant.environment_generation == 0
        || grant
            .profile
            .as_ref()
            .is_none_or(|profile| profile.revision == 0)
        || lease.material_generation() == 0
        || permission.operation.as_str() != OPERATION
        || permission.route.as_str() != ROUTE
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

pub(crate) fn route() -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: "codewire-gemini-api-key".into(),
        base_url: BASE_URL.into(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(ProxyInjectionConfig::Header {
            secret_key: CREDENTIAL_KEY.into(),
            header: "x-goog-api-key".into(),
            prefix: String::new(),
        }),
        body_substitutions: BTreeMap::new(),
        allowed_methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
            .map(String::from)
            .into(),
        allowed_exact_paths: Vec::new(),
        allowed_path_prefixes: vec!["/".into()],
        allowed_request_headers: Vec::new(),
        allowed_response_headers: Vec::new(),
        allowed_query_parameters: Vec::new(),
        allowed_content_types: Vec::new(),
        max_body_bytes: MAX_REQUEST_BYTES,
        response_mode: ProxyResponseMode::Streaming,
        max_response_bytes: MAX_RESPONSE_BYTES,
        websocket: None,
    }
}
