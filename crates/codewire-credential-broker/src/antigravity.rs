//! Antigravity Cloud Code adapter: a front-door-only transparent route to
//! `daily-cloudcode-pa.googleapis.com` and `cloudcode-pa.googleapis.com`
//! pinned strictly to `POST ^/v1internal:[A-Za-z][A-Za-z0-9_]*$` (#6555).
//!
//! Real Google OAuth tokens never enter a Sandbox or local VM. The guest holds
//! only this environment's `cwp1_` placeholder in
//! `~/.gemini/antigravity-cli/antigravity-oauth-token`, sends it as
//! `Authorization: Bearer <cwp1_...>`, and this adapter swaps in the leased
//! Google access token while streaming responses through AV `RedactionSet`.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig, RedactionSet,
    StreamingRedactor, prepare_credentials, validate_proxy_route,
};
use codewire_access::{
    ANTIGRAVITY_DAILY_HOST, ANTIGRAVITY_LOGIN_OPERATION, ANTIGRAVITY_LOGIN_ROUTE,
    ANTIGRAVITY_PROD_HOST, CredentialAuthKind, CredentialStatus,
};
use http::{HeaderMap, Method};
use url::Url;

use crate::antigravity_oauth::AntigravityOAuthCredential;
use crate::transparent::TransparentRequest;
use crate::{BrokerCredentialLease, CredentialBrokerError};

const PROVIDER: &str = "google";
const SLOT: &str = "antigravity";
pub(crate) const ROUTE: &str = "antigravity-api";
pub(crate) const OPERATION: &str = "generate";
const CREDENTIAL_KEY: &str = "ANTIGRAVITY_ACCESS_TOKEN";
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Strict path grammar pinned by #6555: exact single-segment
/// `^/v1internal:[A-Za-z][A-Za-z0-9_]*$` (no extra `/`, no `%`, no `..`, no
/// empty RPC method name).
pub(crate) fn is_antigravity_api_path(path: &str) -> bool {
    let Some(method_name) = path.strip_prefix("/v1internal:") else {
        return false;
    };
    let mut bytes = method_name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Immutable Antigravity API policy; it never accepts a caller-selected
/// destination or non-`POST` / non-`/v1internal:` call for swapping.
pub struct AntigravityApiAdapter {
    route: ProxyRouteConfig,
}

impl AntigravityApiAdapter {
    pub fn new() -> Result<Self, CredentialBrokerError> {
        let route = route();
        validate_proxy_route(ROUTE, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Validate framing, headers, and size before requesting a lease.
    pub fn validate_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedAntigravityRequest, CredentialBrokerError> {
        Ok(ValidatedAntigravityRequest(TransparentRequest::admit(
            method,
            path,
            query,
            headers,
            body,
            MAX_REQUEST_BYTES,
        )?))
    }

    /// Check every coordinate of a proxied Antigravity API lease and parse its
    /// OAuth envelope.
    pub(crate) fn credential_from_lease<L: BrokerCredentialLease>(
        &self,
        lease: L,
    ) -> Result<AntigravityOAuthCredential, CredentialBrokerError> {
        validate_lease(&lease, OPERATION, ROUTE)?;
        lease.with_material(|material| {
            AntigravityOAuthCredential::parse(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)
        })
    }

    /// Check the dedicated `antigravity-login` lease and parse its OAuth
    /// envelope so the broker can read non-secret `account_hint` (email) and
    /// verify the sign-in is Active/fresh before delivering the placeholder
    /// login payload.
    pub(crate) fn login_credential_from_lease<L: BrokerCredentialLease>(
        &self,
        lease: L,
    ) -> Result<AntigravityOAuthCredential, CredentialBrokerError> {
        validate_lease(&lease, ANTIGRAVITY_LOGIN_OPERATION, ANTIGRAVITY_LOGIN_ROUTE)?;
        lease.with_material(|material| {
            AntigravityOAuthCredential::parse(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)
        })
    }

    /// Inject the leased Google OAuth access token as `Authorization: Bearer`
    /// for a validated `POST /v1internal:<Method>` request targeting `host`.
    pub(crate) fn prepare_credential(
        &self,
        host: &str,
        credential: &AntigravityOAuthCredential,
        request: ValidatedAntigravityRequest,
    ) -> Result<PreparedAntigravityRequest, CredentialBrokerError> {
        let base_url = base_url_for_host(host)?;
        if request.0.method != Method::POST || !is_antigravity_api_path(&request.0.path) {
            return Err(CredentialBrokerError::RequestDenied);
        }
        let target = request.0.target(base_url)?;
        let mut headers = request.0.outbound_headers(&[]);
        let prepared = prepare_credentials(
            &self.route,
            &Material {
                key: CREDENTIAL_KEY,
                value: credential.access_token(),
            },
            &request.0.body,
        )
        .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        headers.insert(
            prepared.injection_name().clone(),
            prepared.injection_value().clone(),
        );
        let (body, redaction) = prepared.into_body_and_redaction();
        Ok(PreparedAntigravityRequest {
            method: request.0.method,
            target,
            headers,
            body,
            response: PreparedAntigravityResponse {
                redaction,
                max_body_bytes: MAX_RESPONSE_BYTES,
            },
        })
    }
}

impl Default for AntigravityApiAdapter {
    fn default() -> Self {
        Self::new().expect("built-in Antigravity policy must be valid")
    }
}

fn base_url_for_host(host: &str) -> Result<&'static str, CredentialBrokerError> {
    match host {
        ANTIGRAVITY_DAILY_HOST => Ok("https://daily-cloudcode-pa.googleapis.com"),
        ANTIGRAVITY_PROD_HOST => Ok("https://cloudcode-pa.googleapis.com"),
        _ => Err(CredentialBrokerError::RequestDenied),
    }
}

/// Credential-free validated request.
#[derive(Clone)]
pub struct ValidatedAntigravityRequest(TransparentRequest);

impl ValidatedAntigravityRequest {
    pub(crate) fn is_swappable_endpoint(&self) -> bool {
        self.0.method == Method::POST && is_antigravity_api_path(&self.0.path)
    }

    pub(crate) fn into_forwarded(
        self,
        host: &str,
    ) -> Result<(Method, Url, HeaderMap, Vec<u8>), CredentialBrokerError> {
        let base_url = base_url_for_host(host)?;
        let target = self.0.target(base_url)?;
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
pub struct PreparedAntigravityRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
    response: PreparedAntigravityResponse,
}

impl PreparedAntigravityRequest {
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, PreparedAntigravityResponse) {
        (
            self.method,
            self.target,
            self.headers,
            self.body,
            self.response,
        )
    }
}

pub struct PreparedAntigravityResponse {
    redaction: RedactionSet,
    max_body_bytes: usize,
}

impl PreparedAntigravityResponse {
    pub fn begin(
        self,
        upstream: &HeaderMap,
    ) -> Result<(HeaderMap, AntigravityStreamingResponse), CredentialBrokerError> {
        let headers = crate::transparent::response_headers(upstream, &self.redaction)?;
        Ok((
            headers,
            AntigravityStreamingResponse {
                redactor: self.redaction.into_streaming(),
                max_body_bytes: self.max_body_bytes,
                received_body_bytes: 0,
                terminal_error: None,
            },
        ))
    }
}

/// Byte-bounded streaming redactor without parsing or rewriting SSE framing.
pub struct AntigravityStreamingResponse {
    redactor: StreamingRedactor,
    max_body_bytes: usize,
    received_body_bytes: usize,
    terminal_error: Option<CredentialBrokerError>,
}

impl AntigravityStreamingResponse {
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CredentialBrokerError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        let next = self
            .received_body_bytes
            .checked_add(chunk.len())
            .ok_or(CredentialBrokerError::ResponseTooLarge)?;
        if next > self.max_body_bytes {
            self.terminal_error = Some(CredentialBrokerError::ResponseTooLarge);
            return Err(CredentialBrokerError::ResponseTooLarge);
        }
        self.received_body_bytes = next;
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

fn route() -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: "codewire-antigravity-oauth".into(),
        base_url: "https://daily-cloudcode-pa.googleapis.com".into(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(ProxyInjectionConfig::Bearer {
            secret_key: CREDENTIAL_KEY.into(),
        }),
        body_substitutions: BTreeMap::new(),
        allowed_methods: ["POST"].map(String::from).into(),
        allowed_exact_paths: Vec::new(),
        allowed_path_prefixes: vec!["/v1internal:".into()],
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

fn validate_lease<L: BrokerCredentialLease>(
    lease: &L,
    expected_operation: &str,
    expected_route: &str,
) -> Result<(), CredentialBrokerError> {
    let grant = lease.grant();
    let credential = lease.credential_metadata();
    let permission = lease.permission();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CredentialBrokerError::UnsupportedLease)?;
    if credential.provider.as_str() != PROVIDER
        || credential.authentication_kind != CredentialAuthKind::OAuth
        || credential.status != CredentialStatus::Active
        || credential.revocation_generation == 0
        || credential.revocation_generation != grant.credential_revocation_generation
        || credential
            .expires_at_unix
            .is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.capability_slot.as_str() != SLOT
        || grant.credential_id != credential.id
        || grant.environment_generation == 0
        || grant
            .profile
            .as_ref()
            .is_none_or(|profile| profile.revision == 0)
        || lease.material_generation() == 0
        || permission.operation.as_str() != expected_operation
        || permission.route.as_str() != expected_route
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1internal_path_grammar_is_strict() {
        for good in [
            "/v1internal:loadCodeAssist",
            "/v1internal:streamGenerateContent",
            "/v1internal:generate_content_2",
        ] {
            assert!(is_antigravity_api_path(good), "{good}");
        }
        for bad in [
            "/v1internal:",
            "/v1internal:1bad",
            "/v1internal:loadCodeAssist/extra",
            "/v1internal:loadCodeAssist%2fextra",
            "/v1internal:..",
            "/v1beta/models",
            "/v1/projects/foo",
            "/",
        ] {
            assert!(!is_antigravity_api_path(bad), "{bad}");
        }
    }
}
