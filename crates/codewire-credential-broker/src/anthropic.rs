//! Anthropic API adapter: a transparent route to `api.anthropic.com` (#2536).
//!
//! Any CRUD request Claude Code or another stock client sends under the
//! managed Anthropic base path reaches the provider unchanged except for its
//! credential; see [`crate::transparent`]. The API-key form injects
//! `x-api-key`. The Claude subscription token form, the provider's OAuth kind,
//! is [`AnthropicSubscriptionTokenAdapter`], and the Claude sign-in form is
//! [`AnthropicClaudeSignInAdapter`]. Every form shares one route and its one
//! operation, leased for every request. No federation, Bedrock or
//! Vertex/Foundry, and no WebSockets. Requests stay within AV's 4 MiB limit.

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

mod sign_in;
mod subscription;
pub(crate) use sign_in::AnthropicClaudeSignInAdapter;
pub use subscription::AnthropicSubscriptionTokenAdapter;

const PROVIDER: &str = "anthropic";
const ROUTE: &str = "anthropic-api";
/// The route's one operation; every request leases it.
pub(crate) const OPERATION: &str = "messages";
/// The pinned origin. Guest paths keep their own `/v1` prefix.
pub(crate) const BASE_URL: &str = "https://api.anthropic.com";
const CREDENTIAL_KEY: &str = "ANTHROPIC_API_KEY";
const MAX_KEY_BYTES: usize = 1024;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Immutable API-key policy; it never accepts a caller-selected destination.
pub struct AnthropicApiKeyAdapter {
    route: ProxyRouteConfig,
}

impl AnthropicApiKeyAdapter {
    pub fn new() -> Result<Self, CredentialBrokerError> {
        let route = route();
        validate_proxy_route(ROUTE, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Provider paths are relative to the Anthropic origin, for example
    /// `/v1/messages`.
    pub fn prepare<L: BrokerCredentialLease>(
        &self,
        lease: L,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        let request = self.validate_request(method, path, query, headers.clone(), body.to_vec())?;
        self.prepare_validated(lease, request)
    }

    /// Run before requesting a lease or reading protected storage.
    pub fn validate_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedAnthropicRequest, CredentialBrokerError> {
        Ok(ValidatedAnthropicRequest(TransparentRequest::admit(
            method,
            path,
            query,
            headers,
            body,
            MAX_REQUEST_BYTES,
        )?))
    }

    /// Consume one exact operation lease. This does not authorize a caller or
    /// renew an expired grant; lifecycle checks still belong to the runtime.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedAnthropicRequest,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        validate_lease_kind(&lease, CredentialAuthKind::ApiKey)?;
        prepare_transparent(&self.route, CREDENTIAL_KEY, lease, request.0, |_| Ok(()))
    }
}

impl Default for AnthropicApiKeyAdapter {
    fn default() -> Self {
        Self::new().expect("built-in Anthropic policy must be valid")
    }
}

/// Credential-free validated request; its private field prevents route
/// changes between validation and lease consumption.
pub struct ValidatedAnthropicRequest(TransparentRequest);

/// Secret-bearing broker-only plan. No Debug, Clone, or serialization.
pub struct PreparedAnthropicRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
    response: PreparedAnthropicResponse,
}

impl PreparedAnthropicRequest {
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, PreparedAnthropicResponse) {
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
pub struct PreparedAnthropicResponse {
    redaction: RedactionSet,
    max_body_bytes: usize,
}

impl PreparedAnthropicResponse {
    pub fn begin(
        self,
        upstream: &HeaderMap,
    ) -> Result<(HeaderMap, AnthropicStreamingResponse), CredentialBrokerError> {
        let headers = crate::transparent::response_headers(upstream, &self.redaction)?;
        Ok((
            headers,
            AnthropicStreamingResponse {
                redactor: self.redaction.into_streaming(),
                max_body_bytes: self.max_body_bytes,
                received_body_bytes: 0,
                terminal_error: None,
            },
        ))
    }
}

/// Byte-bounded redaction without parsing or rewriting SSE event framing.
pub struct AnthropicStreamingResponse {
    redactor: StreamingRedactor,
    max_body_bytes: usize,
    received_body_bytes: usize,
    terminal_error: Option<CredentialBrokerError>,
}

impl AnthropicStreamingResponse {
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

/// The leased material under the one key its route injects.
struct Material<'a> {
    key: &'static str,
    value: &'a str,
}

impl CredentialSource for Material<'_> {
    fn credential(&self, key: &str) -> Option<&str> {
        (key == self.key).then_some(self.value)
    }
}

/// Borrow the leased material once, inject it as `route` specifies and keep
/// its redaction set. `extra` adjusts form-specific outbound headers before
/// the material is borrowed.
fn prepare_transparent<L: BrokerCredentialLease>(
    route: &ProxyRouteConfig,
    key: &'static str,
    lease: L,
    request: TransparentRequest,
    extra: impl FnOnce(&mut HeaderMap) -> Result<(), CredentialBrokerError>,
) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
    let outbound = Outbound::new(request, extra)?;
    lease.with_material(|material| {
        let value = std::str::from_utf8(material)
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        outbound.inject(route, key, value)
    })
}

/// A validated request's target and form-specific outbound headers, prepared
/// before any material is borrowed.
struct Outbound {
    request: TransparentRequest,
    target: Url,
    headers: HeaderMap,
}

impl Outbound {
    fn new(
        request: TransparentRequest,
        extra: impl FnOnce(&mut HeaderMap) -> Result<(), CredentialBrokerError>,
    ) -> Result<Self, CredentialBrokerError> {
        let target = request.target(BASE_URL)?;
        let mut headers = request.outbound_headers(&[]);
        extra(&mut headers)?;
        Ok(Self {
            request,
            target,
            headers,
        })
    }

    /// Inject one credential value as `route` specifies and keep its
    /// redaction set.
    fn inject(
        self,
        route: &ProxyRouteConfig,
        key: &'static str,
        value: &str,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        let Self {
            request,
            target,
            mut headers,
        } = self;
        if value.is_empty()
            || value.len() > MAX_KEY_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CredentialBrokerError::InvalidCredentialMaterial);
        }
        let prepared = prepare_credentials(route, &Material { key, value }, &request.body)
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        headers.insert(
            prepared.injection_name().clone(),
            prepared.injection_value().clone(),
        );
        // Preserve AV's exact injected value AND its derived encodings.
        let (body, redaction) = prepared.into_body_and_redaction();
        Ok(PreparedAnthropicRequest {
            method: request.method,
            target,
            headers,
            body,
            response: PreparedAnthropicResponse {
                redaction,
                max_body_bytes: MAX_RESPONSE_BYTES,
            },
        })
    }
}

/// The exact lease checks of every form, which differ only in the credential
/// kind each accepts.
fn validate_lease_kind(
    lease: &impl BrokerCredentialLease,
    kind: CredentialAuthKind,
) -> Result<(), CredentialBrokerError> {
    validate_lease(lease, kind, OPERATION, ROUTE)
}

/// [`validate_lease_kind`] for an exact permission of the Anthropic slot.
fn validate_lease(
    lease: &impl BrokerCredentialLease,
    kind: CredentialAuthKind,
    operation: &str,
    route: &str,
) -> Result<(), CredentialBrokerError> {
    let metadata = lease.credential_metadata();
    let grant = lease.grant();
    let permission = lease.permission();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CredentialBrokerError::UnsupportedLease)?
        .as_secs();
    if metadata.provider.as_str() != PROVIDER
        || metadata.authentication_kind != kind
        || metadata.status != CredentialStatus::Active
        || metadata.revocation_generation == 0
        || metadata.revocation_generation != grant.credential_revocation_generation
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.capability_slot.as_str() != PROVIDER
        || grant.credential_id != metadata.id
        || grant.environment_generation == 0
        || grant
            .profile
            .as_ref()
            .is_none_or(|profile| profile.revision == 0)
        || lease.material_generation() == 0
        || permission.operation.as_str() != operation
        || permission.route.as_str() != route
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

/// AV's injection and redaction policy for one credential form. Paths,
/// headers and queries are the transparent layer's, not this config's.
fn route_with(profile: &str, injection: ProxyInjectionConfig) -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: profile.into(),
        base_url: BASE_URL.into(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(injection),
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

pub(crate) fn route() -> ProxyRouteConfig {
    route_with(
        "codewire-anthropic-api-key",
        ProxyInjectionConfig::Header {
            secret_key: CREDENTIAL_KEY.into(),
            header: "x-api-key".into(),
            prefix: String::new(),
        },
    )
}

#[cfg(test)]
mod tests;
