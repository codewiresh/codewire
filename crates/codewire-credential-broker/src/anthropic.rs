//! Direct Anthropic API-key Messages and token-counting adapter.
//!
//! Policy references (reviewed 2026-09-07):
//! - <https://platform.claude.com/docs/en/api/messages/create>
//! - <https://platform.claude.com/docs/en/api/messages/count_tokens>
//! - <https://platform.claude.com/docs/en/build-with-claude/streaming>
//! - <https://platform.claude.com/docs/en/api/beta-headers>
//! - <https://platform.claude.com/docs/en/api/rate-limits>
//! - <https://github.com/anthropics/anthropic-sdk-typescript/blob/main/src/resources/beta/messages/messages.ts>
//!
//! This prepares requests inside an already-authorized broker, not a listener,
//! authority, or new HTTP transport. The transport must pin the fixed HTTPS
//! destination, disable redirects and implicit decoding, call response `begin`
//! before releasing headers or polling body bytes, and recheck the original
//! grant before dispatch/delivery. Request bodies remain ordinary API payloads;
//! the upstream validates their model/tool schema.
//!
//! Only the two POST routes below are supported, with no query or exactly the
//! official SDK's `beta=true` query. The Claude subscription token form, the
//! provider's OAuth kind, is [`AnthropicSubscriptionTokenAdapter`]; it shares
//! these routes and this request validation. No federation, Bedrock,
//! Vertex/Foundry, workspace/user-profile selection, models/files/batches/admin
//! routes, or WebSockets. API keys needing explicit workspace selection are not
//! supported. Beta names are bounded feature tokens forwarded to these same
//! endpoints; forwarding is not a claim that every provider beta is supported.
//! Requests are capped at AV's 4 MiB limit (below Anthropic's 32 MB API limit).
//! Response redaction is AV's finite raw/JSON/percent/base64 pattern matching,
//! not protection against arbitrary transformations or opaque encoded payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig, RedactionSet,
    StreamingRedactor, ValidatedProxyRequest, build_target_url, is_websocket_attempt,
    prepare_credentials, prepare_outbound_headers, validate_proxy_request, validate_proxy_route,
};
use codewire_access::{CredentialAuthKind, CredentialStatus};
use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use url::Url;

use crate::{BrokerCredentialLease, CredentialBrokerError};

mod subscription;
pub use subscription::AnthropicSubscriptionTokenAdapter;

const PROVIDER: &str = "anthropic";
const ROUTE: &str = "anthropic-api";
const CREDENTIAL_KEY: &str = "ANTHROPIC_API_KEY";
const API_VERSION: &str = "2023-06-01";
const MAX_KEY_BYTES: usize = 1024;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const MAX_COUNT_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
const REQUEST_HEADERS: &[&str] = &[
    "accept",
    "content-type",
    "anthropic-version",
    "anthropic-beta",
];
const RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "request-id",
    "retry-after",
    // The official SDK uses these two finite retry hints.
    "retry-after-ms",
    "x-should-retry",
    "anthropic-ratelimit-requests-limit",
    "anthropic-ratelimit-requests-remaining",
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-tokens-limit",
    "anthropic-ratelimit-tokens-remaining",
    "anthropic-ratelimit-tokens-reset",
    "anthropic-ratelimit-input-tokens-limit",
    "anthropic-ratelimit-input-tokens-remaining",
    "anthropic-ratelimit-input-tokens-reset",
    "anthropic-ratelimit-output-tokens-limit",
    "anthropic-ratelimit-output-tokens-remaining",
    "anthropic-ratelimit-output-tokens-reset",
];

/// The operation must select the corresponding authority permission, not just
/// the shared provider route. A token-count lease cannot create a Message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnthropicOperation {
    Messages,
    CountTokens,
}

impl AnthropicOperation {
    pub fn operation_name(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CountTokens => "count-tokens",
        }
    }

    fn for_path(path: &str) -> Result<Self, CredentialBrokerError> {
        match path {
            "/messages" => Ok(Self::Messages),
            "/messages/count_tokens" => Ok(Self::CountTokens),
            _ => Err(CredentialBrokerError::RequestDenied),
        }
    }
}

/// Immutable direct-API policy; it never accepts a caller-selected destination.
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

    /// Provider-relative paths exclude the fixed upstream `/v1` base.
    pub fn prepare<L: BrokerCredentialLease>(
        &self,
        lease: L,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        // Check the borrowed inputs before cloning potentially large buffers.
        self.validate_fields(method, path, query, headers, body.len())?;
        let request = self.validate_request(method, path, query, headers.clone(), body.to_vec())?;
        self.prepare_validated(lease, request)
    }

    /// Run before requesting a lease or reading protected storage. All fields
    /// that can affect routing, injection, or framing are validated here.
    pub fn validate_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedAnthropicRequest, CredentialBrokerError> {
        let (operation, request) =
            self.validate_fields(method, path, query, &headers, body.len())?;
        Ok(ValidatedAnthropicRequest {
            operation,
            request,
            headers,
            body,
        })
    }

    fn validate_fields(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body_len: usize,
    ) -> Result<(AnthropicOperation, ValidatedProxyRequest), CredentialBrokerError> {
        let denied = CredentialBrokerError::RequestDenied;
        let operation = AnthropicOperation::for_path(path)?;
        if method != Method::POST
            || !matches!(query, None | Some("") | Some("beta=true"))
            || body_len == 0
            || body_len > MAX_REQUEST_BYTES
            || is_websocket_attempt(headers)
            || !bounded_headers(headers)
            || !identity_encoding(headers)
            || headers.contains_key("anthropic-workspace-id")
            || headers.contains_key("anthropic-user-profile-id")
        {
            return Err(denied);
        }
        for name in REQUEST_HEADERS {
            if headers.get_all(*name).iter().count() > 1 {
                return Err(denied);
            }
        }
        if headers.get("anthropic-version").map(HeaderValue::as_bytes)
            != Some(API_VERSION.as_bytes())
            || !supported_content_type(headers, false)
        {
            return Err(denied);
        }
        if let Some(beta) = headers.get("anthropic-beta") {
            let beta = beta.to_str().map_err(|_| denied)?;
            let mut tokens = BTreeSet::new();
            for token in beta.split(',').map(str::trim) {
                if token.is_empty()
                    || token.len() > 128
                    || !token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || !tokens.insert(token)
                    || tokens.len() > 32
                {
                    return Err(denied);
                }
            }
        }
        let request = validate_proxy_request(&self.route, path, query, method, headers, body_len)
            .map_err(|_| denied)?;
        Ok((operation, request))
    }

    /// Consume one exact operation lease. This does not authorize a caller or
    /// renew an expired grant; lifecycle checks still belong to the runtime.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedAnthropicRequest,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        validate_lease(&lease, request.operation)?;
        let target = build_target_url(&self.route, &request.request)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        lease.with_material(|material| {
            if material.is_empty()
                || material.len() > MAX_KEY_BYTES
                || !material.iter().all(|byte| byte.is_ascii_graphic())
            {
                return Err(CredentialBrokerError::InvalidCredentialMaterial);
            }
            let material = std::str::from_utf8(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            let prepared = prepare_credentials(&self.route, &ApiKey(material), &request.body)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            let mut headers = prepare_outbound_headers(&self.route, &request.headers, &prepared)
                .map_err(|_| CredentialBrokerError::RequestDenied)?;
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
            // Preserve AV's exact injected value AND its derived encodings.
            let (body, redaction) = prepared.into_body_and_redaction();
            Ok(PreparedAnthropicRequest {
                target,
                headers,
                body,
                response: PreparedAnthropicResponse {
                    operation: request.operation,
                    redaction,
                    max_body_bytes: if request.operation == AnthropicOperation::CountTokens {
                        MAX_COUNT_RESPONSE_BYTES
                    } else {
                        self.route.max_response_bytes
                    },
                    response_headers: RESPONSE_HEADERS,
                },
            })
        })
    }
}

impl Default for AnthropicApiKeyAdapter {
    fn default() -> Self {
        Self::new().expect("built-in Anthropic policy must be valid")
    }
}

/// Credential-free validated request; its private fields prevent route changes
/// between validation and lease consumption.
pub struct ValidatedAnthropicRequest {
    operation: AnthropicOperation,
    request: ValidatedProxyRequest,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ValidatedAnthropicRequest {
    pub fn operation(&self) -> AnthropicOperation {
        self.operation
    }
}

/// Secret-bearing broker-only plan. No Debug, Clone, or serialization.
pub struct PreparedAnthropicRequest {
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
    response: PreparedAnthropicResponse,
}

impl PreparedAnthropicRequest {
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, PreparedAnthropicResponse) {
        (
            Method::POST,
            self.target,
            self.headers,
            self.body,
            self.response,
        )
    }
}

/// One response's finite AV redaction state. Call `begin` before any
/// child-visible headers or body bytes; content-coding rejection comes first.
pub struct PreparedAnthropicResponse {
    operation: AnthropicOperation,
    redaction: RedactionSet,
    max_body_bytes: usize,
    /// The credential form's finite response allowlist.
    response_headers: &'static [&'static str],
}

impl PreparedAnthropicResponse {
    pub fn begin(
        self,
        upstream: &HeaderMap,
    ) -> Result<(HeaderMap, AnthropicStreamingResponse), CredentialBrokerError> {
        if !bounded_headers(upstream)
            || !identity_encoding(upstream)
            || !supported_content_type(upstream, self.operation == AnthropicOperation::Messages)
        {
            return Err(CredentialBrokerError::ResponseDenied);
        }
        let mut headers = HeaderMap::new();
        for name in self.response_headers {
            let mut values = upstream.get_all(*name).iter();
            let Some(value) = values.next() else {
                continue;
            };
            if values.next().is_some() {
                return Err(CredentialBrokerError::ResponseDenied);
            }
            headers.insert(
                HeaderName::from_static(name),
                self.redaction
                    .redact_header(value)
                    .ok_or(CredentialBrokerError::ResponseDenied)?,
            );
        }
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

struct ApiKey<'a>(&'a str);
impl CredentialSource for ApiKey<'_> {
    fn credential(&self, key: &str) -> Option<&str> {
        (key == CREDENTIAL_KEY).then_some(self.0)
    }
}

fn validate_lease(
    lease: &impl BrokerCredentialLease,
    operation: AnthropicOperation,
) -> Result<(), CredentialBrokerError> {
    validate_lease_kind(lease, operation, CredentialAuthKind::ApiKey)
}

/// The exact lease checks of both forms, which differ only in the credential
/// kind each accepts.
fn validate_lease_kind(
    lease: &impl BrokerCredentialLease,
    operation: AnthropicOperation,
    kind: CredentialAuthKind,
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
        || permission.operation.as_str() != operation.operation_name()
        || permission.route.as_str() != ROUTE
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

fn bounded_headers(headers: &HeaderMap) -> bool {
    if headers.len() > MAX_HEADERS {
        return false;
    }
    let mut total = 0_usize;
    for (name, value) in headers {
        if name.as_str().len() > 128 || value.as_bytes().len() > MAX_HEADER_VALUE_BYTES {
            return false;
        }
        let Some(next) = total
            .checked_add(name.as_str().len() + value.as_bytes().len())
            .filter(|next| *next <= MAX_HEADER_BYTES)
        else {
            return false;
        };
        total = next;
    }
    true
}

// Same strict admission as F0: absent or exactly one identity coding. Never
// accept a compound/duplicate/empty/opaque coding and then discard its header.
fn identity_encoding(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    let Some(value) = values.next() else {
        return true;
    };
    values.next().is_none()
        && value.to_str().is_ok_and(|value| {
            value
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case("identity")
        })
}

fn supported_content_type(headers: &HeaderMap, allow_sse: bool) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let mut parts = value.split(';').map(str::trim);
    let Some(media) = parts.next() else {
        return false;
    };
    if !(media.eq_ignore_ascii_case("application/json")
        || allow_sse && media.eq_ignore_ascii_case("text/event-stream"))
    {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(parameter), None) => parameter.split_once('=').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("charset")
                && (value.trim().eq_ignore_ascii_case("utf-8")
                    || value.trim().eq_ignore_ascii_case("\"utf-8\""))
        }),
        _ => false,
    }
}

pub(crate) fn route() -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: "codewire-anthropic-api-key".into(),
        base_url: "https://api.anthropic.com/v1".into(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(ProxyInjectionConfig::Header {
            secret_key: CREDENTIAL_KEY.into(),
            header: "x-api-key".into(),
            prefix: String::new(),
        }),
        body_substitutions: BTreeMap::new(),
        allowed_methods: vec!["POST".into()],
        allowed_exact_paths: vec!["/messages".into(), "/messages/count_tokens".into()],
        allowed_path_prefixes: Vec::new(),
        allowed_request_headers: REQUEST_HEADERS.iter().map(|name| (*name).into()).collect(),
        allowed_response_headers: RESPONSE_HEADERS.iter().map(|name| (*name).into()).collect(),
        allowed_query_parameters: vec!["beta".into()],
        allowed_content_types: vec!["application/json".into()],
        max_body_bytes: MAX_REQUEST_BYTES,
        response_mode: ProxyResponseMode::Streaming,
        max_response_bytes: MAX_RESPONSE_BYTES,
        websocket: None,
    }
}

#[cfg(test)]
mod tests;
