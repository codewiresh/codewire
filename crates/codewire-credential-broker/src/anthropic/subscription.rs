//! Claude subscription token form of the Anthropic adapter.
//!
//! A Claude subscription token is the long-lived OAuth token `claude setup-token`
//! prints for a Claude Pro, Max, Team or Enterprise plan. Claude Code reads it
//! from `CLAUDE_CODE_OAUTH_TOKEN`; the token "can only make model requests"
//! (<https://code.claude.com/docs/en/authentication>). It stays in Codewire:
//! the Sandbox holds only the `codewire-managed` placeholder, and this adapter
//! replaces it with the stored token as `Authorization: Bearer`. It is not a
//! direct delivery exception and has no refresh.
//!
//! Everything else is the API-key adapter's: the same two POST routes with no
//! query or exactly `beta=true`, the same request validation (run before any
//! lease), size limits, identity-only codings and AV redaction of the injected
//! token and its derived encodings. The differences, all for this form only:
//!
//! - `Authorization` replaces `x-api-key`. The caller must present exactly one
//!   `Authorization: Bearer codewire-managed`, the placeholder Claude Code
//!   sends in subscription mode; it is never forwarded.
//! - `anthropic-beta` always carries `oauth-2025-04-20`, which the provider
//!   requires for an OAuth bearer; it is appended when the caller omitted it.
//! - Claude Code's bounded client-identity headers are forwarded. Probed
//!   against Claude Code 2.1.238 and 2.1.288 in subscription mode, every model request
//!   carries `user-agent: claude-cli/<version> (...)`, `x-app: cli`,
//!   `anthropic-dangerous-direct-browser-access: true` and a UUID
//!   `x-claude-code-session-id`. The provider may treat subscription requests
//!   without them differently, and Claude Code sends the same values when it
//!   talks to the provider directly, so forwarding them discloses nothing a
//!   stock login would not. They are non-secret, length-bounded and exactly
//!   named. A malformed or repeated one is dropped, never forwarded, so a
//!   Claude Code release that changes one degrades instead of failing.
//!   Claude Code's SDK telemetry (`x-stainless-*`) is still dropped.
//! - The provider's unified subscription rate-limit headers, which Claude Code
//!   reads to show plan usage limits, are returned after redaction.

use std::collections::BTreeMap;

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig, build_target_url,
    prepare_credentials, prepare_outbound_headers, validate_proxy_route,
};
use codewire_access::CredentialAuthKind;
use http::{HeaderMap, HeaderName, HeaderValue, header};

use super::{
    AnthropicOperation, MAX_COUNT_RESPONSE_BYTES, MAX_KEY_BYTES, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, PreparedAnthropicRequest, PreparedAnthropicResponse, REQUEST_HEADERS,
    RESPONSE_HEADERS, ValidatedAnthropicRequest, validate_lease_kind,
};
use crate::{BrokerCredentialLease, CredentialBrokerError};

const ROUTE: &str = "anthropic-api";
const CREDENTIAL_KEY: &str = "CLAUDE_CODE_OAUTH_TOKEN";
/// The provider's beta flag for an OAuth bearer on the Messages API.
pub(crate) const OAUTH_BETA: &str = "oauth-2025-04-20";
/// The Sandbox's projected `CLAUDE_CODE_OAUTH_TOKEN`, as Claude Code sends it.
const PLACEHOLDER_AUTHORIZATION: &[u8] = b"Bearer codewire-managed";
const MAX_USER_AGENT_BYTES: usize = 256;
const MAX_APP_BYTES: usize = 32;
const MAX_SESSION_ID_BYTES: usize = 64;
/// Unified subscription rate-limit headers read by Claude Code 2.1.238 and
/// 2.1.288.
const SUBSCRIPTION_RATE_LIMIT_HEADERS: &[&str] = &[
    "anthropic-ratelimit-unified-status",
    "anthropic-ratelimit-unified-reset",
    "anthropic-ratelimit-unified-fallback",
    "anthropic-ratelimit-unified-representative-claim",
    "anthropic-ratelimit-unified-upgrade-paths",
    "anthropic-ratelimit-unified-5h-reset",
    "anthropic-ratelimit-unified-5h-surpassed-threshold",
    "anthropic-ratelimit-unified-5h-utilization",
    "anthropic-ratelimit-unified-7d-reset",
    "anthropic-ratelimit-unified-7d-surpassed-threshold",
    "anthropic-ratelimit-unified-7d-utilization",
    "anthropic-ratelimit-unified-7d_oi-reset",
    "anthropic-ratelimit-unified-7d_oi-surpassed-threshold",
    "anthropic-ratelimit-unified-7d_oi-utilization",
    "anthropic-ratelimit-unified-grace-status",
    "anthropic-ratelimit-unified-grace-5h-utilization",
    "anthropic-ratelimit-unified-grace-7d-utilization",
    "anthropic-ratelimit-unified-overage-status",
    "anthropic-ratelimit-unified-overage-reset",
    "anthropic-ratelimit-unified-overage-in-use",
    "anthropic-ratelimit-unified-overage-utilization",
    "anthropic-ratelimit-unified-overage-surpassed-threshold",
    "anthropic-ratelimit-unified-overage-disabled-reason",
    "anthropic-ratelimit-unified-overage-period",
    "anthropic-ratelimit-unified-overage-period-channel-utilization",
    "anthropic-ratelimit-unified-overage-period-monthly-utilization",
    "anthropic-ratelimit-unified-overage-scope",
    "anthropic-ratelimit-unified-slow-status",
    "anthropic-ratelimit-unified-slow-offer",
    "anthropic-ratelimit-unified-slow-budget-reset",
    "anthropic-ratelimit-unified-slow-budget-utilization",
    "anthropic-ratelimit-unified-slow-max-wait",
    "anthropic-ratelimit-unified-slow-retry-after",
];

/// Response headers returned for this form: the API-key adapter's, then the
/// unified subscription rate limits.
pub(super) fn response_headers() -> &'static [&'static str] {
    static HEADERS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    HEADERS.get_or_init(|| {
        RESPONSE_HEADERS
            .iter()
            .chain(SUBSCRIPTION_RATE_LIMIT_HEADERS)
            .copied()
            .collect()
    })
}

/// Immutable subscription-token policy; it never accepts a caller-selected
/// destination. Requests are validated by
/// [`super::AnthropicApiKeyAdapter::validate_request`] before any lease.
pub struct AnthropicSubscriptionTokenAdapter {
    route: ProxyRouteConfig,
}

impl AnthropicSubscriptionTokenAdapter {
    pub fn new() -> Result<Self, CredentialBrokerError> {
        let route = route();
        validate_proxy_route(ROUTE, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Consume one exact operation lease for an Active Claude subscription
    /// token. Every lease coordinate and the caller's placeholder are checked,
    /// and its identity headers selected, before the material is borrowed.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedAnthropicRequest,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        validate_lease_kind(&lease, request.operation, CredentialAuthKind::OAuth)?;
        require_placeholder(&request.headers)?;
        let identity = client_identity(&request.headers);
        let beta = with_oauth_beta(request.headers.get("anthropic-beta"))?;
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
            let prepared = prepare_credentials(&self.route, &Token(material), &request.body)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            let mut headers = prepare_outbound_headers(&self.route, &request.headers, &prepared)
                .map_err(|_| CredentialBrokerError::RequestDenied)?;
            // AV copies none of these; only the bounded values selected above
            // are forwarded.
            for (name, value) in identity {
                headers.insert(name, value);
            }
            headers.insert("anthropic-beta", beta);
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
            // AV's redaction set holds the injected token and its encodings.
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
                    response_headers: response_headers(),
                },
            })
        })
    }
}

impl Default for AnthropicSubscriptionTokenAdapter {
    fn default() -> Self {
        Self::new().expect("built-in Anthropic subscription policy must be valid")
    }
}

struct Token<'a>(&'a str);
impl CredentialSource for Token<'_> {
    fn credential(&self, key: &str) -> Option<&str> {
        (key == CREDENTIAL_KEY).then_some(self.0)
    }
}

/// The caller's one bearer must be exactly the projected placeholder: a
/// missing, repeated or different `Authorization` is denied.
fn require_placeholder(headers: &HeaderMap) -> Result<(), CredentialBrokerError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    match (values.next(), values.next()) {
        (Some(value), None) if value.as_bytes() == PLACEHOLDER_AUTHORIZATION => Ok(()),
        _ => Err(CredentialBrokerError::RequestDenied),
    }
}

/// Claude Code's identity headers that are present exactly once in their
/// bounded form. Anything else is dropped, never forwarded, and never fails
/// the request.
fn client_identity(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    fn visible(value: &HeaderValue, maximum: usize, allowed: fn(u8) -> bool) -> bool {
        let bytes = value.as_bytes();
        !bytes.is_empty() && bytes.len() <= maximum && bytes.iter().copied().all(allowed)
    }
    type Check = fn(&HeaderValue) -> bool;
    let checks: [(HeaderName, Check); 4] = [
        (header::USER_AGENT, |value| {
            visible(value, MAX_USER_AGENT_BYTES, |byte| {
                (0x20..0x7f).contains(&byte)
            })
        }),
        (HeaderName::from_static("x-app"), |value| {
            visible(value, MAX_APP_BYTES, |byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
            })
        }),
        (
            HeaderName::from_static("anthropic-dangerous-direct-browser-access"),
            |value| value.as_bytes() == b"true",
        ),
        (
            HeaderName::from_static("x-claude-code-session-id"),
            |value| {
                visible(value, MAX_SESSION_ID_BYTES, |byte| {
                    byte.is_ascii_alphanumeric() || byte == b'-'
                })
            },
        ),
    ];
    checks
        .into_iter()
        .filter_map(|(name, valid)| {
            let mut values = headers.get_all(&name).iter();
            match (values.next(), values.next()) {
                (Some(value), None) if valid(value) => Some((name, value.clone())),
                _ => None,
            }
        })
        .collect()
}

/// The caller's already validated beta list with the OAuth flag present
/// exactly once.
fn with_oauth_beta(existing: Option<&HeaderValue>) -> Result<HeaderValue, CredentialBrokerError> {
    let Some(existing) = existing else {
        return Ok(HeaderValue::from_static(OAUTH_BETA));
    };
    let value = existing
        .to_str()
        .map_err(|_| CredentialBrokerError::RequestDenied)?;
    if value
        .split(',')
        .map(str::trim)
        .any(|token| token == OAUTH_BETA)
    {
        return Ok(existing.clone());
    }
    HeaderValue::from_str(&format!("{value},{OAUTH_BETA}"))
        .map_err(|_| CredentialBrokerError::RequestDenied)
}

fn route() -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: "codewire-anthropic-subscription-token".into(),
        base_url: "https://api.anthropic.com/v1".into(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(ProxyInjectionConfig::Bearer {
            secret_key: CREDENTIAL_KEY.into(),
        }),
        body_substitutions: BTreeMap::new(),
        allowed_methods: vec!["POST".into()],
        allowed_exact_paths: vec!["/messages".into(), "/messages/count_tokens".into()],
        allowed_path_prefixes: Vec::new(),
        allowed_request_headers: REQUEST_HEADERS.iter().map(|name| (*name).into()).collect(),
        allowed_response_headers: response_headers()
            .iter()
            .map(|name| (*name).into())
            .collect(),
        allowed_query_parameters: vec!["beta".into()],
        allowed_content_types: vec!["application/json".into()],
        max_body_bytes: MAX_REQUEST_BYTES,
        response_mode: ProxyResponseMode::Streaming,
        max_response_bytes: MAX_RESPONSE_BYTES,
        websocket: None,
    }
}

#[cfg(test)]
#[path = "subscription_tests.rs"]
mod tests;
