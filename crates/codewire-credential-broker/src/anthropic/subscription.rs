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
//! - `Authorization` replaces `x-api-key`. The caller's own `Authorization` may
//!   only be absent or exactly the placeholder; it is never forwarded.
//! - `anthropic-beta` always carries `oauth-2025-04-20`, which the provider
//!   requires for an OAuth bearer; it is appended when the caller omitted it.
//! - Claude Code's bounded client-identity headers are forwarded. Probed
//!   against Claude Code 2.1.238 in subscription mode, every model request
//!   carries `user-agent: claude-cli/<version> (...)`, `x-app: cli`,
//!   `anthropic-dangerous-direct-browser-access: true` and a UUID
//!   `x-claude-code-session-id`. The provider may treat subscription requests
//!   without them differently, and Claude Code sends the same values when it
//!   talks to the provider directly, so forwarding them discloses nothing a
//!   stock login would not. They are non-secret, length-bounded and exactly
//!   named; a malformed or repeated one is denied rather than dropped.
//!   Claude Code's SDK telemetry (`x-stainless-*`) is still dropped.
//! - The provider's unified subscription rate-limit headers, which Claude Code
//!   reads to show plan usage limits, are returned after redaction.

use std::collections::BTreeMap;

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig, build_target_url,
    prepare_credentials, prepare_outbound_headers, validate_proxy_route,
};
use codewire_access::CredentialAuthKind;
use http::{HeaderMap, HeaderValue, header};

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
/// Claude Code's client identity headers forwarded for this form. `user-agent`
/// is constructed separately because AV never allowlists it.
const IDENTITY_HEADERS: &[&str] = &[
    "x-app",
    "anthropic-dangerous-direct-browser-access",
    "x-claude-code-session-id",
];
const MAX_USER_AGENT_BYTES: usize = 256;
const MAX_APP_BYTES: usize = 32;
const MAX_SESSION_ID_BYTES: usize = 64;
/// Unified subscription rate-limit headers read by Claude Code 2.1.238.
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
    /// token. Every lease coordinate and the caller's placeholder and identity
    /// headers are checked before the material is borrowed.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedAnthropicRequest,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        validate_lease_kind(&lease, request.operation, CredentialAuthKind::OAuth)?;
        let user_agent = client_identity(&request.headers)?;
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
            if let Some(user_agent) = user_agent {
                headers.insert(header::USER_AGENT, user_agent);
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

/// Accept only the projected placeholder as the caller's bearer, and admit
/// Claude Code's identity headers only in their exact bounded forms. Returns
/// the validated `user-agent`, which is forwarded outside AV's allowlist.
fn client_identity(headers: &HeaderMap) -> Result<Option<HeaderValue>, CredentialBrokerError> {
    let denied = CredentialBrokerError::RequestDenied;
    let single = |name: &str| -> Result<Option<&HeaderValue>, CredentialBrokerError> {
        let mut values = headers.get_all(name).iter();
        let value = values.next();
        if values.next().is_some() {
            return Err(denied);
        }
        Ok(value)
    };
    if single(header::AUTHORIZATION.as_str())?
        .is_some_and(|value| value.as_bytes() != PLACEHOLDER_AUTHORIZATION)
    {
        return Err(denied);
    }
    let visible = |value: &HeaderValue, maximum: usize, allowed: fn(u8) -> bool| {
        let bytes = value.as_bytes();
        !bytes.is_empty() && bytes.len() <= maximum && bytes.iter().copied().all(allowed)
    };
    let user_agent = single(header::USER_AGENT.as_str())?;
    if user_agent.is_some_and(|value| {
        !visible(value, MAX_USER_AGENT_BYTES, |byte| {
            (0x20..0x7f).contains(&byte)
        })
    }) {
        return Err(denied);
    }
    if single("x-app")?.is_some_and(|value| {
        !visible(value, MAX_APP_BYTES, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
        })
    }) {
        return Err(denied);
    }
    if single("anthropic-dangerous-direct-browser-access")?
        .is_some_and(|value| value.as_bytes() != b"true")
    {
        return Err(denied);
    }
    if single("x-claude-code-session-id")?.is_some_and(|value| {
        !visible(value, MAX_SESSION_ID_BYTES, |byte| {
            byte.is_ascii_alphanumeric() || byte == b'-'
        })
    }) {
        return Err(denied);
    }
    Ok(user_agent.cloned())
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
        allowed_request_headers: REQUEST_HEADERS
            .iter()
            .chain(IDENTITY_HEADERS)
            .map(|name| (*name).into())
            .collect(),
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
