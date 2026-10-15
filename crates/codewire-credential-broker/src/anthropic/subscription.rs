//! Claude subscription token form of the Anthropic adapter.
//!
//! A Claude subscription token is the long-lived OAuth token `claude setup-token`
//! prints for a Claude Pro, Max, Team or Enterprise plan. Claude Code reads it
//! from `CLAUDE_CODE_OAUTH_TOKEN`. It stays in Codewire: the Sandbox holds only
//! the `codewire-managed` placeholder, and this adapter injects the stored
//! token as `Authorization: Bearer`. It is not a direct delivery exception and
//! has no refresh.
//!
//! Everything else is the transparent route's: the guest's own `Authorization`
//! is dropped and every other header, the path, query and body pass unchanged.
//! The one addition is the provider's requirement for an OAuth bearer:
//! `anthropic-beta` carries `oauth-2025-04-20`, appended when absent.

use av_credential_proxy::{ProxyInjectionConfig, ProxyRouteConfig, validate_proxy_route};
use codewire_access::CredentialAuthKind;
use http::{HeaderMap, HeaderValue};

use super::{
    PreparedAnthropicRequest, ValidatedAnthropicRequest, prepare_transparent, route_with,
    validate_lease_kind,
};
use crate::{BrokerCredentialLease, CredentialBrokerError};

const ROUTE: &str = "anthropic-api";
const CREDENTIAL_KEY: &str = "CLAUDE_CODE_OAUTH_TOKEN";
/// The provider's beta flag for an OAuth bearer.
pub(crate) const OAUTH_BETA: &str = "oauth-2025-04-20";

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
    /// token. Every lease coordinate is checked before the material is
    /// borrowed.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedAnthropicRequest,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        validate_lease_kind(&lease, CredentialAuthKind::OAuth)?;
        prepare_transparent(
            &self.route,
            CREDENTIAL_KEY,
            lease,
            request.0,
            with_oauth_beta,
        )
    }
}

impl Default for AnthropicSubscriptionTokenAdapter {
    fn default() -> Self {
        Self::new().expect("built-in Anthropic subscription policy must be valid")
    }
}

/// The caller's beta list, as one value, with the OAuth flag present.
pub(super) fn with_oauth_beta(headers: &mut HeaderMap) -> Result<(), CredentialBrokerError> {
    let mut tokens = Vec::new();
    for value in headers.get_all("anthropic-beta") {
        let value = value
            .to_str()
            .map_err(|_| CredentialBrokerError::RequestDenied)?;
        tokens.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_owned),
        );
    }
    if !tokens.iter().any(|token| token == OAUTH_BETA) {
        tokens.push(OAUTH_BETA.to_owned());
    }
    let value = HeaderValue::from_str(&tokens.join(","))
        .map_err(|_| CredentialBrokerError::RequestDenied)?;
    headers.insert("anthropic-beta", value);
    Ok(())
}

pub(super) fn route() -> ProxyRouteConfig {
    route_with(
        "codewire-anthropic-subscription-token",
        ProxyInjectionConfig::Bearer {
            secret_key: CREDENTIAL_KEY.into(),
        },
    )
}

#[cfg(test)]
#[path = "subscription_tests.rs"]
mod tests;
