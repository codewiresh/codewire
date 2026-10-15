//! Claude sign-in form of the Anthropic adapter.
//!
//! A Claude sign-in is Claude Code's own claude.ai OAuth login, enrolled by
//! Codewire. Its protected material is the canonical envelope
//! ([`ClaudeOAuthCredential`]); this adapter injects only its access token,
//! exactly as the subscription-token form injects its token: as
//! `Authorization: Bearer`, with `anthropic-beta` carrying the OAuth flag. The
//! guest's own authorization is dropped, so a Sandbox's copy of the token (or a
//! placeholder) never reaches the provider through the route. The refresh token
//! is never injected anywhere; the runtime refreshes it at Claude's token
//! endpoint before the access token is used.

use av_credential_proxy::{ProxyRouteConfig, validate_proxy_route};
use codewire_access::CredentialAuthKind;

use super::subscription::{route, with_oauth_beta};
use super::{Outbound, PreparedAnthropicRequest, ValidatedAnthropicRequest, validate_lease_kind};
use crate::claude_oauth::ClaudeOAuthCredential;
use crate::{BrokerCredentialLease, CredentialBrokerError};

const ROUTE: &str = "anthropic-api";
const CREDENTIAL_KEY: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// Immutable sign-in policy; it never accepts a caller-selected destination.
/// Requests are validated by
/// [`super::AnthropicApiKeyAdapter::validate_request`] before any lease.
pub(crate) struct AnthropicClaudeSignInAdapter {
    route: ProxyRouteConfig,
}

impl AnthropicClaudeSignInAdapter {
    pub(crate) fn new() -> Result<Self, CredentialBrokerError> {
        let route = route();
        validate_proxy_route(ROUTE, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Check every coordinate of a proxied request's lease for an Active
    /// Claude sign-in, then parse its material. A setup token or API key
    /// lease is refused before its material is read.
    pub(crate) fn credential_from_lease<L: BrokerCredentialLease>(
        &self,
        lease: L,
    ) -> Result<ClaudeOAuthCredential, CredentialBrokerError> {
        validate_lease_kind(&lease, CredentialAuthKind::ClaudeSignIn)?;
        lease.with_material(|material| {
            ClaudeOAuthCredential::parse(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)
        })
    }

    /// Inject the access token of an already admitted, fresh enough sign-in.
    pub(crate) fn prepare_credential(
        &self,
        credential: &ClaudeOAuthCredential,
        request: ValidatedAnthropicRequest,
    ) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
        Outbound::new(request.0, with_oauth_beta)?.inject(
            &self.route,
            CREDENTIAL_KEY,
            credential.access_token(),
        )
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method};
    use zeroize::Zeroizing;

    use super::*;
    use crate::claude_oauth::{ClaudeIssuedTokens, ClaudeProfile, import_tokens_at};
    use crate::http_test_support::Lease;

    fn material() -> Zeroizing<Vec<u8>> {
        let (bundle, _) = import_tokens_at(
            ClaudeIssuedTokens {
                access_token: Zeroizing::new("synthetic-sign-in-access".into()),
                refresh_token: Some(Zeroizing::new("synthetic-sign-in-refresh".into())),
                expires_in: 28_800,
                refresh_token_expires_in: None,
                scope: Some("user:inference user:profile".into()),
            },
            ClaudeProfile::default(),
            1_800_000_000,
        )
        .unwrap()
        .into_parts();
        bundle.into_bytes()
    }

    fn lease(kind: CredentialAuthKind) -> Lease {
        let mut lease = Lease::new("anthropic", kind, "anthropic", "messages", "anthropic-api");
        lease.material = material();
        lease
    }

    fn request() -> ValidatedAnthropicRequest {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer guest-held-token"),
        );
        headers.insert("anthropic-beta", HeaderValue::from_static("files-2025"));
        super::super::AnthropicApiKeyAdapter::new()
            .unwrap()
            .validate_request(
                &Method::POST,
                "/v1/messages",
                None,
                headers,
                br#"{"model":"claude"}"#.to_vec(),
            )
            .unwrap()
    }

    #[test]
    fn injects_only_the_access_token_as_an_oauth_bearer() {
        let adapter = AnthropicClaudeSignInAdapter::new().unwrap();
        let credential = adapter
            .credential_from_lease(lease(CredentialAuthKind::ClaudeSignIn))
            .unwrap();
        let (method, target, headers, body, _) = adapter
            .prepare_credential(&credential, request())
            .unwrap()
            .into_parts();
        assert_eq!(method, Method::POST);
        assert_eq!(target.as_str(), "https://api.anthropic.com/v1/messages");
        assert_eq!(
            headers.get_all("authorization").iter().collect::<Vec<_>>(),
            [HeaderValue::from_static("Bearer synthetic-sign-in-access")]
        );
        assert_eq!(
            headers["anthropic-beta"],
            HeaderValue::from_static("files-2025,oauth-2025-04-20")
        );
        assert_eq!(body, br#"{"model":"claude"}"#);
        let sent = format!("{headers:?}");
        assert!(!sent.contains("refresh") && !sent.contains("guest-held"));
    }

    #[test]
    fn other_anthropic_forms_are_refused_before_their_material_is_read() {
        let adapter = AnthropicClaudeSignInAdapter::new().unwrap();
        for kind in [CredentialAuthKind::OAuth, CredentialAuthKind::ApiKey] {
            let lease = lease(kind);
            let reads = lease.reads.clone();
            assert!(matches!(
                adapter.credential_from_lease(lease),
                Err(CredentialBrokerError::UnsupportedLease)
            ));
            assert_eq!(reads.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
        // A sign-in lease whose material is a raw token is invalid material.
        let mut raw = lease(CredentialAuthKind::ClaudeSignIn);
        raw.material = Zeroizing::new(b"sk-ant-oat01-synthetic".to_vec());
        assert!(matches!(
            adapter.credential_from_lease(raw),
            Err(CredentialBrokerError::InvalidCredentialMaterial)
        ));
    }
}
