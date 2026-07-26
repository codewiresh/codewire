//! OpenID Provider configuration — the `/.well-known/openid-configuration`
//! document (OpenID Connect Discovery 1.0).

use serde::{Deserialize, Serialize};

use crate::types::Issuer;

/// Endpoint paths (relative to the issuer origin). Defaults match the
/// current Go provider's custom endpoints so the discovery document is
/// wire-compatible.
#[derive(Debug, Clone)]
pub struct EndpointPaths {
    /// Authorization endpoint path.
    pub authorization: String,
    /// Token endpoint path.
    pub token: String,
    /// UserInfo endpoint path.
    pub userinfo: String,
    /// JWKS endpoint path.
    pub jwks: String,
    /// Revocation endpoint path.
    pub revocation: String,
    /// Introspection endpoint path.
    pub introspection: String,
    /// End-session (RP-initiated logout) endpoint path.
    pub end_session: String,
    /// Device-authorization endpoint path (RFC 8628).
    pub device_authorization: String,
}

impl Default for EndpointPaths {
    fn default() -> Self {
        Self {
            authorization: "/api/oauth/authorize".into(),
            token: "/api/oauth/token".into(),
            userinfo: "/api/oauth/userinfo".into(),
            jwks: "/.well-known/jwks.json".into(),
            revocation: "/api/oauth/revoke".into(),
            introspection: "/api/oauth/introspect".into(),
            end_session: "/api/oauth/end_session".into(),
            device_authorization: "/api/oauth/device_authorization".into(),
        }
    }
}

/// The OpenID Provider metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// `issuer`.
    pub issuer: String,
    /// `authorization_endpoint`.
    pub authorization_endpoint: String,
    /// `token_endpoint`.
    pub token_endpoint: String,
    /// `userinfo_endpoint`.
    pub userinfo_endpoint: String,
    /// `jwks_uri`.
    pub jwks_uri: String,
    /// `revocation_endpoint`.
    pub revocation_endpoint: String,
    /// `introspection_endpoint`.
    pub introspection_endpoint: String,
    /// `end_session_endpoint`.
    pub end_session_endpoint: String,
    /// `device_authorization_endpoint` (RFC 8628; only when device flow is enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
    /// `scopes_supported`.
    pub scopes_supported: Vec<String>,
    /// `response_types_supported`.
    pub response_types_supported: Vec<String>,
    /// `response_modes_supported`.
    pub response_modes_supported: Vec<String>,
    /// `grant_types_supported`.
    pub grant_types_supported: Vec<String>,
    /// `subject_types_supported`.
    pub subject_types_supported: Vec<String>,
    /// `id_token_signing_alg_values_supported`.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// `token_endpoint_auth_methods_supported`.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// `code_challenge_methods_supported`.
    pub code_challenge_methods_supported: Vec<String>,
    /// `claims_supported`.
    pub claims_supported: Vec<String>,
}

impl DiscoveryDocument {
    /// Build the discovery document for an issuer with the given endpoint
    /// paths and supported scopes.
    ///
    /// `subject_types` is `["public"]`, signing alg `["EdDSA"]`, PKCE
    /// `["S256"]`, and grant types `authorization_code`/`refresh_token` —
    /// matching this provider's capabilities.
    pub fn build(
        issuer: &Issuer,
        paths: &EndpointPaths,
        scopes_supported: Vec<String>,
        device_flow: bool,
    ) -> Self {
        let origin = issuer.as_str().trim_end_matches('/');
        let url = |p: &str| format!("{origin}{p}");
        let mut grant_types_supported = vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ];
        if device_flow {
            grant_types_supported.push("urn:ietf:params:oauth:grant-type:device_code".into());
        }
        Self {
            issuer: issuer.as_str().to_string(),
            authorization_endpoint: url(&paths.authorization),
            token_endpoint: url(&paths.token),
            userinfo_endpoint: url(&paths.userinfo),
            jwks_uri: url(&paths.jwks),
            revocation_endpoint: url(&paths.revocation),
            introspection_endpoint: url(&paths.introspection),
            end_session_endpoint: url(&paths.end_session),
            device_authorization_endpoint: device_flow.then(|| url(&paths.device_authorization)),
            scopes_supported,
            response_types_supported: vec!["code".into()],
            response_modes_supported: vec!["query".into()],
            grant_types_supported,
            subject_types_supported: vec!["public".into()],
            id_token_signing_alg_values_supported: vec!["EdDSA".into()],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic".into(),
                "client_secret_post".into(),
                "none".into(),
            ],
            code_challenge_methods_supported: vec!["S256".into()],
            claims_supported: vec![
                "sub".into(),
                "email".into(),
                "email_verified".into(),
                "name".into(),
                "picture".into(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_urls_are_absolute_and_capabilities_pinned() {
        let doc = DiscoveryDocument::build(
            &Issuer("https://codewire.sh".into()),
            &EndpointPaths::default(),
            vec!["openid".into(), "profile".into(), "email".into()],
            true,
        );
        assert_eq!(doc.issuer, "https://codewire.sh");
        assert_eq!(
            doc.authorization_endpoint,
            "https://codewire.sh/api/oauth/authorize"
        );
        assert_eq!(doc.jwks_uri, "https://codewire.sh/.well-known/jwks.json");
        assert_eq!(doc.id_token_signing_alg_values_supported, vec!["EdDSA"]);
        assert_eq!(doc.code_challenge_methods_supported, vec!["S256"]);
        assert_eq!(doc.subject_types_supported, vec!["public"]);
        assert_eq!(doc.response_types_supported, vec!["code"]);
        // device flow enabled → endpoint + grant advertised.
        assert_eq!(
            doc.device_authorization_endpoint.as_deref(),
            Some("https://codewire.sh/api/oauth/device_authorization")
        );
        assert!(
            doc.grant_types_supported
                .iter()
                .any(|g| g.contains("device_code"))
        );
    }

    #[test]
    fn device_flow_absent_when_disabled() {
        let doc = DiscoveryDocument::build(
            &Issuer("https://x.test".into()),
            &EndpointPaths::default(),
            vec!["openid".into()],
            false,
        );
        assert!(doc.device_authorization_endpoint.is_none());
        assert!(
            !doc.grant_types_supported
                .iter()
                .any(|g| g.contains("device_code"))
        );
    }

    #[test]
    fn trailing_slash_issuer_normalized() {
        let doc = DiscoveryDocument::build(
            &Issuer("https://x.test/".into()),
            &EndpointPaths::default(),
            vec!["openid".into()],
            false,
        );
        assert_eq!(doc.token_endpoint, "https://x.test/api/oauth/token");
    }
}
