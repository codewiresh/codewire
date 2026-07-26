//! Token Introspection (RFC 7662) and Token Revocation (RFC 7009).
//!
//! Both endpoints authenticate the calling client (a resource server or the
//! token's own client) the same way the token endpoint does, then act on an
//! opaque access or refresh token.
//!
//! Introspection deliberately does **not** report `exp`/`iat`: token lifetime
//! is owned by the [`crate::store::TokenStore`] (an expired token simply
//! resolves to `None` → `active: false`), and the grant records the library
//! holds carry no timestamps. The standard marks those fields OPTIONAL.

use serde::{Deserialize, Serialize};

use crate::Provider;
use crate::error::OAuthError;
use crate::types::{AccessGrant, RefreshGrant};

/// An RFC 7662 introspection response. Inactive tokens serialize as
/// `{"active": false}` only; the rest is present only when `active` is true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    pub active: bool,
    /// Space-delimited granted scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The client the token was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The subject the token authenticates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// `Bearer` for access tokens, `refresh_token` for refresh tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// The token's audience (the issuing client).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    /// The issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

impl IntrospectionResponse {
    /// The canonical inactive response.
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            sub: None,
            token_type: None,
            aud: None,
            iss: None,
        }
    }
}

/// Which kind of token a lookup resolved to.
enum Resolved {
    Access(AccessGrant),
    Refresh(RefreshGrant),
}

impl Provider {
    /// Introspect an opaque access or refresh token (RFC 7662).
    ///
    /// The caller (`client_id`/`client_secret`) is authenticated first. A
    /// token that is unknown/expired/revoked — or that belongs to a different
    /// client — returns `{active: false}` (never leaking another client's
    /// token state).
    pub async fn introspect(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<IntrospectionResponse, OAuthError> {
        let client = self.authenticated_caller(client_id, client_secret).await?;

        let Some(resolved) = self.resolve_token(token, token_type_hint).await? else {
            return Ok(IntrospectionResponse::inactive());
        };

        let (subject, owner, scopes, token_type) = match resolved {
            Resolved::Access(g) => (g.subject, g.client_id, g.scopes, "Bearer"),
            Resolved::Refresh(g) => (g.subject, g.client_id, g.scopes, "refresh_token"),
        };
        // A client may only introspect its own tokens.
        if owner != client.id {
            return Ok(IntrospectionResponse::inactive());
        }

        Ok(IntrospectionResponse {
            active: true,
            scope: Some(scopes.to_space_delimited()),
            client_id: Some(owner.clone()),
            sub: Some(subject.0),
            token_type: Some(token_type.to_string()),
            aud: Some(vec![owner]),
            iss: Some(self.config().issuer.as_str().to_string()),
        })
    }

    /// Revoke an opaque access or refresh token (RFC 7009).
    ///
    /// The caller is authenticated first. Per the RFC, revoking an unknown
    /// token is a success no-op; we additionally no-op (rather than error)
    /// when the token belongs to another client, so token state never leaks.
    pub async fn revoke(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        token: &str,
        token_type_hint: Option<&str>,
    ) -> Result<(), OAuthError> {
        let client = self.authenticated_caller(client_id, client_secret).await?;

        let owner = match self.resolve_token(token, token_type_hint).await? {
            Some(Resolved::Access(g)) => g.client_id,
            Some(Resolved::Refresh(g)) => g.client_id,
            None => return Ok(()),
        };
        if owner == client.id {
            self.tokens().revoke(token).await?;
        }
        Ok(())
    }

    /// Authenticate the calling client for introspection/revocation.
    async fn authenticated_caller(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<crate::Client, OAuthError> {
        let client = match self.clients().get(client_id).await? {
            Some(c) if !c.disabled => c,
            _ => return Err(OAuthError::invalid_client("unknown or disabled client")),
        };
        self.authenticate_client(&client, client_secret).await?;
        Ok(client)
    }

    /// Look up a token, honoring `token_type_hint` for lookup order.
    async fn resolve_token(
        &self,
        token: &str,
        hint: Option<&str>,
    ) -> Result<Option<Resolved>, OAuthError> {
        let refresh_first = matches!(hint, Some("refresh_token"));
        if refresh_first {
            if let Some(g) = self.tokens().get_refresh(token).await? {
                return Ok(Some(Resolved::Refresh(g)));
            }
            if let Some(g) = self.tokens().get_access(token).await? {
                return Ok(Some(Resolved::Access(g)));
            }
        } else {
            if let Some(g) = self.tokens().get_access(token).await? {
                return Ok(Some(Resolved::Access(g)));
            }
            if let Some(g) = self.tokens().get_refresh(token).await? {
                return Ok(Some(Resolved::Refresh(g)));
            }
        }
        Ok(None)
    }
}
