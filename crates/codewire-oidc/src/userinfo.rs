//! The UserInfo endpoint (OIDC Core §5.3).
//!
//! A protected resource: the RP presents the opaque access token as a Bearer
//! credential, and the provider returns the claims authorized by the token's
//! scopes. `sub` is always present; everything else comes from the host's
//! [`crate::store::TokenCustomizer`], so the library stays free of any
//! profile schema.

use crate::Provider;
use crate::error::{ErrorCode, OAuthError};
use crate::types::Claims;

impl Provider {
    /// Resolve an opaque access token to its UserInfo claims.
    ///
    /// An unknown/expired/revoked token yields [`ErrorCode::InvalidToken`]
    /// (RFC 6750), which the transport renders as a `401` with a
    /// `WWW-Authenticate: Bearer error="invalid_token"` header.
    pub async fn userinfo(&self, access_token: &str) -> Result<Claims, OAuthError> {
        let grant = self
            .tokens()
            .get_access(access_token)
            .await?
            .ok_or_else(|| {
                OAuthError::new(ErrorCode::InvalidToken, "invalid or expired access token")
            })?;

        let client = self
            .clients()
            .get(&grant.client_id)
            .await?
            .ok_or_else(|| OAuthError::server_error("client not found"))?;

        let extra = self
            .customizer()
            .extra_claims(&grant.subject, &grant.scopes, &client)
            .await?;
        Ok(Claims {
            sub: grant.subject.0,
            extra,
            ..Default::default()
        })
    }
}
