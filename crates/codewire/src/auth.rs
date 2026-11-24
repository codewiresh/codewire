//! Bearer credentials and the provider seam every RPC authenticates through.
//! Sign-in flows that produce a credential (OAuth device and PKCE, the
//! credential stores, refresh) live in `codewire-client`.

use std::fmt;

use async_trait::async_trait;
use connectrpc::ErrorCode;
use http::HeaderValue;

use crate::ClientError;

/// A validated bearer credential.
///
/// Debug output is always redacted. Callers that must authenticate a
/// non-Connect transport, such as the permanent terminal WebSocket, can use
/// [`expose_secret`](Self::expose_secret) deliberately.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken(String);

impl BearerToken {
    pub fn new(token: impl Into<String>) -> Result<Self, ClientError> {
        let token = token.into();
        if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(ClientError::new(
                ErrorCode::InvalidArgument,
                "bearer token must not be empty or contain whitespace",
            ));
        }
        HeaderValue::try_from(format!("Bearer {token}")).map_err(|_| {
            ClientError::new(
                ErrorCode::InvalidArgument,
                "bearer token contains invalid header characters",
            )
        })?;
        Ok(Self(token))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub(crate) fn authorization_header(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

/// Supplies the current bearer credential for each RPC.
///
/// The provider is asynchronous so the later OAuth convergence can refresh
/// and atomically persist a token pair behind this same seam. API keys and
/// OAuth access tokens both use this interface; the server remains the
/// authority for their distinct semantics.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn token(&self) -> Result<BearerToken, ClientError>;

    /// Another bearer to send a unary call with once more, after the
    /// server's auth layer itself refused `rejected`, or `None`.
    /// Only a provider that can renew a sign-in has one; an API key or user
    /// token is sent as it is, and its refusal ends the call
    /// (docs/dev/AUTH-POLICY.md, "Native sign-in lifetimes").
    async fn after_refusal(
        &self,
        _rejected: &BearerToken,
    ) -> Result<Option<BearerToken>, ClientError> {
        Ok(None)
    }
}

/// A non-refreshing provider for an already-resolved token or `cw_` API key.
#[derive(Clone, Debug)]
pub struct StaticTokenProvider {
    token: BearerToken,
}

impl StaticTokenProvider {
    pub fn new(token: impl Into<String>) -> Result<Self, ClientError> {
        Ok(Self {
            token: BearerToken::new(token)?,
        })
    }

    /// Move an already validated credential into a static provider without
    /// manufacturing another plaintext copy.
    pub fn from_token(token: BearerToken) -> Self {
        Self { token }
    }
}

#[async_trait]
impl TokenProvider for StaticTokenProvider {
    async fn token(&self) -> Result<BearerToken, ClientError> {
        Ok(self.token.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_tokens_are_validated_without_echoing_the_value() {
        assert!(BearerToken::new("").is_err());
        assert!(BearerToken::new("token with whitespace").is_err());
        assert!(BearerToken::new("token\r\ninjected: true").is_err());

        let token = BearerToken::new("secret-value").expect("valid token");
        assert_eq!(format!("{token:?}"), "BearerToken([REDACTED])");
        assert!(!format!("{token:?}").contains("secret-value"));
        assert_eq!(token.expose_secret(), "secret-value");
    }
}
