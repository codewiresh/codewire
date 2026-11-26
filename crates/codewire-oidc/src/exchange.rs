//! The token-exchange grant (RFC 8693) for user tokens.
//!
//! A client allowed the grant exchanges its own live access token for a
//! separate opaque access token, a user token, with a lifetime the caller
//! chooses and no refresh token. The subject must carry a sign-in, and the
//! user token records it, so ending that sign-in ends the user token. A user
//! token is never a subject: it lives in its own store, so the subject lookup
//! never finds one. Every refusal of the subject is the same `invalid_grant`.

use serde::Serialize;

use crate::Provider;
use crate::error::{ErrorCode, OAuthError};
use crate::store::UserTokenIssue;
use crate::token;
use crate::types::{GrantType, UserTokenGrant};

/// The only subject token type accepted: an access token.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The longest finite lifetime a user token may be given, in days.
pub const MAX_LIFETIME_DAYS: u32 = 3650;

const SECONDS_PER_DAY: u64 = 86_400;

/// How long a user token lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserTokenLifetime {
    /// A whole number of days, 1 to [`MAX_LIFETIME_DAYS`].
    Days(u32),
    /// Until it is revoked.
    Never,
}

impl UserTokenLifetime {
    /// Parse the request's `codewire_expires_in_days`: absent is 1 day, then
    /// `never` or 1 to [`MAX_LIFETIME_DAYS`].
    pub fn parse(value: Option<&str>) -> Result<Self, OAuthError> {
        match value.map(str::trim) {
            None | Some("") => Ok(Self::Days(1)),
            Some("never") => Ok(Self::Never),
            Some(days) => match days.parse::<u32>() {
                Ok(days @ 1..=MAX_LIFETIME_DAYS) => Ok(Self::Days(days)),
                _ => Err(OAuthError::new(
                    ErrorCode::InvalidRequest,
                    format!("codewire_expires_in_days must be 1 to {MAX_LIFETIME_DAYS}, or never"),
                )),
            },
        }
    }

    fn seconds(self) -> Option<u64> {
        match self {
            Self::Days(days) => Some(u64::from(days) * SECONDS_PER_DAY),
            Self::Never => None,
        }
    }
}

/// The token endpoint's answer to a token exchange (RFC 8693 §2.2.1).
#[derive(Debug, Clone, Serialize)]
pub struct TokenExchangeResponse {
    /// The user token: an opaque bearer, returned once.
    pub access_token: String,
    /// Always [`ACCESS_TOKEN_TYPE`].
    pub issued_token_type: &'static str,
    /// Always `Bearer`.
    pub token_type: String,
    /// Absent for a token that lives until it is revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// The token's scopes, space-delimited: the exchanged token's.
    pub scope: String,
}

impl Provider {
    /// Exchange the client's own access token for a user token.
    pub async fn exchange_token(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        subject_token: &str,
        subject_token_type: Option<&str>,
        lifetime: UserTokenLifetime,
    ) -> Result<TokenExchangeResponse, OAuthError> {
        let Some(store) = self.user_tokens() else {
            return Err(OAuthError::new(
                ErrorCode::UnsupportedGrantType,
                "token exchange is not enabled",
            ));
        };
        let client = match self.clients().get(client_id).await? {
            Some(c) if !c.disabled => c,
            _ => return Err(OAuthError::invalid_client("unknown or disabled client")),
        };
        self.authenticate_client(&client, client_secret).await?;
        if !client.grant_types.contains(&GrantType::TokenExchange) {
            return Err(OAuthError::new(
                ErrorCode::UnauthorizedClient,
                "client may not use the token-exchange grant",
            ));
        }
        if subject_token_type != Some(ACCESS_TOKEN_TYPE) {
            return Err(OAuthError::new(
                ErrorCode::InvalidRequest,
                format!("subject_token_type must be {ACCESS_TOKEN_TYPE}"),
            ));
        }

        // The subject is this client's own live access token, with a sign-in.
        // Each refusal answers the same, so the grant tells a caller nothing
        // about a token it doesn't hold.
        let refused = || OAuthError::invalid_grant("the subject token can't be exchanged");
        let subject = self
            .tokens()
            .get_access(subject_token)
            .await?
            .ok_or_else(refused)?;
        if subject.client_id != client.id {
            return Err(refused());
        }
        let sign_in = subject.sign_in.ok_or_else(refused)?;

        let user_token = token::mint_opaque_token();
        let issue = store
            .store_user_token(
                &user_token,
                UserTokenGrant {
                    subject: subject.subject,
                    client_id: client.id.clone(),
                    scopes: subject.scopes.clone(),
                    sign_in,
                    expires_in_secs: lifetime.seconds(),
                },
            )
            .await?;
        match issue {
            UserTokenIssue::Issued => Ok(TokenExchangeResponse {
                access_token: user_token,
                issued_token_type: ACCESS_TOKEN_TYPE,
                token_type: "Bearer".into(),
                expires_in: lifetime.seconds(),
                scope: subject.scopes.to_space_delimited(),
            }),
            UserTokenIssue::SignInEnded => Err(refused()),
            UserTokenIssue::RateLimited => Err(OAuthError::new(
                ErrorCode::SlowDown,
                "too many user tokens were issued lately; try again later",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_defaults_to_a_day_and_is_bounded() {
        assert_eq!(
            UserTokenLifetime::parse(None).unwrap(),
            UserTokenLifetime::Days(1)
        );
        assert_eq!(
            UserTokenLifetime::parse(Some("")).unwrap(),
            UserTokenLifetime::Days(1)
        );
        assert_eq!(
            UserTokenLifetime::parse(Some("never")).unwrap(),
            UserTokenLifetime::Never
        );
        assert_eq!(
            UserTokenLifetime::parse(Some("30")).unwrap(),
            UserTokenLifetime::Days(30)
        );
        assert_eq!(
            UserTokenLifetime::parse(Some("3650")).unwrap().seconds(),
            Some(3650 * 86_400)
        );
        for bad in ["0", "3651", "-1", "1.5", "forever", "30d"] {
            assert_eq!(
                UserTokenLifetime::parse(Some(bad)).unwrap_err().code,
                ErrorCode::InvalidRequest,
                "{bad}"
            );
        }
    }
}
