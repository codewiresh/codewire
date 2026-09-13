//! The Device Authorization Grant (RFC 8628).
//!
//! A browserless/input-constrained device (e.g. a CLI or relay node) starts
//! the flow at the device-authorization endpoint, shows the returned
//! `user_code` to the operator, and polls the token endpoint with its
//! `device_code` until the operator approves at the verification URI.
//!
//! Device flow is **opt-in**: it works only when the host injected a
//! [`crate::store::DeviceAuthorizationStore`] via the builder; otherwise the
//! methods return `invalid_request` / `unsupported_grant_type`.

use std::fmt;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::Provider;
use crate::error::OAuthError;
use crate::flow::TokenResponse;
use crate::store::DeviceAuthorizationStore;
use crate::token;
use crate::types::{DeviceAuthorization, DeviceStatus, GrantType, Scopes, Subject};

/// Device-code lifetime (RFC 8628 — 10 minutes is typical).
const DEVICE_CODE_TTL_SECS: u64 = 600;
/// Minimum seconds between the device's token-endpoint polls.
const POLL_INTERVAL_SECS: u64 = 5;
/// User-code alphabet — consonants only (no vowels → no accidental words; no
/// ambiguous 0/O/1/I), per RFC 8628 §6.1 guidance.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// Normalize a human-entered device user code to the canonical `XXXX-XXXX`
/// representation minted by the provider.
///
/// The visual separator is optional at input time, but when supplied it must
/// appear between the two four-character groups. Only characters from the
/// provider's unambiguous user-code alphabet are accepted.
pub fn normalize_user_code(input: &str) -> Option<String> {
    let input = input.trim().as_bytes();
    let compact = match input {
        [a, b, c, d, e, f, g, h] => [*a, *b, *c, *d, *e, *f, *g, *h],
        [a, b, c, d, b'-', e, f, g, h] => [*a, *b, *c, *d, *e, *f, *g, *h],
        _ => return None,
    };
    let compact = compact.map(|byte| byte.to_ascii_uppercase());
    if !compact.iter().all(|byte| USER_CODE_ALPHABET.contains(byte)) {
        return None;
    }

    let mut normalized = String::with_capacity(9);
    for (index, byte) in compact.into_iter().enumerate() {
        if index == 4 {
            normalized.push('-');
        }
        normalized.push(char::from(byte));
    }
    Some(normalized)
}

/// The device-authorization response (RFC 8628 §3.2).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code (polled at the token endpoint).
    pub device_code: String,
    /// The end-user code shown on the device.
    pub user_code: String,
    /// The end-user verification URI.
    pub verification_uri: String,
    /// The verification URI with the user code pre-filled.
    pub verification_uri_complete: String,
    /// Device-code lifetime in seconds.
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    pub interval: u64,
}

impl fmt::Debug for DeviceAuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorizationResponse")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("verification_uri", &self.verification_uri)
            .field(
                "verification_uri_complete",
                &"[REDACTED: contains user_code]",
            )
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

impl Provider {
    /// Start a device-authorization flow (RFC 8628 §3.1–3.2).
    pub async fn authorize_device(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        scope: Option<&str>,
    ) -> Result<DeviceAuthorizationResponse, OAuthError> {
        let store = self.require_device_store()?;

        let client = match self.clients().get(client_id).await? {
            Some(c) if !c.disabled => c,
            _ => return Err(OAuthError::invalid_client("unknown or disabled client")),
        };
        self.authenticate_client(&client, client_secret).await?;
        if !client.grant_types.contains(&GrantType::DeviceCode) {
            return Err(OAuthError::new(
                crate::ErrorCode::UnauthorizedClient,
                "client may not use the device_code grant",
            ));
        }

        let scopes = Scopes::parse(scope.unwrap_or(""));
        if let Some(bad) = scopes.0.iter().find(|s| !client.scopes.contains(s)) {
            return Err(OAuthError::new(
                crate::ErrorCode::InvalidScope,
                format!("scope not allowed for client: {bad}"),
            ));
        }

        let device_code = token::mint_opaque_token();
        let user_code = mint_user_code();
        store
            .store_device(
                DeviceAuthorization {
                    device_code: device_code.clone(),
                    user_code: user_code.clone(),
                    client_id: client_id.to_string(),
                    scopes,
                    status: DeviceStatus::Pending,
                },
                DEVICE_CODE_TTL_SECS,
            )
            .await?;

        let verification_uri = self.device_verification_uri();
        let verification_uri_complete = format!(
            "{verification_uri}{}user_code={}",
            if verification_uri.contains('?') {
                '&'
            } else {
                '?'
            },
            user_code,
        );
        Ok(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: DEVICE_CODE_TTL_SECS,
            interval: POLL_INTERVAL_SECS,
        })
    }

    /// Exchange a `device_code` at the token endpoint (RFC 8628 §3.4–3.5).
    ///
    /// While the operator has not yet acted this returns `authorization_pending`;
    /// a denied request returns `access_denied`; an expired/unknown code
    /// returns `expired_token`. On approval it consumes the device code and
    /// issues tokens for the approved subject and scopes.
    pub async fn exchange_device_code(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        device_code: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let store = self.require_device_store()?;

        let client = match self.clients().get(client_id).await? {
            Some(c) if !c.disabled => c,
            _ => return Err(OAuthError::invalid_client("unknown or disabled client")),
        };
        self.authenticate_client(&client, client_secret).await?;
        if !client.grant_types.contains(&GrantType::DeviceCode) {
            return Err(OAuthError::new(
                crate::ErrorCode::UnauthorizedClient,
                "client may not use the device_code grant",
            ));
        }

        // The store returns `None` for an expired (or unknown) code.
        let Some(record) = store.get_by_device_code(device_code).await? else {
            return Err(OAuthError::new(
                crate::ErrorCode::ExpiredToken,
                "the device_code has expired",
            ));
        };
        if record.client_id != client_id {
            return Err(OAuthError::invalid_grant(
                "device_code was issued to another client",
            ));
        }

        match record.status {
            DeviceStatus::Pending => Err(OAuthError::new(
                crate::ErrorCode::AuthorizationPending,
                "the authorization request is still pending",
            )),
            DeviceStatus::Denied => {
                let _ = store.delete(device_code).await;
                Err(OAuthError::access_denied("the end-user denied the request"))
            }
            DeviceStatus::Approved { .. } => {
                // Like authorization codes and refresh tokens, a device code
                // has to be atomically consumed. A read followed by delete
                // would allow concurrent pollers to mint two token sets.
                let Some(DeviceAuthorization {
                    status: DeviceStatus::Approved { subject, auth_time },
                    scopes,
                    ..
                }) = store.consume_approved(device_code).await?
                else {
                    return Err(OAuthError::new(
                        crate::ErrorCode::ExpiredToken,
                        "the device_code has expired",
                    ));
                };
                let tokens = self
                    .issue_tokens(&client, subject, scopes, None, auth_time)
                    .await?;
                Ok(tokens)
            }
        }
    }

    /// Look up a pending device request by its user code — for the verification
    /// UI to show the operator what they're authorizing.
    pub async fn lookup_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceAuthorization>, OAuthError> {
        Ok(self
            .require_device_store()?
            .get_by_user_code(user_code)
            .await?)
    }

    /// Approve a pending device request (called by the verification UI once the
    /// operator is authenticated).
    pub async fn approve_device(
        &self,
        user_code: &str,
        subject: Subject,
        auth_time: Option<i64>,
    ) -> Result<(), OAuthError> {
        self.set_device_status(user_code, DeviceStatus::Approved { subject, auth_time })
            .await
    }

    /// Deny a pending device request.
    pub async fn deny_device(&self, user_code: &str) -> Result<(), OAuthError> {
        self.set_device_status(user_code, DeviceStatus::Denied)
            .await
    }

    async fn set_device_status(
        &self,
        user_code: &str,
        status: DeviceStatus,
    ) -> Result<(), OAuthError> {
        let store = self.require_device_store()?;
        let Some(mut record) = store.get_by_user_code(user_code).await? else {
            return Err(OAuthError::invalid_request("unknown or expired user_code"));
        };
        if record.status != DeviceStatus::Pending {
            return Err(OAuthError::invalid_request(
                "the request has already been resolved",
            ));
        }
        record.status = status;
        store.update(&record).await?;
        Ok(())
    }

    fn require_device_store(
        &self,
    ) -> Result<&std::sync::Arc<dyn DeviceAuthorizationStore>, OAuthError> {
        self.device_store()
            .ok_or_else(|| OAuthError::invalid_request("device flow is not enabled"))
    }
}

/// Mint a human-friendly user code formatted `XXXX-XXXX`.
fn mint_user_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let pick = |rng: &mut rand::rngs::OsRng| {
        let i = rng.gen_range(0..USER_CODE_ALPHABET.len());
        USER_CODE_ALPHABET[i] as char
    };
    let mut s = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            s.push('-');
        }
        s.push(pick(&mut rng));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_authorization_response_debug_redacts_capabilities() {
        let response = DeviceAuthorizationResponse {
            device_code: "device-response-marker".into(),
            user_code: "user-response-marker".into(),
            verification_uri: "https://issuer.example/device".into(),
            verification_uri_complete:
                "https://issuer.example/device?user_code=user-response-marker".into(),
            expires_in: 600,
            interval: 5,
        };

        let diagnostic = format!("{response:?}");
        assert!(!diagnostic.contains("device-response-marker"));
        assert!(!diagnostic.contains("user-response-marker"));
        assert!(diagnostic.contains("https://issuer.example/device"));
        assert!(diagnostic.contains("[REDACTED]"));
    }

    #[test]
    fn user_codes_normalize_to_the_provider_format() {
        for input in ["BCDF-GHJK", "bcdf-ghjk", "BCDFGHJK", "  bcdfghjk  "] {
            assert_eq!(normalize_user_code(input).as_deref(), Some("BCDF-GHJK"));
        }
    }

    #[test]
    fn user_code_normalization_rejects_noncanonical_input() {
        for input in [
            "",
            "BCDF-GHJ",
            "BCDF-GHJKL",
            "BCD-FGHJK",
            "BCDFG-HJK",
            "BCDF--GHJK",
            "ABCD-EFGH",
            "BCDF-1HJK",
            "BCDF GHJK",
        ] {
            assert_eq!(normalize_user_code(input), None, "accepted {input:?}");
        }
    }
}
