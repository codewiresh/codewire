//! Short-lived, exact-scope HMAC credentials for platform-internal RPC hops.
//!
//! This is the platform-internal fourth authentication flavor in its
//! narrowly-scoped service form. It never represents a user, never carries a
//! caller credential, and is valid only for one calling service, one exact RPC
//! method, and a short time window.

use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// Lifetime of an internal service-hop credential.
pub const INTERNAL_HMAC_TOKEN_TTL: Duration = Duration::minutes(5);

/// Verified, non-secret claims from an internal service credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalHmacClaims {
    pub service: String,
    pub method: String,
    pub expires_at: DateTime<Utc>,
}

/// All malformed/signature/scope failures stay deliberately value-free.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum InternalHmacError {
    #[error("internal HMAC configuration is invalid")]
    InvalidConfiguration,
    #[error("internal HMAC token is invalid")]
    InvalidToken,
    #[error("internal HMAC token is expired")]
    Expired,
    #[error("internal HMAC token scope does not match")]
    ScopeMismatch,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedClaims {
    version: u8,
    service: String,
    method: String,
    expires_at: i64,
}

/// Issues a short-lived HMAC credential scoped to exactly one RPC method.
///
/// The returned bearer is transport material, not a product credential: do
/// not log, persist, place in protobuf, or return it from any RPC.
pub fn issue_internal_hmac_token(
    secret: &str,
    service: &str,
    method: &str,
    now: DateTime<Utc>,
) -> Result<String, InternalHmacError> {
    validate_inputs(secret, service, method)?;
    let claims = SignedClaims {
        version: 1,
        service: service.to_owned(),
        method: method.to_owned(),
        expires_at: (now + INTERNAL_HMAC_TOKEN_TTL).timestamp(),
    };
    let payload =
        serde_json::to_vec(&claims).map_err(|_| InternalHmacError::InvalidConfiguration)?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let encoded_payload = engine.encode(payload);
    let signature = sign(secret, encoded_payload.as_bytes())?;
    Ok(format!("{encoded_payload}.{}", engine.encode(signature)))
}

/// Verifies an internal HMAC credential without exposing its transport value.
pub fn verify_internal_hmac_token(
    secret: &str,
    token: &str,
    expected_service: &str,
    expected_method: &str,
    now: DateTime<Utc>,
) -> Result<InternalHmacClaims, InternalHmacError> {
    validate_inputs(secret, expected_service, expected_method)?;
    let (encoded_payload, encoded_signature) = token
        .split_once('.')
        .filter(|(_, trailing)| !trailing.contains('.'))
        .ok_or(InternalHmacError::InvalidToken)?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature = engine
        .decode(encoded_signature)
        .map_err(|_| InternalHmacError::InvalidToken)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| InternalHmacError::InvalidConfiguration)?;
    mac.update(encoded_payload.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| InternalHmacError::InvalidToken)?;
    let payload = engine
        .decode(encoded_payload)
        .map_err(|_| InternalHmacError::InvalidToken)?;
    let claims: SignedClaims =
        serde_json::from_slice(&payload).map_err(|_| InternalHmacError::InvalidToken)?;
    if claims.version != 1 {
        return Err(InternalHmacError::InvalidToken);
    }
    if claims.expires_at <= now.timestamp() {
        return Err(InternalHmacError::Expired);
    }
    if claims.service != expected_service || claims.method != expected_method {
        return Err(InternalHmacError::ScopeMismatch);
    }
    let expires_at =
        DateTime::from_timestamp(claims.expires_at, 0).ok_or(InternalHmacError::InvalidToken)?;
    Ok(InternalHmacClaims {
        service: claims.service,
        method: claims.method,
        expires_at,
    })
}

fn validate_inputs(secret: &str, service: &str, method: &str) -> Result<(), InternalHmacError> {
    if secret.is_empty() || service.is_empty() || method.is_empty() {
        return Err(InternalHmacError::InvalidConfiguration);
    }
    Ok(())
}

/// Derives the signing key of one internal service from a shared root
/// secret: lowercase hex of HMAC-SHA256(root, label). A credential signed for
/// one label never verifies under another, so a hop that shares the root
/// with another service cannot be replayed against it.
pub fn derive_internal_hmac_secret(root: &str, label: &str) -> Result<String, InternalHmacError> {
    if root.is_empty() || label.is_empty() {
        return Err(InternalHmacError::InvalidConfiguration);
    }
    Ok(sign(root, label.as_bytes())?
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn sign(secret: &str, payload: &[u8]) -> Result<Vec<u8>, InternalHmacError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| InternalHmacError::InvalidConfiguration)?;
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_credentials_are_short_lived_and_exactly_scoped() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let token = issue_internal_hmac_token("test-secret", "mesh", "service/method", now)
            .expect("issue HMAC");
        let claims =
            verify_internal_hmac_token("test-secret", &token, "mesh", "service/method", now)
                .expect("verify exact scope");
        assert_eq!(claims.expires_at, now + INTERNAL_HMAC_TOKEN_TTL);
        assert_eq!(
            verify_internal_hmac_token("test-secret", &token, "other", "service/method", now),
            Err(InternalHmacError::ScopeMismatch)
        );
        assert_eq!(
            verify_internal_hmac_token(
                "test-secret",
                &token,
                "mesh",
                "service/method",
                now + INTERNAL_HMAC_TOKEN_TTL,
            ),
            Err(InternalHmacError::Expired)
        );
    }

    #[test]
    fn derived_service_keys_do_not_verify_each_other() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let first = derive_internal_hmac_secret("root", "codewire/first/v1").expect("derive");
        let second = derive_internal_hmac_secret("root", "codewire/second/v1").expect("derive");
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        assert_ne!(first, "root");
        let token =
            issue_internal_hmac_token(&first, "mesh", "service/method", now).expect("issue HMAC");
        assert_eq!(
            verify_internal_hmac_token(&second, &token, "mesh", "service/method", now),
            Err(InternalHmacError::InvalidToken)
        );
        assert_eq!(
            verify_internal_hmac_token("root", &token, "mesh", "service/method", now),
            Err(InternalHmacError::InvalidToken)
        );
        assert_eq!(
            derive_internal_hmac_secret("", "label"),
            Err(InternalHmacError::InvalidConfiguration)
        );
    }
}
