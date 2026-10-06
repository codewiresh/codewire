//! Environment peer tokens (Program #2238, daemon-hosted access).
//!
//! A peer token lets one environment's in-sandbox daemon act as that
//! environment's tailnet peer at the coordinator. Because it lives inside the
//! sandbox, it is short-lived and bound to the environment's operation
//! generation:
//!
//! `base64url(claims) "." base64url(HMAC-SHA256(key, base64url(claims)))`
//! with `key = HMAC-SHA256(session_secret, PEER_TOKEN_KEY_LABEL)` and claims
//! `{"environment_id","exp","generation","scope":"peer"}` in that order. The
//! derived key never signs anything else, and the session secret never signs
//! a peer token directly. Orchestration issues tokens on the Pod-bound
//! workspace-binding listener; the coordinator validates them here and then
//! checks the generation and environment state against the database.

use std::borrow::Cow;

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

/// The only scope a peer token carries.
pub const SCOPE_PEER: &str = "peer";
/// Lifetime of one peer token. The daemon refreshes and re-proves at half.
pub const PEER_TOKEN_LIFETIME_SECS: i64 = 10 * 60;
/// Clock skew tolerated between issuer and validator.
pub const PEER_TOKEN_LEEWAY_SECS: i64 = 60;
/// Derivation label of the key that signs peer tokens.
const PEER_TOKEN_KEY_LABEL: &[u8] = b"codewire/environment-peer-token/v1";
/// Longest token accepted, well above a real one (about 200 bytes).
const MAX_PEER_TOKEN_BYTES: usize = 512;

/// Validated peer-token claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerClaims {
    pub environment_id: String,
    pub generation: i64,
    pub expires_at: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerTokenError {
    #[error("invalid peer token: {0}")]
    Invalid(Cow<'static, str>),
    #[error("peer token expired")]
    Expired,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireClaims {
    environment_id: String,
    exp: i64,
    generation: i64,
    scope: String,
}

fn derived_key(secret: &str) -> Result<[u8; 32], PeerTokenError> {
    if secret.is_empty() {
        return Err(PeerTokenError::Invalid(Cow::Borrowed("missing secret")));
    }
    let mut key = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("hmac init")))?;
    key.update(PEER_TOKEN_KEY_LABEL);
    Ok(key.finalize().into_bytes().into())
}

/// Issues a peer token for `environment_id` at `generation`, expiring at
/// unix second `expires_at`.
pub fn issue(
    secret: &str,
    environment_id: &str,
    generation: i64,
    expires_at: i64,
) -> Result<String, PeerTokenError> {
    if environment_id.is_empty() || generation <= 0 || expires_at <= 0 {
        return Err(PeerTokenError::Invalid(Cow::Borrowed("invalid claims")));
    }
    let key = derived_key(secret)?;
    let payload = format!(
        r#"{{"environment_id":{},"exp":{},"generation":{},"scope":{}}}"#,
        serde_json::to_string(environment_id)
            .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("encode claims")))?,
        expires_at,
        generation,
        serde_json::to_string(SCOPE_PEER)
            .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("encode claims")))?,
    );
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let encoded = engine.encode(payload.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("hmac init")))?;
    mac.update(encoded.as_bytes());
    Ok(format!(
        "{encoded}.{}",
        engine.encode(mac.finalize().into_bytes())
    ))
}

/// Validates the signature, the claims and the expiry window at unix second
/// `now`: the token must not be expired (beyond the leeway) and must not
/// expire further ahead than one lifetime plus the leeway. The caller still
/// checks the generation and environment state against current records.
pub fn validate(secret: &str, token: &str, now: i64) -> Result<PeerClaims, PeerTokenError> {
    if token.is_empty() || token.len() > MAX_PEER_TOKEN_BYTES {
        return Err(PeerTokenError::Invalid(Cow::Borrowed("invalid format")));
    }
    let (payload_part, signature_part) = token
        .split_once('.')
        .filter(|(_, signature)| !signature.contains('.'))
        .ok_or(PeerTokenError::Invalid(Cow::Borrowed("invalid format")))?;
    let key = derived_key(secret)?;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature = engine
        .decode(signature_part)
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("invalid signature")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("hmac init")))?;
    mac.update(payload_part.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("invalid signature")))?;
    let payload = engine
        .decode(payload_part)
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("invalid payload")))?;
    let claims: WireClaims = serde_json::from_slice(&payload)
        .map_err(|_| PeerTokenError::Invalid(Cow::Borrowed("invalid claims")))?;
    if claims.scope != SCOPE_PEER
        || claims.environment_id.is_empty()
        || claims.generation <= 0
        || claims.exp <= 0
    {
        return Err(PeerTokenError::Invalid(Cow::Borrowed("invalid claims")));
    }
    if claims.exp + PEER_TOKEN_LEEWAY_SECS < now {
        return Err(PeerTokenError::Expired);
    }
    if claims.exp > now + PEER_TOKEN_LIFETIME_SECS + PEER_TOKEN_LEEWAY_SECS {
        return Err(PeerTokenError::Invalid(Cow::Borrowed(
            "expiry beyond one lifetime",
        )));
    }
    Ok(PeerClaims {
        environment_id: claims.environment_id,
        generation: claims.generation,
        expires_at: claims.exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "parity-secret";
    const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
    const NOW: i64 = 1_791_000_000;

    #[test]
    fn issued_token_matches_pinned_wire_vector() {
        // Independently computed with Python hmac/hashlib/base64:
        // key = HMAC-SHA256(secret, label); sig = HMAC-SHA256(key, b64(payload)).
        let token = issue(SECRET, ENVIRONMENT, 7, NOW + 600).unwrap();
        assert_eq!(token, PINNED);
    }

    const PINNED: &str = "eyJlbnZpcm9ubWVudF9pZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCIsImV4cCI6MTc5MTAwMDYwMCwiZ2VuZXJhdGlvbiI6Nywic2NvcGUiOiJwZWVyIn0.3qyz05fzVgVHv-3QJM9ssL-KmXFRcZgQtlw_ti45D2U";

    #[test]
    fn a_fresh_token_validates_with_its_claims() {
        let token = issue(SECRET, ENVIRONMENT, 7, NOW + PEER_TOKEN_LIFETIME_SECS).unwrap();
        assert_eq!(
            validate(SECRET, &token, NOW).unwrap(),
            PeerClaims {
                environment_id: ENVIRONMENT.into(),
                generation: 7,
                expires_at: NOW + PEER_TOKEN_LIFETIME_SECS,
            }
        );
    }

    #[test]
    fn expiry_window_is_enforced_with_leeway() {
        let token = issue(SECRET, ENVIRONMENT, 7, NOW).unwrap();
        assert!(validate(SECRET, &token, NOW + PEER_TOKEN_LEEWAY_SECS).is_ok());
        assert_eq!(
            validate(SECRET, &token, NOW + PEER_TOKEN_LEEWAY_SECS + 1),
            Err(PeerTokenError::Expired)
        );
        // A token minted to outlive one lifetime is refused outright.
        let far = issue(
            SECRET,
            ENVIRONMENT,
            7,
            NOW + PEER_TOKEN_LIFETIME_SECS + PEER_TOKEN_LEEWAY_SECS + 1,
        )
        .unwrap();
        assert!(matches!(
            validate(SECRET, &far, NOW),
            Err(PeerTokenError::Invalid(_))
        ));
    }

    #[test]
    fn other_keys_scopes_and_tampering_are_refused() {
        let token = issue(SECRET, ENVIRONMENT, 7, NOW + 300).unwrap();
        assert!(validate("other-secret", &token, NOW).is_err());
        // The raw session secret (the legacy coordinate format) never verifies.
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let (payload, _) = token.split_once('.').unwrap();
        let mut raw = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        raw.update(payload.as_bytes());
        let raw_signed = format!(
            "{payload}.{}",
            engine.encode(raw.finalize().into_bytes())
        );
        assert!(validate(SECRET, &raw_signed, NOW).is_err());
        // A legacy coordinate token (no exp, no generation) is refused.
        let legacy = "eyJlbnZpcm9ubWVudF9pZCI6ImVudi1wYXJpdHktMSIsInNjb3BlIjoiY29vcmRpbmF0ZSJ9.vSHW3CqDqOLFEMxllVJokbJ8xK519tNE8VOddemyXBA";
        assert!(validate("parity-secret", legacy, NOW).is_err());
        // Tampered payloads fail the MAC.
        let forged_payload = engine.encode(
            br#"{"environment_id":"550e8400-e29b-41d4-a716-446655440000","exp":1791000300,"generation":8,"scope":"peer"}"#,
        );
        let (_, signature) = token.split_once('.').unwrap();
        assert!(validate(SECRET, &format!("{forged_payload}.{signature}"), NOW).is_err());
        assert!(validate(SECRET, "not-a-token", NOW).is_err());
        assert!(validate(SECRET, &"a".repeat(600), NOW).is_err());
    }

    #[test]
    fn invalid_claims_are_never_issued() {
        assert!(issue(SECRET, "", 7, NOW).is_err());
        assert!(issue(SECRET, ENVIRONMENT, 0, NOW).is_err());
        assert!(issue(SECRET, ENVIRONMENT, 7, 0).is_err());
        assert!(issue("", ENVIRONMENT, 7, NOW).is_err());
    }
}
