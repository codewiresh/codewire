//! Token minting — opaque access/refresh tokens and EdDSA-signed
//! `id_token`s.
//!
//! Access and refresh tokens are **opaque**: 256 bits of CSPRNG output,
//! base64url-encoded. They carry no structure; their meaning lives in the
//! [`crate::store::TokenStore`]. Only the `id_token` is a JWT, signed with
//! **EdDSA (Ed25519)** so RPs can verify it against the JWKS.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{OAuthError, StoreError};
use crate::jwks::SigningKey;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Mint a fresh opaque token: 32 CSPRNG bytes, base64url (no padding) → 43
/// chars. Used for both access and refresh tokens (and authorization
/// codes).
pub fn mint_opaque_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

/// The `at_hash` claim (OIDC Core §3.1.3.6): base64url of the left-most half
/// of the SHA-256 of the ASCII access-token, binding the id_token to the
/// access token it was issued with.
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    B64.encode(&digest[..16])
}

/// The registered + custom claims of an `id_token`, ready to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// `iss` — the issuer identifier.
    pub iss: String,
    /// `sub` — the subject identifier.
    pub sub: String,
    /// `aud` — the audience. Always serialized as a JSON array (matching the
    /// reference Go provider), even for a single audience.
    pub aud: Vec<String>,
    /// `azp` — the authorized party (the client the token was issued to). The
    /// reference provider always sets this equal to the sole audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// `exp` — expiry (seconds since epoch).
    pub exp: i64,
    /// `iat` — issued-at (seconds since epoch).
    pub iat: i64,
    /// `nonce` — echoed from the authorization request, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// `auth_time` — when the end-user authenticated, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// `at_hash` — access-token hash, if issued alongside an access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// All other claims (standard profile/email + deployment extras),
    /// flattened into the top-level object.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The JOSE header for an EdDSA-signed id_token.
#[derive(Debug, Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Sign an [`IdTokenClaims`] set into a compact-serialization JWT using the
/// provider's active Ed25519 key.
///
/// The header pins `alg=EdDSA` and carries the key's `kid` so RPs select the
/// right JWKS entry.
pub fn sign_id_token(key: &SigningKey, claims: &IdTokenClaims) -> Result<String, OAuthError> {
    let header = JwtHeader {
        alg: "EdDSA",
        typ: "JWT",
        kid: &key.kid,
    };
    let header_b64 = B64
        .encode(serde_json::to_vec(&header).map_err(|e| OAuthError::server_error(e.to_string()))?);
    let claims_b64 = B64
        .encode(serde_json::to_vec(claims).map_err(|e| OAuthError::server_error(e.to_string()))?);
    let signing_input = format!("{header_b64}.{claims_b64}");

    let seed: [u8; 32] = key
        .secret_key
        .as_slice()
        .try_into()
        .map_err(|_| OAuthError::server_error("signing key must be a 32-byte Ed25519 seed"))?;
    let signer = Ed25519SigningKey::from_bytes(&seed);
    let signature = signer.sign(signing_input.as_bytes());
    let sig_b64 = B64.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify an `id_token` this provider issued and return its claims.
///
/// Used to read an `id_token_hint` at the end-session endpoint. The EdDSA
/// signature is checked against the published key whose `kid` matches the
/// JWT header (or, if the header carries no `kid`, against every published
/// key). Expiry is **not** enforced — a logout hint is routinely expired.
///
/// On any structural or signature failure this returns `invalid_request`;
/// it never reflects internal detail.
pub fn verify_id_token(
    jwt: &str,
    keys: &[crate::jwks::PublicJwk],
) -> Result<IdTokenClaims, OAuthError> {
    use ed25519_dalek::{Verifier, VerifyingKey};

    let bad = || OAuthError::invalid_request("invalid id_token_hint");
    let mut parts = jwt.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(bad()),
    };

    // Header → optional kid (we only sign EdDSA, so alg is implied).
    let header: serde_json::Value =
        serde_json::from_slice(&B64.decode(h).map_err(|_| bad())?).map_err(|_| bad())?;
    let kid = header.get("kid").and_then(|v| v.as_str());

    let sig_bytes: [u8; 64] = B64
        .decode(s)
        .map_err(|_| bad())?
        .as_slice()
        .try_into()
        .map_err(|_| bad())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let signing_input = format!("{h}.{p}");

    // Try the kid-matching key first, otherwise any published key.
    let candidates = keys.iter().filter(|k| kid.is_none_or(|want| k.kid == want));
    let mut verified = false;
    for key in candidates {
        let pk: [u8; 32] = match key.public_key.as_slice().try_into() {
            Ok(pk) => pk,
            Err(_) => continue,
        };
        if let Ok(vk) = VerifyingKey::from_bytes(&pk)
            && vk.verify(signing_input.as_bytes(), &signature).is_ok()
        {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(bad());
    }

    serde_json::from_slice(&B64.decode(p).map_err(|_| bad())?).map_err(|_| bad())
}

impl From<StoreError> for OAuthError {
    fn from(e: StoreError) -> Self {
        // Store failures never leak detail to the client.
        let _ = e;
        OAuthError::server_error("internal error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn test_key() -> SigningKey {
        let signer = Ed25519SigningKey::from_bytes(&[7u8; 32]);
        SigningKey {
            kid: "codewire-1".into(),
            secret_key: signer.to_bytes().to_vec(),
            public_key: signer.verifying_key().to_bytes().to_vec(),
        }
    }

    #[test]
    fn opaque_tokens_are_unique_and_url_safe() {
        let a = mint_opaque_token();
        let b = mint_opaque_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // 32 bytes, base64url no pad
        assert!(!a.contains('=') && !a.contains('+') && !a.contains('/'));
    }

    #[test]
    fn id_token_verifies_against_public_key() {
        let key = test_key();
        let claims = IdTokenClaims {
            iss: "https://idp.example".into(),
            sub: "user_1".into(),
            aud: vec!["client_1".into()],
            azp: Some("client_1".into()),
            exp: 2_000_000_000,
            iat: 1_999_996_400,
            nonce: Some("n-0S6_WzA2Mj".into()),
            auth_time: None,
            at_hash: Some(at_hash("an-access-token")),
            extra: Default::default(),
        };
        let jwt = sign_id_token(&key, &claims).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Header pins EdDSA + kid.
        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "codewire-1");

        // Signature verifies against the published public key.
        let pk: [u8; 32] = key.public_key.as_slice().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes: [u8; 64] = B64.decode(parts[2]).unwrap().as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());

        // Claims round-trip.
        let body: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(body["iss"], "https://idp.example");
        assert_eq!(body["sub"], "user_1");
        assert_eq!(body["aud"], serde_json::json!(["client_1"])); // always an array
        assert_eq!(body["azp"], "client_1");
        assert_eq!(body["nonce"], "n-0S6_WzA2Mj");
        assert!(body.get("auth_time").is_none()); // skipped when None
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = test_key();
        let claims = IdTokenClaims {
            iss: "https://idp.example".into(),
            sub: "user_1".into(),
            aud: vec!["client_1".into()],
            azp: Some("client_1".into()),
            exp: 2_000_000_000,
            iat: 1_999_996_400,
            nonce: None,
            auth_time: None,
            at_hash: None,
            extra: Default::default(),
        };
        let jwt = sign_id_token(&key, &claims).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        // Swap in a forged payload, keep the original signature.
        let forged = IdTokenClaims {
            sub: "attacker".into(),
            ..claims
        };
        let forged_b64 = B64.encode(serde_json::to_vec(&forged).unwrap());
        let pk: [u8; 32] = key.public_key.as_slice().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let signing_input = format!("{}.{}", parts[0], forged_b64);
        let sig_bytes: [u8; 64] = B64.decode(parts[2]).unwrap().as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_err());
    }
}
