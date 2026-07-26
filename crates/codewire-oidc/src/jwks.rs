//! JSON Web Key Set — the public half of the signing keys, served at the
//! JWKS endpoint and used by RPs to verify id_tokens.
//!
//! This provider signs id_tokens with **EdDSA (Ed25519)**, so keys are
//! OKP-type. Access tokens are opaque (not JWTs), so the JWKS is only
//! about id_token verification.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// A single public JWK (Ed25519 / OKP). Field order matches the common
/// `kty,crv,x,use,alg,kid` shape; JSON object key order is not
/// significant to consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type — always `OKP` for Ed25519.
    pub kty: String,
    /// Curve — always `Ed25519`.
    pub crv: String,
    /// Base64url (no padding) of the 32-byte public key.
    pub x: String,
    /// Public key use — `sig`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm — `EdDSA`.
    pub alg: String,
    /// Key id (matches the id_token header `kid`).
    pub kid: String,
}

impl Jwk {
    /// Build an Ed25519 public JWK from the raw 32-byte public key.
    pub fn ed25519(kid: impl Into<String>, public_key: &[u8]) -> Self {
        Self {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
            use_: "sig".into(),
            alg: "EdDSA".into(),
            kid: kid.into(),
        }
    }
}

/// A JWK Set — the document served at the JWKS endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// The published keys (active signer first, then still-valid retired
    /// keys, so id_tokens signed before a rotation still verify).
    pub keys: Vec<Jwk>,
}

/// A public signing key as the [`crate::store::KeyStore`] hands it to the
/// provider for JWKS publication.
#[derive(Debug, Clone)]
pub struct PublicJwk {
    /// Key id.
    pub kid: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

impl PublicJwk {
    /// Convert to the serialized [`Jwk`].
    pub fn to_jwk(&self) -> Jwk {
        Jwk::ed25519(self.kid.clone(), &self.public_key)
    }
}

/// The active signing key the provider uses to mint id_tokens. The private
/// material stays opaque here; the actual signing lands with the token
/// endpoint slice (#40).
#[derive(Clone)]
pub struct SigningKey {
    /// Key id, written into the id_token header `kid`.
    pub kid: String,
    /// Raw 32-byte Ed25519 secret seed.
    pub secret_key: Vec<u8>,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_jwk_shape() {
        // 32 zero bytes → base64url "AAAA…" (43 chars, no padding).
        let jwk = Jwk::ed25519("codewire-1", &[0u8; 32]);
        let v = serde_json::to_value(&jwk).unwrap();
        assert_eq!(v["kty"], "OKP");
        assert_eq!(v["crv"], "Ed25519");
        assert_eq!(v["use"], "sig");
        assert_eq!(v["alg"], "EdDSA");
        assert_eq!(v["kid"], "codewire-1");
        assert_eq!(v["x"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        // x has no padding.
        assert!(!v["x"].as_str().unwrap().contains('='));
    }

    #[test]
    fn jwks_wraps_keys() {
        let jwks = Jwks {
            keys: vec![
                PublicJwk {
                    kid: "k1".into(),
                    public_key: vec![1u8; 32],
                }
                .to_jwk(),
            ],
        };
        let v = serde_json::to_value(&jwks).unwrap();
        assert_eq!(v["keys"][0]["kid"], "k1");
        assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    }
}
