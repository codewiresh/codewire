//! Codec between the `jwks` table's public JOSE metadata and the raw Ed25519
//! public bytes the [`codewire_oidc`] library wants.
//!
//! Existing public rows retain the Go provider's `jose.JSONWebKey` shape with
//! `kty=OKP`, `crv=Ed25519`. Signing seeds are handled only by the authenticated
//! envelope codec and never serialized as private JWKs.

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A JOSE JWK as serialized by go-jose (the fields we care about).
#[derive(Debug, Serialize, Deserialize)]
struct JosePublicJwk {
    kty: String,
    crv: String,
    /// Public key (base64url, 32 bytes).
    x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
}

fn decode_32(label: &str, s: &str) -> Result<Vec<u8>> {
    let bytes = B64.decode(s).with_context(|| format!("decode {label}"))?;
    if bytes.len() != 32 {
        bail!("{label} must be 32 bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

/// Parse a stored public JWK JSON into a [`PublicJwk`] (for JWKS publication).
pub fn parse_public_key(kid: &str, public_json: &str) -> Result<codewire_oidc::PublicJwk> {
    let jwk: JosePublicJwk = serde_json::from_str(public_json).context("parse public JWK json")?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
        bail!(
            "unsupported key: kty={} crv={} (want OKP/Ed25519)",
            jwk.kty,
            jwk.crv
        );
    }
    Ok(codewire_oidc::PublicJwk {
        kid: kid.to_string(),
        public_key: decode_32("x", &jwk.x)?,
    })
}

/// Encode a freshly generated public key for the `jwks` registry, retaining
/// the published Go/go-jose shape without serializing private material.
pub fn encode_public_key(kid: &str, public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        bail!("public key must be 32 bytes, got {}", public_key.len());
    }
    let public = JosePublicJwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: B64.encode(public_key),
        kid: Some(kid.into()),
        alg: Some("EdDSA".into()),
        use_: Some("sig".into()),
    };
    Ok(serde_json::to_string(&public)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;

    #[test]
    fn roundtrip_generate_encode_parse_public() {
        let signer = Ed25519SigningKey::from_bytes(&[3u8; 32]);
        let public = signer.verifying_key().to_bytes().to_vec();

        let pub_json = encode_public_key("codewire-123", &public).unwrap();
        let pv: serde_json::Value = serde_json::from_str(&pub_json).unwrap();
        assert_eq!(pv["kty"], "OKP");
        assert_eq!(pv["crv"], "Ed25519");
        assert_eq!(pv["use"], "sig");
        assert!(pv.get("d").is_none());

        let key = parse_public_key("codewire-123", &pub_json).unwrap();
        assert_eq!(key.kid, "codewire-123");
        assert_eq!(key.public_key, public);
    }

    #[test]
    fn parses_go_jose_style_public_jwk() {
        let signer = Ed25519SigningKey::from_bytes(&[9u8; 32]);
        let x = B64.encode(signer.verifying_key().to_bytes());
        let json = format!(
            r#"{{"use":"sig","kty":"OKP","kid":"codewire-1700000000","crv":"Ed25519","alg":"EdDSA","x":"{x}"}}"#
        );
        let key = parse_public_key("codewire-1700000000", &json).unwrap();
        assert_eq!(key.public_key, signer.verifying_key().to_bytes());
    }

    #[test]
    fn rejects_non_ed25519() {
        let json = r#"{"kty":"RSA","crv":"","x":"AAAA"}"#;
        assert!(parse_public_key("k", json).is_err());
    }
}
