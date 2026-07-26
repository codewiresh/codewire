//! PKCE — Proof Key for Code Exchange (RFC 7636).
//!
//! This provider supports the **S256** method only (`plain` is rejected —
//! see threat T2). The authorization request carries a `code_challenge`
//! that is stored with the issued code; the token request carries the
//! `code_verifier`, and the challenge is recomputed and compared in
//! constant time.

use base64::Engine;
use sha2::{Digest, Sha256};

/// The PKCE method. Only `S256` is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    /// SHA-256 of the verifier, base64url-encoded (RFC 7636 §4.2).
    S256,
}

impl CodeChallengeMethod {
    /// Parse a `code_challenge_method` parameter. `None`/absent defaults to
    /// `plain` per the RFC — which this provider does **not** support — so a
    /// missing method is rejected by returning `None` here.
    pub fn parse(s: Option<&str>) -> Option<Self> {
        match s {
            Some("S256") => Some(Self::S256),
            _ => None,
        }
    }
}

/// Compute the S256 challenge for a verifier: `base64url(sha256(verifier))`,
/// no padding.
pub fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify a `code_verifier` against a stored `code_challenge` using S256, in
/// constant time over the encoded challenge.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    let computed = s256_challenge(verifier);
    constant_time_eq(computed.as_bytes(), challenge.as_bytes())
}

/// Length-independent constant-time byte comparison. Returns `false` fast on
/// a length mismatch (length is not secret), then folds all bytes so equal
/// lengths take the same time regardless of where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_vector() {
        // The canonical RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), challenge);
        assert!(verify_s256(verifier, challenge));
    }

    #[test]
    fn wrong_verifier_rejected() {
        let challenge = s256_challenge("the-real-verifier");
        assert!(!verify_s256("a-different-verifier", &challenge));
    }

    #[test]
    fn plain_method_not_accepted() {
        assert_eq!(CodeChallengeMethod::parse(Some("plain")), None);
        assert_eq!(CodeChallengeMethod::parse(None), None);
        assert_eq!(
            CodeChallengeMethod::parse(Some("S256")),
            Some(CodeChallengeMethod::S256)
        );
    }

    #[test]
    fn challenge_has_no_padding() {
        assert!(!s256_challenge("anything").contains('='));
    }
}
