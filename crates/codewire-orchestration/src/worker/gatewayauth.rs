//! Gateway sidecar token issuance. The token format is
//! `base64url(claims).base64url(hmac)`
//! with HMAC-SHA256 over the encoded payload; the sidecar validates it
//! with the same shared session secret.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const SCOPE_COORDINATE: &str = "coordinate";

/// Issues the canonical token with stable claim-field order. The unit test
/// pins an independently accepted wire vector.
pub fn issue_token(secret: &str, environment_id: &str, scope: &str) -> anyhow::Result<String> {
    if secret.is_empty() {
        anyhow::bail!("sidecar token secret is required");
    }
    if environment_id.is_empty() {
        anyhow::bail!("sidecar environment id is required");
    }
    if scope.is_empty() {
        anyhow::bail!("sidecar token scope is required");
    }

    let payload = format!(
        r#"{{"environment_id":{},"scope":{}}}"#,
        serde_json::to_string(environment_id)?,
        serde_json::to_string(scope)?,
    );
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let encoded_payload = engine.encode(payload.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    mac.update(encoded_payload.as_bytes());
    let signature = engine.encode(mac.finalize().into_bytes());
    Ok(format!("{encoded_payload}.{signature}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_matches_accepted_wire_fixture() {
        let got = issue_token("parity-secret", "env-parity-1", SCOPE_COORDINATE).unwrap();
        assert_eq!(
            got,
            "eyJlbnZpcm9ubWVudF9pZCI6ImVudi1wYXJpdHktMSIsInNjb3BlIjoiY29vcmRpbmF0ZSJ9.vSHW3CqDqOLFEMxllVJokbJ8xK519tNE8VOddemyXBA"
        );
    }

    #[test]
    fn empty_inputs_rejected() {
        assert!(issue_token("", "env", "scope").is_err());
        assert!(issue_token("s", "", "scope").is_err());
        assert!(issue_token("s", "env", "").is_err());
    }
}
