//! Hosted environment capability issuance. The token format is
//! `base64url(claims).base64url(hmac)`
//! with HMAC-SHA256 over the encoded payload. The scope domain-separates
//! coordinator access from private daemon authentication.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const SCOPE_COORDINATE: &str = "coordinate";
pub const SCOPE_DAEMON: &str = "daemon";

/// Distinct capabilities rendered into one hosted environment. These fields
/// intentionally do not implement `Debug`: both values are bearer material.
pub struct EnvironmentAuthTokens {
    pub coordinate: String,
    pub daemon: String,
}

/// Issues the canonical token with stable claim-field order. The unit test
/// pins an independently accepted wire vector.
pub fn issue_token(secret: &str, environment_id: &str, scope: &str) -> anyhow::Result<String> {
    if secret.is_empty() {
        anyhow::bail!("environment capability secret is required");
    }
    if environment_id.is_empty() {
        anyhow::bail!("environment capability environment id is required");
    }
    if scope.is_empty() {
        anyhow::bail!("environment capability scope is required");
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

/// Issues the two domain-separated capabilities needed by a hosted runtime.
pub fn issue_environment_tokens(
    secret: &str,
    environment_id: &str,
) -> anyhow::Result<EnvironmentAuthTokens> {
    let coordinate = issue_token(secret, environment_id, SCOPE_COORDINATE)?;
    let daemon = issue_token(secret, environment_id, SCOPE_DAEMON)?;
    anyhow::ensure!(
        coordinate != daemon,
        "coordinate and daemon capabilities must be distinct"
    );
    Ok(EnvironmentAuthTokens { coordinate, daemon })
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

    #[test]
    fn hosted_environment_tokens_are_domain_separated() {
        let tokens = issue_environment_tokens("synthetic-secret", "env-synthetic").unwrap();

        assert_ne!(tokens.coordinate, tokens.daemon);
        assert_eq!(
            tokens.coordinate,
            issue_token("synthetic-secret", "env-synthetic", SCOPE_COORDINATE).unwrap()
        );
        assert_eq!(
            tokens.daemon,
            issue_token("synthetic-secret", "env-synthetic", SCOPE_DAEMON).unwrap()
        );
    }
}
