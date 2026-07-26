use std::borrow::Cow;

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid sidecar token: {0}")]
    Invalid(Cow<'static, str>),
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub environment_id: String,
    pub scope: String,
}

pub fn validate(secret: &str, token: &str) -> Result<Claims, Error> {
    if secret.is_empty() {
        return Err(Error::Invalid(Cow::Borrowed("missing secret")));
    }

    let mut parts = token.split('.');
    let Some(payload_part) = parts.next() else {
        return Err(Error::Invalid(Cow::Borrowed("invalid format")));
    };
    let Some(signature_part) = parts.next() else {
        return Err(Error::Invalid(Cow::Borrowed("invalid format")));
    };
    if parts.next().is_some() {
        return Err(Error::Invalid(Cow::Borrowed("invalid format")));
    }

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature = engine
        .decode(signature_part)
        .map_err(|err| Error::Invalid(Cow::Owned(format!("decode signature: {err}"))))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|err| Error::Invalid(Cow::Owned(format!("hmac init: {err}"))))?;
    mac.update(payload_part.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| Error::Invalid(Cow::Borrowed("invalid signature")))?;

    let payload = engine
        .decode(payload_part)
        .map_err(|err| Error::Invalid(Cow::Owned(format!("decode payload: {err}"))))?;
    let claims: Claims = serde_json::from_slice(&payload)
        .map_err(|err| Error::Invalid(Cow::Owned(format!("decode claims: {err}"))))?;
    if claims.environment_id.is_empty() || claims.scope.is_empty() {
        return Err(Error::Invalid(Cow::Borrowed("invalid claims")));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_go_generated_fixture() {
        // Generated with Go gatewayauth.IssueToken("parity-secret",
        // "env-parity-1", ScopeCoordinate).
        let claims = validate(
            "parity-secret",
            "eyJlbnZpcm9ubWVudF9pZCI6ImVudi1wYXJpdHktMSIsInNjb3BlIjoiY29vcmRpbmF0ZSJ9.vSHW3CqDqOLFEMxllVJokbJ8xK519tNE8VOddemyXBA",
        )
        .unwrap();
        assert_eq!(
            claims,
            Claims {
                environment_id: "env-parity-1".into(),
                scope: "coordinate".into(),
            }
        );
    }

    #[test]
    fn rejects_garbage_and_tampering() {
        assert!(validate("secret", "not-a-real-token").is_err());
        assert!(
            validate(
                "wrong-secret",
                "eyJlbnZpcm9ubWVudF9pZCI6ImVudi1wYXJpdHktMSIsInNjb3BlIjoiY29vcmRpbmF0ZSJ9.vSHW3CqDqOLFEMxllVJokbJ8xK519tNE8VOddemyXBA"
            )
            .is_err()
        );
    }
}
