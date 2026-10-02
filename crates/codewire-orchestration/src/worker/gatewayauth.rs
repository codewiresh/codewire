//! Hosted environment capability issuance. The token format is
//! `base64url(claims).base64url(hmac)`
//! with HMAC-SHA256 over the encoded payload. The scope domain-separates
//! coordinator access from private daemon authentication.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const SCOPE_COORDINATE: &str = "coordinate";
pub const SCOPE_DAEMON: &str = "daemon";
/// Scope of the per-Pod daemon credential. It is never accepted by the
/// coordinator, which accepts only [`SCOPE_COORDINATE`].
pub const SCOPE_WORKSPACE_DAEMON: &str = "workspace-daemon";
/// Derivation label for the per-purpose key that signs workspace daemon
/// credentials. The session secret also keys unrelated purposes, so it never
/// signs these credentials directly.
const WORKSPACE_DAEMON_CREDENTIAL_KEY_LABEL: &[u8] = b"codewire/workspace-daemon-credential/v1";

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

/// How a recorded workspace binding authenticates its daemon. `Pod` is the
/// claim-time binding; `Environment` keeps a pre-binding Pod on the
/// environment-wide daemon token it was rendered with until it restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceCredentialScope {
    Environment,
    Pod,
}

impl WorkspaceCredentialScope {
    /// The database spelling of `sandbox_workspace_bindings.credential_scope`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Pod => "pod",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "environment" => Some(Self::Environment),
            "pod" => Some(Self::Pod),
            _ => None,
        }
    }
}

/// Issues the daemon credential bound to one environment and one Pod UID:
/// `base64url(payload) "." base64url(HMAC-SHA256(key, base64url(payload)))`
/// with `key = HMAC-SHA256(session_secret, label)`. It carries no operation
/// generation, so relabelling a running Pod keeps its credential; any replica
/// can derive it and the database never stores it.
pub fn issue_workspace_daemon_credential(
    secret: &str,
    environment_id: &str,
    pod_uid: &str,
) -> anyhow::Result<String> {
    if secret.is_empty() {
        anyhow::bail!("workspace daemon credential secret is required");
    }
    if environment_id.is_empty() {
        anyhow::bail!("workspace daemon credential environment id is required");
    }
    if pod_uid.is_empty() {
        anyhow::bail!("workspace daemon credential Pod UID is required");
    }

    let mut key = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    key.update(WORKSPACE_DAEMON_CREDENTIAL_KEY_LABEL);
    let key = key.finalize().into_bytes();

    let payload = format!(
        r#"{{"environment_id":{},"pod_uid":{},"scope":{}}}"#,
        serde_json::to_string(environment_id)?,
        serde_json::to_string(pod_uid)?,
        serde_json::to_string(SCOPE_WORKSPACE_DAEMON)?,
    );
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let encoded_payload = engine.encode(payload.as_bytes());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
    mac.update(encoded_payload.as_bytes());
    let signature = engine.encode(mac.finalize().into_bytes());
    Ok(format!("{encoded_payload}.{signature}"))
}

/// The one daemon credential for a recorded binding. Callers pass the live
/// binding's environment, Pod UID and scope; none computes it from a name.
pub fn daemon_credential_for(
    secret: &str,
    environment_id: &str,
    pod_uid: &str,
    scope: WorkspaceCredentialScope,
) -> anyhow::Result<String> {
    match scope {
        WorkspaceCredentialScope::Pod => {
            issue_workspace_daemon_credential(secret, environment_id, pod_uid)
        }
        WorkspaceCredentialScope::Environment => issue_token(secret, environment_id, SCOPE_DAEMON),
    }
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
    fn workspace_daemon_credential_matches_pinned_wire_vector() {
        // Independently computed with Python's hmac/hashlib/base64 from the
        // design's derivation: key = HMAC-SHA256(secret, label), then
        // HMAC-SHA256(key, base64url(payload)). It pins the derived key too.
        let got = issue_workspace_daemon_credential(
            "parity-secret",
            "550e8400-e29b-41d4-a716-446655440000",
            "7e7b20f6-0bd2-4f11-8b16-9c239851eb52",
        )
        .unwrap();
        assert_eq!(
            got,
            "eyJlbnZpcm9ubWVudF9pZCI6IjU1MGU4NDAwLWUyOWItNDFkNC1hNzE2LTQ0NjY1NTQ0MDAwMCIsInBvZF91aWQiOiI3ZTdiMjBmNi0wYmQyLTRmMTEtOGIxNi05YzIzOTg1MWViNTIiLCJzY29wZSI6IndvcmtzcGFjZS1kYWVtb24ifQ.jRZNY1G2AooDBD2mt7jRaMB0xzy1Rn5dYn0cga-3-Rc"
        );
    }

    /// Synthetic identifiers, named so no literal sits beside a secret
    /// argument where the source scanner reads it as a key.
    const OTHER_ENVIRONMENT: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const OTHER_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";

    #[test]
    fn workspace_daemon_credential_is_bound_to_environment_and_pod() {
        let secret = "synthetic-secret";
        let environment = "550e8400-e29b-41d4-a716-446655440000";
        let pod = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
        let credential = issue_workspace_daemon_credential(secret, environment, pod).unwrap();
        assert_eq!(
            credential,
            issue_workspace_daemon_credential(secret, environment, pod).unwrap()
        );
        for other in [
            issue_workspace_daemon_credential(secret, environment, OTHER_POD).unwrap(),
            issue_workspace_daemon_credential(secret, OTHER_ENVIRONMENT, pod).unwrap(),
            issue_workspace_daemon_credential("other-secret", environment, pod).unwrap(),
            issue_token(secret, environment, SCOPE_DAEMON).unwrap(),
            issue_token(secret, environment, SCOPE_COORDINATE).unwrap(),
        ] {
            assert_ne!(credential, other);
        }
        // The session secret never signs the credential directly: a plain
        // HMAC over the same payload under the session secret differs.
        let (payload, signature) = credential.split_once('.').unwrap();
        let mut direct = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        direct.update(payload.as_bytes());
        let direct =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(direct.finalize().into_bytes());
        assert_ne!(signature, direct);
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            claims,
            serde_json::json!({
                "environment_id": environment,
                "pod_uid": pod,
                "scope": SCOPE_WORKSPACE_DAEMON,
            })
        );
        assert!(codewire_gateway_proto::DaemonAuthToken::new(credential).is_ok());
    }

    #[test]
    fn workspace_daemon_credential_rejects_empty_inputs() {
        assert!(issue_workspace_daemon_credential("", "env", "pod").is_err());
        assert!(issue_workspace_daemon_credential("s", "", "pod").is_err());
        assert!(issue_workspace_daemon_credential("s", "env", "").is_err());
    }

    #[test]
    fn daemon_credential_follows_the_recorded_binding_scope() {
        let secret = "synthetic-secret";
        let environment = "550e8400-e29b-41d4-a716-446655440000";
        let pod = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
        assert_eq!(
            daemon_credential_for(secret, environment, pod, WorkspaceCredentialScope::Pod).unwrap(),
            issue_workspace_daemon_credential(secret, environment, pod).unwrap()
        );
        // A pre-binding Pod keeps the environment-wide token it was rendered
        // with, independent of its Pod UID.
        assert_eq!(
            daemon_credential_for(
                secret,
                environment,
                pod,
                WorkspaceCredentialScope::Environment
            )
            .unwrap(),
            issue_token(secret, environment, SCOPE_DAEMON).unwrap()
        );
        for scope in [
            WorkspaceCredentialScope::Environment,
            WorkspaceCredentialScope::Pod,
        ] {
            assert_eq!(WorkspaceCredentialScope::parse(scope.as_str()), Some(scope));
        }
        for unknown in ["", "POD", "daemon", "environment "] {
            assert_eq!(WorkspaceCredentialScope::parse(unknown), None);
        }
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
