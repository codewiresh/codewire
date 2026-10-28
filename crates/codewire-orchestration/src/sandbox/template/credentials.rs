//! Selected material-free stock-client configuration and purpose-specific mounts.
//!
//! Codex needs no Pod object: the workspace daemon writes its `config.toml`
//! into the user's `~/.codex` on the persistent home before it listens
//! (`codewire_daemon::codex_home`).

use codewire_access::CODEX_PLATFORM_TOKEN_FILE;
use codewire_daemon_proto::CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE;
use serde_json::{Value, json};

use super::TemplateOpts;

pub use codewire_access::MANAGED_CREDENTIAL_CLIENTS_ENV;

const INPUTS: [&str; 1] = ["SANDBOX_CREDENTIAL_BROKER_NAMESPACE"];

/// The administrator-selected namespace of the credential broker. There is no
/// private key, bearer or provider URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRuntimeTemplateConfig {
    sandbox_namespace: String,
    broker_namespace: String,
}

impl CredentialRuntimeTemplateConfig {
    pub fn from_env(sandbox_namespace: &str) -> anyhow::Result<Option<Self>> {
        Self::from_lookup(sandbox_namespace, |name| std::env::var_os(name))
    }

    fn from_lookup(
        sandbox_namespace: &str,
        lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> anyhow::Result<Option<Self>> {
        let values = INPUTS.map(lookup);
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        let names = values
            .into_iter()
            .map(|value| {
                value
                    .and_then(|value| value.into_string().ok())
                    .filter(|value| dns_label(value))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "invalid or incomplete platform credential runtime configuration"
                        )
                    })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        anyhow::ensure!(
            dns_label(sandbox_namespace),
            "invalid credential sandbox namespace"
        );
        Ok(Some(Self {
            sandbox_namespace: sandbox_namespace.to_owned(),
            broker_namespace: names[0].clone(),
        }))
    }

    pub fn broker_namespace(&self) -> &str {
        &self.broker_namespace
    }

    /// The broker's private TLS origin, which the credential relay dials.
    pub fn broker_https_origin(&self) -> String {
        format!(
            "https://codewire-credential-service.{}.svc.cluster.local:9443",
            self.broker_namespace
        )
    }

    #[cfg(test)]
    pub(crate) fn synthetic(namespace: &str) -> Self {
        Self::from_lookup(namespace, |name| {
            INPUTS
                .iter()
                .position(|input| *input == name)
                .map(|index| format!("synthetic-trust-{index}").into())
        })
        .unwrap()
        .unwrap()
    }

    pub(crate) fn assert_namespace(&self, namespace: &str) {
        assert_eq!(
            self.sandbox_namespace, namespace,
            "credential runtime namespace must match its owning template"
        );
    }
}

fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn projected_token(name: &str, audience: &str) -> Value {
    json!({"name":name,"projected":{"defaultMode":0o440,"sources":[{"serviceAccountToken":{
        "audience":audience,"expirationSeconds":600,"path":"token"}}]}})
}

pub(super) fn workspace_volumes(opts: &TemplateOpts) -> Vec<Value> {
    assert!(
        opts.credential_runtime.is_some(),
        "credential runtime enabled"
    );
    vec![projected_token(
        "credential-workspace-identity",
        CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
    )]
}

pub(super) fn workspace_mounts() -> Vec<Value> {
    vec![
        json!({"name":"credential-workspace-identity","mountPath":CODEX_PLATFORM_TOKEN_FILE.rsplit_once('/').unwrap().0,"readOnly":true}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_configuration_is_absent_or_complete_and_canonical() {
        assert!(
            CredentialRuntimeTemplateConfig::from_lookup("test-sandboxes", |_| None)
                .unwrap()
                .is_none()
        );
        let configured = |key: &str| {
            INPUTS
                .iter()
                .position(|input| *input == key)
                .map(|index| format!("synthetic-trust-{index}").into())
        };
        assert!(
            CredentialRuntimeTemplateConfig::from_lookup("test-sandboxes", configured)
                .unwrap()
                .is_some()
        );
        for invalid in [
            "",
            "../trust",
            "https://trust",
            "Trust",
            "trust.svc",
            "private-canary\n",
        ] {
            let error = CredentialRuntimeTemplateConfig::from_lookup("test-sandboxes", |_| {
                Some(invalid.into())
            })
            .unwrap_err();
            assert!(!error.to_string().contains("private-canary"));
        }
    }
}
