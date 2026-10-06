//! Selected material-free stock-client configuration and purpose-specific mounts.
//!
//! Codex needs no Pod object: the workspace daemon writes its `config.toml`
//! into the user's `~/.codex` on the persistent home before it listens, in
//! both identity modes (`codewire_daemon::codex_home`).

use codewire_access::{CODEX_PLATFORM_TOKEN_FILE, ManagedCredentialClientPlacement};
use codewire_gateway_proto::{
    CREDENTIAL_GATEWAY_TOKEN_AUDIENCE, CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
};
use serde_json::{Value, json};

use super::TemplateOpts;

const GATEWAY_TOKEN_DIRECTORY: &str = "/run/codewire-credentials/gateway";
const BROKER_ROOTS_DIRECTORY: &str = "/run/codewire-credentials/broker-roots";
const PROJECTION_SHA256_ENV: &str = "CODEWIRE_ENVIRONMENT_PROJECTION_SHA256";
pub use codewire_access::MANAGED_CREDENTIAL_CLIENTS_ENV;

pub(super) fn projection_environment(opts: &TemplateOpts) -> Option<Value> {
    let digest = opts.projection_selection_sha256?;
    assert!(
        opts.credential_runtime.is_some(),
        "selected sources require credential runtime trust"
    );
    assert_ne!(
        digest, [0; 32],
        "selected projection digest must be nonzero"
    );
    Some(json!({"name":PROJECTION_SHA256_ENV,
        "value":digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()}))
}

const INPUTS: [&str; 2] = [
    "SANDBOX_CREDENTIAL_BROKER_NAMESPACE",
    "SANDBOX_CREDENTIAL_BROKER_ROOTS_CONFIGMAP",
];

/// Administrator-selected names of separately provisioned public trust
/// objects. There is no private key, bearer or provider URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRuntimeTemplateConfig {
    sandbox_namespace: String,
    broker_namespace: String,
    broker_roots_configmap: String,
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
        anyhow::ensure!(
            !names[1].starts_with("cw-credential-codex-"),
            "credential broker roots must be a separate trust object"
        );
        Ok(Some(Self {
            sandbox_namespace: sandbox_namespace.to_owned(),
            broker_namespace: names[0].clone(),
            broker_roots_configmap: names[1].clone(),
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

/// The per-environment gateway TLS Certificate, and its leaf Secret, that
/// environments created before the gateway's workspace-facing HTTPS listener
/// was removed still own. Nothing creates them now; final destruction removes
/// remaining ones under the same ownership checks.
pub fn credential_gateway_certificate_name(environment_id: &str) -> String {
    format!("cw-credential-gateway-{environment_id}")
}

/// The per-environment Codex ConfigMap that environments created before the
/// daemon wrote `~/.codex` still own. Nothing creates it now; final
/// destruction removes a remaining one under the same ownership checks.
pub fn credential_codex_config_name(environment_id: &str) -> String {
    format!("cw-credential-codex-{environment_id}")
}

pub(super) fn gateway_environment(opts: &TemplateOpts) -> Vec<Value> {
    let projection = projection_environment(opts);
    let Some(cfg) = &opts.credential_runtime else {
        return Vec::new();
    };
    assert!(
        opts.operation_generation > 0,
        "credential operation generation must be captured"
    );
    let mut environment: Vec<_> = [
        (
            "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
            opts.operation_generation.to_string(),
        ),
        (
            "CODEWIRE_CREDENTIAL_GATEWAY_TOKEN_FILE",
            format!("{GATEWAY_TOKEN_DIRECTORY}/token"),
        ),
        (
            "CODEWIRE_CREDENTIAL_BROKER_HTTPS_ORIGIN",
            cfg.broker_https_origin(),
        ),
        (
            "CODEWIRE_CREDENTIAL_BROKER_TLS_ROOTS_FILE",
            format!("{BROKER_ROOTS_DIRECTORY}/ca.crt"),
        ),
    ]
    .into_iter()
    .map(|(name, value)| json!({"name":name,"value":value}))
    .collect();
    environment.extend(projection);
    environment
}

fn projected_token(name: &str, audience: &str) -> Value {
    json!({"name":name,"projected":{"defaultMode":0o440,"sources":[{"serviceAccountToken":{
        "audience":audience,"expirationSeconds":600,"path":"token"}}]}})
}

pub(super) fn gateway_mounts() -> Vec<Value> {
    [
        ("credential-gateway-identity", GATEWAY_TOKEN_DIRECTORY),
        ("credential-broker-roots", BROKER_ROOTS_DIRECTORY),
    ]
    .into_iter()
    .map(|(name, path)| json!({"name":name,"mountPath":path,"readOnly":true}))
    .collect()
}

pub(super) fn gateway_volumes(opts: &TemplateOpts) -> Vec<Value> {
    let cfg = opts
        .credential_runtime
        .as_ref()
        .expect("credential runtime enabled");
    vec![
        projected_token(
            "credential-gateway-identity",
            CREDENTIAL_GATEWAY_TOKEN_AUDIENCE,
        ),
        json!({"name":"credential-broker-roots","configMap":{"name":cfg.broker_roots_configmap}}),
    ]
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

pub(super) fn workspace_environment(opts: &TemplateOpts) -> Vec<Value> {
    opts.managed_credential_clients
        .for_placement(ManagedCredentialClientPlacement::Platform)
        .environment
        .into_iter()
        .map(|(name, value)| json!({"name":name,"value":value}))
        .collect()
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
        for missing in INPUTS {
            assert!(
                CredentialRuntimeTemplateConfig::from_lookup("test-sandboxes", |key| {
                    if key == missing {
                        None
                    } else {
                        configured(key)
                    }
                })
                .is_err()
            );
        }
        for managed_root in &INPUTS[1..] {
            assert!(
                CredentialRuntimeTemplateConfig::from_lookup("test-sandboxes", |key| {
                    if key == *managed_root {
                        Some("cw-credential-codex-untrusted".into())
                    } else {
                        configured(key)
                    }
                })
                .is_err()
            );
        }
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
