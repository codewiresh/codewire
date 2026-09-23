//! Selected material-free stock-client configuration and purpose-specific mounts.

use codewire_access::{
    CODEX_PLATFORM_HOME, CODEX_PLATFORM_ROOTS_FILE, CODEX_PLATFORM_TOKEN_FILE,
    ManagedCredentialClient, ManagedCredentialClientPlacement,
};
use codewire_gateway_proto::{
    CREDENTIAL_GATEWAY_TOKEN_AUDIENCE, CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
};
use serde_json::{Value, json};

use super::{TemplateOpts, gateway_service_name};

pub const CREDENTIAL_GATEWAY_HTTPS_PORT: i64 = 8443;
pub const CREDENTIAL_GATEWAY_ISSUER_NAME: &str = "codewire-credential-gateway";
const GATEWAY_TOKEN_DIRECTORY: &str = "/run/codewire-credentials/gateway";
const GATEWAY_TLS_DIRECTORY: &str = "/run/codewire-credentials/gateway-tls";
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

const INPUTS: [&str; 3] = [
    "SANDBOX_CREDENTIAL_BROKER_NAMESPACE",
    "SANDBOX_CREDENTIAL_GATEWAY_ROOTS_CONFIGMAP",
    "SANDBOX_CREDENTIAL_BROKER_ROOTS_CONFIGMAP",
];

/// Administrator-selected names of separately provisioned public trust
/// objects. The issuer is fixed. There is no private key, bearer or provider URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRuntimeTemplateConfig {
    sandbox_namespace: String,
    broker_namespace: String,
    gateway_roots_configmap: String,
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
            names[1] != names[2]
                && !names[1].starts_with("cw-credential-codex-")
                && !names[2].starts_with("cw-credential-codex-"),
            "credential gateway and broker roots must be separate"
        );
        Ok(Some(Self {
            sandbox_namespace: sandbox_namespace.to_owned(),
            broker_namespace: names[0].clone(),
            gateway_roots_configmap: names[1].clone(),
            broker_roots_configmap: names[2].clone(),
        }))
    }

    pub fn broker_namespace(&self) -> &str {
        &self.broker_namespace
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

    pub(super) fn assert_namespace(&self, namespace: &str) {
        assert_eq!(
            self.sandbox_namespace, namespace,
            "credential runtime namespace must match its owning template"
        );
    }

    fn gateway_dns(&self, opts: &TemplateOpts) -> String {
        assert!(
            uuid::Uuid::parse_str(&opts.environment_id)
                .is_ok_and(|id| id.to_string() == opts.environment_id),
            "credential environment ID must be canonical"
        );
        format!(
            "{}.{}.svc.cluster.local",
            gateway_service_name(&opts.environment_id),
            self.sandbox_namespace
        )
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

pub fn credential_gateway_certificate_name(environment_id: &str) -> String {
    format!("cw-credential-gateway-{environment_id}")
}

pub fn credential_codex_config_name(environment_id: &str) -> String {
    format!("cw-credential-codex-{environment_id}")
}

fn labels(opts: &TemplateOpts) -> Value {
    json!({"app.kubernetes.io/name":"codewire", "app.kubernetes.io/managed-by":"codewire",
        "codewire.sh/environment-id":opts.environment_id, "codewire.sh/org-id":opts.organization_id,
        "codewire.sh/type":"credential-bootstrap"})
}

/// Cert-manager owns key generation; orchestration submits only its exact
/// environment DNS intent. The namespace-local Issuer is provisioned outside
/// this renderer. The Secret never enters the workspace or API response.
pub fn render_credential_gateway_certificate(
    namespace: &str,
    opts: &TemplateOpts,
) -> Option<Value> {
    let cfg = opts.credential_runtime.as_ref()?;
    cfg.assert_namespace(namespace);
    let name = credential_gateway_certificate_name(&opts.environment_id);
    Some(
        json!({"apiVersion":"cert-manager.io/v1", "kind":"Certificate",
        "metadata":{"name":name,"namespace":namespace,"labels":labels(opts)},
        "spec":{"secretName":name, "secretTemplate":{"labels":labels(opts)},
            "issuerRef":{"name":CREDENTIAL_GATEWAY_ISSUER_NAME,"kind":"Issuer","group":"cert-manager.io"},
            "dnsNames":[cfg.gateway_dns(opts)], "duration":"24h", "renewBefore":"8h",
            "privateKey":{"algorithm":"ECDSA","size":256,"encoding":"PKCS8","rotationPolicy":"Always"},
            "isCA":false,"revisionHistoryLimit":1,
            "usages":["digital signature","server auth"]}}),
    )
}

pub fn render_credential_codex_config(namespace: &str, opts: &TemplateOpts) -> Option<Value> {
    let cfg = opts.credential_runtime.as_ref()?;
    cfg.assert_namespace(namespace);
    let projection = opts
        .managed_credential_clients
        .for_placement(ManagedCredentialClientPlacement::Platform)
        .codex?;
    Some(json!({"apiVersion":"v1","kind":"ConfigMap",
        "metadata":{"name":credential_codex_config_name(&opts.environment_id),"namespace":namespace,"labels":labels(opts)},
        "data":{"config.toml":projection.config_toml()}}))
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
        ("CODEWIRE_CREDENTIAL_HTTPS_AUTHORITY", cfg.gateway_dns(opts)),
        (
            "CODEWIRE_CREDENTIAL_HTTPS_LISTEN_ADDR",
            "0.0.0.0:8443".to_owned(),
        ),
        (
            "CODEWIRE_CREDENTIAL_GATEWAY_TOKEN_FILE",
            format!("{GATEWAY_TOKEN_DIRECTORY}/token"),
        ),
        (
            "CODEWIRE_CREDENTIAL_TLS_CERT_FILE",
            format!("{GATEWAY_TLS_DIRECTORY}/tls.crt"),
        ),
        (
            "CODEWIRE_CREDENTIAL_TLS_KEY_FILE",
            format!("{GATEWAY_TLS_DIRECTORY}/tls.key"),
        ),
        (
            "CODEWIRE_CREDENTIAL_BROKER_HTTPS_ORIGIN",
            format!(
                "https://codewire-credential-service.{}.svc.cluster.local:9443",
                cfg.broker_namespace
            ),
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
        ("credential-gateway-tls", GATEWAY_TLS_DIRECTORY),
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
        json!({"name":"credential-gateway-tls","secret":{"secretName":credential_gateway_certificate_name(&opts.environment_id),"defaultMode":0o440}}),
        json!({"name":"credential-broker-roots","configMap":{"name":cfg.broker_roots_configmap}}),
    ]
}

pub(super) fn workspace_volumes(opts: &TemplateOpts) -> Vec<Value> {
    let cfg = opts
        .credential_runtime
        .as_ref()
        .expect("credential runtime enabled");
    let mut volumes = vec![
        projected_token(
            "credential-workspace-identity",
            CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
        ),
        json!({"name":"credential-gateway-roots","configMap":{"name":cfg.gateway_roots_configmap}}),
    ];
    volumes.extend(workspace_client_volumes(opts));
    volumes
}

pub(super) fn workspace_mounts(opts: &TemplateOpts) -> Vec<Value> {
    let mut mounts = vec![
        json!({"name":"credential-workspace-identity","mountPath":CODEX_PLATFORM_TOKEN_FILE.rsplit_once('/').unwrap().0,"readOnly":true}),
        json!({"name":"credential-gateway-roots","mountPath":CODEX_PLATFORM_ROOTS_FILE.rsplit_once('/').unwrap().0,"readOnly":true}),
    ];
    mounts.extend(workspace_client_mounts(opts));
    mounts
}

pub(super) fn workspace_client_volumes(opts: &TemplateOpts) -> Vec<Value> {
    if !opts
        .managed_credential_clients
        .contains(ManagedCredentialClient::Codex)
    {
        return Vec::new();
    }
    vec![
        json!({"name":"credential-codex-config","configMap":{"name":credential_codex_config_name(&opts.environment_id),"defaultMode":0o644}}),
        json!({"name":"credential-codex-home","emptyDir":{"medium":"Memory","sizeLimit":"256Mi"}}),
    ]
}

pub(super) fn workspace_client_mounts(opts: &TemplateOpts) -> Vec<Value> {
    if !opts
        .managed_credential_clients
        .contains(ManagedCredentialClient::Codex)
    {
        return Vec::new();
    }
    vec![
        json!({"name":"credential-codex-home","mountPath":CODEX_PLATFORM_HOME.rsplit_once('/').unwrap().0}),
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

pub(super) fn configure_bootstrap(init: &mut Value, opts: &TemplateOpts) {
    if !opts
        .managed_credential_clients
        .contains(ManagedCredentialClient::Codex)
    {
        return;
    }
    let command = init["command"][2].as_str().expect("trusted init command");
    init["command"][2] = format!("{command} && mkdir -p -m 0700 {CODEX_PLATFORM_HOME} && cp /codewire/codex-bootstrap/config.toml {CODEX_PLATFORM_HOME}/config.toml").into();
    let mounts = init["volumeMounts"]
        .as_array_mut()
        .expect("trusted init mounts");
    mounts.push(json!({"name":"credential-codex-config","mountPath":"/codewire/codex-bootstrap","readOnly":true}));
    mounts.push(json!({"name":"credential-codex-home","mountPath":CODEX_PLATFORM_HOME.rsplit_once('/').unwrap().0}));
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
        assert!(
            CredentialRuntimeTemplateConfig::from_lookup("test-sandboxes", |_| Some(
                "same-trust".into()
            ))
            .is_err()
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
