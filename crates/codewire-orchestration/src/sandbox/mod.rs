//! Agent-sandbox CRD identifiers and CR renderers.
//!
//! The Rust renderer owns these live CR shapes. Checked-in fixtures under
//! `tests/fixtures/sandbox` pin the serialized output byte-for-byte.

pub mod client;
pub mod exec;
pub mod sidecar;
pub mod template;

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use self::template::TemplateOpts;

/// CRD coordinates, mirroring `sandbox.SandboxGVR` et al.
pub const SANDBOX_GROUP: &str = "agents.x-k8s.io";
pub const EXTENSIONS_GROUP: &str = "extensions.agents.x-k8s.io";
pub const CRD_VERSION: &str = "v1beta1";
pub const EXTENSIONS_API_VERSION: &str = "extensions.agents.x-k8s.io/v1beta1";

/// Labels, mirroring `sandbox.LabelEnvID` / `LabelOrgID` / `LabelType`.
pub const LABEL_ENV_ID: &str = "codewire.sh/environment-id";
pub const LABEL_ORG_ID: &str = "codewire.sh/org-id";
pub const LABEL_TYPE: &str = "codewire.sh/type";

const DELETION_PROTECTION_FINALIZER: &str = "codewire.sh/deletion-protection";

/// Mirrors `sandbox.CanonicalWorkspaceRuntimeImage`.
pub const CANONICAL_WORKSPACE_RUNTIME_IMAGE: &str = "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467";

/// Mirrors `sandbox.IsCanonicalWorkspaceRuntimeImage`.
pub fn is_canonical_workspace_runtime_image(image_ref: &str) -> bool {
    image_ref.trim() == CANONICAL_WORKSPACE_RUNTIME_IMAGE
}

/// Mirrors `sandbox.EnvironmentTemplateName`: base + "-" + envID,
/// base truncated so the whole name fits the 253-char k8s limit.
pub fn environment_template_name(base: &str, env_id: &str) -> String {
    const MAX_LEN: usize = 253;
    let suffix_len = 1 + env_id.len();
    let base = if base.len() + suffix_len > MAX_LEN {
        &base[..MAX_LEN - suffix_len]
    } else {
        base
    };
    format!("{base}-{env_id}")
}

pub fn truncate_kubernetes_name(name: &str) -> String {
    const MAX_LEN: usize = 63;
    let truncated = if name.len() > MAX_LEN {
        name[..MAX_LEN].to_string()
    } else {
        name.to_string()
    };
    truncated.trim_end_matches(['-', '.']).to_string()
}

pub fn shadow_warm_pool_name(template_ref: &str) -> String {
    truncate_kubernetes_name(&format!("shadow-pool-{template_ref}"))
}

pub fn warm_pool_name(template_name: &str, opts: &TemplateOpts) -> String {
    truncate_kubernetes_name(&format!(
        "sandbox-warmpool-{template_name}-{}",
        warm_pool_revision_hash(opts)
    ))
}

/// Mirrors `sandbox.WarmPoolRevisionHash`.
pub fn warm_pool_revision_hash(opts: &TemplateOpts) -> String {
    let mut buf = String::new();
    buf.push_str(&format!("Image={}\n", opts.image));
    buf.push_str(&format!(
        "ImageCommand=[{}]\n",
        opts.image_command.join(" ")
    ));
    buf.push_str(&format!("SupportImage={}\n", opts.support_image));
    buf.push_str(&format!("RuntimeProfile={}\n", opts.runtime_profile));
    buf.push_str(&format!("RuntimeClassName={}\n", opts.runtime_class_name));
    buf.push_str(&format!("DockerMode={}\n", opts.docker_mode));
    buf.push_str(&format!(
        "SidecarResourceMode={}\n",
        opts.sidecar_resource_mode
    ));

    let mut selector = opts.node_selector.clone();
    selector.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in &selector {
        buf.push_str(&format!("NodeSelector.{k}={v}\n"));
    }

    for (i, t) in opts.tolerations.iter().enumerate() {
        buf.push_str(&format!(
            "Tolerations[{i}]={}:{}:{}:{}\n",
            t.key, t.operator, t.value, t.effect
        ));
    }

    buf.push_str(&format!("APIBaseURL={}\n", opts.api_base_url));
    if !opts.coordinator_url.is_empty() {
        buf.push_str(&format!("CoordinatorURL={}\n", opts.coordinator_url));
    }
    buf.push_str(&format!("ServerNamespace={}\n", opts.server_namespace));
    buf.push_str(&format!("DERPHost={}\n", opts.derp_host));
    buf.push_str(&format!("DERPPort={}\n", opts.derp_port));
    buf.push_str(&format!("STUNHost={}\n", opts.stun_host));
    buf.push_str(&format!("STUNServers={}\n", opts.stun_servers));
    if !opts.udp_relay_allocator_url.is_empty() {
        buf.push_str(&format!(
            "UDPRelayAllocatorURL={}\n",
            opts.udp_relay_allocator_url
        ));
    }
    if !opts.udp_relay_allocator_token.is_empty() {
        buf.push_str(&format!(
            "UDPRelayAllocatorToken={}\n",
            opts.udp_relay_allocator_token
        ));
    }
    if !opts.udp_relay_bind_addrs.is_empty() {
        buf.push_str(&format!(
            "UDPRelayBindAddrs={}\n",
            opts.udp_relay_bind_addrs
        ));
    }
    buf.push_str(&format!("CPUMillicores={}\n", opts.cpu_millicores));
    buf.push_str(&format!("MemoryMiB={}\n", opts.memory_mib));
    buf.push_str(&format!("DiskGiB={}\n", opts.disk_gib));
    if !opts.workspace_storage_class.is_empty() {
        buf.push_str(&format!(
            "WorkspaceStorageClass={}\n",
            opts.workspace_storage_class
        ));
    }
    buf.push_str(&format!(
        "NetworkPolicyManagement={}\n",
        opts.network_policy_management
    ));
    buf.push_str(&format!("DinDEnabled={}\n", opts.dind_enabled));
    buf.push_str(&format!(
        "KataAgentPolicyEnabled={}\n",
        opts.kata_agent_policy_enabled
    ));
    buf.push_str(&format!(
        "KataCoCoInitDataEnabled={}\n",
        opts.kata_coco_init_data_enabled
    ));
    if !opts.kata_coco_kbs_url.is_empty() {
        buf.push_str(&format!("KataCoCoKBSURL={}\n", opts.kata_coco_kbs_url));
    }
    if !opts.kata_coco_image_registry_auth_uri.is_empty() {
        buf.push_str(&format!(
            "KataCoCoImageRegistryAuthURI={}\n",
            opts.kata_coco_image_registry_auth_uri
        ));
    }
    if !opts.kata_coco_test_resource_uri.is_empty() {
        buf.push_str(&format!(
            "KataCoCoTestResourceURI={}\n",
            opts.kata_coco_test_resource_uri
        ));
    }
    if !opts.kata_coco_test_resource_path.is_empty() {
        buf.push_str(&format!(
            "KataCoCoTestResourcePath={}\n",
            opts.kata_coco_test_resource_path
        ));
    }

    let digest = Sha256::digest(buf.as_bytes());
    let mut hex = String::with_capacity(8);
    for b in digest.iter().take(4) {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Mirrors `sandbox.ClaimOpts`.
#[derive(Debug, Clone, Default)]
pub struct ClaimOpts {
    pub environment_id: String,
    pub org_id: String,
    /// Name of the SandboxTemplate CR in k8s.
    pub template_ref: String,
    /// Name of the SandboxWarmPool CR in k8s.
    pub warm_pool_ref: String,
    /// Per-container env overrides.
    pub env_overrides: BTreeMap<String, BTreeMap<String, String>>,
    /// Labels propagated onto the Sandbox Pod through additionalPodMetadata.
    pub additional_pod_labels: BTreeMap<String, String>,
    pub cpu_millicores: i64,
    pub memory_mib: i64,
    pub disk_gib: i64,
}

/// Build `sandbox-` + environment ID, truncated to the 63-character
/// Kubernetes name limit.
pub fn claim_name(env_id: &str) -> String {
    const PREFIX: &str = "sandbox-";
    const MAX_ENV_ID_LEN: usize = 63 - PREFIX.len();
    let env_id = if env_id.len() > MAX_ENV_ID_LEN {
        &env_id[..MAX_ENV_ID_LEN]
    } else {
        env_id
    };
    format!("{PREFIX}{env_id}")
}

pub fn environment_pod_selector(env_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(LABEL_ENV_ID.to_string(), env_id.to_string())])
}

/// Render the Rust-owned SandboxClaim CR for `opts`.
pub fn render_sandbox_claim(namespace: &str, opts: &ClaimOpts) -> Value {
    let mut spec = Map::new();
    let warm_pool_ref = if opts.warm_pool_ref.is_empty() {
        shadow_warm_pool_name(&opts.template_ref)
    } else {
        opts.warm_pool_ref.clone()
    };
    spec.insert("warmPoolRef".into(), json!({ "name": warm_pool_ref }));
    if !opts.env_overrides.is_empty() {
        let env: Vec<Value> = opts
            .env_overrides
            .iter()
            .flat_map(|(container, vars)| {
                vars.iter().map(move |(name, value)| {
                    json!({
                        "containerName": container,
                        "name": name,
                        "value": value,
                    })
                })
            })
            .collect();
        spec.insert("env".into(), Value::Array(env));
    }
    if !opts.additional_pod_labels.is_empty() {
        let labels: Map<String, Value> = opts
            .additional_pod_labels
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        spec.insert(
            "additionalPodMetadata".into(),
            json!({ "labels": Value::Object(labels) }),
        );
    }
    if opts.cpu_millicores > 0 || opts.memory_mib > 0 || opts.disk_gib > 0 {
        let mut requests = Map::new();
        let mut limits = Map::new();
        if opts.cpu_millicores > 0 {
            let quantity = format!("{}m", opts.cpu_millicores);
            requests.insert("cpu".into(), json!(quantity));
            limits.insert("cpu".into(), json!(quantity));
        }
        if opts.memory_mib > 0 {
            let quantity = format!("{}Mi", opts.memory_mib);
            requests.insert("memory".into(), json!(quantity));
            limits.insert("memory".into(), json!(quantity));
        }
        if opts.disk_gib > 0 {
            let quantity = format!("{}Gi", opts.disk_gib);
            requests.insert("ephemeral-storage".into(), json!(quantity));
            limits.insert("ephemeral-storage".into(), json!(quantity));
        }
        spec.insert(
            "workspaceResources".into(),
            json!({
                "containerName": "workspace",
                "resources": {
                    "requests": Value::Object(requests),
                    "limits": Value::Object(limits),
                },
            }),
        );
    }

    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxClaim",
        "metadata": {
            "name": claim_name(&opts.environment_id),
            "namespace": namespace,
            "labels": {
                LABEL_ENV_ID: opts.environment_id,
                LABEL_ORG_ID: opts.org_id,
                LABEL_TYPE: "sandbox",
            },
            "finalizers": [DELETION_PROTECTION_FINALIZER],
        },
        "spec": Value::Object(spec),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Inputs covering the complete Rust-owned SandboxClaim fixture.
    fn golden_fixture() -> ClaimOpts {
        ClaimOpts {
            environment_id: "env-golden-fixture-1234".into(),
            org_id: "org-golden-fixture".into(),
            template_ref: "tmpl-golden".into(),
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 10,
            env_overrides: BTreeMap::from([(
                "workspace".into(),
                BTreeMap::from([
                    ("CODEWIRE_ENV_ID".into(), "env-golden-fixture-1234".into()),
                    ("GIT_BRANCH".into(), "main".into()),
                ]),
            )]),
            ..Default::default()
        }
    }

    #[test]
    fn sandbox_claim_matches_golden_file() {
        let golden_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sandbox/sandboxclaim.golden.json"
        );
        let want: Value = serde_json::from_str(
            &std::fs::read_to_string(golden_path).expect("Rust-owned golden file missing"),
        )
        .unwrap();

        let got = render_sandbox_claim("codewire-runtime", &golden_fixture());
        assert_eq!(
            got, want,
            "SandboxClaim render drifted from its golden file"
        );
    }

    #[test]
    fn truncate_kubernetes_name_removes_trailing_separator_after_truncation() {
        let name = "shadow-pool-codewiresh-workspace-sha256-d864f5f3afec8f7e56e38e-ignored";
        let got = truncate_kubernetes_name(name);
        assert_eq!(
            got,
            "shadow-pool-codewiresh-workspace-sha256-d864f5f3afec8f7e56e38e"
        );
    }

    #[test]
    fn shadow_warm_pool_name_handles_digest_derived_template_refs() {
        let template_ref = "codewiresh-workspace-sha256-d864f5f3afec8f7e56e38ee8f6aaba2af33ed2d984316a90c68f3dd5fcdb2d9a";
        let got = shadow_warm_pool_name(template_ref);
        assert_eq!(
            got,
            "shadow-pool-codewiresh-workspace-sha256-d864f5f3afec8f7e56e38ee"
        );
        assert!(got.len() <= 63);
        assert!(got.ends_with(|c: char| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn claim_name_truncates_to_63_chars() {
        let long = format!("env-{}", "a".repeat(80));
        let name = claim_name(&long);
        assert_eq!(name.len(), 63);
        assert!(name.starts_with("sandbox-"));
        assert_eq!(claim_name("env-1"), "sandbox-env-1");
    }

    #[test]
    fn sandbox_claim_renders_environment_pod_label() {
        let got = render_sandbox_claim(
            "codewire-runtime",
            &ClaimOpts {
                environment_id: "env-1".into(),
                org_id: "org-1".into(),
                template_ref: "tmpl-1".into(),
                additional_pod_labels: environment_pod_selector("env-1"),
                ..Default::default()
            },
        );

        assert_eq!(
            got["spec"]["additionalPodMetadata"]["labels"][LABEL_ENV_ID].as_str(),
            Some("env-1")
        );
    }
}
