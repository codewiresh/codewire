//! Per-environment SandboxTemplate and zero-replica SandboxWarmPool rendering facade.
//!
//! Runtime decisions, deterministic encoding, names/selectors, workspace
//! objects, and network objects live in one-way internal modules. This facade
//! owns their stable internal API.

use std::fmt;
use std::time::Duration;

use serde_json::{Value, json};

use super::{EXTENSIONS_API_VERSION, LABEL_ENV_ID, LABEL_TYPE};

mod credentials;
mod encoding;
mod naming;
mod network;
mod runtime_policy;
mod workspace;

pub use credentials::{CredentialRuntimeTemplateConfig, MANAGED_CREDENTIAL_CLIENTS_ENV};

#[cfg(test)]
use encoding::gzip_base64;
pub use naming::{
    SANDBOX_UID_LABEL, direct_udp_service_name, warm_member_daemon_bridge_name,
    workspace_daemon_network_policy_name, workspace_daemon_service_addr,
    workspace_daemon_service_name,
};
pub use network::{
    render_direct_udp_service, render_warm_member_bridge, render_workspace_daemon_network_policy,
};
pub use runtime_policy::{
    DOCKER_MODE_GUEST_DIND, DOCKER_MODE_LOCAL_DIND_DIRECT, DOCKER_MODE_NONE,
    DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_CLASS_COMMODITY, RUNTIME_CLASS_CONFIDENTIAL,
    RUNTIME_CLASS_RUNC, RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL,
    RUNTIME_PROFILE_NONE, RUNTIME_PROFILE_RUNC, RuntimeProfileSpec, runtime_profile_spec,
    validate_managed_runtime_profile,
};
#[cfg(test)]
use workspace::custom_workspace_supervisor_command;
pub(crate) use workspace::{
    CLIENT_BOOTSTRAP_CONTAINER, DAEMON_INIT_CONTAINER, DAEMON_VOLUME,
    render_workspace_client_bootstrap,
};
pub use workspace::{
    ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP, orchestration_internal_tls_host,
    render_sandbox_template, render_workspace_daemon_service,
};

/// Return the exact raw TOML bytes that the hypervisor annotation compresses
/// and the SNP verifier hashes into HOST_DATA. Callers use this single source
/// of truth when preauthorizing a confidential environment in Trustee.
pub(crate) fn confidential_init_data(opts: &TemplateOpts) -> anyhow::Result<String> {
    let runtime_spec = opts.runtime_profile_spec();
    anyhow::ensure!(
        runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL && opts.disk_gib > 0,
        "init-data authorization requires confidential persistent storage"
    );
    anyhow::ensure!(
        runtime_policy::uses_kata_policy_init_data(opts, &runtime_spec),
        "confidential runtime does not emit measured Kata init-data"
    );
    opts.validate_confidential_storage_manifest()?;
    crate::confidential_storage::validate_environment_id(&opts.environment_id)?;

    Ok(encoding::build_codewire_kata_policy_init_data(opts, true))
}

/// How long one create or start waits for a workspace to become ready. The
/// workspace's Docker startup probe uses the same budget, so Kubernetes never
/// restarts it during a start that can still succeed.
pub const WORKSPACE_READY_TIMEOUT: Duration = Duration::from_secs(600);
/// Confidential guests initialize encrypted storage before the daemon listens.
pub const CONFIDENTIAL_WORKSPACE_READY_TIMEOUT: Duration = Duration::from_secs(1_800);

// Canonical sandbox and daemon contract constants.
pub const DEFAULT_DAEMON_IMAGE: &str = codewire_server_core::runtime_images::DEFAULT_DAEMON_IMAGE;
pub const DEFAULT_DIND_IMAGE: &str = "docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c";
pub const WORKSPACE_DAEMON_PORT: i64 = 7777;
pub const WORKSPACE_DAEMON_LISTEN_ADDR: &str = "0.0.0.0:7777";
pub const SANDBOX_SERVICE_ACCOUNT: &str = codewire_daemon_proto::SANDBOX_SERVICE_ACCOUNT;
pub const DIND_SOCKET_PATH: &str = "/var/run/docker/docker.sock";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
pub const KATA_COCO_INIT_DATA_ANNOTATION_KEY: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
pub const KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY: &str =
    "io.katacontainers.config.hypervisor.kernel_params";
pub const DEFAULT_KATA_COCO_TEST_RESOURCE_PATH: &str =
    "/run/confidential-containers/cdh/kbs/codewire/runtime-test-resource";
pub const DEFAULT_WORKSPACE_STORAGE_CLASS: &str = "example-volumes";
pub const CONFIDENTIAL_WORKSPACE_STORAGE_CLASS: &str = "longhorn-confidential";
pub const KATA_CONFIDENTIAL_VOLUME_ANNOTATION: &str = "io.katacontainers.volume.confidential";
pub const KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH: &str = "/dev/codewire-workspace";
const WORKSPACE_EPHEMERAL_STORAGE_GI: i64 = 8;
const HOME_ROOT: &str = "/home/codewire";
const WORKSPACE_ANNOTATION_KEY: &str = "codewire.sh/workspace";
const WORKSPACE_DISK_GIB_ANNOTATION_KEY: &str = "codewire.sh/disk-gib";
const APP_PREVIEW_MIN_PORT: i64 = 1;
const APP_PREVIEW_MAX_PORT: i64 = 65535;

/// How a hosted workspace Pod gets its environment identity (Program #2238
/// B2, design §8 and §13).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum WorkspaceIdentity {
    /// Today's rendering: the environment-wide daemon token, environment ID,
    /// generation, projection digest and managed clients are rendered into
    /// the workspace container. Only confidential Pods use it, until B2c: such
    /// a Pod never serves SSH or the tailnet.
    #[default]
    EnvironmentToken,
    /// Identity-free: the Pod carries only a Pod-bound projected token for the
    /// workspace-binding audience, its own UID from the downward API and the
    /// binding listener URL. Everything environment-specific comes from the
    /// bind response.
    Binding { binding_url: String },
}

/// Inputs for rendering one environment-scoped sandbox template.
#[derive(Clone, Default)]
pub struct TemplateOpts {
    pub name: String,
    pub image: String,
    pub image_command: Vec<String>,
    pub support_image: String,
    pub dind_image: String,
    pub runtime_profile: String,
    pub docker_mode: String,
    pub environment_id: String,
    pub organization_id: String,
    /// Captured existing environment operation authority, not a new generation.
    pub operation_generation: i64,
    pub credential_runtime: Option<CredentialRuntimeTemplateConfig>,
    /// Shared metadata-only selection captured for this operation, never values.
    pub projection_selection_sha256: Option<[u8; 32]>,
    /// Exact clients selected by the captured immutable profile revision.
    pub managed_credential_clients: codewire_access::ManagedCredentialClients,
    pub confidential_storage_manifest_uri: String,
    pub daemon_auth_token: String,
    /// How the workspace Pod is bound to this environment.
    pub workspace_identity: WorkspaceIdentity,
    pub api_base_url: String,
    pub coordinator_url: String,
    pub server_namespace: String,
    /// Mount `COORDINATOR_EXTRA_ROOTS_CONFIGMAP` for the daemon's coordinator
    /// trust (local clusters only).
    pub coordinator_extra_roots: bool,
    /// The workspace daemon's Codex login check period, rendered only when the
    /// Kind test deployment selects one; `None` keeps its production period.
    pub codex_login_check_period_seconds: Option<u64>,
    /// The ingress controller workspace egress may reach on 80/443; empty
    /// fields keep RKE2's `kube-system`/`rke2-ingress-nginx`.
    pub ingress_namespace: String,
    pub ingress_pod_name: String,
    pub derp_host: String,
    pub derp_port: i64,
    pub stun_host: String,
    pub stun_port: i64,
    pub stun_servers: String,
    pub direct_udp_lb_enabled: bool,
    pub direct_udp_lb_ip: String,
    pub direct_udp_lb_port: i64,
    pub direct_udp_lb_port_start: i64,
    pub direct_udp_lb_port_end: i64,
    pub direct_udp_lb_class: String,
    pub direct_udp_lb_sharing_key: String,
    pub direct_udp_transport_zone: String,
    pub udp_relay_allocator_url: String,
    pub udp_relay_allocator_token: String,
    pub udp_relay_bind_addrs: String,
    pub udp_relay_allocator_egress_enabled: bool,
    pub cpu_millicores: i64,
    pub memory_mib: i64,
    pub disk_gib: i64,
    pub workspace_storage_class: String,
    pub network_policy_management: String,
    pub dind_enabled: bool,
    pub kata_agent_policy_enabled: bool,
    pub kata_coco_init_data_enabled: bool,
    pub kata_coco_kbs_url: String,
    pub kata_coco_kbs_ca_pem: String,
    pub kata_coco_image_registry_auth_uri: String,
    pub kata_coco_test_resource_uri: String,
    pub kata_coco_test_resource_path: String,
    pub debug_tailnet: bool,
}

impl fmt::Debug for TemplateOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateOpts")
            .field("name", &self.name)
            .field("image", &self.image)
            .field("image_command", &self.image_command)
            .field("support_image", &self.support_image)
            .field("dind_image", &self.dind_image)
            .field("runtime_profile", &self.runtime_profile)
            .field("docker_mode", &self.docker_mode)
            .field("environment_id", &self.environment_id)
            .field("organization_id", &self.organization_id)
            .field("operation_generation", &self.operation_generation)
            .field("credential_runtime", &self.credential_runtime)
            .field(
                "managed_credential_clients",
                &self.managed_credential_clients,
            )
            .field(
                "projection_selection_sha256",
                &self.projection_selection_sha256,
            )
            .field(
                "confidential_storage_manifest_uri",
                &self.confidential_storage_manifest_uri,
            )
            .field("daemon_auth_token", &"<redacted>")
            .field("workspace_identity", &self.workspace_identity)
            .field("api_base_url", &self.api_base_url)
            .field("coordinator_url", &self.coordinator_url)
            .field("server_namespace", &self.server_namespace)
            .field("derp_host", &self.derp_host)
            .field("derp_port", &self.derp_port)
            .field("stun_host", &self.stun_host)
            .field("stun_port", &self.stun_port)
            .field("stun_servers", &self.stun_servers)
            .field("direct_udp_lb_enabled", &self.direct_udp_lb_enabled)
            .field("direct_udp_lb_ip", &self.direct_udp_lb_ip)
            .field("direct_udp_lb_port", &self.direct_udp_lb_port)
            .field("direct_udp_lb_port_start", &self.direct_udp_lb_port_start)
            .field("direct_udp_lb_port_end", &self.direct_udp_lb_port_end)
            .field("direct_udp_lb_class", &self.direct_udp_lb_class)
            .field("direct_udp_lb_sharing_key", &self.direct_udp_lb_sharing_key)
            .field("direct_udp_transport_zone", &self.direct_udp_transport_zone)
            .field("udp_relay_allocator_url", &self.udp_relay_allocator_url)
            .field("udp_relay_allocator_token", &"<redacted>")
            .field("udp_relay_bind_addrs", &self.udp_relay_bind_addrs)
            .field(
                "udp_relay_allocator_egress_enabled",
                &self.udp_relay_allocator_egress_enabled,
            )
            .field("cpu_millicores", &self.cpu_millicores)
            .field("memory_mib", &self.memory_mib)
            .field("disk_gib", &self.disk_gib)
            .field("workspace_storage_class", &self.workspace_storage_class)
            .field("network_policy_management", &self.network_policy_management)
            .field("dind_enabled", &self.dind_enabled)
            .field("kata_agent_policy_enabled", &self.kata_agent_policy_enabled)
            .field(
                "kata_coco_init_data_enabled",
                &self.kata_coco_init_data_enabled,
            )
            .field("kata_coco_kbs_url", &self.kata_coco_kbs_url)
            .field(
                "kata_coco_kbs_ca_pem",
                &if self.kata_coco_kbs_ca_pem.is_empty() {
                    "<unset>"
                } else {
                    "<configured>"
                },
            )
            .field(
                "kata_coco_image_registry_auth_uri",
                &self.kata_coco_image_registry_auth_uri,
            )
            .field(
                "kata_coco_test_resource_uri",
                &self.kata_coco_test_resource_uri,
            )
            .field(
                "kata_coco_test_resource_path",
                &self.kata_coco_test_resource_path,
            )
            .field("debug_tailnet", &self.debug_tailnet)
            .finish()
    }
}

/// The support image a rendering mounts the workspace daemon from: the
/// configured one, or this release's default. A resume re-pins a
/// Sandbox's daemon image volume to this same value.
pub fn effective_support_image(configured: &str) -> &str {
    if configured.is_empty() {
        DEFAULT_DAEMON_IMAGE
    } else {
        configured
    }
}

impl TemplateOpts {
    pub fn runtime_profile_spec(&self) -> RuntimeProfileSpec {
        runtime_profile_spec(&self.runtime_profile, &self.docker_mode, self.dind_enabled)
    }

    /// The workspace-binding listener URL when this workspace is rendered
    /// identity-free.
    pub fn workspace_binding_url(&self) -> Option<&str> {
        match &self.workspace_identity {
            WorkspaceIdentity::Binding { binding_url } => Some(binding_url),
            WorkspaceIdentity::EnvironmentToken => None,
        }
    }

    pub fn identity_free(&self) -> bool {
        self.workspace_binding_url().is_some()
    }

    /// The support image this rendering mounts or copies the daemon from.
    pub fn effective_support_image(&self) -> &str {
        effective_support_image(&self.support_image)
    }

    /// The StorageClass the workspace volume claim template names.
    pub fn effective_workspace_storage_class(&self) -> &str {
        runtime_policy::workspace_storage_class(self)
    }

    pub fn validate_confidential_storage_manifest(&self) -> anyhow::Result<()> {
        let needs_manifest = self.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL
            && self.disk_gib > 0;
        if needs_manifest {
            anyhow::ensure!(
                crate::confidential_storage::validate_manifest_uri(
                    &self.confidential_storage_manifest_uri
                ),
                "confidential runtime requires a canonical content-addressed storage manifest URI"
            );
        } else {
            anyhow::ensure!(
                self.confidential_storage_manifest_uri.is_empty(),
                "non-confidential runtime must not carry a confidential storage manifest URI"
            );
        }
        Ok(())
    }
}

/// Render the zero-replica shadow pool required by the SandboxClaim contract.
pub fn render_sandbox_shadow_pool(
    namespace: &str,
    name: &str,
    template_ref: &str,
    environment_id: &str,
) -> Value {
    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxWarmPool",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                LABEL_ENV_ID: environment_id,
                LABEL_TYPE: "sandbox-claim-shadow",
            },
        },
        "spec": {
            "replicas": 0,
            "sandboxTemplateRef": { "name": template_ref },
        },
    })
}

include!("tests.rs");

#[cfg(test)]
mod bridge_tests;
