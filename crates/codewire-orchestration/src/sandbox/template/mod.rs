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
mod dind;
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
pub(crate) use runtime_policy::docker_data_size_gib;
pub use runtime_policy::{
    DOCKER_MODE_GUEST_DIND, DOCKER_MODE_LOCAL_DIND_DIRECT, DOCKER_MODE_NONE,
    DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_CLASS_COMMODITY, RUNTIME_CLASS_COMMODITY_32G,
    RUNTIME_CLASS_CONFIDENTIAL, RUNTIME_CLASS_RUNC, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_CONFIDENTIAL, RUNTIME_PROFILE_NONE, RUNTIME_PROFILE_RUNC, RuntimeProfileSpec,
    commodity_runtime_class, confidential_workspace_storage_class, is_commodity_runtime_class,
    required_workspace_storage_class, runtime_profile_spec, validate_managed_runtime_profile,
};
#[cfg(test)]
use workspace::custom_workspace_supervisor_command;
#[cfg(test)]
pub(crate) use workspace::docker_data_image_prepare_script;
pub(crate) use workspace::{
    DAEMON_INIT_CONTAINER, DAEMON_VOLUME, DOCKER_DATA_INIT_CONTAINER, DOCKER_DATA_INIT_ENV,
    LEGACY_DIND_BOOTSTRAP_SCRIPT, LEGACY_WORKSPACE_MOUNT_VOLUME, MOUNT_WORKSPACE_CONTAINER,
    WORKSPACE_MOUNT_VOLUME, WorkspaceVolume, commodity_dind_bootstrap_script,
    dind_bootstrap_script, docker_data_init_container, eager_mkfs_dind_bootstrap_script,
    growth_in_dind_bootstrap_script, pre_growth_dind_bootstrap_script,
};
#[cfg(test)]
pub(crate) use workspace::{
    DIND_WORKSPACE_ROOT, MOUNT_WORKSPACE_DEVICE_PATH, MOUNT_WORKSPACE_SCRIPT, WORKSPACE_DIR_VOLUME,
    WORKSPACE_FLUSH_CONTAINER, WORKSPACE_FLUSH_SCRIPT,
};
pub use workspace::{
    ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP, WORKSPACE_LAYOUT_ENV, orchestration_internal_tls_host,
    render_sandbox_template, render_workspace_daemon_service, workspace_subfolder_layout,
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
    anyhow::ensure!(
        opts.measured_workspace_environment().is_some(),
        "confidential init-data requires a binding URL and measured binding roots"
    );

    Ok(encoding::build_codewire_kata_policy_init_data(opts, true))
}

/// How long one create or start waits for a workspace to become ready. The
/// workspace's daemon-ready startup probe uses the same budget, so Kubernetes
/// never restarts it during a start that can still succeed.
pub const WORKSPACE_READY_TIMEOUT: Duration = Duration::from_secs(600);
/// Confidential guests initialize encrypted storage before the daemon listens.
pub const CONFIDENTIAL_WORKSPACE_READY_TIMEOUT: Duration = Duration::from_secs(1_800);

// Canonical sandbox and daemon contract constants.
/// A digest-pinned support image for unit tests. A deployment names its own
/// (`SANDBOX_DAEMON_IMAGE`, docs/CONFIGURATION.md); there is no default.
#[cfg(test)]
pub(crate) const TEST_SUPPORT_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:adaba1f8e5ca50ed7aaeaf1b15d0588e441cadd1830e508a83108f798f66e029";
pub const DEFAULT_DIND_IMAGE: &str = "docker.io/library/docker:29.9.2-dind@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977";
pub const WORKSPACE_DAEMON_PORT: i64 = 7777;
pub const WORKSPACE_DAEMON_LISTEN_ADDR: &str = "0.0.0.0:7777";
pub const SANDBOX_SERVICE_ACCOUNT: &str = codewire_daemon_proto::SANDBOX_SERVICE_ACCOUNT;
pub const DIND_SOCKET_PATH: &str = "/var/run/docker/docker.sock";
pub const KATA_COCO_INIT_DATA_ANNOTATION_KEY: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
pub const KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY: &str =
    "io.katacontainers.config.hypervisor.kernel_params";
pub const DEFAULT_KATA_COCO_TEST_RESOURCE_PATH: &str =
    "/run/confidential-containers/cdh/kbs/codewire/runtime-test-resource";
/// The StorageClass commodity workspace volumes use. It has no default; see
/// [`required_workspace_storage_class`].
pub const WORKSPACE_STORAGE_CLASS_ENV: &str = "SANDBOX_WORKSPACE_STORAGE_CLASS";
/// The StorageClass confidential workspaces claim as a raw Block,
/// ReadWriteOncePod volume. It has no default; a confidential environment is
/// refused without one (see [`confidential_workspace_storage_class`]).
pub const CONFIDENTIAL_WORKSPACE_STORAGE_CLASS_ENV: &str =
    "SANDBOX_CONFIDENTIAL_WORKSPACE_STORAGE_CLASS";
pub const KATA_CONFIDENTIAL_VOLUME_ANNOTATION: &str = "io.katacontainers.volume.confidential";
pub const KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH: &str = "/dev/codewire-workspace";
const WORKSPACE_EPHEMERAL_STORAGE_GI: i64 = 8;
const HOME_ROOT: &str = "/home/codewire";
const WORKSPACE_ANNOTATION_KEY: &str = "codewire.sh/workspace";
const WORKSPACE_DISK_GIB_ANNOTATION_KEY: &str = "codewire.sh/disk-gib";
/// The Pod annotation Cilium's bandwidth manager enforces as an egress rate.
pub const EGRESS_BANDWIDTH_ANNOTATION_KEY: &str = "kubernetes.io/egress-bandwidth";
/// The egress rate cap on every workspace Pod (`SANDBOX_EGRESS_BANDWIDTH`), as
/// a decimal count of bits per second with an optional `K`, `M` or `G`
/// suffix. A cluster without an enforcing CNI ignores the annotation.
pub const EGRESS_BANDWIDTH_ENV: &str = "SANDBOX_EGRESS_BANDWIDTH";
pub const DEFAULT_EGRESS_BANDWIDTH: &str = "100M";

/// [`EGRESS_BANDWIDTH_ENV`], or [`DEFAULT_EGRESS_BANDWIDTH`] when unset or
/// empty. Anything else than digits with an optional `K`, `M` or `G` suffix,
/// or zero, is refused, so a typo stops orchestration instead of rendering a
/// value the CNI would ignore.
pub fn sandbox_egress_bandwidth(value: Option<&str>) -> Result<String, String> {
    let value = match value.map(str::trim) {
        None | Some("") => return Ok(DEFAULT_EGRESS_BANDWIDTH.to_string()),
        Some(value) => value,
    };
    let digits = value.strip_suffix(['K', 'M', 'G']).unwrap_or(value);
    let valid = !digits.is_empty()
        && digits.len() <= 12
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !digits.starts_with('0');
    if valid {
        Ok(value.to_string())
    } else {
        Err(format!(
            "{EGRESS_BANDWIDTH_ENV} must be a positive whole number of bits per second with an optional K, M or G suffix, such as {DEFAULT_EGRESS_BANDWIDTH}; got {value:?}"
        ))
    }
}

/// How many of a workspace's vCPUs share one CPU reserved on its node. A
/// whole number from 1 to [`MAX_CPU_SHARING_RATIO`]; unset, empty or 1 is off.
pub const CPU_SHARING_RATIO_ENV: &str = "CODEWIRE_SANDBOX_CPU_SHARING_RATIO";
const MAX_CPU_SHARING_RATIO: i64 = 8;

/// CPU sharing (#3635): the workspace container's CPU request is its vCPUs
/// divided by this ratio. Its limit stays the full vCPUs, which is what the VM
/// is sized from and what quota, billing and the shape users see count. Only
/// the workspace shares: DinD and the Kata overhead keep their requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSharingRatio(i64);

impl Default for CpuSharingRatio {
    fn default() -> Self {
        Self::NONE
    }
}

impl CpuSharingRatio {
    /// One reserved CPU per vCPU.
    pub const NONE: Self = Self(1);

    /// [`CPU_SHARING_RATIO_ENV`]. Anything else than a whole number in range
    /// is refused, so a typo stops orchestration instead of overcommitting
    /// every new sandbox's CPU.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        let value = match value.map(str::trim) {
            None | Some("") => return Ok(Self::NONE),
            Some(value) => value,
        };
        value
            .parse()
            .ok()
            .filter(|ratio| (1..=MAX_CPU_SHARING_RATIO).contains(ratio))
            .map(Self)
            .ok_or_else(|| {
                format!(
                    "{CPU_SHARING_RATIO_ENV} must be a whole number from 1 (off) to {MAX_CPU_SHARING_RATIO}; got {value:?}"
                )
            })
    }

    /// The ratio a live workspace runs at, from its CPU request and limit: the
    /// nearest whole number, because the request was rounded up. Without a
    /// positive request and limit there is nothing to share.
    pub fn observed(request_millicores: i64, limit_millicores: i64) -> Self {
        if request_millicores <= 0 || limit_millicores <= 0 {
            return Self::NONE;
        }
        Self(((limit_millicores + request_millicores / 2) / request_millicores).max(1))
    }

    /// The CPU request of `vcpu_millicores`, rounded up.
    pub fn request_millicores(self, vcpu_millicores: i64) -> i64 {
        (vcpu_millicores + self.0 - 1) / self.0
    }
}

const APP_PREVIEW_MIN_PORT: i64 = 1;
const APP_PREVIEW_MAX_PORT: i64 = 65535;

/// The workload a non-first-party image runs beside the managed daemon: a
/// keepalive, never the image's own entrypoint.
pub const WORKSPACE_KEEPALIVE_COMMAND: [&str; 2] = ["sleep", "infinity"];

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
    /// The binding listener's public roots (PEM) that a confidential
    /// workspace measures: orchestration's own issuing CA, never the
    /// tenant-namespace ConfigMap. Empty for every other runtime.
    pub measured_binding_roots: String,
    /// The workspace-binding listener every hosted workspace binds through
    /// (Program #2238 B2, B2c). The Pod carries only a Pod-bound projected
    /// token for the binding audience, its own UID from the downward API and
    /// this URL; everything environment-specific comes from the bind
    /// response.
    pub workspace_binding_url: String,
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
    /// The workspace Pod's [`EGRESS_BANDWIDTH_ANNOTATION_KEY`] value; empty
    /// renders no cap.
    pub egress_bandwidth: String,
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
    pub udp_relay_bind_addrs: String,
    pub udp_relay_allocator_egress_enabled: bool,
    pub cpu_millicores: i64,
    /// What `cpu_millicores` is divided by for the CPU request.
    pub cpu_sharing: CpuSharingRatio,
    pub memory_mib: i64,
    pub disk_gib: i64,
    pub workspace_storage_class: String,
    /// A Block (commodity) workspace's `/workspace` is its filesystem's
    /// `workspace/` folder, not its root, which stays the home
    /// (`SANDBOX_WORKSPACE_LAYOUT=subfolder`, #4026).
    pub workspace_subfolder: bool,
    /// The `VolumeSnapshot` a new workspace PVC restores from. Only a create
    /// from a hosted snapshot has one; such a claim never comes from a pool.
    pub workspace_source_snapshot: Option<String>,
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
            .field(
                "measured_binding_roots_bytes",
                &self.measured_binding_roots.len(),
            )
            .field("workspace_binding_url", &self.workspace_binding_url)
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
            .field("udp_relay_bind_addrs", &self.udp_relay_bind_addrs)
            .field(
                "udp_relay_allocator_egress_enabled",
                &self.udp_relay_allocator_egress_enabled,
            )
            .field("cpu_millicores", &self.cpu_millicores)
            .field("cpu_sharing", &self.cpu_sharing)
            .field("memory_mib", &self.memory_mib)
            .field("disk_gib", &self.disk_gib)
            .field("workspace_storage_class", &self.workspace_storage_class)
            .field("workspace_subfolder", &self.workspace_subfolder)
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

impl TemplateOpts {
    /// The runtime this workspace renders: a commodity workspace takes the
    /// class of its memory tier.
    pub fn runtime_profile_spec(&self) -> RuntimeProfileSpec {
        let mut spec =
            runtime_profile_spec(&self.runtime_profile, &self.docker_mode, self.dind_enabled);
        if spec.runtime_class_name == RUNTIME_CLASS_COMMODITY {
            spec.runtime_class_name = commodity_runtime_class(self.memory_mib).to_string();
        }
        spec
    }

    /// The measured trust anchors of a confidential workspace (B2c), as the
    /// exact env entries its workspace container carries and its measured
    /// Kata policy pins: the binding listener URL, its public roots and the
    /// only environment the Pod may bind as. `None` for any other runtime,
    /// and for a confidential rendering without a binding URL or measured
    /// roots, which never renders init-data.
    pub fn measured_workspace_environment(&self) -> Option<[(&'static str, &str); 3]> {
        if self.runtime_profile_spec().profile != RUNTIME_PROFILE_CONFIDENTIAL
            || self.measured_binding_roots.trim().is_empty()
            || self.workspace_binding_url.trim().is_empty()
        {
            return None;
        }
        Some([
            (
                codewire_daemon_proto::WORKSPACE_BINDING_URL_ENV,
                &self.workspace_binding_url,
            ),
            (
                codewire_daemon_proto::WORKSPACE_MEASURED_BINDING_ROOTS_ENV,
                &self.measured_binding_roots,
            ),
            (
                codewire_daemon_proto::WORKSPACE_MEASURED_ENVIRONMENT_ID_ENV,
                &self.environment_id,
            ),
        ])
    }

    /// The support image this rendering mounts or copies the daemon from. A
    /// resume re-pins a Sandbox's daemon image volume to this same value.
    pub fn effective_support_image(&self) -> &str {
        &self.support_image
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
#[cfg(test)]
mod docker_data_tests;
#[cfg(test)]
mod mount_workspace_tests;
