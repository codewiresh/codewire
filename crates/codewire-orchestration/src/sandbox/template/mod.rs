//! SandboxTemplate + SandboxWarmPool rendering facade.
//!
//! Runtime decisions, deterministic encoding, names/selectors, workspace
//! objects, gateway objects, and network policies live in one-way internal
//! modules. This facade preserves the historical `sandbox::template` API.

use std::fmt;

use serde_json::{Value, json};

use super::EXTENSIONS_API_VERSION;

mod encoding;
mod gateway;
mod naming;
mod network;
mod runtime_policy;
mod workspace;

#[cfg(test)]
use encoding::gzip_base64;
#[cfg(test)]
use gateway::build_sidecar_env;
pub use gateway::{
    render_gateway_deployment, render_gateway_direct_udp_service, render_gateway_host_key_secret,
    render_gateway_service,
};
pub use naming::{
    gateway_direct_udp_service_name, gateway_host_key_secret_name, gateway_network_policy_name,
    gateway_service_name, gateway_workload_name, workspace_daemon_network_policy_name,
    workspace_daemon_service_addr, workspace_daemon_service_name,
};
pub use network::{render_gateway_network_policy, render_workspace_daemon_network_policy};
pub use runtime_policy::{
    DOCKER_MODE_EXTERNAL_ISOL8_PROXY, DOCKER_MODE_GUEST_DIND, DOCKER_MODE_LOCAL_DIND_DIRECT,
    DOCKER_MODE_NONE, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_CLASS_COMMODITY,
    RUNTIME_CLASS_CONFIDENTIAL, RUNTIME_CLASS_EXTERNAL_ISOL8_XEN, RUNTIME_CLASS_NAME,
    RUNTIME_CLASS_RUNC, RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL,
    RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN, RUNTIME_PROFILE_NONE, RUNTIME_PROFILE_RUNC,
    RuntimeProfileSpec, SIDECAR_RESOURCE_MODE_EXPLICIT, SIDECAR_RESOURCE_MODE_RUNTIME_ENVELOPE,
    Toleration, default_node_selector, default_tolerations, isol8_tolerations,
    runtime_profile_spec, validate_managed_runtime_profile,
};
#[cfg(test)]
use workspace::custom_workspace_supervisor_command;
pub use workspace::{render_sandbox_template, render_workspace_daemon_service};

// Constants mirrored from internal/sandbox/types.go and internal/shim.
pub const DEFAULT_GATEWAY_IMAGE: &str = "ghcr.io/codewiresh/gateway@sha256:686a2437f023fe2a4759e87ba93b8d4a71885eefdc5ec7c3486a95f3d6da2836";
pub const DEFAULT_DIND_IMAGE: &str = "docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c";
pub const DEFAULT_GATEWAY_READYZ_PORT: i64 = 2223;
pub const DEFAULT_GATEWAY_SSH_PORT: i64 = 2222;
pub const GATEWAY_TAILNET_UDP_PORT: i64 = 31000;
pub const GATEWAY_TAILNET_UDP_LISTEN_ADDR: &str = "0.0.0.0:31000";
pub const GATEWAY_HOST_KEY_SECRET_KEY: &str = "host_ed25519";
pub const GATEWAY_HOST_KEY_SECRET_MOUNT_PATH: &str = "/codewire/gateway-host-key";
pub const GATEWAY_HOST_KEY_PATH: &str = "/codewire/gateway/ssh/host_ed25519";
pub const WORKSPACE_DAEMON_PORT: i64 = 7777;
pub const WORKSPACE_DAEMON_LISTEN_ADDR: &str = "0.0.0.0:7777";
pub const SANDBOX_SERVICE_ACCOUNT: &str = "codewire-sandbox";
pub const GATEWAY_DOCKER_PROXY_SOCK_PATH: &str = "/codewire/run/docker.sock";
pub const GATEWAY_DOCKER_UPSTREAM_SOCK_ENV: &str = "CODEWIRE_DOCKER_UPSTREAM_SOCK";
pub const GATEWAY_DOCKER_UPSTREAM_SOCK_PATH: &str = "/var/run/docker/docker.sock";
pub const DAEMON_AUTH_TOKEN_ENV: &str = "CODEWIRE_DAEMON_AUTH_TOKEN";
pub const GATEWAY_BINDING_URL_ENV: &str = "CODEWIRE_BINDING_URL";
pub const GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV: &str = "CODEWIRE_TAILNET_UDP_LISTEN_ADDR";
pub const GATEWAY_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV: &str =
    "CODEWIRE_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS";
pub const GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_URL";
pub const GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV: &str = "CODEWIRE_UDP_RELAY_ALLOCATOR_TOKEN";
pub const GATEWAY_UDP_RELAY_BIND_ADDRS_ENV: &str = "CODEWIRE_UDP_RELAY_BIND_ADDRS";
pub const KATA_COCO_INIT_DATA_ANNOTATION_KEY: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
pub const KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY: &str =
    "io.katacontainers.config.hypervisor.kernel_params";
pub const DEFAULT_KATA_COCO_TEST_RESOURCE_PATH: &str =
    "/run/confidential-containers/cdh/kbs/codewire/runtime-test-resource";
pub const DEFAULT_WORKSPACE_STORAGE_CLASS: &str = "example-volumes";
pub const CONFIDENTIAL_WORKSPACE_STORAGE_CLASS: &str = "longhorn-confidential";
pub const CONFIDENTIAL_STORAGE_KEY_ID_ANNOTATION: &str = "codewire.sh/confidential-storage-key-id";
const WORKSPACE_EPHEMERAL_STORAGE_GI: i64 = 8;
const INTERNAL_DERP_TLS_PORT: i64 = 8443;
const INTERNAL_DERP_STUN_PORT: i64 = 3478;
const HOME_ROOT: &str = "/home/codewire";
const WORKSPACE_ANNOTATION_KEY: &str = "codewire.sh/workspace";
const WORKSPACE_DISK_GIB_ANNOTATION_KEY: &str = "codewire.sh/disk-gib";
const ISOL8_WORKSPACE_ANNOTATION_KEY: &str = "isol8.codewire.sh/workspace";
const ISOL8_DISK_GIB_ANNOTATION_KEY: &str = "isol8.codewire.sh/disk-gb";
const APP_PREVIEW_MIN_PORT: i64 = 1;
const APP_PREVIEW_MAX_PORT: i64 = 65535;

/// Mirrors `sandbox.TemplateOpts`. Tolerations are pre-flattened to the
/// JSON shape (key/operator/effect/value) the Go renderer emits.
#[derive(Clone, Default)]
pub struct TemplateOpts {
    pub name: String,
    pub image: String,
    pub image_command: Vec<String>,
    pub support_image: String,
    pub dind_image: String,
    pub runtime_profile: String,
    pub runtime_class_name: String,
    pub docker_mode: String,
    pub sidecar_resource_mode: String,
    /// (key, value) pairs; rendered as a JSON object (order-insensitive).
    pub node_selector: Vec<(String, String)>,
    pub tolerations: Vec<Toleration>,
    pub environment_id: String,
    pub gateway_token: String,
    pub api_base_url: String,
    pub coordinator_url: String,
    pub server_namespace: String,
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
            .field("runtime_class_name", &self.runtime_class_name)
            .field("docker_mode", &self.docker_mode)
            .field("sidecar_resource_mode", &self.sidecar_resource_mode)
            .field("node_selector", &self.node_selector)
            .field("tolerations", &self.tolerations)
            .field("environment_id", &self.environment_id)
            .field("gateway_token", &"<redacted>")
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

impl TemplateOpts {
    pub fn runtime_profile_spec(&self) -> RuntimeProfileSpec {
        let mut spec = runtime_profile_spec(
            &self.runtime_profile,
            &self.runtime_class_name,
            &self.docker_mode,
            self.dind_enabled,
        );
        if !self.sidecar_resource_mode.is_empty() {
            spec.sidecar_resource_mode = self.sidecar_resource_mode.clone();
        }
        spec
    }
}

/// Mirrors `sandbox.RenderSandboxWarmPool`.
pub fn render_sandbox_warm_pool(
    namespace: &str,
    name: &str,
    template_ref: &str,
    replicas: i64,
) -> Value {
    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxWarmPool",
        "metadata": { "name": name, "namespace": namespace },
        "spec": {
            "replicas": replicas,
            "sandboxTemplateRef": { "name": template_ref },
        },
    })
}

include!("tests.rs");
