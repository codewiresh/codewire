//! SandboxTemplate + SandboxWarmPool renderers.
//!
//! The Rust renderer owns the live sandbox runtime shape. The workspace
//! SandboxTemplate contains only the user workspace, workspace-local dockerd,
//! and daemon bootstrap; the gateway is rendered as a separate Deployment,
//! Service, and NetworkPolicy. Rust-owned fixtures pin shared claim and
//! warm-pool contracts, including the gateway/workspace split.

use base64::Engine;
use crc32fast::Hasher as Crc32Hasher;
use serde_json::{Map, Value, json};

use super::EXTENSIONS_API_VERSION;

// Constants mirrored from internal/sandbox/types.go and internal/shim.
pub const DEFAULT_GATEWAY_IMAGE: &str = "ghcr.io/codewiresh/gateway@sha256:1141293d909627af0e303f4ec0c5788dbda58495acd273cb243580a47828c4ca";
pub const DEFAULT_DIND_IMAGE: &str = "ghcr.io/codewiresh/dind@sha256:00815afb718e35fa8c71e8eb411df2919f74a149908593ae3fe94b55b34feec9";
pub const DEFAULT_GATEWAY_READYZ_PORT: i64 = 2223;
pub const DEFAULT_GATEWAY_SSH_PORT: i64 = 2222;
pub const GATEWAY_TAILNET_UDP_PORT: i64 = 31000;
pub const GATEWAY_TAILNET_UDP_LISTEN_ADDR: &str = "0.0.0.0:31000";
pub const GATEWAY_HOST_KEY_SECRET_KEY: &str = "host_ed25519";
pub const GATEWAY_HOST_KEY_SECRET_MOUNT_PATH: &str = "/codewire/gateway-host-key";
pub const GATEWAY_HOST_KEY_PATH: &str = "/codewire/gateway/ssh/host_ed25519";
pub const WORKSPACE_DAEMON_PORT: i64 = 7777;
pub const WORKSPACE_DAEMON_LISTEN_ADDR: &str = "0.0.0.0:7777";
pub const RUNTIME_CLASS_NAME: &str = RUNTIME_CLASS_EXTERNAL_ISOL8_XEN;
pub const RUNTIME_CLASS_RUNC: &str = "runc";
pub const RUNTIME_CLASS_COMMODITY: &str = "commodity";
pub const RUNTIME_CLASS_CONFIDENTIAL: &str = "confidential";
pub const RUNTIME_CLASS_EXTERNAL_ISOL8_XEN: &str = "isol8";
pub const RUNTIME_PROFILE_NONE: &str = "none";
pub const RUNTIME_PROFILE_RUNC: &str = "runc";
pub const RUNTIME_PROFILE_COMMODITY: &str = "commodity";
pub const RUNTIME_PROFILE_CONFIDENTIAL: &str = "confidential";
pub const RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN: &str = "external-isol8-xen";
pub const DOCKER_MODE_PROFILE_DEFAULT: &str = "profile-default";
pub const DOCKER_MODE_NONE: &str = "none";
pub const DOCKER_MODE_LOCAL_DIND_DIRECT: &str = "local-dind-direct";
pub const DOCKER_MODE_GUEST_DIND: &str = "guest-dind";
pub const DOCKER_MODE_EXTERNAL_ISOL8_PROXY: &str = "external-isol8-proxy";
pub const SIDECAR_RESOURCE_MODE_EXPLICIT: &str = "explicit";
pub const SIDECAR_RESOURCE_MODE_RUNTIME_ENVELOPE: &str = "runtime-envelope";
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
const WORKSPACE_EPHEMERAL_STORAGE_GI: i64 = 8;
const INTERNAL_DERP_TLS_PORT: i64 = 8443;
const INTERNAL_DERP_STUN_PORT: i64 = 3478;
const HOME_ROOT: &str = "/home/codewire"; // internal/shim DefaultHomeRoot
const WORKSPACE_ANNOTATION_KEY: &str = "codewire.sh/workspace";
const WORKSPACE_DISK_GIB_ANNOTATION_KEY: &str = "codewire.sh/disk-gib";
const ISOL8_WORKSPACE_ANNOTATION_KEY: &str = "isol8.codewire.sh/workspace";
const ISOL8_DISK_GIB_ANNOTATION_KEY: &str = "isol8.codewire.sh/disk-gb";
const APP_PREVIEW_MIN_PORT: i64 = 1;
const APP_PREVIEW_MAX_PORT: i64 = 65535;
const CODEWIRE_KATA_AGENT_POLICY_REGO: &str = r#"package agent_policy

# Codewire-owned base policy for commodity Kata Agent Policy and confidential
# CoCo bootstrap. Commodity uses this only as defense in depth: without SNP/TDX
# the host can still replace the guest image, agent, or policy.
default AddARPNeighborsRequest := true
default AddSwapPathRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := true
default GetDiagnosticDataRequest := false
default GetIPTablesRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemAgentCompactConfig := true
default MemAgentMemcgConfig := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResizeVolumeRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetIPTablesRequest := true
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := false
default StatsContainerRequest := true
default StopTracingRequest := false
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default VolumeStatsRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
"#;

/// Mirrors `sandbox.TemplateOpts`. Tolerations are pre-flattened to the
/// JSON shape (key/operator/effect/value) the Go renderer emits.
#[derive(Debug, Clone, Default)]
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
    pub kata_coco_image_registry_auth_uri: String,
    pub kata_coco_test_resource_uri: String,
    pub kata_coco_test_resource_path: String,
    pub debug_tailnet: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Toleration {
    pub key: String,
    pub operator: String,
    pub value: String,
    pub effect: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct RuntimeProfileSpec {
    pub profile: String,
    pub runtime_class_name: String,
    pub docker_mode: String,
    pub sidecar_resource_mode: String,
}

pub fn runtime_profile_spec(
    profile: &str,
    legacy_runtime_class: &str,
    docker_mode: &str,
    dind_enabled: bool,
) -> RuntimeProfileSpec {
    let mut profile = normalize_runtime_profile(profile);
    let legacy_runtime_class = legacy_runtime_class.trim();
    if profile.is_empty() {
        profile = profile_from_legacy_runtime_class(legacy_runtime_class);
    }

    let sidecar_resource_mode = if profile == RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN {
        SIDECAR_RESOURCE_MODE_RUNTIME_ENVELOPE
    } else {
        SIDECAR_RESOURCE_MODE_EXPLICIT
    };

    RuntimeProfileSpec {
        runtime_class_name: runtime_class_for_profile(&profile, legacy_runtime_class),
        docker_mode: resolve_docker_mode(&profile, docker_mode, dind_enabled),
        sidecar_resource_mode: sidecar_resource_mode.to_string(),
        profile,
    }
}

pub fn validate_managed_runtime_profile(
    spec: &RuntimeProfileSpec,
    allow_diagnostic: bool,
) -> Result<(), String> {
    match spec.profile.as_str() {
        RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL => Ok(()),
        RUNTIME_PROFILE_RUNC | RUNTIME_PROFILE_NONE | "" => {
            if allow_diagnostic {
                Ok(())
            } else {
                Err(format!(
                    "managed sandboxes require an approved runtime profile; {:?} is diagnostic-only",
                    spec.profile
                ))
            }
        }
        other => Err(format!(
            "unsupported managed sandbox runtime profile {other:?}"
        )),
    }
}

fn normalize_runtime_profile(profile: &str) -> String {
    match profile.trim() {
        ""
        | RUNTIME_PROFILE_NONE
        | RUNTIME_PROFILE_RUNC
        | RUNTIME_PROFILE_COMMODITY
        | RUNTIME_PROFILE_CONFIDENTIAL
        | RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN => profile.trim().to_string(),
        RUNTIME_CLASS_EXTERNAL_ISOL8_XEN => RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN.to_string(),
        other => other.to_string(),
    }
}

fn profile_from_legacy_runtime_class(runtime_class_name: &str) -> String {
    match runtime_class_name.trim() {
        "" => RUNTIME_PROFILE_NONE.to_string(),
        RUNTIME_CLASS_RUNC => RUNTIME_PROFILE_RUNC.to_string(),
        RUNTIME_CLASS_COMMODITY => RUNTIME_PROFILE_COMMODITY.to_string(),
        RUNTIME_CLASS_CONFIDENTIAL => RUNTIME_PROFILE_CONFIDENTIAL.to_string(),
        RUNTIME_CLASS_EXTERNAL_ISOL8_XEN => RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN.to_string(),
        other => other.to_string(),
    }
}

fn runtime_class_for_profile(profile: &str, legacy_runtime_class: &str) -> String {
    match profile {
        RUNTIME_PROFILE_NONE => String::new(),
        RUNTIME_PROFILE_RUNC => RUNTIME_CLASS_RUNC.to_string(),
        RUNTIME_PROFILE_COMMODITY => RUNTIME_CLASS_COMMODITY.to_string(),
        RUNTIME_PROFILE_CONFIDENTIAL => RUNTIME_CLASS_CONFIDENTIAL.to_string(),
        RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN => RUNTIME_CLASS_EXTERNAL_ISOL8_XEN.to_string(),
        _ if !legacy_runtime_class.is_empty() => legacy_runtime_class.to_string(),
        _ => profile.to_string(),
    }
}

fn resolve_docker_mode(profile: &str, docker_mode: &str, dind_enabled: bool) -> String {
    let docker_mode = docker_mode.trim();
    if !docker_mode.is_empty() && docker_mode != DOCKER_MODE_PROFILE_DEFAULT {
        return docker_mode.to_string();
    }
    if dind_enabled {
        return DOCKER_MODE_LOCAL_DIND_DIRECT.to_string();
    }
    match profile {
        RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN => DOCKER_MODE_EXTERNAL_ISOL8_PROXY.to_string(),
        RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL => {
            DOCKER_MODE_GUEST_DIND.to_string()
        }
        _ => DOCKER_MODE_NONE.to_string(),
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

/// Mirrors `sandbox.Isol8Tolerations`.
pub fn isol8_tolerations() -> Vec<Toleration> {
    vec![
        Toleration {
            key: "isol8.codewire.sh/xen".into(),
            operator: "Equal".into(),
            value: "true".into(),
            effect: "NoSchedule".into(),
        },
        Toleration {
            key: "node.kubernetes.io/memory-pressure".into(),
            operator: "Exists".into(),
            value: String::new(),
            effect: "NoSchedule".into(),
        },
    ]
}

/// Mirrors `sandbox.DefaultTolerations`: external isol8 taints only when
/// targeting external-isol8-xen.
pub fn default_tolerations(runtime_profile_or_class: &str) -> Vec<Toleration> {
    if profile_from_legacy_runtime_class(&normalize_runtime_profile(runtime_profile_or_class))
        != RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN
    {
        return Vec::new();
    }
    isol8_tolerations()
}

/// Mirrors `sandbox.DefaultNodeSelector`.
pub fn default_node_selector(runtime_profile_or_class: &str) -> Vec<(String, String)> {
    if profile_from_legacy_runtime_class(&normalize_runtime_profile(runtime_profile_or_class))
        != RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN
    {
        return Vec::new();
    }
    vec![
        ("codewire.sh/node-pool".into(), "sandbox".into()),
        ("isol8.codewire.sh/enabled".into(), "true".into()),
    ]
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

/// Mirrors `sandbox.RenderSandboxTemplate`.
pub fn render_sandbox_template(namespace: &str, opts: &TemplateOpts) -> Value {
    let support_image = if opts.support_image.is_empty() {
        DEFAULT_GATEWAY_IMAGE
    } else {
        &opts.support_image
    };

    const ENSURE_USER_CMD: &str = "user_shell=/bin/bash; [ -x /bin/bash ] || user_shell=/bin/sh; grep -q '^[^:]*:[^:]*:1000:' /etc/passwd || echo \"codewire:x:1000:1000:codewire:/home/codewire:${user_shell}\" >> /etc/passwd; grep -q '^[^:]*:[^:]*:1000:' /etc/group || echo 'codewire:x:1000:' >> /etc/group;";
    const WAIT_DAEMON_CMD: &str = "while [ ! -x /codewire/bin/cw ]; do sleep 0.1; done;";

    let ws_command: Vec<Value> = if !opts.image_command.is_empty() {
        let entrypoint = opts.image_command.join(" ");
        vec![
            "sh".into(),
            "-c".into(),
            custom_workspace_supervisor_command(
                ENSURE_USER_CMD,
                WAIT_DAEMON_CMD,
                "/codewire/bin/cw daemon",
                &entrypoint,
            )
            .into(),
        ]
    } else {
        vec![
            "sh".into(),
            "-c".into(),
            format!("{ENSURE_USER_CMD} {WAIT_DAEMON_CMD} exec /codewire/bin/cw daemon").into(),
        ]
    };

    let mut ws_container = json!({
        "name": "workspace",
        "image": opts.image,
        "command": ws_command,
        "env": build_workspace_env(opts),
        "ports": [
            { "name": "daemon", "containerPort": WORKSPACE_DAEMON_PORT, "protocol": "TCP" },
        ],
        "resources": {
            "requests": {
                "cpu": format!("{}m", opts.cpu_millicores),
                "memory": format!("{}Mi", opts.memory_mib),
                "ephemeral-storage": format!("{WORKSPACE_EPHEMERAL_STORAGE_GI}Gi"),
            },
            "limits": {
                "cpu": format!("{}m", opts.cpu_millicores),
                "memory": format!("{}Mi", opts.memory_mib),
                "ephemeral-storage": format!("{WORKSPACE_EPHEMERAL_STORAGE_GI}Gi"),
            },
        },
        "resizePolicy": [
            { "resourceName": "cpu", "restartPolicy": "NotRequired" },
            { "resourceName": "memory", "restartPolicy": "NotRequired" },
        ],
        "volumeMounts": [
            { "name": "workspace", "mountPath": "/home/codewire" },
            { "name": "workspace", "mountPath": "/workspace" },
            { "name": "codewire-bin", "mountPath": "/codewire/bin" },
            { "name": "codewire-run", "mountPath": "/codewire/run" },
        ],
    });

    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxTemplate",
        "metadata": { "name": opts.name, "namespace": namespace },
        "spec": build_template_spec(opts, &mut ws_container, support_image),
    })
}

fn custom_workspace_supervisor_command(
    ensure_user: &str,
    wait_daemon: &str,
    daemon_command: &str,
    entrypoint: &str,
) -> String {
    format!(
        "{ensure_user} {wait_daemon} \
         {daemon_command} & daemon_pid=$!; \
         {entrypoint} & workload_pid=$!; \
         shutdown() {{ \
           kill \"$workload_pid\" \"$daemon_pid\" 2>/dev/null || true; \
           wait \"$workload_pid\" 2>/dev/null || true; \
           wait \"$daemon_pid\" 2>/dev/null || true; \
         }}; \
         trap 'shutdown; exit 0' TERM INT; \
         while kill -0 \"$workload_pid\" 2>/dev/null; do \
           if ! kill -0 \"$daemon_pid\" 2>/dev/null; then \
             wait \"$daemon_pid\" 2>/dev/null || true; \
             sleep 1; \
             {daemon_command} & daemon_pid=$!; \
           fi; \
           sleep 1; \
         done; \
         wait \"$workload_pid\"; status=$?; \
         kill \"$daemon_pid\" 2>/dev/null || true; \
         wait \"$daemon_pid\" 2>/dev/null || true; \
         exit \"$status\""
    )
}

fn build_template_spec(opts: &TemplateOpts, ws: &mut Value, support_image: &str) -> Value {
    let runtime_spec = opts.runtime_profile_spec();
    let mut annotations = Map::new();
    annotations.insert(WORKSPACE_ANNOTATION_KEY.into(), "true".into());
    if opts.disk_gib > 0 {
        annotations.insert(
            WORKSPACE_DISK_GIB_ANNOTATION_KEY.into(),
            format!("{}", opts.disk_gib).into(),
        );
    }
    if runtime_spec.profile == RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN {
        annotations.insert(ISOL8_WORKSPACE_ANNOTATION_KEY.into(), "true".into());
        if opts.disk_gib > 0 {
            annotations.insert(
                ISOL8_DISK_GIB_ANNOTATION_KEY.into(),
                format!("{}", opts.disk_gib).into(),
            );
        }
    }
    if uses_kata_policy_init_data(opts, &runtime_spec) {
        annotations.insert(
            KATA_COCO_INIT_DATA_ANNOTATION_KEY.into(),
            kata_policy_init_data_annotation(opts).into(),
        );
    }
    if let Some(kernel_params) = kata_coco_kernel_params_annotation(opts, &runtime_spec) {
        annotations.insert(
            KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY.into(),
            kernel_params.into(),
        );
    }

    let labels = workspace_template_labels();
    let mut spec = Map::new();
    spec.insert(
        "podTemplate".into(),
        json!({
            "metadata": { "annotations": annotations, "labels": labels },
            "spec": build_pod_spec(opts, ws, support_image),
        }),
    );
    if !opts.network_policy_management.is_empty() && opts.network_policy_management != "Managed" {
        spec.insert(
            "networkPolicyManagement".into(),
            opts.network_policy_management.clone().into(),
        );
    }

    if opts.disk_gib > 0 {
        let storage_class = workspace_storage_class(opts);
        spec.insert(
            "volumeClaimTemplates".into(),
            json!([{
                "metadata": { "name": "workspace" },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": storage_class,
                    "resources": { "requests": { "storage": format!("{}Gi", opts.disk_gib) } },
                },
            }]),
        );
    }

    let egress = workspace_egress_rules(opts);
    spec.insert("networkPolicy".into(), json!({ "egress": egress }));

    Value::Object(spec)
}

fn workspace_egress_rules(opts: &TemplateOpts) -> Vec<Value> {
    let mut egress = vec![
        json!({
            "to": [
                { "ipBlock": { "cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"] } },
                { "ipBlock": { "cidr": "::/0", "except": ["fc00::/7"] } },
            ],
        }),
        json!({
            "to": [
                { "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } } },
            ],
            "ports": [
                { "protocol": "UDP", "port": 53 },
                { "protocol": "TCP", "port": 53 },
            ],
        }),
        json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/name": "rke2-ingress-nginx" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": 443 },
                { "protocol": "TCP", "port": 80 },
            ],
        }),
    ];
    if let Some(rule) = kata_coco_kbs_egress_rule(&opts.kata_coco_kbs_url) {
        egress.push(rule);
    }
    egress
}

fn tailnet_udp_listener_enabled(opts: &TemplateOpts) -> bool {
    direct_udp_ingress_enabled(opts)
        || gateway_direct_udp_endpoint(opts).is_some()
        || !opts.udp_relay_allocator_url.trim().is_empty()
        || !opts.udp_relay_bind_addrs.trim().is_empty()
}

fn direct_udp_ingress_enabled(opts: &TemplateOpts) -> bool {
    !opts.stun_host.trim().is_empty() || !opts.stun_servers.trim().is_empty()
}

fn gateway_direct_udp_endpoint(opts: &TemplateOpts) -> Option<String> {
    if !opts.direct_udp_lb_enabled {
        return None;
    }
    let ip = opts.direct_udp_lb_ip.trim();
    if ip.is_empty() || opts.direct_udp_lb_port <= 0 || opts.direct_udp_lb_port > 65535 {
        return None;
    }
    Some(format!("{ip}:{}", opts.direct_udp_lb_port))
}

fn kata_coco_kbs_egress_rule(kbs_url: &str) -> Option<Value> {
    let parsed = url::Url::parse(kbs_url.trim()).ok()?;
    let host = parsed.host_str()?.trim_end_matches('.');
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2] != "svc" {
        return None;
    }

    let port = parsed.port_or_known_default()? as i64;
    Some(json!({
        "to": [
            {
                "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": parts[1] } },
                "podSelector": { "matchLabels": { "app.kubernetes.io/name": parts[0] } },
            },
        ],
        "ports": [
            { "protocol": "TCP", "port": port },
        ],
    }))
}

fn uses_kata_policy_init_data(opts: &TemplateOpts, runtime_spec: &RuntimeProfileSpec) -> bool {
    let profile = runtime_spec.profile.as_str();
    (opts.kata_agent_policy_enabled
        && matches!(
            profile,
            RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL
        ))
        || (opts.kata_coco_init_data_enabled && matches!(profile, RUNTIME_PROFILE_CONFIDENTIAL))
}

fn kata_coco_kernel_params_annotation(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
) -> Option<String> {
    if runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL || !opts.kata_coco_init_data_enabled {
        return None;
    }
    let kbs_url = kernel_param_value(&opts.kata_coco_kbs_url)?;
    let mut params = Vec::new();
    let auth_uri = opts.kata_coco_image_registry_auth_uri.trim();
    if !auth_uri.is_empty() {
        let auth_uri = kernel_param_value(auth_uri)?;
        params.push(format!("agent.image_registry_auth={auth_uri}"));
    }
    params.push("agent.guest_components_rest_api=resource".to_string());
    params.push(format!("agent.aa_kbc_params=cc_kbc::{kbs_url}"));
    Some(params.join(" "))
}

fn kernel_param_value(raw: &str) -> Option<&str> {
    let value = raw.trim();
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        None
    } else {
        Some(value)
    }
}

fn kata_policy_init_data_annotation(opts: &TemplateOpts) -> String {
    gzip_base64(&build_codewire_kata_policy_init_data(
        &opts.kata_coco_kbs_url,
        &opts.kata_coco_test_resource_uri,
        &opts.kata_coco_test_resource_path,
    ))
}

fn build_codewire_kata_policy_init_data(
    kbs_url: &str,
    test_resource_uri: &str,
    test_resource_path: &str,
) -> String {
    let mut payload = format!(
        "version = \"0.1.0\"\nalgorithm = \"sha256\"\n\n[data]\n\"policy.rego\" = '''\n{CODEWIRE_KATA_AGENT_POLICY_REGO}'''\n"
    );

    let kbs_url = kbs_url.trim();
    if kbs_url.is_empty() {
        return payload;
    }
    let _ = test_resource_uri;
    let _ = test_resource_path;

    payload.push_str("\n\"aa.toml\" = '''\n[token_configs]\n[token_configs.kbs]\nurl = ");
    payload.push_str(&toml_string(kbs_url));
    payload.push_str("\n'''\n\n\"cdh.toml\" = '''\nsocket = \"unix:///run/confidential-containers/cdh.sock\"\n\n[kbc]\nname = \"cc_kbc\"\nurl = ");
    payload.push_str(&toml_string(kbs_url));
    payload.push('\n');
    payload.push_str("'''\n");
    payload
}

fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn gzip_base64(payload: &str) -> String {
    let data = payload.as_bytes();
    let mut out = Vec::with_capacity(data.len() + 32);
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);

    let mut write_block = |chunk: &[u8], final_block: bool| {
        out.push(if final_block { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    };

    if data.is_empty() {
        write_block(&[], true);
    } else {
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + 65_535).min(data.len());
            write_block(&data[offset..end], end == data.len());
            offset = end;
        }
    }

    let mut hasher = Crc32Hasher::new();
    hasher.update(data);
    out.extend_from_slice(&hasher.finalize().to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());

    base64::engine::general_purpose::STANDARD.encode(out)
}

fn workspace_storage_class(opts: &TemplateOpts) -> &str {
    let storage_class = opts.workspace_storage_class.trim();
    if storage_class.is_empty() {
        DEFAULT_WORKSPACE_STORAGE_CLASS
    } else {
        storage_class
    }
}

fn build_pod_spec(opts: &TemplateOpts, ws: &mut Value, support_image: &str) -> Value {
    let runtime_spec = opts.runtime_profile_spec();
    let mut volumes = vec![
        json!({ "name": "codewire-bin", "emptyDir": {} }),
        json!({ "name": "codewire-run", "emptyDir": {} }),
    ];
    if opts.disk_gib == 0 {
        volumes.insert(0, json!({ "name": "workspace", "emptyDir": {} }));
    }

    let mut spec = Map::new();
    spec.insert("restartPolicy".into(), "Never".into());
    spec.insert("serviceAccountName".into(), SANDBOX_SERVICE_ACCOUNT.into());
    spec.insert(
        "securityContext".into(),
        json!({ "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000 }),
    );
    spec.insert("dnsPolicy".into(), "ClusterFirst".into());

    if !runtime_spec.runtime_class_name.is_empty() {
        spec.insert(
            "runtimeClassName".into(),
            runtime_spec.runtime_class_name.clone().into(),
        );
    }
    if !opts.node_selector.is_empty() {
        let sel: Map<String, Value> = opts
            .node_selector
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        spec.insert("nodeSelector".into(), Value::Object(sel));
    }
    if !opts.tolerations.is_empty() {
        let tolerations: Vec<Value> = opts
            .tolerations
            .iter()
            .map(|t| {
                let mut tol = Map::new();
                tol.insert("key".into(), t.key.clone().into());
                tol.insert("operator".into(), t.operator.clone().into());
                tol.insert("effect".into(), t.effect.clone().into());
                if !t.value.is_empty() {
                    tol.insert("value".into(), t.value.clone().into());
                }
                Value::Object(tol)
            })
            .collect();
        spec.insert("tolerations".into(), Value::Array(tolerations));
    }

    let mut containers: Vec<Value> = Vec::new();
    if runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT
        || runtime_spec.docker_mode == DOCKER_MODE_GUEST_DIND
    {
        volumes.push(json!({ "name": "docker-sock", "emptyDir": {} }));
    }

    if runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT {
        // Local-kind: workspace talks directly to the DinD socket.
        ws["env"]
            .as_array_mut()
            .expect("ws env array")
            .push(json!({ "name": "DOCKER_HOST", "value": "unix:///var/run/docker/docker.sock" }));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("ws mounts array")
            .push(json!({ "name": "docker-sock", "mountPath": "/var/run/docker" }));

        containers.push(ws.clone());
        containers.push(dind_container(opts, &runtime_spec, false));
    } else if runtime_spec.docker_mode == DOCKER_MODE_GUEST_DIND {
        // Split gateway mode: keep dockerd inside the workspace runtime
        // boundary. The Docker API hardening proxy is tracked separately.
        ws["env"]
            .as_array_mut()
            .expect("ws env array")
            .push(json!({ "name": "DOCKER_HOST", "value": "unix:///var/run/docker/docker.sock" }));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("ws mounts array")
            .push(json!({ "name": "docker-sock", "mountPath": "/var/run/docker" }));

        containers.push(ws.clone());
        containers.push(dind_container(opts, &runtime_spec, true));
    } else {
        containers.push(ws.clone());
    }

    spec.insert(
        "initContainers".into(),
        json!([daemon_init_container(support_image)]),
    );
    spec.insert("containers".into(), Value::Array(containers));
    spec.insert("volumes".into(), Value::Array(volumes));
    Value::Object(spec)
}

fn daemon_init_container(support_image: &str) -> Value {
    json!({
        "name": "codewire-daemon-init",
        "image": support_image,
        "command": [
            "sh", "-c",
            "cp /usr/local/bin/cw /codewire/bin/.cw.tmp && chmod 0755 /codewire/bin/.cw.tmp && mv /codewire/bin/.cw.tmp /codewire/bin/cw && ln -sf cw /codewire/bin/daemon && ln -sf cw /codewire/bin/codewire-daemon",
        ],
        "volumeMounts": [
            { "name": "codewire-bin", "mountPath": "/codewire/bin" },
        ],
        "resources": {
            "requests": { "cpu": "25m", "memory": "32Mi" },
            "limits": { "cpu": "100m", "memory": "128Mi" },
        },
    })
}

fn docker_data_size_gib(disk_gib: i64) -> i64 {
    if disk_gib <= 0 {
        return 8;
    }
    if disk_gib <= 4 {
        return 2;
    }
    disk_gib - 2
}

fn dind_memory_limit_gib(memory_mib: i64) -> i64 {
    if memory_mib >= 8192 { 4 } else { 2 }
}

fn dind_image(opts: &TemplateOpts) -> &str {
    let image = opts.dind_image.trim();
    if image.is_empty() {
        DEFAULT_DIND_IMAGE
    } else {
        image
    }
}

fn dind_bootstrap_script() -> String {
    format!(
        r#"data_image="${{CODEWIRE_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}}"
data_root="${{CODEWIRE_DOCKER_DATA_ROOT:-/var/lib/docker}}"
data_size="${{CODEWIRE_DOCKER_DATA_SIZE:-8G}}"
mount_mode="${{CODEWIRE_DOCKER_MOUNT_MODE:-loop}}"
codewire_dir="$(dirname "$data_image")"
mkdir -p "$codewire_dir" "$data_root"
chown 1000:1000 "$codewire_dir"
chmod 0775 "$codewire_dir"
if [ "$mount_mode" = "loop" ]; then
  if [ ! -s "$data_image" ]; then
    truncate -s "$data_size" "$data_image"
    mkfs.ext4 -q -F "$data_image"
  fi
  if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" {{ found = 1 }} END {{ exit found ? 0 : 1 }}' /proc/mounts; then
    mount -o loop "$data_image" "$data_root"
  fi
elif [ "$mount_mode" != "none" ]; then
  echo "unsupported CODEWIRE_DOCKER_MOUNT_MODE=$mount_mode" >&2
  exit 1
fi
exec dockerd --host "unix://{GATEWAY_DOCKER_UPSTREAM_SOCK_PATH}" --group 1000 --data-root "$data_root" --storage-driver vfs"#
    )
}

fn dind_container(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
    ext4_data_root: bool,
) -> Value {
    let command = if ext4_data_root {
        json!(["sh", "-ec", dind_bootstrap_script()])
    } else {
        json!([
            "dockerd",
            "--host",
            format!("unix://{GATEWAY_DOCKER_UPSTREAM_SOCK_PATH}"),
            "--group",
            "1000",
            "--storage-driver",
            "vfs"
        ])
    };
    let env = if ext4_data_root {
        let (data_root, mount_mode) = if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
            ("/workspace/.codewire/docker-root", "none")
        } else {
            ("/var/lib/docker", "loop")
        };
        json!([
            { "name": "DOCKER_TLS_CERTDIR", "value": "" },
            { "name": "CODEWIRE_DOCKER_DATA_IMAGE", "value": "/workspace/.codewire/docker-data.ext4" },
            { "name": "CODEWIRE_DOCKER_DATA_ROOT", "value": data_root },
            { "name": "CODEWIRE_DOCKER_DATA_SIZE", "value": format!("{}G", docker_data_size_gib(opts.disk_gib)) },
            { "name": "CODEWIRE_DOCKER_MOUNT_MODE", "value": mount_mode },
        ])
    } else {
        json!([ { "name": "DOCKER_TLS_CERTDIR", "value": "" } ])
    };

    json!({
        "name": "dind",
        "image": dind_image(opts),
        "command": command,
        "securityContext": { "privileged": true, "runAsUser": 0, "runAsGroup": 0 },
        "env": env,
        "volumeMounts": [
            { "name": "docker-sock", "mountPath": "/var/run/docker" },
            { "name": "workspace", "mountPath": "/workspace" },
        ],
        "resources": {
            "requests": { "cpu": "500m", "memory": "1Gi" },
            "limits": { "cpu": "2", "memory": format!("{}Gi", dind_memory_limit_gib(opts.memory_mib)) },
        },
    })
}

fn build_workspace_env(opts: &TemplateOpts) -> Vec<Value> {
    let mut env = vec![
        json!({ "name": "CODEWIRE_WORKSPACE_SHIM_ADDR", "value": WORKSPACE_DAEMON_LISTEN_ADDR }),
        json!({ "name": "HOME", "value": HOME_ROOT }),
        json!({ "name": "USER", "value": "codewire" }),
    ];
    if !opts.gateway_token.is_empty() {
        env.push(json!({ "name": DAEMON_AUTH_TOKEN_ENV, "value": opts.gateway_token }));
    }
    env
}

fn gateway_http_probe(failure_threshold: i64) -> Value {
    json!({
        "httpGet": { "path": "/readyz", "port": DEFAULT_GATEWAY_READYZ_PORT },
        "periodSeconds": 2,
        "timeoutSeconds": 2,
        "failureThreshold": failure_threshold,
    })
}

fn apply_sidecar_probes(gateway: &mut Value) {
    gateway["startupProbe"] = gateway_http_probe(45);
    gateway["readinessProbe"] = gateway_http_probe(3);
}

fn build_sidecar_env(opts: &TemplateOpts) -> Vec<Value> {
    let mut env = vec![json!({
        "name": "CODEWIRE_WORKSPACE_SHIM_ADDR",
        "value": workspace_daemon_service_addr(&opts.environment_id),
    })];
    if !opts.gateway_token.is_empty() {
        env.push(json!({ "name": DAEMON_AUTH_TOKEN_ENV, "value": opts.gateway_token }));
    }
    if !opts.environment_id.is_empty() {
        env.push(json!({ "name": "CODEWIRE_ENVIRONMENT_ID", "value": opts.environment_id }));
    }
    if !opts.gateway_token.is_empty() {
        env.push(json!({ "name": "CODEWIRE_GATEWAY_TOKEN", "value": opts.gateway_token }));
    }
    if !opts.api_base_url.is_empty() {
        env.push(json!({ "name": "CODEWIRE_API_URL", "value": opts.api_base_url }));
    }
    if let Some(binding_url) = gateway_binding_url(opts) {
        env.push(json!({
            "name": GATEWAY_BINDING_URL_ENV,
            "value": binding_url,
        }));
    }
    if let Some(coordinator_url) = gateway_coordinator_url(opts) {
        env.push(json!({
            "name": "CODEWIRE_COORDINATOR_URL",
            "value": coordinator_url,
        }));
    }
    if !opts.server_namespace.is_empty() {
        env.push(json!({ "name": "CODEWIRE_SERVER_NAMESPACE", "value": opts.server_namespace }));
    }
    if let Some(derp_url) = gateway_derp_url(opts) {
        env.push(json!({ "name": "CODEWIRE_DERP_URL", "value": derp_url }));
    }
    if !opts.stun_host.is_empty() {
        env.push(json!({ "name": "CODEWIRE_STUN_HOST", "value": opts.stun_host }));
        env.push(json!({ "name": "CODEWIRE_STUN_PORT", "value": opts.stun_port.to_string() }));
    }
    if !opts.stun_servers.is_empty() {
        env.push(json!({ "name": "CODEWIRE_STUN_SERVERS", "value": opts.stun_servers }));
    }
    if tailnet_udp_listener_enabled(opts) {
        env.push(json!({
            "name": GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV,
            "value": GATEWAY_TAILNET_UDP_LISTEN_ADDR,
        }));
    }
    if let Some(endpoint) = gateway_direct_udp_endpoint(opts) {
        env.push(json!({
            "name": GATEWAY_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV,
            "value": endpoint,
        }));
    }
    if !opts.udp_relay_allocator_url.trim().is_empty() {
        env.push(json!({
            "name": GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV,
            "value": opts.udp_relay_allocator_url,
        }));
    }
    if !opts.udp_relay_allocator_token.trim().is_empty() {
        env.push(json!({
            "name": GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV,
            "value": opts.udp_relay_allocator_token,
        }));
    }
    if !opts.udp_relay_bind_addrs.trim().is_empty() {
        env.push(json!({
            "name": GATEWAY_UDP_RELAY_BIND_ADDRS_ENV,
            "value": opts.udp_relay_bind_addrs,
        }));
    }
    if opts.debug_tailnet {
        env.push(json!({ "name": "CODEWIRE_DEBUG_TAILNET", "value": "1" }));
    }
    env.push(json!({
        "name": "CODEWIRE_SSH_HOST_KEY_PATH",
        "value": GATEWAY_HOST_KEY_PATH,
    }));
    env.push(json!({
        "name": "POD_NAMESPACE",
        "valueFrom": { "fieldRef": { "fieldPath": "metadata.namespace" } },
    }));
    env
}

pub fn gateway_workload_name(env_id: &str) -> String {
    dns_name("cw-gateway", env_id)
}

pub fn workspace_daemon_service_name(env_id: &str) -> String {
    dns_name("cw-daemon", env_id)
}

pub fn gateway_service_name(env_id: &str) -> String {
    dns_name("cw-gateway-svc", env_id)
}

pub fn gateway_direct_udp_service_name(env_id: &str) -> String {
    dns_name("cw-gateway-udp", env_id)
}

pub fn gateway_network_policy_name(env_id: &str) -> String {
    dns_name("cw-gw-net", env_id)
}

pub fn gateway_host_key_secret_name(env_id: &str) -> String {
    dns_name("cw-gateway-host-key", env_id)
}

pub fn workspace_daemon_network_policy_name(env_id: &str) -> String {
    dns_name("cw-daemon-net", env_id)
}

fn dns_name(prefix: &str, suffix: &str) -> String {
    let suffix = suffix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let mut name = format!("{prefix}-{suffix}");
    if name.len() > 63 {
        name.truncate(63);
    }
    while name.ends_with('-') {
        name.pop();
    }
    if name.is_empty() {
        prefix.to_string()
    } else {
        name
    }
}

pub fn workspace_daemon_service_addr(env_id: &str) -> String {
    format!(
        "{}:{}",
        workspace_daemon_service_name(env_id),
        WORKSPACE_DAEMON_PORT
    )
}

fn workspace_selector(opts: &TemplateOpts) -> Value {
    json!({
        "codewire.sh/environment-id": opts.environment_id,
        "codewire.sh/type": "workspace",
    })
}

fn workspace_template_labels() -> Value {
    json!({
        "codewire.sh/type": "workspace",
    })
}

fn gateway_selector(opts: &TemplateOpts) -> Value {
    json!({
        "codewire.sh/environment-id": opts.environment_id,
        "codewire.sh/type": "gateway",
    })
}

fn gateway_labels(opts: &TemplateOpts) -> Value {
    let mut labels = gateway_selector(opts);
    let object = labels.as_object_mut().expect("labels object");
    object.insert("app.kubernetes.io/name".into(), "codewire-gateway".into());
    object.insert("app.kubernetes.io/component".into(), "gateway".into());
    object.insert("app.kubernetes.io/managed-by".into(), "codewire".into());
    labels
}

pub fn render_workspace_daemon_service(namespace: &str, opts: &TemplateOpts) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": workspace_daemon_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "codewire-workspace-daemon",
                "app.kubernetes.io/component": "workspace-daemon",
                "app.kubernetes.io/managed-by": "codewire",
                "codewire.sh/environment-id": opts.environment_id,
                "codewire.sh/type": "workspace-daemon",
            },
        },
        "spec": {
            "type": "ClusterIP",
            "selector": workspace_selector(opts),
            "ports": [
                { "name": "daemon", "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT, "targetPort": WORKSPACE_DAEMON_PORT },
            ],
        },
    })
}

pub fn render_gateway_service(namespace: &str, opts: &TemplateOpts) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": gateway_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": gateway_labels(opts),
        },
        "spec": {
            "type": "ClusterIP",
            "selector": gateway_selector(opts),
            "ports": [
                { "name": "ssh", "protocol": "TCP", "port": DEFAULT_GATEWAY_SSH_PORT, "targetPort": DEFAULT_GATEWAY_SSH_PORT },
                { "name": "readyz", "protocol": "TCP", "port": DEFAULT_GATEWAY_READYZ_PORT, "targetPort": DEFAULT_GATEWAY_READYZ_PORT },
                { "name": "tailnet-udp", "protocol": "UDP", "port": GATEWAY_TAILNET_UDP_PORT, "targetPort": GATEWAY_TAILNET_UDP_PORT },
            ],
        },
    })
}

pub fn render_gateway_direct_udp_service(namespace: &str, opts: &TemplateOpts) -> Option<Value> {
    let _endpoint = gateway_direct_udp_endpoint(opts)?;
    let lb_class = opts.direct_udp_lb_class.trim();
    let sharing_key = opts.direct_udp_lb_sharing_key.trim();
    let mut annotations = Map::new();
    annotations.insert(
        "lbipam.cilium.io/ips".into(),
        opts.direct_udp_lb_ip.trim().into(),
    );
    if !sharing_key.is_empty() {
        annotations.insert("lbipam.cilium.io/sharing-key".into(), sharing_key.into());
        annotations.insert(
            "lbipam.cilium.io/sharing-cross-namespace".into(),
            "*".into(),
        );
    }

    let mut labels = gateway_labels(opts);
    let labels_obj = labels.as_object_mut().expect("labels object");
    labels_obj.insert("codewire.sh/type".into(), "direct-udp-lb".into());
    labels_obj.insert("codewire.sh/runtime-network".into(), "direct-udp".into());
    labels_obj.insert("codewire.sh/transport".into(), "direct-udp".into());
    if !opts.direct_udp_transport_zone.trim().is_empty() {
        labels_obj.insert(
            "codewire.sh/transport-zone".into(),
            opts.direct_udp_transport_zone.trim().into(),
        );
    }

    let mut spec = json!({
        "type": "LoadBalancer",
        "allocateLoadBalancerNodePorts": false,
        "ipFamilyPolicy": "SingleStack",
        "ipFamilies": ["IPv4"],
        "externalTrafficPolicy": "Cluster",
        "selector": gateway_selector(opts),
        "ports": [
            {
                "name": "tailnet-udp",
                "protocol": "UDP",
                "port": opts.direct_udp_lb_port,
                "targetPort": GATEWAY_TAILNET_UDP_PORT,
            },
        ],
    });
    if !lb_class.is_empty() {
        spec["loadBalancerClass"] = lb_class.into();
    }

    Some(json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": gateway_direct_udp_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": spec,
    }))
}

pub fn render_gateway_host_key_secret(
    namespace: &str,
    opts: &TemplateOpts,
    host_key_openssh: &str,
) -> Value {
    let mut string_data = Map::new();
    string_data.insert(GATEWAY_HOST_KEY_SECRET_KEY.into(), host_key_openssh.into());

    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": gateway_host_key_secret_name(&opts.environment_id),
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "codewire-gateway",
                "app.kubernetes.io/component": "gateway-host-key",
                "app.kubernetes.io/managed-by": "codewire",
                "codewire.sh/environment-id": opts.environment_id,
                "codewire.sh/type": "gateway-host-key",
            },
        },
        "type": "Opaque",
        "stringData": Value::Object(string_data),
    })
}

fn gateway_host_key_init_container(support_image: &str) -> Value {
    json!({
        "name": "codewire-gateway-host-key-init",
        "image": support_image,
        "command": [
            "sh",
            "-ec",
            format!(
                "umask 077; mkdir -p /codewire/gateway/ssh; cp {}/{} {}; chmod 0600 {}",
                GATEWAY_HOST_KEY_SECRET_MOUNT_PATH,
                GATEWAY_HOST_KEY_SECRET_KEY,
                GATEWAY_HOST_KEY_PATH,
                GATEWAY_HOST_KEY_PATH,
            ),
        ],
        "volumeMounts": [
            { "name": "gateway-state", "mountPath": "/codewire/gateway" },
            { "name": "gateway-host-key", "mountPath": GATEWAY_HOST_KEY_SECRET_MOUNT_PATH, "readOnly": true },
        ],
        "resources": {
            "requests": { "cpu": "10m", "memory": "16Mi" },
            "limits": { "cpu": "50m", "memory": "64Mi" },
        },
    })
}

pub fn render_gateway_deployment(namespace: &str, opts: &TemplateOpts) -> Value {
    let runtime_spec = opts.runtime_profile_spec();
    let support_image = if opts.support_image.is_empty() {
        DEFAULT_GATEWAY_IMAGE
    } else {
        &opts.support_image
    };
    let labels = gateway_labels(opts);
    let mut gateway_container = json!({
        "name": "codewire-gateway",
        "image": support_image,
        "command": ["/usr/local/bin/codewire-gateway"],
        "env": build_sidecar_env(opts),
        "ports": [
            { "name": "ssh", "containerPort": DEFAULT_GATEWAY_SSH_PORT, "protocol": "TCP" },
            { "name": "readyz", "containerPort": DEFAULT_GATEWAY_READYZ_PORT, "protocol": "TCP" },
            { "name": "tailnet-udp", "containerPort": GATEWAY_TAILNET_UDP_PORT, "protocol": "UDP" },
        ],
        "volumeMounts": [
            { "name": "gateway-state", "mountPath": "/codewire/gateway" },
        ],
        "resources": {
            "requests": { "cpu": "100m", "memory": "128Mi" },
            "limits": { "cpu": "500m", "memory": "256Mi" },
        },
    });
    apply_sidecar_probes(&mut gateway_container);

    let mut pod_spec = Map::new();
    pod_spec.insert("serviceAccountName".into(), SANDBOX_SERVICE_ACCOUNT.into());
    pod_spec.insert("automountServiceAccountToken".into(), false.into());
    pod_spec.insert(
        "securityContext".into(),
        json!({ "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000 }),
    );
    pod_spec.insert("dnsPolicy".into(), "ClusterFirst".into());
    pod_spec.insert(
        "initContainers".into(),
        json!([gateway_host_key_init_container(support_image)]),
    );
    pod_spec.insert("containers".into(), json!([gateway_container]));
    pod_spec.insert(
        "volumes".into(),
        json!([
            { "name": "gateway-state", "emptyDir": {} },
            {
                "name": "gateway-host-key",
                "secret": {
                    "secretName": gateway_host_key_secret_name(&opts.environment_id),
                    "items": [
                        {
                            "key": GATEWAY_HOST_KEY_SECRET_KEY,
                            "path": GATEWAY_HOST_KEY_SECRET_KEY,
                            "mode": 0o444,
                        },
                    ],
                },
            },
        ]),
    );
    if !runtime_spec.runtime_class_name.is_empty() {
        pod_spec.insert(
            "runtimeClassName".into(),
            runtime_spec.runtime_class_name.clone().into(),
        );
    }
    if !opts.node_selector.is_empty() {
        let sel: Map<String, Value> = opts
            .node_selector
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        pod_spec.insert("nodeSelector".into(), Value::Object(sel));
    }
    if !opts.tolerations.is_empty() {
        let tolerations: Vec<Value> = opts
            .tolerations
            .iter()
            .map(|t| {
                let mut tol = Map::new();
                tol.insert("key".into(), t.key.clone().into());
                tol.insert("operator".into(), t.operator.clone().into());
                tol.insert("effect".into(), t.effect.clone().into());
                if !t.value.is_empty() {
                    tol.insert("value".into(), t.value.clone().into());
                }
                Value::Object(tol)
            })
            .collect();
        pod_spec.insert("tolerations".into(), Value::Array(tolerations));
    }

    let mut pod_annotations = Map::new();
    if let Some(kernel_params) = kata_coco_kernel_params_annotation(opts, &runtime_spec) {
        pod_annotations.insert(
            KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY.into(),
            kernel_params.into(),
        );
    }
    let mut pod_metadata = Map::new();
    pod_metadata.insert("labels".into(), labels.clone());
    if !pod_annotations.is_empty() {
        pod_metadata.insert("annotations".into(), Value::Object(pod_annotations));
    }

    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": gateway_workload_name(&opts.environment_id),
            "namespace": namespace,
            "labels": labels,
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": gateway_selector(opts) },
            "template": {
                "metadata": Value::Object(pod_metadata),
                "spec": Value::Object(pod_spec),
            },
        },
    })
}

pub fn render_workspace_daemon_network_policy(namespace: &str, opts: &TemplateOpts) -> Value {
    let mut ingress = vec![json!({
        "from": [ { "podSelector": { "matchLabels": gateway_selector(opts) } } ],
        "ports": [
            { "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT },
            { "protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT },
        ],
    })];
    if !opts.server_namespace.is_empty() {
        ingress.push(json!({
            "from": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "codewire",
                            "app.kubernetes.io/component": "orchestration",
                        },
                    },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT },
                {
                    "protocol": "TCP",
                    "port": APP_PREVIEW_MIN_PORT,
                    "endPort": APP_PREVIEW_MAX_PORT,
                },
            ],
        }));
    }

    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": workspace_daemon_network_policy_name(&opts.environment_id),
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "codewire-workspace-daemon",
                "app.kubernetes.io/component": "workspace-daemon",
                "app.kubernetes.io/managed-by": "codewire",
                "codewire.sh/environment-id": opts.environment_id,
            },
        },
        "spec": {
            "podSelector": { "matchLabels": workspace_selector(opts) },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": ingress,
            "egress": workspace_egress_rules(opts),
        },
    })
}

pub fn render_gateway_network_policy(namespace: &str, opts: &TemplateOpts) -> Value {
    let mut egress = vec![
        json!({
            "to": [ { "podSelector": { "matchLabels": workspace_selector(opts) } } ],
            "ports": [
                { "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT },
                { "protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT },
            ],
        }),
        json!({
            "to": [
                { "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } } },
            ],
            "ports": [
                { "protocol": "UDP", "port": 53 },
                { "protocol": "TCP", "port": 53 },
            ],
        }),
        json!({
            "to": [
                { "ipBlock": { "cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"] } },
                { "ipBlock": { "cidr": "::/0", "except": ["fc00::/7"] } },
            ],
            "ports": [
                { "protocol": "TCP", "port": 443 },
                { "protocol": "UDP", "port": INTERNAL_DERP_STUN_PORT },
                { "protocol": "UDP", "port": GATEWAY_TAILNET_UDP_PORT },
            ],
        }),
    ];
    if !opts.server_namespace.is_empty() {
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "orchestration" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": 8084 },
                { "protocol": "TCP", "port": 8085 },
            ],
        }));
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "coordinator" } },
                },
            ],
            "ports": [ { "protocol": "TCP", "port": 8090 } ],
        }));
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "derp" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": INTERNAL_DERP_TLS_PORT },
                { "protocol": "UDP", "port": INTERNAL_DERP_STUN_PORT },
            ],
        }));
        if opts.udp_relay_allocator_egress_enabled
            || !opts.udp_relay_allocator_url.trim().is_empty()
        {
            egress.push(json!({
                "to": [
                    {
                        "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                        "podSelector": { "matchLabels": { "app.kubernetes.io/component": "udp-relay" } },
                    },
                ],
                "ports": [
                    { "protocol": "TCP", "port": 8095 },
                    { "protocol": "UDP", "port": 41641 },
                ],
            }));
        }
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/name": "codewire-mesh" } },
                },
            ],
            "ports": [ { "protocol": "TCP", "port": 8080 } ],
        }));
    }
    if let Some(rule) = kata_coco_kbs_egress_rule(&opts.kata_coco_kbs_url) {
        egress.push(rule);
    }

    let mut ingress = vec![json!({
        "ports": [ { "protocol": "TCP", "port": DEFAULT_GATEWAY_READYZ_PORT } ],
    })];
    if !opts.server_namespace.is_empty() {
        ingress.push(json!({
            "from": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "orchestration" } },
                },
            ],
            "ports": [ { "protocol": "TCP", "port": DEFAULT_GATEWAY_SSH_PORT } ],
        }));
    }
    if tailnet_udp_listener_enabled(opts) {
        ingress.push(json!({
            "ports": [ { "protocol": "UDP", "port": GATEWAY_TAILNET_UDP_PORT } ],
        }));
    }

    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": gateway_network_policy_name(&opts.environment_id),
            "namespace": namespace,
            "labels": gateway_labels(opts),
        },
        "spec": {
            "podSelector": { "matchLabels": gateway_selector(opts) },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": ingress,
            "egress": egress,
        },
    })
}

fn gateway_coordinator_url(opts: &TemplateOpts) -> Option<String> {
    let explicit = opts.coordinator_url.trim();
    if !explicit.is_empty() {
        return Some(explicit.to_string());
    }
    if opts.api_base_url.is_empty() {
        return None;
    }
    Some(opts.api_base_url.trim_end_matches('/').to_string())
}

fn gateway_binding_url(opts: &TemplateOpts) -> Option<String> {
    (!opts.server_namespace.is_empty()).then(|| {
        format!(
            "http://codewire-orchestration.{}.svc.cluster.local:8085",
            opts.server_namespace
        )
    })
}

/// Mirrors `sandbox.gatewayDERPURL`.
fn gateway_derp_url(opts: &TemplateOpts) -> Option<String> {
    if !opts.server_namespace.is_empty() {
        return Some(format!(
            "https://codewire-derp.{}.svc.cluster.local:{}",
            opts.server_namespace, INTERNAL_DERP_TLS_PORT
        ));
    }
    if !opts.derp_host.is_empty() && !is_loopback(&opts.derp_host) {
        let host = if opts.derp_port != 0 && opts.derp_port != 443 {
            format!("{}:{}", opts.derp_host, opts.derp_port)
        } else {
            opts.derp_host.clone()
        };
        return Some(format!("https://{host}"));
    }
    if !opts.api_base_url.is_empty()
        && let Ok(u) = url_host_scheme(&opts.api_base_url)
    {
        return Some(u);
    }
    None
}

/// `scheme://host[:port]` of a URL, mirroring the Go fallback's use of
/// `url.Parse` (`u.Scheme + "://" + u.Host`).
fn url_host_scheme(raw: &str) -> Result<String, ()> {
    let (scheme, rest) = raw.split_once("://").ok_or(())?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return Err(());
    }
    Ok(format!("{scheme}://{host}"))
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    use base64::Engine;
    use flate2::read::GzDecoder;
    use serde_json::Value;

    fn decode_gzip_base64(encoded: &str) -> String {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut decoder = GzDecoder::new(&raw[..]);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        decoded
    }

    fn load_golden(name: &str) -> Value {
        let path = format!(
            "{}/tests/fixtures/sandbox/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(
            &std::fs::read_to_string(&path).expect("Rust-owned golden file missing"),
        )
        .unwrap()
    }

    /// Inputs cover every branch represented by the checked-in fixtures.
    fn isol8_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-isol8".into(),
            image: "git.example.com/codewire/workspace:golden".into(),
            image_command: vec!["/bin/start".into(), "--flag".into()],
            support_image: "git.example.com/codewire/gateway:golden".into(),
            runtime_class_name: RUNTIME_CLASS_NAME.into(),
            node_selector: default_node_selector(RUNTIME_CLASS_NAME),
            tolerations: isol8_tolerations(),
            environment_id: "env-golden-isol8".into(),
            gateway_token: "gw-token-golden".into(),
            api_base_url: "https://codewire.sh".into(),
            server_namespace: "prod".into(),
            derp_host: "derp.codewire.sh".into(),
            derp_port: 443,
            stun_host: "stun.codewire.sh".into(),
            stun_port: 3478,
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
            network_policy_management: "Unmanaged".into(),
            debug_tailnet: true,
            ..Default::default()
        }
    }

    fn commodity_opts() -> TemplateOpts {
        TemplateOpts {
            name: "tmpl-golden-commodity".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:golden".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-golden-commodity".into(),
            gateway_token: "gw-token-golden-commodity".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            server_namespace: "dev".into(),
            derp_host: "derp.codewire-dev.sh".into(),
            derp_port: 443,
            stun_host: "stun.codewire-dev.sh".into(),
            stun_port: 3478,
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 40,
            workspace_storage_class: "local-path".into(),
            ..Default::default()
        }
    }

    #[test]
    fn workspace_declares_live_cpu_and_memory_resize_policy() {
        let template = render_sandbox_template("dev-sandboxes", &commodity_opts());
        assert_eq!(
            template.pointer("/spec/podTemplate/spec/containers/0/resizePolicy"),
            Some(&json!([
                {"resourceName": "cpu", "restartPolicy": "NotRequired"},
                {"resourceName": "memory", "restartPolicy": "NotRequired"}
            ]))
        );
    }

    #[test]
    fn runtime_profile_spec_resolves_guard_profiles() {
        assert_eq!(
            runtime_profile_spec("", RUNTIME_CLASS_RUNC, DOCKER_MODE_PROFILE_DEFAULT, false),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_RUNC.into(),
                runtime_class_name: RUNTIME_CLASS_RUNC.into(),
                docker_mode: DOCKER_MODE_NONE.into(),
                sidecar_resource_mode: SIDECAR_RESOURCE_MODE_EXPLICIT.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                RUNTIME_PROFILE_COMMODITY,
                RUNTIME_CLASS_EXTERNAL_ISOL8_XEN,
                DOCKER_MODE_PROFILE_DEFAULT,
                false,
            ),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_COMMODITY.into(),
                runtime_class_name: RUNTIME_CLASS_COMMODITY.into(),
                docker_mode: DOCKER_MODE_GUEST_DIND.into(),
                sidecar_resource_mode: SIDECAR_RESOURCE_MODE_EXPLICIT.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                "",
                RUNTIME_CLASS_EXTERNAL_ISOL8_XEN,
                DOCKER_MODE_PROFILE_DEFAULT,
                false,
            ),
            RuntimeProfileSpec {
                profile: RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN.into(),
                runtime_class_name: RUNTIME_CLASS_EXTERNAL_ISOL8_XEN.into(),
                docker_mode: DOCKER_MODE_EXTERNAL_ISOL8_PROXY.into(),
                sidecar_resource_mode: SIDECAR_RESOURCE_MODE_RUNTIME_ENVELOPE.into(),
            }
        );

        assert_eq!(
            runtime_profile_spec(
                RUNTIME_PROFILE_COMMODITY,
                RUNTIME_CLASS_COMMODITY,
                DOCKER_MODE_NONE,
                false,
            )
            .docker_mode,
            DOCKER_MODE_NONE
        );

        assert_eq!(
            runtime_profile_spec("", RUNTIME_CLASS_RUNC, DOCKER_MODE_PROFILE_DEFAULT, true)
                .docker_mode,
            DOCKER_MODE_LOCAL_DIND_DIRECT
        );
    }

    #[test]
    fn managed_runtime_validation_rejects_diagnostic_profiles() {
        let commodity = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_COMMODITY.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&commodity, false).is_ok());

        let confidential = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&confidential, false).is_ok());

        let external_isol8 = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_EXTERNAL_ISOL8_XEN.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&external_isol8, false).is_err());

        let runc = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_RUNC.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&runc, false).is_err());
        assert!(validate_managed_runtime_profile(&runc, true).is_ok());

        let none = RuntimeProfileSpec {
            profile: RUNTIME_PROFILE_NONE.into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&none, false).is_err());

        let unknown = RuntimeProfileSpec {
            profile: "kata-dev".into(),
            ..Default::default()
        };
        assert!(validate_managed_runtime_profile(&unknown, true).is_err());
    }

    #[test]
    fn commodity_template_uses_neutral_annotations_and_guest_dockerd() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                disk_gib: 40,
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        assert_eq!(
            pod_template["metadata"]["labels"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        assert!(
            pod_template["metadata"]["labels"]
                .get("codewire.sh/environment-id")
                .is_none(),
            "reusable SandboxTemplates must not pin an empty environment-id label"
        );
        assert!(
            rendered["spec"]["networkPolicy"].get("ingress").is_none(),
            "workspace daemon ingress is owned by the per-environment companion NetworkPolicy"
        );
        assert_eq!(
            annotations.get(WORKSPACE_ANNOTATION_KEY).unwrap().as_str(),
            Some("true")
        );
        assert_eq!(
            annotations
                .get(WORKSPACE_DISK_GIB_ANNOTATION_KEY)
                .unwrap()
                .as_str(),
            Some("40")
        );
        assert!(!annotations.contains_key(ISOL8_WORKSPACE_ANNOTATION_KEY));
        assert!(!annotations.contains_key(KATA_COCO_INIT_DATA_ANNOTATION_KEY));
        assert_eq!(
            pod_template["spec"]["runtimeClassName"].as_str(),
            Some(RUNTIME_CLASS_COMMODITY)
        );

        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        assert_eq!(
            containers
                .iter()
                .filter_map(|container| container["name"].as_str())
                .collect::<Vec<_>>(),
            vec!["workspace", "dind"]
        );
        assert!(
            containers
                .iter()
                .all(|container| container["name"].as_str() != Some("codewire-gateway")),
            "gateway must not share the workspace runtime pod"
        );
        let init_containers = pod_template["spec"]["initContainers"].as_array().unwrap();
        assert_eq!(
            init_containers[0]["name"].as_str(),
            Some("codewire-daemon-init")
        );
        assert_eq!(
            init_containers[0]["image"].as_str(),
            Some(DEFAULT_GATEWAY_IMAGE)
        );
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        assert_eq!(dind["image"].as_str(), Some(DEFAULT_DIND_IMAGE));
        let command = dind["command"].as_array().unwrap();
        assert_eq!(command[0].as_str(), Some("sh"));
        assert_eq!(command[1].as_str(), Some("-ec"));
        let bootstrap = command[2].as_str().unwrap();
        assert!(bootstrap.contains("mkfs.ext4"));
        assert!(bootstrap.contains("mount -o loop"));
        assert!(bootstrap.contains("chown 1000:1000 \"$codewire_dir\""));
        assert!(bootstrap.contains("chmod 0775 \"$codewire_dir\""));
        assert!(bootstrap.contains("--data-root \"$data_root\""));
        assert!(bootstrap.contains("--storage-driver vfs"));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_IMAGE")
                && env["value"].as_str() == Some("/workspace/.codewire/docker-data.ext4")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_ROOT")
                && env["value"].as_str() == Some("/var/lib/docker")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_SIZE")
                && env["value"].as_str() == Some("38G")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_MOUNT_MODE")
                && env["value"].as_str() == Some("loop")
        }));
        let workspace = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("workspace"))
            .unwrap();
        assert!(workspace["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("DOCKER_HOST")
                && env["value"].as_str() == Some("unix:///var/run/docker/docker.sock")
        }));
        assert!(
            workspace["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["name"].as_str() == Some("docker-sock")
                    && mount["mountPath"].as_str() == Some("/var/run/docker"))
        );
        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        assert!(
            volumes
                .iter()
                .all(|volume| volume.get("hostPath").is_none()),
            "commodity workspace pod must not mount host Docker or containerd sockets"
        );

        let gateway = render_gateway_deployment(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                environment_id: "env-commodity".into(),
                gateway_token: "gw-token".into(),
                server_namespace: "dev".into(),
                ..Default::default()
            },
        );
        let spec = &gateway["spec"]["template"]["spec"];
        assert_eq!(
            spec["runtimeClassName"].as_str(),
            Some(RUNTIME_CLASS_COMMODITY)
        );
        let gateway_container = &spec["containers"][0];
        assert_eq!(gateway_container["name"].as_str(), Some("codewire-gateway"));
        assert!(gateway_container.get("resources").is_some());
        assert!(
            spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|volume| volume.get("hostPath").is_none()),
            "split gateway pod must not mount host Docker or containerd sockets"
        );
        assert!(
            gateway_container["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| {
                    mount["name"].as_str() == Some("gateway-state")
                        && mount["mountPath"].as_str() == Some("/codewire/gateway")
                })
        );
        assert!(
            gateway_container["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["name"].as_str() != Some("docker-sock")
                    && mount["mountPath"].as_str() != Some("/var/run/docker")),
            "split gateway must not mount the workspace pod-local Docker socket"
        );
        assert!(
            gateway_container["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"].as_str() == Some(DAEMON_AUTH_TOKEN_ENV)
                    && env["value"].as_str() == Some("gw-token"))
        );
        assert!(
            gateway_container["env"]
                .as_array()
                .unwrap()
                .iter()
                .all(|env| {
                    !matches!(
                        env["name"].as_str(),
                        Some("CODEWIRE_DOCKER_PROXY_SOCK") | Some(GATEWAY_DOCKER_UPSTREAM_SOCK_ENV)
                    )
                }),
            "split gateway must not advertise Docker proxy env vars unless a future proxy mode is explicitly enabled"
        );
    }

    #[test]
    fn managed_and_custom_workspaces_supervise_the_self_contained_daemon() {
        let managed = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-managed-daemon".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                environment_id: "env-managed-daemon".into(),
                gateway_token: "managed-daemon-token".into(),
                ..Default::default()
            },
        );
        let managed_spec = &managed["spec"]["podTemplate"]["spec"];
        let managed_workspace = &managed_spec["containers"][0];
        let managed_command = managed_workspace["command"][2].as_str().unwrap();
        assert!(managed_command.contains("while [ ! -x /codewire/bin/cw ]"));
        assert!(managed_command.contains("exec /codewire/bin/cw daemon"));
        assert!(!managed_command.contains("nohup cw node"));
        assert!(
            managed_workspace["env"]
                .as_array()
                .unwrap()
                .iter()
                .any(|env| env["name"].as_str() == Some(DAEMON_AUTH_TOKEN_ENV)
                    && env["value"].as_str() == Some("managed-daemon-token"))
        );
        let init_command = managed_spec["initContainers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(init_command.contains("cp /usr/local/bin/cw"));
        assert!(init_command.contains("ln -sf cw /codewire/bin/daemon"));
        assert!(init_command.contains("ln -sf cw /codewire/bin/codewire-daemon"));

        let custom = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-custom-daemon".into(),
                image: "example.invalid/custom:golden".into(),
                image_command: vec!["/bin/custom-entrypoint".into(), "--serve".into()],
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                environment_id: "env-custom-daemon".into(),
                gateway_token: "custom-daemon-token".into(),
                ..Default::default()
            },
        );
        let custom_command = custom["spec"]["podTemplate"]["spec"]["containers"][0]["command"][2]
            .as_str()
            .unwrap();
        assert!(custom_command.contains("/bin/custom-entrypoint --serve & workload_pid=$!"));
        assert!(custom_command.contains("/codewire/bin/cw daemon & daemon_pid=$!"));
        assert!(custom_command.contains("if ! kill -0 \"$daemon_pid\""));
        assert!(
            custom_command
                .matches("/codewire/bin/cw daemon & daemon_pid=$!")
                .count()
                >= 2,
            "custom supervisor must restart the daemon while the workload remains alive"
        );
        assert!(!custom_command.contains("nohup cw node"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn custom_workspace_supervisor_restarts_a_failed_daemon() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Stdio;

        let temp = tempfile::tempdir().unwrap();
        let daemon = temp.path().join("daemon");
        let workload = temp.path().join("workload");
        let count = temp.path().join("daemon-count");
        let pid = temp.path().join("daemon-pid");
        std::fs::write(
            &daemon,
            format!(
                "#!/bin/sh\n\
                 count=0\n\
                 [ ! -f {count} ] || count=\"$(cat {count})\"\n\
                 echo $((count + 1)) > {count}\n\
                 echo $$ > {pid}\n\
                 trap 'exit 0' TERM INT\n\
                 while true; do sleep 0.1; done\n",
                count = count.display(),
                pid = pid.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            &workload,
            "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile true; do sleep 0.1; done\n",
        )
        .unwrap();
        for path in [&daemon, &workload] {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }

        let command = custom_workspace_supervisor_command(
            "",
            "",
            &format!("sh {}", daemon.display()),
            &format!("sh {}", workload.display()),
        );
        let mut supervisor = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        wait_for_file_value(&count, "1").await;
        let daemon_pid = std::fs::read_to_string(&pid).unwrap();
        assert!(
            tokio::process::Command::new("kill")
                .args(["-TERM", daemon_pid.trim()])
                .status()
                .await
                .unwrap()
                .success()
        );
        wait_for_file_value(&count, "2").await;

        let supervisor_pid = supervisor.id().unwrap().to_string();
        assert!(
            tokio::process::Command::new("kill")
                .args(["-TERM", &supervisor_pid])
                .status()
                .await
                .unwrap()
                .success()
        );
        tokio::time::timeout(std::time::Duration::from_secs(3), supervisor.wait())
            .await
            .expect("custom supervisor shutdown")
            .unwrap();
    }

    #[cfg(unix)]
    async fn wait_for_file_value(path: &std::path::Path, expected: &str) {
        for _ in 0..80 {
            if std::fs::read_to_string(path)
                .ok()
                .is_some_and(|value| value.trim() == expected)
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "timed out waiting for {} to contain {expected}",
            path.display()
        );
    }

    #[test]
    fn dind_memory_limit_scales_for_large_environments() {
        for (name, memory_mib, want_limit) in [("small", 4096, "2Gi"), ("large", 16384, "4Gi")] {
            let rendered = render_sandbox_template(
                "codewire-runtime",
                &TemplateOpts {
                    name: format!("tmpl-dind-memory-{name}"),
                    image: "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467".into(),
                    runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                    memory_mib,
                    disk_gib: 50,
                    ..Default::default()
                },
            );
            let containers = rendered["spec"]["podTemplate"]["spec"]["containers"]
                .as_array()
                .unwrap();
            let dind = containers
                .iter()
                .find(|container| container["name"].as_str() == Some("dind"))
                .unwrap();
            assert_eq!(
                dind["resources"]["limits"]["memory"].as_str(),
                Some(want_limit)
            );
        }
    }

    #[test]
    fn dind_image_override_preserves_guest_dind_shape() {
        let image = "ghcr.io/codewiresh/dind@sha256:00815afb718e35fa8c71e8eb411df2919f74a149908593ae3fe94b55b34feec9";
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-dind-image".into(),
                image: "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467".into(),
                dind_image: image.into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                disk_gib: 50,
                ..Default::default()
            },
        );
        let containers = rendered["spec"]["podTemplate"]["spec"]["containers"]
            .as_array()
            .unwrap();
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        assert_eq!(dind["image"].as_str(), Some(image));
        assert_eq!(
            dind["securityContext"]["privileged"].as_bool(),
            Some(true),
            "the support image override must not change the guest-local Docker shape"
        );
    }

    #[test]
    fn gateway_host_key_secret_and_mount_are_environment_scoped() {
        let opts = TemplateOpts {
            name: "tmpl-gateway-host-key".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            environment_id: "env-gateway-host-key".into(),
            gateway_token: "gw-token".into(),
            server_namespace: "dev".into(),
            ..Default::default()
        };
        let secret = render_gateway_host_key_secret(
            "codewire-runtime",
            &opts,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n",
        );
        assert_eq!(
            secret["metadata"]["name"].as_str(),
            Some("cw-gateway-host-key-env-gateway-host-key")
        );
        assert_eq!(
            secret["metadata"]["labels"]["codewire.sh/type"].as_str(),
            Some("gateway-host-key")
        );
        assert_eq!(
            secret["metadata"]["labels"]["codewire.sh/environment-id"].as_str(),
            Some("env-gateway-host-key")
        );
        assert_eq!(
            secret["stringData"][GATEWAY_HOST_KEY_SECRET_KEY].as_str(),
            Some(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----\n"
            )
        );

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let pod_spec = &deployment["spec"]["template"]["spec"];
        let volumes = pod_spec["volumes"].as_array().unwrap();
        assert!(volumes.iter().any(|volume| {
            volume["name"].as_str() == Some("gateway-state") && volume.get("emptyDir").is_some()
        }));
        let host_key_volume = volumes
            .iter()
            .find(|volume| volume["name"].as_str() == Some("gateway-host-key"))
            .expect("gateway-host-key volume");
        assert_eq!(
            host_key_volume["secret"]["secretName"].as_str(),
            Some("cw-gateway-host-key-env-gateway-host-key")
        );
        assert_eq!(
            host_key_volume["secret"]["items"][0]["key"].as_str(),
            Some(GATEWAY_HOST_KEY_SECRET_KEY)
        );
        assert_eq!(
            host_key_volume["secret"]["items"][0]["mode"].as_i64(),
            Some(0o444)
        );

        let init = &pod_spec["initContainers"][0];
        assert_eq!(
            init["name"].as_str(),
            Some("codewire-gateway-host-key-init")
        );
        assert_eq!(
            init["image"].as_str(),
            Some("git.example.invalid/codewire/gateway:test")
        );
        let init_command = init["command"][2].as_str().unwrap();
        assert!(init_command.contains(GATEWAY_HOST_KEY_SECRET_MOUNT_PATH));
        assert!(init_command.contains(GATEWAY_HOST_KEY_PATH));
        assert!(init_command.contains("chmod 0600"));
        assert!(
            init["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| {
                    mount["name"].as_str() == Some("gateway-host-key")
                        && mount["mountPath"].as_str() == Some(GATEWAY_HOST_KEY_SECRET_MOUNT_PATH)
                        && mount["readOnly"].as_bool() == Some(true)
                })
        );

        let gateway_container = &pod_spec["containers"][0];
        assert!(gateway_container["env"].as_array().unwrap().iter().any(
            |env| env["name"].as_str() == Some("CODEWIRE_SSH_HOST_KEY_PATH")
                && env["value"].as_str() == Some(GATEWAY_HOST_KEY_PATH)
        ));
        assert!(
            gateway_container["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|mount| mount["name"].as_str() != Some("workspace")),
            "gateway must not mount workspace state for host-key persistence"
        );
    }

    #[test]
    fn commodity_template_agent_policy_init_data_when_enabled() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                kata_agent_policy_enabled: true,
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        let decoded = decode_gzip_base64(
            annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .unwrap()
                .as_str()
                .unwrap(),
        );
        for want in [
            "package agent_policy",
            "default ExecProcessRequest := true",
            "default ReadStreamRequest := true",
            "default WriteStreamRequest := true",
            "default GetDiagnosticDataRequest := false",
            "default SetPolicyRequest := false",
            "default StartTracingRequest := false",
            "default StopTracingRequest := false",
        ] {
            assert!(decoded.contains(want), "missing {want:?} in {decoded}");
        }
    }

    #[test]
    fn commodity_template_ignores_coco_only_init_data_flag() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-commodity".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
                kata_coco_init_data_enabled: true,
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        assert!(!annotations.contains_key(KATA_COCO_INIT_DATA_ANNOTATION_KEY));
    }

    #[test]
    fn confidential_template_policy_init_data_carries_kbs_config() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-confidential".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                kata_coco_init_data_enabled: true,
                kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
                kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
                ..Default::default()
            },
        );

        let pod_template = &rendered["spec"]["podTemplate"];
        let annotations = pod_template["metadata"]["annotations"].as_object().unwrap();
        let decoded = decode_gzip_base64(
            annotations
                .get(KATA_COCO_INIT_DATA_ANNOTATION_KEY)
                .unwrap()
                .as_str()
                .unwrap(),
        );
        for want in [
            "\"aa.toml\" = '''".to_string(),
            "[token_configs.kbs]".to_string(),
            "\"cdh.toml\" = '''".to_string(),
            "default SetPolicyRequest := false".to_string(),
            "url = \"https://kbs.codewire-dev.sh\"".to_string(),
        ] {
            assert!(decoded.contains(&want), "missing {want:?} in {decoded}");
        }
        assert!(
            !decoded.contains("[[credentials]]"),
            "init-data should use post-boot CDH REST resource fetch instead of credential prefetch:\n{decoded}"
        );
        let containers = pod_template["spec"]["containers"].as_array().unwrap();
        let dind = containers
            .iter()
            .find(|container| container["name"].as_str() == Some("dind"))
            .unwrap();
        let command = dind["command"].as_array().unwrap();
        assert_eq!(command[0].as_str(), Some("sh"));
        assert_eq!(command[1].as_str(), Some("-ec"));
        let bootstrap = command[2].as_str().unwrap();
        assert!(bootstrap.contains("CODEWIRE_DOCKER_MOUNT_MODE"));
        assert!(bootstrap.contains("--data-root \"$data_root\""));
        assert!(bootstrap.contains("--storage-driver vfs"));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_DATA_ROOT")
                && env["value"].as_str() == Some("/workspace/.codewire/docker-root")
        }));
        assert!(dind["env"].as_array().unwrap().iter().any(|env| {
            env["name"].as_str() == Some("CODEWIRE_DOCKER_MOUNT_MODE")
                && env["value"].as_str() == Some("none")
        }));
    }

    #[test]
    fn confidential_template_and_gateway_carry_coco_resource_kernel_params() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-auth".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            environment_id: "env-confidential-auth".into(),
            server_namespace: "dev".into(),
            ..Default::default()
        };
        let want_kernel_params = "agent.image_registry_auth=kbs:///default/containers/auth agent.guest_components_rest_api=resource agent.aa_kbc_params=cc_kbc::http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080";

        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert_eq!(
            annotations
                .get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                .and_then(Value::as_str),
            Some(want_kernel_params)
        );

        let gateway = render_gateway_deployment("codewire-runtime", &opts);
        assert_eq!(
            gateway["spec"]["template"]["metadata"]["annotations"]
                [KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY]
                .as_str(),
            Some(want_kernel_params)
        );

        let policy = render_gateway_network_policy("codewire-runtime", &opts);
        let egress = policy["spec"]["egress"].as_array().unwrap();
        let kbs_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("codewire-trustee")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/name"].as_str()
                            == Some("codewire-trustee-kbs")
                })
            })
        });
        assert!(kbs_rule.is_some(), "gateway KBS egress rule missing");
    }

    #[test]
    fn confidential_template_carries_resource_kernel_params_without_registry_auth() {
        let opts = TemplateOpts {
            name: "tmpl-confidential-resource".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url:
                "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
            ..Default::default()
        };
        let want_kernel_params = "agent.guest_components_rest_api=resource agent.aa_kbc_params=cc_kbc::http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080";

        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert_eq!(
            annotations
                .get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                .and_then(Value::as_str),
            Some(want_kernel_params)
        );
    }

    #[test]
    fn commodity_template_ignores_registry_auth_kernel_params() {
        let opts = TemplateOpts {
            name: "tmpl-commodity-auth".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            ..Default::default()
        };

        let rendered = render_sandbox_template("codewire-runtime", &opts);
        let annotations = rendered["spec"]["podTemplate"]["metadata"]["annotations"]
            .as_object()
            .unwrap();
        assert!(!annotations.contains_key(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY));

        let gateway = render_gateway_deployment("codewire-runtime", &opts);
        assert!(
            gateway["spec"]["template"]["metadata"]
                .get("annotations")
                .is_none()
        );
    }

    #[test]
    fn gzip_base64_uses_deterministic_stored_blocks() {
        let want = "H4sIAAAAAAAA/wEFAPr/aGVsbG+GphA2BQAAAA==";
        assert_eq!(gzip_base64("hello"), want);
        assert_eq!(decode_gzip_base64(want), "hello");
    }

    #[test]
    fn template_allows_derp_egress() {
        let rendered = render_gateway_network_policy(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-derp-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                api_base_url: "https://codewire-dev.sh".into(),
                server_namespace: "dev".into(),
                derp_host: "derp.codewire-dev.sh".into(),
                derp_port: 443,
                stun_host: "stun.codewire.sh".into(),
                stun_port: 3478,
                cpu_millicores: 1000,
                memory_mib: 2048,
                ..Default::default()
            },
        );

        let egress = rendered["spec"]["egress"].as_array().unwrap();
        let derp_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("derp")
                })
            })
        });
        let derp_rule = derp_rule.expect("DERP egress rule missing");
        let ports = derp_rule["ports"].as_array().unwrap();
        assert!(ports.iter().any(|port| {
            port["protocol"].as_str() == Some("TCP")
                && port["port"].as_i64() == Some(INTERNAL_DERP_TLS_PORT)
        }));
        assert!(ports.iter().any(|port| {
            port["protocol"].as_str() == Some("UDP")
                && port["port"].as_i64() == Some(INTERNAL_DERP_STUN_PORT)
        }));
    }

    #[test]
    fn template_omits_legacy_server_egress() {
        let rendered = render_gateway_network_policy(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-no-legacy-server-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                api_base_url: "https://codewire-dev.sh".into(),
                server_namespace: "dev".into(),
                cpu_millicores: 1000,
                memory_mib: 2048,
                ..Default::default()
            },
        );

        let egress = rendered["spec"]["egress"].as_array().unwrap();
        let legacy_server_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("server")
                })
            })
        });
        assert!(
            legacy_server_rule.is_none(),
            "legacy monolith egress rule should be absent"
        );
    }

    #[test]
    fn template_allows_direct_udp_ingress_when_stun_is_configured() {
        let opts = TemplateOpts {
            name: "tmpl-direct-udp-ingress".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            stun_host: "stun.codewire-dev.sh".into(),
            stun_port: 3478,
            cpu_millicores: 1000,
            memory_mib: 2048,
            ..Default::default()
        };
        let rendered = render_gateway_network_policy("codewire-runtime", &opts);

        let ingress = rendered["spec"]["ingress"].as_array().unwrap();
        assert!(ingress.iter().any(|rule| {
            rule["ports"].as_array().is_some_and(|ports| {
                ports.iter().any(|port| {
                    port["protocol"].as_str() == Some("UDP")
                        && port["port"].as_i64() == Some(GATEWAY_TAILNET_UDP_PORT)
                })
            })
        }));

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV)
                && entry["value"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR)
        }));
    }

    #[test]
    fn template_wires_udp_relay_allocator_env_and_egress() {
        let opts = TemplateOpts {
            name: "tmpl-udp-relay".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            server_namespace: "dev".into(),
            udp_relay_allocator_url:
                "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
                    .into(),
            udp_relay_allocator_token: "relay-token".into(),
            udp_relay_bind_addrs: "codewire-udp-relay.dev.svc.cluster.local:41641".into(),
            cpu_millicores: 1000,
            memory_mib: 2048,
            ..Default::default()
        };
        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV)
                && entry["value"].as_str()
                    == Some(
                        "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations",
                    )
        }));
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV)
                && entry["value"].as_str() == Some("relay-token")
        }));
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_UDP_RELAY_BIND_ADDRS_ENV)
                && entry["value"].as_str() == Some("codewire-udp-relay.dev.svc.cluster.local:41641")
        }));

        let policy = render_gateway_network_policy("codewire-runtime", &opts);
        let egress = policy["spec"]["egress"].as_array().unwrap();
        let relay_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("udp-relay")
                })
            })
        });
        let relay_rule = relay_rule.expect("UDP relay allocator egress rule missing");
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("TCP") && port["port"].as_i64() == Some(8095)
        }));
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("UDP") && port["port"].as_i64() == Some(41641)
        }));
    }

    #[test]
    fn template_allows_udp_relay_egress_without_flat_env_in_registry_mode() {
        let opts = TemplateOpts {
            name: "tmpl-udp-relay-registry".into(),
            image: "ghcr.io/codewiresh/workspace:golden".into(),
            support_image: "git.example.invalid/codewire/gateway:test".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            server_namespace: "dev".into(),
            udp_relay_allocator_egress_enabled: true,
            cpu_millicores: 1000,
            memory_mib: 2048,
            ..Default::default()
        };

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(!env.iter().any(|entry| {
            matches!(
                entry["name"].as_str(),
                Some(GATEWAY_UDP_RELAY_ALLOCATOR_URL_ENV)
                    | Some(GATEWAY_UDP_RELAY_ALLOCATOR_TOKEN_ENV)
                    | Some(GATEWAY_UDP_RELAY_BIND_ADDRS_ENV)
            )
        }));

        let policy = render_gateway_network_policy("codewire-runtime", &opts);
        let egress = policy["spec"]["egress"].as_array().unwrap();
        let relay_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("dev")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                            .as_str()
                            == Some("udp-relay")
                })
            })
        });
        let relay_rule = relay_rule.expect("UDP relay allocator egress rule missing");
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("TCP") && port["port"].as_i64() == Some(8095)
        }));
        assert!(relay_rule["ports"].as_array().unwrap().iter().any(|port| {
            port["protocol"].as_str() == Some("UDP") && port["port"].as_i64() == Some(41641)
        }));
    }

    #[test]
    fn template_allows_cluster_local_kbs_egress() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-kbs-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                kata_coco_init_data_enabled: true,
                kata_coco_kbs_url:
                    "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".into(),
                kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
                kata_coco_test_resource_path: DEFAULT_KATA_COCO_TEST_RESOURCE_PATH.into(),
                api_base_url: "https://codewire-dev.sh".into(),
                server_namespace: "dev".into(),
                derp_host: "derp.codewire-dev.sh".into(),
                derp_port: 443,
                stun_host: "stun.codewire.sh".into(),
                stun_port: 3478,
                cpu_millicores: 1000,
                memory_mib: 2048,
                ..Default::default()
            },
        );

        let egress = rendered["spec"]["networkPolicy"]["egress"]
            .as_array()
            .unwrap();
        let kbs_rule = egress.iter().find(|rule| {
            rule["to"].as_array().is_some_and(|targets| {
                targets.iter().any(|target| {
                    target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                        .as_str()
                        == Some("codewire-trustee")
                        && target["podSelector"]["matchLabels"]["app.kubernetes.io/name"].as_str()
                            == Some("codewire-trustee-kbs")
                })
            })
        });
        let kbs_rule = kbs_rule.expect("KBS egress rule missing");
        let ports = kbs_rule["ports"].as_array().unwrap();
        assert!(ports.iter().any(|port| {
            port["protocol"].as_str() == Some("TCP") && port["port"].as_i64() == Some(8080)
        }));
    }

    #[test]
    fn workspace_storage_class_defaults_and_overrides() {
        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-storage-default".into(),
                disk_gib: 20,
                ..Default::default()
            },
        );
        assert_eq!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"].as_str(),
            Some(DEFAULT_WORKSPACE_STORAGE_CLASS)
        );

        let rendered = render_sandbox_template(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-storage-local".into(),
                disk_gib: 20,
                workspace_storage_class: "local-path".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"].as_str(),
            Some("local-path")
        );
    }

    #[test]
    fn template_isol8_renders_workspace_pod_without_gateway_container() {
        let rendered = render_sandbox_template("codewire-runtime", &isol8_opts());
        let pod_spec = &rendered["spec"]["podTemplate"]["spec"];
        let containers = pod_spec["containers"].as_array().unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0]["name"].as_str(), Some("workspace"));
        assert!(
            containers
                .iter()
                .all(|container| container["name"].as_str() != Some("codewire-gateway"))
        );
        assert_eq!(
            pod_spec["initContainers"][0]["name"].as_str(),
            Some("codewire-daemon-init")
        );
        assert_eq!(pod_spec["runtimeClassName"].as_str(), Some("isol8"));
    }

    #[test]
    fn gateway_service_is_cluster_ip_without_node_ports() {
        let rendered = render_gateway_service("codewire-runtime", &commodity_opts());
        assert_eq!(
            rendered["spec"]["type"].as_str(),
            Some("ClusterIP"),
            "gateway service must not reintroduce per-sandbox NodePorts"
        );
        let ports = rendered["spec"]["ports"].as_array().unwrap();
        assert!(
            ports.iter().all(|port| port.get("nodePort").is_none()),
            "gateway service ports must not carry static nodePort fields: {ports:?}"
        );
    }

    #[test]
    fn direct_udp_load_balancer_service_uses_cilium_lb_ipam_without_nodeports() {
        let opts = TemplateOpts {
            direct_udp_lb_enabled: true,
            direct_udp_lb_ip: "192.0.2.36".into(),
            direct_udp_lb_port: 33123,
            direct_udp_lb_class: "io.cilium/l2-announcer".into(),
            direct_udp_lb_sharing_key: "codewire-direct-udp".into(),
            direct_udp_transport_zone: "prod-node".into(),
            ..commodity_opts()
        };

        let service = render_gateway_direct_udp_service("codewire-runtime", &opts)
            .expect("direct UDP LoadBalancer service");
        assert_eq!(
            service["metadata"]["name"].as_str(),
            Some("cw-gateway-udp-env-golden-commodity")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/ips"].as_str(),
            Some("192.0.2.36")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/sharing-key"].as_str(),
            Some("codewire-direct-udp")
        );
        assert_eq!(
            service["metadata"]["annotations"]["lbipam.cilium.io/sharing-cross-namespace"].as_str(),
            Some("*")
        );
        assert_eq!(
            service["metadata"]["labels"]["codewire.sh/type"].as_str(),
            Some("direct-udp-lb")
        );
        assert_eq!(
            service["metadata"]["labels"]["codewire.sh/runtime-network"].as_str(),
            Some("direct-udp")
        );
        assert_eq!(
            service["metadata"]["labels"]["codewire.sh/transport-zone"].as_str(),
            Some("prod-node")
        );
        assert_eq!(service["spec"]["type"].as_str(), Some("LoadBalancer"));
        assert_eq!(
            service["spec"]["loadBalancerClass"].as_str(),
            Some("io.cilium/l2-announcer")
        );
        assert_eq!(
            service["spec"]["allocateLoadBalancerNodePorts"].as_bool(),
            Some(false)
        );
        assert_eq!(
            service["spec"]["externalTrafficPolicy"].as_str(),
            Some("Cluster")
        );
        assert!(
            service["spec"]["ports"]
                .as_array()
                .unwrap()
                .iter()
                .all(|port| port.get("nodePort").is_none()),
            "direct UDP LoadBalancer service must not allocate NodePorts"
        );
        assert_eq!(service["spec"]["ports"][0]["port"].as_i64(), Some(33123));
        assert_eq!(
            service["spec"]["ports"][0]["targetPort"].as_i64(),
            Some(GATEWAY_TAILNET_UDP_PORT)
        );

        let deployment = render_gateway_deployment("codewire-runtime", &opts);
        let env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR_ENV)
                && entry["value"].as_str() == Some(GATEWAY_TAILNET_UDP_LISTEN_ADDR)
        }));
        assert!(env.iter().any(|entry| {
            entry["name"].as_str() == Some(GATEWAY_TAILNET_DIRECT_UDP_ADVERTISE_ENDPOINTS_ENV)
                && entry["value"].as_str() == Some("192.0.2.36:33123")
        }));
    }

    #[test]
    fn workspace_daemon_service_and_policy_select_expected_identities() {
        let opts = commodity_opts();
        let service = render_workspace_daemon_service("codewire-runtime", &opts);
        assert_eq!(
            service["spec"]["selector"]["codewire.sh/environment-id"].as_str(),
            Some("env-golden-commodity")
        );
        assert_eq!(
            service["spec"]["selector"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        assert_eq!(
            service["spec"]["ports"][0]["port"].as_i64(),
            Some(WORKSPACE_DAEMON_PORT)
        );

        let policy = render_workspace_daemon_network_policy("codewire-runtime", &opts);
        assert_eq!(
            policy["spec"]["podSelector"]["matchLabels"]["codewire.sh/type"].as_str(),
            Some("workspace")
        );
        let ingress = policy["spec"]["ingress"].as_array().unwrap();
        assert_eq!(
            ingress[0]["from"][0]["podSelector"]["matchLabels"]["codewire.sh/type"].as_str(),
            Some("gateway")
        );
        assert_eq!(
            ingress[0]["ports"][0]["port"].as_i64(),
            Some(WORKSPACE_DAEMON_PORT)
        );
        assert_eq!(
            ingress[1]["from"][0]["namespaceSelector"]["matchLabels"]
                ["kubernetes.io/metadata.name"]
                .as_str(),
            Some("dev")
        );
        assert_eq!(
            ingress[1]["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                .as_str(),
            Some("orchestration")
        );
        assert_eq!(ingress[1]["ports"][0]["protocol"].as_str(), Some("TCP"));
        assert_eq!(
            ingress[1]["ports"][0]["port"].as_i64(),
            Some(WORKSPACE_DAEMON_PORT)
        );
        assert_eq!(ingress[1]["ports"][1]["protocol"].as_str(), Some("TCP"));
        assert_eq!(
            ingress[1]["ports"][1]["port"].as_i64(),
            Some(APP_PREVIEW_MIN_PORT)
        );
        assert_eq!(
            ingress[1]["ports"][1]["endPort"].as_i64(),
            Some(APP_PREVIEW_MAX_PORT)
        );
        let egress = policy["spec"]["egress"].as_array().unwrap();
        assert!(egress.iter().any(|rule| {
            rule["to"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| target.get("ipBlock").is_some()))
        }));
        assert_eq!(policy["spec"]["policyTypes"][1].as_str(), Some("Egress"));
    }

    #[test]
    fn explicit_coordinator_url_and_internal_binding_url_are_independent_of_public_api_url() {
        let env = build_sidecar_env(&TemplateOpts {
            api_base_url: "https://codewire.example".into(),
            coordinator_url: "http://codewire-coordinator.default.svc.cluster.local:8090".into(),
            server_namespace: "default".into(),
            ..Default::default()
        });
        let get = |name: &str| {
            env.iter().find_map(|entry| {
                (entry.get("name")?.as_str()? == name)
                    .then(|| entry.get("value")?.as_str().map(str::to_string))
                    .flatten()
            })
        };

        assert_eq!(
            get("CODEWIRE_API_URL").as_deref(),
            Some("https://codewire.example")
        );
        assert_eq!(
            get("CODEWIRE_COORDINATOR_URL").as_deref(),
            Some("http://codewire-coordinator.default.svc.cluster.local:8090")
        );
        assert_eq!(
            get("CODEWIRE_BINDING_URL").as_deref(),
            Some("http://codewire-orchestration.default.svc.cluster.local:8085")
        );
    }

    #[test]
    fn binding_url_is_omitted_without_a_server_namespace() {
        let env = build_sidecar_env(&TemplateOpts {
            api_base_url: "https://codewire.example".into(),
            ..Default::default()
        });

        assert!(
            !env.iter()
                .any(|entry| entry["name"].as_str() == Some(GATEWAY_BINDING_URL_ENV))
        );
    }

    #[test]
    fn gateway_policy_keeps_rest_and_connect_orchestration_egress_during_dual_serve() {
        let rendered = render_gateway_network_policy(
            "codewire-runtime",
            &TemplateOpts {
                name: "tmpl-binding-egress".into(),
                image: "ghcr.io/codewiresh/workspace:golden".into(),
                support_image: "git.example.invalid/codewire/gateway:test".into(),
                server_namespace: "dev".into(),
                ..Default::default()
            },
        );
        let rule = rendered["spec"]["egress"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| {
                rule["to"].as_array().is_some_and(|targets| {
                    targets.iter().any(|target| {
                        target["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                            .as_str()
                            == Some("dev")
                            && target["podSelector"]["matchLabels"]["app.kubernetes.io/component"]
                                .as_str()
                                == Some("orchestration")
                    })
                })
            })
            .expect("orchestration egress rule");
        let ports: Vec<i64> = rule["ports"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|port| port["port"].as_i64())
            .collect();

        assert_eq!(ports, vec![8084, 8085]);
    }

    #[test]
    fn warm_pool_matches_golden_file() {
        assert_eq!(
            render_sandbox_warm_pool("codewire-runtime", "warm-golden", "tmpl-golden-isol8", 3),
            load_golden("sandboxwarmpool.golden.json"),
        );
    }
}
