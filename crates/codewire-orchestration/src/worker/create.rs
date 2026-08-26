//! The `environment.create` job — port of `runEnvironmentCreate`
//! (handler_environment.go), `environmentlifecycle/create.go`'s
//! NextCreateAction policy, and the template/claim opts builders in
//! `worker/environment_sandbox.go` + `sandbox/warm_pools.go`.

use std::time::Duration;

use sqlx::PgPool;

use super::activity_authority::{ActivityAuthority, await_external_mutation};
use super::env_data::{BackendRow, EnvironmentRow, load_backend_row, load_environment};
use super::env_log::emit_authoritative_environment_log_for_states;
use super::gatewayauth::{SCOPE_COORDINATE, issue_token};
use super::{JobPayload, WorkerContext};
use crate::lifecycle::{PgLifecycleStore, Service};
use crate::sandbox::client::{ProbeResult, SandboxClient, WorkspacePodIdentity};
use crate::sandbox::template::{
    DOCKER_MODE_LOCAL_DIND_DIRECT, KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
    RUNTIME_PROFILE_CONFIDENTIAL, TemplateOpts, default_tolerations, runtime_profile_spec,
    validate_managed_runtime_profile,
};
use crate::sandbox::{
    CANONICAL_WORKSPACE_RUNTIME_IMAGE, ClaimOpts, claim_name, environment_pod_selector,
    environment_template_name, is_canonical_workspace_runtime_image, shadow_warm_pool_name,
    warm_pool_name,
};

/// Mirrors `sandbox.CanonicalWorkspaceRuntimeTemplateName`.
pub const CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME: &str = "workspace";

// ── Create action policy (port of environmentlifecycle/create.go) ──────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateAction {
    Done,
    WaitForReady,
    EnsureNamespace,
    CreateClaim,
    StoreBackend,
    MarkRunning,
    PublishSetup,
}

impl std::fmt::Display for CreateAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CreateAction::Done => "done",
            CreateAction::WaitForReady => "wait_for_ready",
            CreateAction::EnsureNamespace => "ensure_namespace",
            CreateAction::CreateClaim => "create_claim",
            CreateAction::StoreBackend => "store_backend",
            CreateAction::MarkRunning => "mark_running",
            CreateAction::PublishSetup => "publish_setup",
        };
        f.write_str(s)
    }
}

/// Mirrors `NextCreateAction` — pure decision function.
pub fn next_create_action(
    state: &str,
    backend: Option<&BackendRow>,
    setup_complete: bool,
    probe: &ProbeResult,
) -> CreateAction {
    let Some(backend) = backend else {
        return CreateAction::EnsureNamespace;
    };
    if backend.namespace.is_empty() {
        return CreateAction::EnsureNamespace;
    }
    if !probe.claim_exists {
        return CreateAction::CreateClaim;
    }
    if backend.claim_name.is_empty() {
        return CreateAction::CreateClaim;
    }
    if !probe.claim_ready {
        return CreateAction::WaitForReady;
    }
    if backend.pod_ip.is_empty() {
        return CreateAction::StoreBackend;
    }
    if state != "running" {
        return CreateAction::MarkRunning;
    }
    if !setup_complete {
        return CreateAction::PublishSetup;
    }
    CreateAction::Done
}

fn create_command_cancelled(state: &str, desired_state: &str) -> bool {
    desired_state == "destroyed" || matches!(state, "destroying" | "destroyed")
}

fn create_retry_recovery_required(state: &str) -> bool {
    state == "pending"
}

// ── Warm pool profiles (port of sandbox/warm_pools.go) ─────────────────

pub const DEFAULT_FULL_CPU_MILLICORES: i32 = 1000;
pub const DEFAULT_FULL_MEMORY_MIB: i32 = 2048;
pub const DEFAULT_FULL_DISK_GIB: i32 = 10;
const LEGACY_FULL_CPU_MILLICORES: i32 = 2000;
const LEGACY_FULL_MEMORY_MIB: i32 = 4096;
const LEGACY_FULL_DISK_GIB: i32 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmPoolProfile {
    pub template_name: String,
    pub cpu_millicores: i32,
    pub memory_mib: i32,
    pub disk_gib: i32,
    pub replicas: i32,
}

/// Mirrors `CanonicalFullWarmPoolTemplateName`.
pub fn canonical_full_warm_pool_template_name(cpu: i32, mem: i32, disk: i32) -> String {
    if cpu == DEFAULT_FULL_CPU_MILLICORES
        && mem == DEFAULT_FULL_MEMORY_MIB
        && disk == DEFAULT_FULL_DISK_GIB
    {
        return CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME.to_string();
    }
    format!("{CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME}-{cpu}m-{mem}mib-{disk}gib")
}

fn default_canonical_full_warm_pool_profiles() -> Vec<WarmPoolProfile> {
    vec![
        WarmPoolProfile {
            template_name: CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME.to_string(),
            cpu_millicores: DEFAULT_FULL_CPU_MILLICORES,
            memory_mib: DEFAULT_FULL_MEMORY_MIB,
            disk_gib: DEFAULT_FULL_DISK_GIB,
            replicas: 2,
        },
        WarmPoolProfile {
            template_name: canonical_full_warm_pool_template_name(
                LEGACY_FULL_CPU_MILLICORES,
                LEGACY_FULL_MEMORY_MIB,
                LEGACY_FULL_DISK_GIB,
            ),
            cpu_millicores: LEGACY_FULL_CPU_MILLICORES,
            memory_mib: LEGACY_FULL_MEMORY_MIB,
            disk_gib: LEGACY_FULL_DISK_GIB,
            replicas: 2,
        },
    ]
}

/// Mirrors `ParseCanonicalFullWarmPoolProfiles`.
pub fn parse_canonical_full_warm_pool_profiles(raw: &str) -> anyhow::Result<Vec<WarmPoolProfile>> {
    if raw.trim().is_empty() {
        return Ok(default_canonical_full_warm_pool_profiles());
    }
    let mut profiles = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let parts: Vec<&str> = entry.split(':').collect();
        if parts.len() != 4 {
            anyhow::bail!(
                "invalid warm profile {entry:?}: want cpuMillicores:memoryMiB:diskGiB:replicas"
            );
        }
        let cpu: i32 = parts[0].parse().unwrap_or(0);
        if cpu <= 0 {
            anyhow::bail!("invalid cpuMillicores in warm profile {entry:?}");
        }
        let mem: i32 = parts[1].parse().unwrap_or(0);
        if mem <= 0 {
            anyhow::bail!("invalid memoryMiB in warm profile {entry:?}");
        }
        let disk: i32 = parts[2].parse().unwrap_or(0);
        if disk <= 0 {
            anyhow::bail!("invalid diskGiB in warm profile {entry:?}");
        }
        let replicas: i32 = parts[3].parse().unwrap_or(0);
        if replicas <= 0 {
            anyhow::bail!("invalid replicas in warm profile {entry:?}");
        }
        let template_name = canonical_full_warm_pool_template_name(cpu, mem, disk);
        if !seen.insert(template_name.clone()) {
            anyhow::bail!("duplicate warm profile template {template_name:?}");
        }
        profiles.push(WarmPoolProfile {
            template_name,
            cpu_millicores: cpu,
            memory_mib: mem,
            disk_gib: disk,
            replicas,
        });
    }
    if profiles.is_empty() {
        anyhow::bail!("no warm profiles configured");
    }
    Ok(profiles)
}

/// Mirrors `MatchCanonicalFullWarmPoolProfile`.
pub fn match_canonical_full_warm_pool_profile(
    profiles: &[WarmPoolProfile],
    cpu: i32,
    mem: i32,
    disk: i32,
) -> Option<&WarmPoolProfile> {
    profiles
        .iter()
        .find(|p| p.cpu_millicores == cpu && p.memory_mib == mem && p.disk_gib == disk)
}

/// Mirrors `warmPoolTemplateOpts`: the TemplateOpts the warm-pool path
/// renders, derived from the worker config and a profile.
pub fn warm_pool_template_opts(cfg: &SandboxWorkerCfg, profile: &WarmPoolProfile) -> TemplateOpts {
    let override_selector = parse_node_selector(&cfg.node_selector);
    let uses_runtime_transport_registry = !cfg.runtime_transport_zones_json.trim().is_empty();
    let runtime_spec = runtime_profile_spec(
        &cfg.runtime_profile,
        &cfg.runtime_class,
        &cfg.docker_mode,
        cfg.dind_enabled,
    );
    TemplateOpts {
        name: profile.template_name.clone(),
        image: if cfg.warm_pool_workspace_image.trim().is_empty() {
            CANONICAL_WORKSPACE_RUNTIME_IMAGE.to_string()
        } else {
            cfg.warm_pool_workspace_image.clone()
        },
        image_command: vec!["sleep".to_string(), "infinity".to_string()],
        support_image: cfg.gateway_image.clone(),
        dind_image: cfg.dind_image.clone(),
        runtime_profile: runtime_spec.profile.clone(),
        runtime_class_name: runtime_spec.runtime_class_name.clone(),
        docker_mode: runtime_spec.docker_mode.clone(),
        sidecar_resource_mode: runtime_spec.sidecar_resource_mode.clone(),
        api_base_url: cfg.api_base_url.clone(),
        coordinator_url: cfg.coordinator_url.clone(),
        server_namespace: cfg.pod_namespace.clone(),
        derp_host: cfg.derp_host.clone(),
        derp_port: parse_derp_port(&cfg.derp_port),
        stun_host: cfg.stun_host.clone(),
        stun_port: parse_stun_port(&cfg.stun_port),
        stun_servers: cfg.stun_servers.clone(),
        udp_relay_allocator_url: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_allocator_url.clone()
        },
        udp_relay_allocator_token: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_allocator_token.clone()
        },
        udp_relay_bind_addrs: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_bind_addrs.clone()
        },
        udp_relay_allocator_egress_enabled: uses_runtime_transport_registry,
        cpu_millicores: i64::from(profile.cpu_millicores),
        memory_mib: i64::from(profile.memory_mib),
        disk_gib: i64::from(profile.disk_gib),
        workspace_storage_class: cfg.workspace_storage_class.clone(),
        node_selector: resolve_node_selector(&runtime_spec.profile, override_selector),
        tolerations: default_tolerations(&runtime_spec.profile),
        network_policy_management: cfg.network_policy_management.clone(),
        dind_enabled: runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT,
        kata_agent_policy_enabled: cfg.kata_agent_policy_enabled,
        kata_coco_init_data_enabled: cfg.kata_coco_init_data_enabled,
        kata_coco_kbs_url: cfg.kata_coco_kbs_url.clone(),
        kata_coco_kbs_ca_pem: cfg.kata_coco_kbs_ca_pem.clone(),
        kata_coco_image_registry_auth_uri: cfg.kata_coco_image_registry_auth_uri.clone(),
        kata_coco_test_resource_uri: cfg.kata_coco_test_resource_uri.clone(),
        kata_coco_test_resource_path: cfg.kata_coco_test_resource_path.clone(),
        ..Default::default()
    }
}

// ── Worker sandbox config (the cfg slice the create path reads) ────────

/// The subset of Go's config.Config the create handler consumes, with
/// the same env names and defaults (config.Load).
#[derive(Debug, Clone, Default)]
pub struct SandboxWorkerCfg {
    pub session_secret: String,
    pub sandbox_namespace: String,
    pub gateway_image: String,
    pub warm_pool_workspace_image: String,
    pub dind_image: String,
    pub runtime_profile: String,
    pub runtime_class: String,
    pub docker_mode: String,
    pub allow_diagnostic_runtime: bool,
    pub node_selector: String,
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
    pub full_warm_profiles: String,
    pub api_base_url: String,
    pub coordinator_url: String,
    pub derp_host: String,
    pub derp_port: String,
    pub stun_host: String,
    pub stun_port: String,
    pub stun_servers: String,
    pub direct_udp_lb_enabled: bool,
    pub direct_udp_lb_ip: String,
    pub direct_udp_lb_port_start: String,
    pub direct_udp_lb_port_end: String,
    pub direct_udp_lb_class: String,
    pub direct_udp_lb_sharing_key: String,
    pub direct_udp_transport_zone: String,
    pub udp_relay_allocator_url: String,
    pub udp_relay_allocator_token: String,
    pub udp_relay_bind_addrs: String,
    pub runtime_transport_zones_json: String,
    pub pod_namespace: String,
    pub debug_tailnet: bool,
}

impl SandboxWorkerCfg {
    pub fn from_env() -> Self {
        let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "dev".to_string());
        let env_prefix = match env.as_str() {
            "local" | "development" => "dev",
            "production" => "prod",
            other => other,
        };
        let getenv = |k: &str, d: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| d.to_string())
        };
        let kata_coco_kbs_url = getenv(
            "SANDBOX_KATA_COCO_KBS_URL",
            &getenv("CONFIDENTIAL_STORAGE_KBS_URL", ""),
        );
        let kbs_ca_path = getenv("CONFIDENTIAL_STORAGE_KBS_CA_PATH", "");
        let kata_coco_kbs_ca_pem = if kbs_ca_path.is_empty() {
            String::new()
        } else {
            std::fs::read_to_string(&kbs_ca_path).unwrap_or_else(|error| {
                panic!(
                    "failed to read public confidential-storage KBS CA at {kbs_ca_path}: {error}"
                )
            })
        };
        Self {
            session_secret: getenv("SESSION_SECRET", ""),
            sandbox_namespace: getenv("SANDBOX_NAMESPACE", &format!("{env_prefix}-sandboxes")),
            gateway_image: getenv(
                "SANDBOX_GATEWAY_IMAGE",
                "ghcr.io/codewiresh/gateway@sha256:686a2437f023fe2a4759e87ba93b8d4a71885eefdc5ec7c3486a95f3d6da2836",
            ),
            warm_pool_workspace_image: getenv(
                "SANDBOX_WARM_POOL_WORKSPACE_IMAGE",
                CANONICAL_WORKSPACE_RUNTIME_IMAGE,
            ),
            dind_image: getenv("SANDBOX_DIND_IMAGE", ""),
            runtime_profile: std::env::var("SANDBOX_RUNTIME_PROFILE").unwrap_or_default(),
            // SANDBOX_RUNTIME_CLASS allows explicit empty (getEnvAllowEmpty).
            runtime_class: std::env::var("SANDBOX_RUNTIME_CLASS")
                .unwrap_or_else(|_| "runc".to_string()),
            docker_mode: getenv("SANDBOX_DOCKER_MODE", "profile-default"),
            allow_diagnostic_runtime: getenv("SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME", "false") == "true",
            node_selector: getenv("SANDBOX_NODE_SELECTOR", ""),
            workspace_storage_class: getenv("SANDBOX_WORKSPACE_STORAGE_CLASS", ""),
            network_policy_management: getenv("SANDBOX_NETWORK_POLICY_MANAGEMENT", "Managed"),
            dind_enabled: getenv("SANDBOX_DIND_ENABLED", "false") == "true",
            kata_agent_policy_enabled: getenv("SANDBOX_KATA_AGENT_POLICY_ENABLED", "false")
                == "true",
            kata_coco_init_data_enabled: getenv("SANDBOX_KATA_COCO_INIT_DATA_ENABLED", "false")
                == "true",
            kata_coco_kbs_url,
            kata_coco_kbs_ca_pem,
            kata_coco_image_registry_auth_uri: getenv(
                "SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI",
                "",
            ),
            kata_coco_test_resource_uri: getenv("SANDBOX_KATA_COCO_TEST_RESOURCE_URI", ""),
            kata_coco_test_resource_path: getenv("SANDBOX_KATA_COCO_TEST_RESOURCE_PATH", ""),
            full_warm_profiles: getenv("SANDBOX_FULL_WARM_PROFILES", ""),
            api_base_url: getenv("CODEWIRE_API_URL", ""),
            coordinator_url: getenv("CODEWIRE_COORDINATOR_URL", ""),
            derp_host: getenv("DERP_HOST", ""),
            derp_port: getenv("DERP_PORT", ""),
            stun_host: getenv("STUN_HOST", ""),
            stun_port: getenv("STUN_PORT", "3478"),
            stun_servers: getenv("STUN_SERVERS", ""),
            direct_udp_lb_enabled: getenv("CODEWIRE_DIRECT_UDP_LB_ENABLED", "false") == "true",
            direct_udp_lb_ip: getenv("CODEWIRE_DIRECT_UDP_LB_IP", ""),
            direct_udp_lb_port_start: getenv("CODEWIRE_DIRECT_UDP_LB_PORT_START", "32000"),
            direct_udp_lb_port_end: getenv("CODEWIRE_DIRECT_UDP_LB_PORT_END", "60999"),
            direct_udp_lb_class: getenv("CODEWIRE_DIRECT_UDP_LB_CLASS", "io.cilium/l2-announcer"),
            direct_udp_lb_sharing_key: getenv(
                "CODEWIRE_DIRECT_UDP_LB_SHARING_KEY",
                "codewire-direct-udp",
            ),
            direct_udp_transport_zone: getenv("CODEWIRE_DIRECT_UDP_TRANSPORT_ZONE", ""),
            udp_relay_allocator_url: getenv("CODEWIRE_UDP_RELAY_ALLOCATOR_URL", ""),
            udp_relay_allocator_token: getenv("CODEWIRE_UDP_RELAY_ALLOCATOR_TOKEN", ""),
            udp_relay_bind_addrs: getenv("CODEWIRE_UDP_RELAY_BIND_ADDRS", ""),
            runtime_transport_zones_json: getenv("CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON", ""),
            pod_namespace: std::env::var("POD_NAMESPACE").unwrap_or_default(),
            debug_tailnet: !std::env::var("CODEWIRE_DEBUG_TAILNET")
                .unwrap_or_default()
                .is_empty(),
        }
    }
}

/// Mirrors `parseDERPPort`.
pub fn parse_derp_port(s: &str) -> i64 {
    if s.is_empty() {
        return 443;
    }
    match s.parse::<i64>() {
        Ok(0) | Err(_) => 443,
        Ok(p) => p,
    }
}

/// Mirrors `parseSTUNPort`.
pub fn parse_stun_port(s: &str) -> i64 {
    if s.is_empty() || s == "-1" {
        return 3478;
    }
    match s.parse::<i64>() {
        Ok(0) | Err(_) => 3478,
        Ok(p) => p,
    }
}

fn parse_udp_lb_port_bound(s: &str) -> i64 {
    match s.parse::<i64>() {
        Ok(port) if port > 0 && port <= 65535 => port,
        _ => 0,
    }
}

/// Mirrors `config.ParseNodeSelector` ("k=v,k2=v2").
pub fn parse_node_selector(s: &str) -> Vec<(String, String)> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            match (it.next(), it.next()) {
                (Some(k), Some(v)) => Some((k.trim().to_string(), v.trim().to_string())),
                _ => None,
            }
        })
        .collect()
}

/// Mirrors `sandbox.ResolveNodeSelector`.
pub fn resolve_node_selector(
    runtime_class: &str,
    override_selector: Vec<(String, String)>,
) -> Vec<(String, String)> {
    if !override_selector.is_empty() {
        return override_selector;
    }
    crate::sandbox::template::default_node_selector(runtime_class)
}

/// Mirrors `isFirstPartyWorkspaceImage`.
pub fn is_first_party_workspace_image(image_ref: &str) -> bool {
    image_ref.contains("codewiresh/workspace-")
        || image_ref.contains("codewiresh/base")
        || image_ref.contains("codewiresh/workspace")
}

/// Mirrors `environmentTemplateOpts`.
pub fn environment_template_opts(
    cfg: &SandboxWorkerCfg,
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    env_id: &str,
    gateway_token: &str,
) -> TemplateOpts {
    // Codewire base images: no ImageCommand → daemon is the main
    // process. Custom images: sleep infinity keeps the container alive.
    let image_command = if is_first_party_workspace_image(image_ref) {
        Vec::new()
    } else {
        vec!["sleep".to_string(), "infinity".to_string()]
    };

    let override_selector = parse_node_selector(&cfg.node_selector);
    let runtime_spec = match runtime_profile_for_isolation_tier(&env.isolation_tier)
        .expect("environment isolation tier is validated at creation")
    {
        Some(profile) => runtime_profile_spec(profile, "", &cfg.docker_mode, cfg.dind_enabled),
        None => runtime_profile_spec(
            &cfg.runtime_profile,
            &cfg.runtime_class,
            &cfg.docker_mode,
            cfg.dind_enabled,
        ),
    };
    let template_base = if is_canonical_workspace_runtime_image(image_ref) {
        CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME
    } else {
        template_base
    };

    let uses_runtime_transport_registry = !cfg.runtime_transport_zones_json.trim().is_empty();

    TemplateOpts {
        name: environment_template_name(template_base, env_id),
        image: image_ref.to_string(),
        image_command,
        support_image: cfg.gateway_image.clone(),
        dind_image: cfg.dind_image.clone(),
        runtime_profile: runtime_spec.profile.clone(),
        runtime_class_name: runtime_spec.runtime_class_name.clone(),
        docker_mode: runtime_spec.docker_mode.clone(),
        sidecar_resource_mode: runtime_spec.sidecar_resource_mode.clone(),
        environment_id: env_id.to_string(),
        gateway_token: gateway_token.to_string(),
        api_base_url: cfg.api_base_url.clone(),
        coordinator_url: cfg.coordinator_url.clone(),
        server_namespace: cfg.pod_namespace.clone(),
        derp_host: cfg.derp_host.clone(),
        derp_port: parse_derp_port(&cfg.derp_port),
        stun_host: cfg.stun_host.clone(),
        stun_port: parse_stun_port(&cfg.stun_port),
        stun_servers: cfg.stun_servers.clone(),
        direct_udp_lb_enabled: cfg.direct_udp_lb_enabled
            && matches!(
                runtime_spec.profile.as_str(),
                crate::sandbox::template::RUNTIME_PROFILE_COMMODITY
                    | crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL
            ),
        direct_udp_lb_ip: cfg.direct_udp_lb_ip.clone(),
        direct_udp_lb_port: 0,
        direct_udp_lb_port_start: parse_udp_lb_port_bound(&cfg.direct_udp_lb_port_start),
        direct_udp_lb_port_end: parse_udp_lb_port_bound(&cfg.direct_udp_lb_port_end),
        direct_udp_lb_class: cfg.direct_udp_lb_class.clone(),
        direct_udp_lb_sharing_key: cfg.direct_udp_lb_sharing_key.clone(),
        direct_udp_transport_zone: cfg.direct_udp_transport_zone.clone(),
        udp_relay_allocator_url: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_allocator_url.clone()
        },
        udp_relay_allocator_token: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_allocator_token.clone()
        },
        udp_relay_bind_addrs: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_bind_addrs.clone()
        },
        udp_relay_allocator_egress_enabled: uses_runtime_transport_registry,
        cpu_millicores: i64::from(env.cpu_millicores),
        memory_mib: i64::from(env.memory_mb),
        disk_gib: i64::from(env.disk_gb),
        workspace_storage_class: cfg.workspace_storage_class.clone(),
        node_selector: resolve_node_selector(&runtime_spec.profile, override_selector),
        tolerations: default_tolerations(&runtime_spec.profile),
        network_policy_management: cfg.network_policy_management.clone(),
        dind_enabled: runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT,
        kata_agent_policy_enabled: cfg.kata_agent_policy_enabled,
        kata_coco_init_data_enabled: cfg.kata_coco_init_data_enabled,
        kata_coco_kbs_url: cfg.kata_coco_kbs_url.clone(),
        kata_coco_kbs_ca_pem: cfg.kata_coco_kbs_ca_pem.clone(),
        kata_coco_image_registry_auth_uri: cfg.kata_coco_image_registry_auth_uri.clone(),
        kata_coco_test_resource_uri: cfg.kata_coco_test_resource_uri.clone(),
        kata_coco_test_resource_path: cfg.kata_coco_test_resource_path.clone(),
        debug_tailnet: cfg.debug_tailnet,
    }
}

/// Product tiers deliberately select the existing approved runtime profiles.
/// The Environment row, not a mutable process-wide runtime setting, is the
/// source of truth for a created environment's isolation.
pub fn runtime_profile_for_isolation_tier(tier: &str) -> anyhow::Result<Option<&'static str>> {
    match tier {
        "standard" => Ok(None),
        "confidential" => Ok(Some(RUNTIME_PROFILE_CONFIDENTIAL)),
        other => anyhow::bail!("unsupported environment isolation tier {other:?}"),
    }
}

/// Mirrors `environmentClaimOpts`.
pub fn environment_claim_opts(
    cfg: &SandboxWorkerCfg,
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    env_id: &str,
    _gateway_token: &str,
) -> ClaimOpts {
    if is_canonical_workspace_runtime_image(image_ref) {
        if env.isolation_tier != "standard" {
            let template_ref =
                environment_template_name(CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME, env_id);
            return ClaimOpts {
                environment_id: env_id.to_string(),
                org_id: env.org_id.clone(),
                warm_pool_ref: shadow_warm_pool_name(&template_ref),
                template_ref,
                additional_pod_labels: environment_pod_selector(env_id),
                ..Default::default()
            };
        }
        match parse_canonical_full_warm_pool_profiles(&cfg.full_warm_profiles) {
            Err(e) => {
                tracing::warn!(error = %e, "environment claim: invalid canonical full warm profiles, falling back to per-environment template");
            }
            Ok(profiles) => {
                if let Some(profile) = match_canonical_full_warm_pool_profile(
                    &profiles,
                    env.cpu_millicores,
                    env.memory_mb,
                    env.disk_gb,
                ) {
                    let template_opts = warm_pool_template_opts(cfg, profile);
                    return ClaimOpts {
                        environment_id: env_id.to_string(),
                        org_id: env.org_id.clone(),
                        template_ref: profile.template_name.clone(),
                        warm_pool_ref: warm_pool_name(&profile.template_name, &template_opts),
                        additional_pod_labels: environment_pod_selector(env_id),
                        ..Default::default()
                    };
                }
            }
        }
        let template_ref =
            environment_template_name(CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME, env_id);
        return ClaimOpts {
            environment_id: env_id.to_string(),
            org_id: env.org_id.clone(),
            warm_pool_ref: shadow_warm_pool_name(&template_ref),
            template_ref,
            additional_pod_labels: environment_pod_selector(env_id),
            ..Default::default()
        };
    }

    let template_ref = environment_template_name(template_base, env_id);
    ClaimOpts {
        environment_id: env_id.to_string(),
        org_id: env.org_id.clone(),
        warm_pool_ref: shadow_warm_pool_name(&template_ref),
        template_ref,
        additional_pod_labels: environment_pod_selector(env_id),
        ..Default::default()
    }
}

pub fn environment_per_env_template_name(
    cfg: &SandboxWorkerCfg,
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    env_id: &str,
) -> Option<String> {
    if is_canonical_workspace_runtime_image(image_ref) {
        // Canonical warm pools are rendered from the process-wide standard
        // runtime configuration. A confidential environment must instead use
        // its tier-derived per-environment template so its Sandbox and Pod are
        // created with the confidential RuntimeClass.
        if env.isolation_tier != "standard" {
            return Some(environment_template_name(
                CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME,
                env_id,
            ));
        }
        if let Ok(profiles) = parse_canonical_full_warm_pool_profiles(&cfg.full_warm_profiles)
            && match_canonical_full_warm_pool_profile(
                &profiles,
                env.cpu_millicores,
                env.memory_mb,
                env.disk_gb,
            )
            .is_some()
        {
            return None;
        }
        return Some(environment_template_name(
            CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME,
            env_id,
        ));
    }

    Some(environment_template_name(template_base, env_id))
}

// ── Backend row mutators (port of environment_data.go) ─────────────────

pub async fn upsert_backend_namespace(
    authority: &ActivityAuthority,
    namespace: &str,
) -> anyhow::Result<()> {
    authority
        .execute_for_states(
            CREATE_MUTATION_STATES,
            sqlx::query(
                r#"INSERT INTO sandbox_environment_backend (environment_id, namespace)
           VALUES ($1, $2)
           ON CONFLICT (environment_id) DO UPDATE SET namespace = $2"#,
            )
            .bind(authority.environment_id())
            .bind(namespace),
        )
        .await?;
    Ok(())
}

pub async fn update_backend_claim(
    authority: &ActivityAuthority,
    claim_name: &str,
    claim_uid: &str,
) -> anyhow::Result<()> {
    authority.execute_for_states(CREATE_MUTATION_STATES, sqlx::query(
        "UPDATE sandbox_environment_backend SET sandbox_claim_name = $1, sandbox_claim_uid = $2 WHERE environment_id = $3",
    )
    .bind(claim_name)
    .bind(claim_uid)
    .bind(authority.environment_id())
    ).await?;
    Ok(())
}

pub async fn update_backend_pod_info(
    authority: &ActivityAuthority,
    pod_ip: &str,
    pod_name: &str,
) -> anyhow::Result<()> {
    authority.execute_for_states(CREATE_MUTATION_STATES, sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_ip = $1, pod_name = $2 WHERE environment_id = $3",
    )
    .bind(pod_ip)
    .bind(pod_name)
    .bind(authority.environment_id())
    ).await?;
    Ok(())
}

// ── Handler (port of runEnvironmentCreate) ─────────────────────────────

const CREATE_READY_TIMEOUT: Duration = Duration::from_secs(600); // SANDBOX_CREATE_READY_TIMEOUT_SECS default
const CONFIDENTIAL_CREATE_READY_TIMEOUT: Duration = Duration::from_secs(1800);
const RUNTIME_METADATA_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(30);
const CREATE_MUTATION_STATES: &[&str] = &["pending", "creating", "starting"];

pub(super) fn ready_timeout_for_isolation(isolation_tier: &str) -> Duration {
    if isolation_tier == "confidential" {
        CONFIDENTIAL_CREATE_READY_TIMEOUT
    } else {
        CREATE_READY_TIMEOUT
    }
}

pub(super) async fn reconcile_confidential_runtime_before_replacement(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    env_id: &str,
    authority: &ActivityAuthority,
    authoritative_states: &[&str],
    client: &SandboxClient,
    stale: &WorkspacePodIdentity,
) -> anyhow::Result<()> {
    if env.isolation_tier != "confidential" {
        return Ok(());
    }

    let preset_id = env
        .preset_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("confidential environment has no preset id"))?;
    let (image_ref, template_base) = load_sandbox_template_config(&ctx.pool, preset_id).await?;
    let cfg = &ctx.sandbox_cfg;
    let expected_template =
        environment_per_env_template_name(cfg, &image_ref, &template_base, env, env_id)
            .ok_or_else(|| {
                anyhow::anyhow!("confidential environment has no private runtime template")
            })?;
    let gateway_token = issue_token(&cfg.session_secret, env_id, SCOPE_COORDINATE)?;
    let template_opts =
        environment_template_opts(cfg, &image_ref, &template_base, env, env_id, &gateway_token);
    if template_opts.name != expected_template {
        anyhow::bail!("confidential runtime template identity is inconsistent");
    }
    validate_managed_runtime_profile(
        &template_opts.runtime_profile_spec(),
        cfg.allow_diagnostic_runtime,
    )
    .map_err(|error| anyhow::anyhow!("runtime profile: {error}"))?;

    let kernel_params = authority
        .run_external_mutation(
            authoritative_states,
            client.reconcile_per_environment_runtime(env_id, &stale.name, &template_opts),
        )
        .await?;
    authority
        .run_while_authoritative_for_states(
            authoritative_states,
            client.wait_for_workspace_pod_annotation(
                &stale.name,
                &stale.uid,
                KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
                &kernel_params,
                RUNTIME_METADATA_PROPAGATION_TIMEOUT,
            ),
        )
        .await
}

/// Mirrors `RunEnvironmentCreateWithoutSetupPublish` — the create
/// activity never publishes the setup job: the Temporal workflow chains
/// the Setup activity explicitly (D3 retired the env-setup NATS path).
pub async fn handle_environment_create_without_setup_publish(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    run_environment_create(ctx, payload, authority).await
}

async fn run_environment_create(
    ctx: &WorkerContext,
    payload: &JobPayload,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let env_id = &payload.environment_id;
    tracing::info!(environment_id = env_id, "environment.create received");
    let svc = Service::<PgLifecycleStore>::for_activity(ctx.pool.clone(), authority.clone());
    let cfg = &ctx.sandbox_cfg;

    loop {
        authority.ensure().await?;
        let env = load_environment(&ctx.pool, env_id).await?;
        if create_command_cancelled(&env.state, &env.desired_state) {
            tracing::info!(
                env = env_id,
                state = env.state,
                desired = env.desired_state,
                "create cancelled: desired state changed"
            );
            return Ok(());
        }

        // No backend row yet is fine — first iteration.
        let backend = load_backend_row(&ctx.pool, env_id).await.ok();

        let mut probe = ProbeResult::default();
        if let Some(b) = &backend
            && !b.namespace.is_empty()
        {
            if let Some(kube) = &ctx.kube {
                match SandboxClient::new(kube.clone(), &b.namespace)
                    .probe_environment(env_id)
                    .await
                {
                    Ok(p) => probe = p,
                    Err(e) => {
                        tracing::warn!(env = env_id, error = %e, "probe failed, assuming empty");
                    }
                }
            } else {
                tracing::warn!(
                    env = env_id,
                    "probe failed, assuming empty (no sandbox backend)"
                );
            }
        }

        let setup_complete = backend.as_ref().is_some_and(|b| b.setup_complete);
        let action = next_create_action(&env.state, backend.as_ref(), setup_complete, &probe);
        tracing::info!(env = env_id, state = env.state, action = %action, "create loop");

        match action {
            CreateAction::Done => return Ok(()),

            CreateAction::WaitForReady => {
                let started = std::time::Instant::now();
                emit_authoritative_environment_log_for_states(
                    authority,
                    CREATE_MUTATION_STATES,
                    "wait_for_ready",
                    "started",
                    "",
                    None,
                )
                .await?;
                tracing::info!(env = env_id, "waiting for claim ready");
                let backend = backend.as_ref().expect("wait_for_ready requires backend");
                let client = match require_client(ctx, &backend.namespace) {
                    Ok(c) => c,
                    Err(e) => {
                        emit_authoritative_environment_log_for_states(
                            authority,
                            CREATE_MUTATION_STATES,
                            "wait_for_ready",
                            "failed",
                            &format!("{e:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(
                            &svc,
                            authority,
                            env_id,
                            &format!("wait for sandbox ready: {e:#}"),
                        )
                        .await?;
                        return Err(e);
                    }
                };
                if create_retry_recovery_required(&env.state)
                    && let Err(e) = replace_terminal_workspace_pod(
                        ctx,
                        &env,
                        authority,
                        env_id,
                        &env.isolation_tier,
                        &client,
                    )
                    .await
                {
                    emit_authoritative_environment_log_for_states(
                        authority,
                        CREATE_MUTATION_STATES,
                        "wait_for_ready",
                        "failed",
                        &format!("{e:#}"),
                        duration_meta(started),
                    )
                    .await?;
                    record_error(
                        &svc,
                        authority,
                        env_id,
                        &format!("replace terminal workspace Pod: {e:#}"),
                    )
                    .await?;
                    return Err(e);
                }
                if let Err(e) = authority
                    .run_while_authoritative_for_states(
                        CREATE_MUTATION_STATES,
                        client.wait_for_ready(
                            env_id,
                            ready_timeout_for_isolation(&env.isolation_tier),
                        ),
                    )
                    .await
                {
                    emit_authoritative_environment_log_for_states(
                        authority,
                        CREATE_MUTATION_STATES,
                        "wait_for_ready",
                        "failed",
                        &format!("{e:#}"),
                        duration_meta(started),
                    )
                    .await?;
                    record_error(
                        &svc,
                        authority,
                        env_id,
                        &format!("wait for sandbox ready: {e:#}"),
                    )
                    .await?;
                    return Err(e);
                }
                emit_authoritative_environment_log_for_states(
                    authority,
                    CREATE_MUTATION_STATES,
                    "wait_for_ready",
                    "completed",
                    "",
                    duration_meta(started),
                )
                .await?;
            }

            CreateAction::EnsureNamespace => {
                emit_create_log(authority, "ensure_namespace", "started", "", None).await?;
                if let Some(kube) = &ctx.kube {
                    authority
                        .run_external_mutation(
                            CREATE_MUTATION_STATES,
                            SandboxClient::new(kube.clone(), &cfg.sandbox_namespace)
                                .ensure_namespace(),
                        )
                        .await?;
                }
                upsert_backend_namespace(authority, &cfg.sandbox_namespace).await?;
                emit_create_log(authority, "ensure_namespace", "completed", "", None).await?;
            }

            CreateAction::CreateClaim => {
                let started = std::time::Instant::now();
                emit_create_log(authority, "create_claim", "started", "", None).await?;
                if env.state == "pending"
                    && let Err(e) = svc.transition(env_id, "pending", "creating").await
                {
                    authority.ensure().await?;
                    tracing::warn!(error = %e, "CAS to creating failed");
                }
                if env.isolation_tier == "confidential" {
                    let Some(storage) = ctx.confidential_storage.as_ref() else {
                        let error =
                            anyhow::anyhow!("confidential storage providers are not configured");
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{error:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(
                            &svc,
                            authority,
                            env_id,
                            &format!("key provisioning: {error:#}"),
                        )
                        .await?;
                        return Err(error);
                    };
                    if let Err(error) = authority
                        .run_external_mutation(CREATE_MUTATION_STATES, storage.ensure_ready(env_id))
                        .await
                    {
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{error:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(
                            &svc,
                            authority,
                            env_id,
                            &format!("key provisioning: {error:#}"),
                        )
                        .await?;
                        return Err(error);
                    }
                }
                let preset_id = env.preset_id.clone().unwrap_or_default();
                let (image_ref, template_base) =
                    match load_sandbox_template_config(&ctx.pool, &preset_id).await {
                        Ok(v) => v,
                        Err(e) => {
                            emit_create_log(
                                authority,
                                "create_claim",
                                "failed",
                                &format!("{e:#}"),
                                None,
                            )
                            .await?;
                            record_error(
                                &svc,
                                authority,
                                env_id,
                                &format!("template config: {e:#}"),
                            )
                            .await?;
                            return Err(e);
                        }
                    };
                let gateway_token = match issue_token(&cfg.session_secret, env_id, SCOPE_COORDINATE)
                {
                    Ok(t) => t,
                    Err(e) => {
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{e:#}"),
                            None,
                        )
                        .await?;
                        record_error(&svc, authority, env_id, &format!("sidecar token: {e:#}"))
                            .await?;
                        return Err(e);
                    }
                };
                let template_opts = environment_template_opts(
                    cfg,
                    &image_ref,
                    &template_base,
                    &env,
                    env_id,
                    &gateway_token,
                );
                let runtime_spec = template_opts.runtime_profile_spec();
                if let Err(e) =
                    validate_managed_runtime_profile(&runtime_spec, cfg.allow_diagnostic_runtime)
                {
                    emit_create_log(
                        authority,
                        "create_claim",
                        "failed",
                        &e,
                        duration_meta(started),
                    )
                    .await?;
                    record_error(&svc, authority, env_id, &format!("runtime profile: {e}")).await?;
                    anyhow::bail!(e);
                }
                let claim_opts = environment_claim_opts(
                    cfg,
                    &image_ref,
                    &template_base,
                    &env,
                    env_id,
                    &gateway_token,
                );

                let backend = backend
                    .as_ref()
                    .expect("create_claim requires backend namespace");
                let client = match require_client(ctx, &backend.namespace) {
                    Ok(c) => c,
                    Err(e) => {
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{e:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(&svc, authority, env_id, &format!("claim: {e:#}")).await?;
                        return Err(e);
                    }
                };

                let mut ensured_template = String::new();
                let mut ensured_warm_pool = String::new();
                if claim_opts.template_ref == template_opts.name {
                    ensured_template = template_opts.name.clone();
                    ensured_warm_pool = if claim_opts.warm_pool_ref.is_empty() {
                        shadow_warm_pool_name(&ensured_template)
                    } else {
                        claim_opts.warm_pool_ref.clone()
                    };
                    if let Err(e) = authority
                        .run_external_mutation(
                            CREATE_MUTATION_STATES,
                            client.ensure_sandbox_template(&template_opts),
                        )
                        .await
                    {
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{e:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(&svc, authority, env_id, &format!("template: {e:#}")).await?;
                        return Err(e);
                    }
                    if let Err(e) = authority
                        .run_external_mutation(
                            CREATE_MUTATION_STATES,
                            client.ensure_warm_pool(&ensured_warm_pool, &ensured_template, 0),
                        )
                        .await
                    {
                        let _ = authority
                            .run_external_mutation(
                                CREATE_MUTATION_STATES,
                                client.delete_sandbox_template(&ensured_template),
                            )
                            .await;
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{e:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(&svc, authority, env_id, &format!("warm pool: {e:#}")).await?;
                        return Err(e);
                    }
                }
                let claim_result = async {
                    let mut guard = authority
                        .begin_external_mutation(CREATE_MUTATION_STATES)
                        .await?;
                    let (created_claim_name, claim_uid) = await_external_mutation(
                        client.create_sandbox_claim(&backend.namespace, &claim_opts),
                    )
                    .await?;
                    #[cfg(feature = "kind-e2e")]
                    super::fencing_evidence::hold_claim_row_lock(
                        env_id,
                        &created_claim_name,
                        &claim_uid,
                    )
                    .await?;
                    let result = sqlx::query(
                        "UPDATE sandbox_environment_backend
                            SET sandbox_claim_name = $1, sandbox_claim_uid = $2
                          WHERE environment_id = $3",
                    )
                    .bind(&created_claim_name)
                    .bind(&claim_uid)
                    .bind(env_id)
                    .execute(&mut **guard.transaction())
                    .await?;
                    if result.rows_affected() != 1 {
                        anyhow::bail!("sandbox backend row missing during claim bookkeeping");
                    }
                    guard.commit().await?;
                    Ok::<_, anyhow::Error>((created_claim_name, claim_uid))
                }
                .await;
                let (_created_claim_name, _claim_uid) = match claim_result {
                    Ok(v) => v,
                    Err(e) => {
                        if !ensured_warm_pool.is_empty() {
                            let _ = authority
                                .run_external_mutation(
                                    CREATE_MUTATION_STATES,
                                    client.delete_warm_pool(&ensured_warm_pool),
                                )
                                .await;
                        }
                        if !ensured_template.is_empty() {
                            let _ = authority
                                .run_external_mutation(
                                    CREATE_MUTATION_STATES,
                                    client.delete_sandbox_template(&ensured_template),
                                )
                                .await;
                        }
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &format!("{e:#}"),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(&svc, authority, env_id, &format!("claim: {e:#}")).await?;
                        return Err(e);
                    }
                };
                if let Err(e) = authority
                    .run_external_mutation(
                        CREATE_MUTATION_STATES,
                        client.ensure_gateway_stack(&template_opts),
                    )
                    .await
                {
                    emit_create_log(
                        authority,
                        "create_claim",
                        "failed",
                        &format!("{e:#}"),
                        duration_meta(started),
                    )
                    .await?;
                    record_error(&svc, authority, env_id, &format!("gateway stack: {e:#}")).await?;
                    return Err(e);
                }
                emit_create_log(
                    authority,
                    "create_claim",
                    "completed",
                    "",
                    duration_meta(started),
                )
                .await?;
            }

            CreateAction::StoreBackend => {
                if let Some(backend) = backend.as_ref()
                    && let Err(e) = ensure_gateway_stack_for_environment(
                        ctx,
                        cfg,
                        &env,
                        env_id,
                        &backend.namespace,
                        authority,
                    )
                    .await
                {
                    record_error(&svc, authority, env_id, &format!("gateway stack: {e:#}")).await?;
                    return Err(e);
                }
                update_backend_pod_info(authority, &probe.pod_ip, &probe.pod_name).await?;
                emit_create_log(authority, "store_backend", "completed", "", None).await?;
            }

            CreateAction::MarkRunning => {
                if let Some(backend) = backend.as_ref()
                    && let Err(e) = ensure_gateway_stack_for_environment(
                        ctx,
                        cfg,
                        &env,
                        env_id,
                        &backend.namespace,
                        authority,
                    )
                    .await
                {
                    record_error(&svc, authority, env_id, &format!("gateway stack: {e:#}")).await?;
                    return Err(e);
                }
                if let Err(e) = svc.transition(env_id, &env.state, "running").await {
                    authority.ensure().await?;
                    tracing::warn!(env = env_id, from = env.state, error = %e, "CAS to running failed");
                }
                if let Err(e) = svc.mark_started(env_id).await {
                    authority.ensure().await?;
                    tracing::warn!(env = env_id, error = %e, "mark started failed");
                }
                emit_running_log(authority, "mark_running", "completed", "", None).await?;
            }

            CreateAction::PublishSetup => {
                // D3: the create activity never publishes setup — the
                // Temporal workflow (and the reconcile recovery path)
                // chain the Setup activity explicitly. The log entry
                // marks the create handler complete.
                emit_running_log(authority, "publish_setup", "completed", "", None).await?;
                return Ok(());
            }
        }
    }
}

async fn emit_create_log(
    authority: &ActivityAuthority,
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    emit_authoritative_environment_log_for_states(
        authority,
        CREATE_MUTATION_STATES,
        phase,
        status,
        message,
        metadata,
    )
    .await
}

async fn emit_running_log(
    authority: &ActivityAuthority,
    phase: &str,
    status: &str,
    message: &str,
    metadata: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    emit_authoritative_environment_log_for_states(
        authority,
        &["running"],
        phase,
        status,
        message,
        metadata,
    )
    .await
}

fn duration_meta(started: std::time::Instant) -> Option<serde_json::Value> {
    Some(serde_json::json!({ "duration_ms": started.elapsed().as_millis() as i64 }))
}

fn require_client(ctx: &WorkerContext, namespace: &str) -> anyhow::Result<SandboxClient> {
    let Some(kube) = &ctx.kube else {
        anyhow::bail!("sandbox backend is not configured");
    };
    Ok(SandboxClient::new(kube.clone(), namespace))
}

async fn replace_terminal_workspace_pod(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    authority: &ActivityAuthority,
    env_id: &str,
    isolation_tier: &str,
    client: &SandboxClient,
) -> anyhow::Result<()> {
    let Some(stale) = client.workspace_pod_replacement_candidate(env_id).await? else {
        return Ok(());
    };
    let started = std::time::Instant::now();
    emit_create_log(authority, "replace_terminal_pod", "started", "", None).await?;
    let result = async {
        tracing::info!(
            env = env_id,
            pod = %stale.name,
            "replacing terminal workspace Pod before waiting for claim readiness"
        );
        reconcile_confidential_runtime_before_replacement(
            ctx,
            env,
            env_id,
            authority,
            CREATE_MUTATION_STATES,
            client,
            &stale,
        )
        .await?;
        authority
            .run_external_mutation(
                CREATE_MUTATION_STATES,
                client.delete_workspace_pod_if_uid(&stale.name, &stale.uid),
            )
            .await?;
        authority
            .run_while_authoritative_for_states(
                CREATE_MUTATION_STATES,
                client.wait_for_replacement_workspace_pod(
                    &stale.name,
                    &stale.uid,
                    ready_timeout_for_isolation(isolation_tier),
                ),
            )
            .await
    }
    .await;

    match result {
        Ok(_) => {
            emit_create_log(
                authority,
                "replace_terminal_pod",
                "completed",
                "",
                duration_meta(started),
            )
            .await
        }
        Err(error) => {
            emit_create_log(
                authority,
                "replace_terminal_pod",
                "failed",
                &format!("{error:#}"),
                duration_meta(started),
            )
            .await?;
            Err(error)
        }
    }
}

async fn ensure_gateway_stack_for_environment(
    ctx: &WorkerContext,
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    env_id: &str,
    namespace: &str,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let preset_id = env.preset_id.clone().unwrap_or_default();
    let (image_ref, template_base) = load_sandbox_template_config(&ctx.pool, &preset_id).await?;
    let gateway_token = issue_token(&cfg.session_secret, env_id, SCOPE_COORDINATE)?;
    let template_opts =
        environment_template_opts(cfg, &image_ref, &template_base, env, env_id, &gateway_token);
    let runtime_spec = template_opts.runtime_profile_spec();
    validate_managed_runtime_profile(&runtime_spec, cfg.allow_diagnostic_runtime)
        .map_err(|e| anyhow::anyhow!("runtime profile: {e}"))?;
    let client = require_client(ctx, namespace)?;
    authority
        .run_external_mutation(
            CREATE_MUTATION_STATES,
            client.ensure_gateway_stack(&template_opts),
        )
        .await
}

async fn record_error(
    svc: &Service<PgLifecycleStore>,
    authority: &ActivityAuthority,
    env_id: &str,
    reason: &str,
) -> anyhow::Result<()> {
    authority.ensure().await?;
    if let Err(e) = svc
        .mark_error_for_states(env_id, reason, CREATE_MUTATION_STATES)
        .await
    {
        authority.ensure().await?;
        tracing::error!(environment_id = env_id, reason, error = %e, "environment lifecycle: failed to mark error");
    }
    Ok(())
}

/// Mirrors `loadSandboxTemplateConfig`.
async fn load_sandbox_template_config(
    pool: &PgPool,
    preset_id: &str,
) -> anyhow::Result<(String, String)> {
    let row: (String, String) = sqlx::query_as(
        "SELECT image_ref, sandbox_template_name FROM sandbox_template_config WHERE preset_id = $1",
    )
    .bind(preset_id)
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("load sandbox_template_config for {preset_id}: {e}"))?;
    Ok(row)
}

/// `claim_name` re-exported check (the create path never recomputes it
/// independently — CreateSandboxClaim derives it from the env ID).
#[allow(dead_code)]
fn _claim_name_used(env_id: &str) -> String {
    claim_name(env_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_tier_selects_only_the_product_runtime_profile() {
        assert_eq!(
            runtime_profile_for_isolation_tier("standard").unwrap(),
            None
        );
        assert_eq!(
            runtime_profile_for_isolation_tier("confidential").unwrap(),
            Some(RUNTIME_PROFILE_CONFIDENTIAL)
        );
        assert!(runtime_profile_for_isolation_tier("unknown").is_err());
    }

    fn backend(ns: &str, claim: &str, ip: &str, setup_complete: bool) -> BackendRow {
        BackendRow {
            namespace: ns.into(),
            claim_name: claim.into(),
            pod_ip: ip.into(),
            setup_complete,
            ..Default::default()
        }
    }

    fn probe(exists: bool, ready: bool) -> ProbeResult {
        ProbeResult {
            claim_exists: exists,
            claim_ready: ready,
            ..Default::default()
        }
    }

    // Port of environmentlifecycle/create_test.go.
    #[test]
    fn next_create_action_mirrors_go() {
        // No backend row → ensure namespace.
        assert_eq!(
            next_create_action("pending", None, false, &probe(false, false)),
            CreateAction::EnsureNamespace
        );
        // Backend without namespace → ensure namespace.
        let b = backend("", "", "", false);
        assert_eq!(
            next_create_action("pending", Some(&b), false, &probe(false, false)),
            CreateAction::EnsureNamespace
        );
        // Namespace, no claim in cluster → create claim.
        let b = backend("ns", "", "", false);
        assert_eq!(
            next_create_action("pending", Some(&b), false, &probe(false, false)),
            CreateAction::CreateClaim
        );
        // Claim exists in cluster but not recorded → create claim (re-record).
        let b = backend("ns", "", "", false);
        assert_eq!(
            next_create_action("pending", Some(&b), false, &probe(true, false)),
            CreateAction::CreateClaim
        );
        // Claim recorded but not ready → wait.
        let b = backend("ns", "sandbox-env", "", false);
        assert_eq!(
            next_create_action("creating", Some(&b), false, &probe(true, false)),
            CreateAction::WaitForReady
        );
        // Ready but pod IP unknown → store backend.
        assert_eq!(
            next_create_action("creating", Some(&b), false, &probe(true, true)),
            CreateAction::StoreBackend
        );
        // Pod IP known, state not running → mark running.
        let b = backend("ns", "sandbox-env", "10.0.0.5", false);
        assert_eq!(
            next_create_action("creating", Some(&b), false, &probe(true, true)),
            CreateAction::MarkRunning
        );
        // Running but setup incomplete → publish setup.
        assert_eq!(
            next_create_action("running", Some(&b), false, &probe(true, true)),
            CreateAction::PublishSetup
        );
        // Running + setup complete → done.
        let b = backend("ns", "sandbox-env", "10.0.0.5", true);
        assert_eq!(
            next_create_action("running", Some(&b), true, &probe(true, true)),
            CreateAction::Done
        );
    }

    #[test]
    fn stale_create_commands_do_not_resurrect_deleted_environments() {
        assert!(create_command_cancelled("pending", "destroyed"));
        assert!(create_command_cancelled("creating", "destroyed"));
        assert!(create_command_cancelled("running", "destroyed"));
        assert!(create_command_cancelled("destroying", "destroyed"));
        assert!(create_command_cancelled("destroyed", "destroyed"));
        assert!(create_command_cancelled("destroying", "started"));
        assert!(!create_command_cancelled("pending", "started"));
        assert!(!create_command_cancelled("creating", "started"));
        assert!(!create_command_cancelled("running", "started"));
    }

    #[test]
    fn terminal_pod_recovery_is_scoped_to_explicit_pending_retries() {
        assert!(create_retry_recovery_required("pending"));
        assert!(!create_retry_recovery_required("creating"));
        assert!(!create_retry_recovery_required("starting"));
        assert!(!create_retry_recovery_required("running"));
    }

    #[test]
    fn confidential_create_waits_outside_the_nested_runtime_deadlines() {
        assert_eq!(
            ready_timeout_for_isolation("standard"),
            Duration::from_secs(600)
        );
        assert_eq!(
            ready_timeout_for_isolation("confidential"),
            Duration::from_secs(1800)
        );
    }

    #[test]
    fn warm_pool_parsing_mirrors_go() {
        // Empty → defaults (workspace + legacy SKU).
        let defaults = parse_canonical_full_warm_pool_profiles("").unwrap();
        assert_eq!(defaults.len(), 2);
        assert_eq!(defaults[0].template_name, "workspace");
        assert_eq!(defaults[1].template_name, "workspace-2000m-4096mib-10gib");

        // Custom entries with the default-SKU shortcut name.
        let custom =
            parse_canonical_full_warm_pool_profiles("1000:2048:10:2, 4000:8192:20:1").unwrap();
        assert_eq!(custom[0].template_name, "workspace");
        assert_eq!(custom[1].template_name, "workspace-4000m-8192mib-20gib");
        assert_eq!(custom[1].replicas, 1);

        // Bad entries.
        assert!(parse_canonical_full_warm_pool_profiles("1000:2048:10").is_err());
        assert!(parse_canonical_full_warm_pool_profiles("0:2048:10:2").is_err());
        assert!(parse_canonical_full_warm_pool_profiles("1000:2048:10:2,1000:2048:10:3").is_err());

        // Matching.
        let p = match_canonical_full_warm_pool_profile(&defaults, 2000, 4096, 10).unwrap();
        assert_eq!(p.template_name, "workspace-2000m-4096mib-10gib");
        assert!(match_canonical_full_warm_pool_profile(&defaults, 123, 456, 7).is_none());
    }

    #[test]
    fn claim_opts_uses_warm_pool_for_canonical_image() {
        let cfg = SandboxWorkerCfg {
            full_warm_profiles: String::new(),
            ..Default::default()
        };
        let env = EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "pending".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 1000,
            memory_mb: 2048,
            disk_gb: 10,
            auth_token: None,
            ttl_seconds: None,
            setup_config: None,
            secret_project_id: None,
        };
        // Canonical image + matching SKU → shared warm-pool template.
        let opts = environment_claim_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
            "tmpl-base",
            &env,
            "env-1",
            "gateway-token",
        );
        assert_eq!(opts.template_ref, "workspace");
        let profile = parse_canonical_full_warm_pool_profiles("").unwrap()[0].clone();
        assert_eq!(
            opts.warm_pool_ref,
            warm_pool_name(
                &profile.template_name,
                &warm_pool_template_opts(&cfg, &profile)
            )
        );
        assert!(opts.env_overrides.is_empty());

        // Confidential environments must never adopt a standard canonical
        // warm-pool Sandbox. Their per-environment template carries the
        // tier-derived confidential RuntimeClass.
        let mut confidential = env.clone();
        confidential.isolation_tier = "confidential".into();
        let opts = environment_claim_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
            "tmpl-base",
            &confidential,
            "env-1",
            "gateway-token",
        );
        assert_eq!(opts.template_ref, "workspace-env-1");
        assert_eq!(opts.warm_pool_ref, "shadow-pool-workspace-env-1");
        assert_eq!(
            environment_per_env_template_name(
                &cfg,
                "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
                "tmpl-base",
                &confidential,
                "env-1",
            ),
            Some("workspace-env-1".into())
        );

        // Canonical image, non-matching SKU → per-env canonical template.
        let mut big = env.clone();
        big.cpu_millicores = 8000;
        let opts = environment_claim_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
            "tmpl-base",
            &big,
            "env-1",
            "gateway-token",
        );
        assert_eq!(opts.template_ref, "workspace-env-1");
        assert_eq!(opts.warm_pool_ref, "shadow-pool-workspace-env-1");
        assert!(opts.env_overrides.is_empty());

        // Custom image → per-env template from the preset base name.
        let opts = environment_claim_opts(
            &cfg,
            "ghcr.io/acme/custom:1",
            "tmpl-base",
            &env,
            "env-1",
            "gateway-token",
        );
        assert_eq!(opts.template_ref, "tmpl-base-env-1");
        assert_eq!(opts.warm_pool_ref, "shadow-pool-tmpl-base-env-1");
        assert!(opts.env_overrides.is_empty());
    }

    #[test]
    fn template_opts_mirror_go_branches() {
        let cfg = SandboxWorkerCfg {
            gateway_image: "gw:1".into(),
            runtime_class: "isol8".into(),
            api_base_url: "https://api".into(),
            derp_port: "".into(),
            stun_port: "".into(),
            kata_agent_policy_enabled: true,
            kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
            kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
            kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
            kata_coco_test_resource_path:
                "/run/confidential-containers/cdh/kbs/codewire/runtime-test-resource".into(),
            ..Default::default()
        };
        let env = EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "pending".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 10,
            auth_token: None,
            ttl_seconds: None,
            setup_config: None,
            secret_project_id: None,
        };
        // First-party image: no image command; canonical name swap.
        let opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
            "preset-base",
            &env,
            "env-1",
            "tok",
        );
        assert!(opts.image_command.is_empty());
        assert_eq!(opts.name, "workspace-env-1");
        assert_eq!(opts.derp_port, 443);
        assert_eq!(opts.stun_port, 3478);
        assert!(opts.kata_agent_policy_enabled);
        assert_eq!(opts.kata_coco_kbs_url, "https://kbs.codewire-dev.sh");
        assert_eq!(
            opts.kata_coco_image_registry_auth_uri,
            "kbs:///default/containers/auth"
        );
        assert_eq!(
            opts.kata_coco_test_resource_uri,
            "kbs:///default/codewire/runtime-test-resource"
        );
        assert_eq!(
            opts.kata_coco_test_resource_path,
            "/run/confidential-containers/cdh/kbs/codewire/runtime-test-resource"
        );
        assert!(
            !opts.node_selector.is_empty(),
            "legacy isol8 RuntimeClass resolves to the external-isol8-xen selector"
        );

        // Custom image: sleep infinity + preset-derived name.
        let opts = environment_template_opts(
            &cfg,
            "ghcr.io/acme/img:1",
            "preset-base",
            &env,
            "env-1",
            "tok",
        );
        assert_eq!(
            opts.image_command,
            vec!["sleep".to_string(), "infinity".to_string()]
        );
        assert_eq!(opts.name, "preset-base-env-1");

        // Non-external-isol8 runtime: no selector/tolerations.
        let mut plain = cfg.clone();
        plain.runtime_class = String::new();
        let opts =
            environment_template_opts(&plain, "ghcr.io/acme/img:1", "b", &env, "env-1", "tok");
        assert!(opts.node_selector.is_empty());
        assert!(opts.tolerations.is_empty());

        // Override selector wins.
        let mut overridden = cfg.clone();
        overridden.node_selector = "pool=custom".into();
        let opts =
            environment_template_opts(&overridden, "ghcr.io/acme/img:1", "b", &env, "env-1", "tok");
        assert_eq!(
            opts.node_selector,
            vec![("pool".to_string(), "custom".to_string())]
        );
    }

    #[test]
    fn confidential_tier_coexists_with_commodity_process_default() {
        let cfg = SandboxWorkerCfg {
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
            runtime_class: crate::sandbox::template::RUNTIME_CLASS_COMMODITY.into(),
            docker_mode: crate::sandbox::template::DOCKER_MODE_PROFILE_DEFAULT.into(),
            workspace_storage_class: "longhorn".into(),
            kata_agent_policy_enabled: true,
            kata_coco_init_data_enabled: true,
            kata_coco_kbs_url: "https://kbs.codewire-dev.sh".into(),
            kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
            ..Default::default()
        };
        let standard = EnvironmentRow {
            id: "env-coexist".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "pending".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 1000,
            memory_mb: 2048,
            disk_gb: 10,
            auth_token: None,
            ttl_seconds: None,
            setup_config: None,
            secret_project_id: None,
        };

        let standard_opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace:golden",
            "workspace",
            &standard,
            "env-coexist",
            "tok",
        );
        assert_eq!(
            standard_opts.runtime_profile,
            crate::sandbox::template::RUNTIME_PROFILE_COMMODITY
        );
        assert_eq!(
            standard_opts.runtime_class_name,
            crate::sandbox::template::RUNTIME_CLASS_COMMODITY
        );
        assert_eq!(
            standard_opts.docker_mode,
            crate::sandbox::template::DOCKER_MODE_GUEST_DIND
        );
        let standard_rendered =
            crate::sandbox::template::render_sandbox_template("codewire-runtime", &standard_opts);
        assert_eq!(
            standard_rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"]
                .as_str(),
            Some("longhorn")
        );
        assert!(
            standard_rendered["spec"]["podTemplate"]["metadata"]["annotations"]
                .get(crate::sandbox::template::KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                .is_none(),
            "commodity environments must not inherit CoCo KBS kernel parameters"
        );

        let mut confidential = standard.clone();
        confidential.isolation_tier = "confidential".into();
        let confidential_opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace:golden",
            "workspace",
            &confidential,
            "env-coexist",
            "tok",
        );
        assert_eq!(
            confidential_opts.runtime_profile,
            crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL
        );
        assert_eq!(
            confidential_opts.runtime_class_name,
            crate::sandbox::template::RUNTIME_CLASS_CONFIDENTIAL
        );
        assert_eq!(
            confidential_opts.docker_mode,
            crate::sandbox::template::DOCKER_MODE_GUEST_DIND
        );
        let confidential_rendered = crate::sandbox::template::render_sandbox_template(
            "codewire-runtime",
            &confidential_opts,
        );
        assert_eq!(
            confidential_rendered["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"]
                .as_str(),
            Some(crate::sandbox::template::CONFIDENTIAL_WORKSPACE_STORAGE_CLASS)
        );
        assert!(
            confidential_rendered["spec"]["podTemplate"]["metadata"]["annotations"]
                .get(crate::sandbox::template::KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
                .is_some(),
            "confidential environments must receive CoCo KBS kernel parameters"
        );
    }

    #[test]
    fn template_opts_enable_direct_udp_lb_for_managed_profiles() {
        let env = EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "pending".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 1000,
            memory_mb: 2048,
            disk_gb: 10,
            auth_token: None,
            ttl_seconds: None,
            setup_config: None,
            secret_project_id: None,
        };
        let cfg = SandboxWorkerCfg {
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
            direct_udp_lb_enabled: true,
            direct_udp_lb_ip: "192.0.2.36".into(),
            direct_udp_lb_port_start: "33000".into(),
            direct_udp_lb_port_end: "33010".into(),
            direct_udp_lb_class: "io.cilium/l2-announcer".into(),
            direct_udp_lb_sharing_key: "codewire-direct-udp".into(),
            direct_udp_transport_zone: "prod-node".into(),
            ..Default::default()
        };

        let opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
            "workspace",
            &env,
            "env-1",
            "tok",
        );

        assert!(opts.direct_udp_lb_enabled);
        assert_eq!(opts.direct_udp_lb_ip, "192.0.2.36");
        assert_eq!(opts.direct_udp_lb_port, 0);
        assert_eq!(opts.direct_udp_lb_port_start, 33000);
        assert_eq!(opts.direct_udp_lb_port_end, 33010);
        assert_eq!(opts.direct_udp_lb_class, "io.cilium/l2-announcer");
        assert_eq!(opts.direct_udp_lb_sharing_key, "codewire-direct-udp");
        assert_eq!(opts.direct_udp_transport_zone, "prod-node");

        let diagnostic = SandboxWorkerCfg {
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_RUNC.into(),
            direct_udp_lb_enabled: true,
            direct_udp_lb_ip: "192.0.2.36".into(),
            ..cfg
        };
        let opts = environment_template_opts(
            &diagnostic,
            "ghcr.io/acme/img:1",
            "workspace",
            &env,
            "env-1",
            "tok",
        );
        assert!(!opts.direct_udp_lb_enabled);
    }

    #[test]
    fn template_opts_uses_binding_for_peer_relay_when_transport_registry_is_configured() {
        let env = EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "pending".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 1000,
            memory_mb: 2048,
            disk_gb: 10,
            auth_token: None,
            ttl_seconds: None,
            setup_config: None,
            secret_project_id: None,
        };
        let cfg = SandboxWorkerCfg {
            runtime_transport_zones_json:
                r#"{"version":1,"zones":[{"name":"prod-node","runtime_region":"dev-eu"}]}"#
                    .into(),
            udp_relay_allocator_url:
                "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
                    .into(),
            udp_relay_allocator_token: "relay-token".into(),
            udp_relay_bind_addrs: "codewire-udp-relay.dev.svc.cluster.local:41641".into(),
            ..Default::default()
        };

        let opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467",
            "workspace",
            &env,
            "env-1",
            "tok",
        );

        assert!(opts.udp_relay_allocator_url.is_empty());
        assert!(opts.udp_relay_allocator_token.is_empty());
        assert!(opts.udp_relay_bind_addrs.is_empty());
    }

    #[test]
    fn port_parsing_mirrors_go() {
        assert_eq!(parse_derp_port(""), 443);
        assert_eq!(parse_derp_port("0"), 443);
        assert_eq!(parse_derp_port("8443"), 8443);
        assert_eq!(parse_stun_port(""), 3478);
        assert_eq!(parse_stun_port("-1"), 3478);
        assert_eq!(parse_stun_port("19302"), 19302);
    }
}
