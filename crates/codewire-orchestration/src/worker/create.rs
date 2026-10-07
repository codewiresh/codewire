//! The `environment.create` job — port of `runEnvironmentCreate`
//! (handler_environment.go), `environmentlifecycle/create.go`'s
//! NextCreateAction policy, and the template/claim opts builders.

use std::time::Duration;

use sqlx::PgPool;

use super::activity_authority::{ActivityAuthority, AuthorityLost, await_external_mutation};
use super::env_data::{
    BackendRow, EnvironmentRow, load_backend_row, load_environment, load_environment_in,
};
use super::env_log::emit_authoritative_environment_log_for_states;
use super::environment_auth::{WorkspaceCredentialScope, issue_environment_daemon_token};
use super::start_timing::{POD_STAGE_PHASES, duration_ms, pod_stage_timings, start_profile};
use super::workspace_binding::{
    EnvironmentBinding, bind_before_ready, bind_workspace_runtime, binding_bootstrap_current,
    credential_scope, definitive_refusal, live_environment_binding, sandbox_bound_by_any,
};
use super::{JobPayload, WorkerContext};
use crate::lifecycle::{PgLifecycleStore, Service};
use crate::sandbox::client::{
    ProbeResult, SandboxClient, WorkspacePodIdentity, WorkspaceSandboxIdentity,
};
use crate::sandbox::host_keys::RecordedHostKeys;
use crate::sandbox::template::{
    CONFIDENTIAL_WORKSPACE_READY_TIMEOUT, DOCKER_MODE_LOCAL_DIND_DIRECT,
    KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY, RUNTIME_PROFILE_CONFIDENTIAL, RuntimeProfileSpec,
    TemplateOpts, WORKSPACE_READY_TIMEOUT, WorkspaceIdentity, confidential_init_data,
    runtime_profile_spec, validate_managed_runtime_profile,
};
use crate::sandbox::warm_pool::{WarmPoolObjects, WorkspaceShape, render_warm_pool};
use crate::sandbox::{
    CANONICAL_WORKSPACE_RUNTIME_IMAGE, ClaimOpts, claim_name, environment_template_name,
    is_canonical_workspace_runtime_image, shadow_warm_pool_name,
};
use crate::start_metrics::{self, StartPath, StartProfile, StartStage};

mod pool_route;
mod warm_bridge;

#[cfg(test)]
mod projection_tests;

#[cfg(test)]
mod projection_database_tests;

#[cfg(test)]
mod warm_pool_tests;

/// Only an exactly owned Pod with stale immutable bootstrap may be restarted.
/// Missing/replaced identities and storage errors must never select recovery.
#[derive(Debug, thiserror::Error)]
#[error("workspace Pod bootstrap does not match the current environment operation")]
pub(super) struct WorkspaceBootstrapMismatch;

/// Mirrors `sandbox.CanonicalWorkspaceRuntimeTemplateName`.
pub const CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME: &str = "workspace";

// ── Create action policy (port of environmentlifecycle/create.go) ──────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateAction {
    Done,
    WaitForReady,
    ResumeWorkspace,
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
            CreateAction::ResumeWorkspace => "resume_workspace",
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
        if create_retry_recovery_required(state) && suspended_workspace_blocks_readiness(probe) {
            return CreateAction::ResumeWorkspace;
        }
        return CreateAction::WaitForReady;
    }
    if !probe.pod_exists
        || probe.pod_phase != "Running"
        || probe.pod_name.is_empty()
        || probe.pod_uid.is_empty()
        || probe.pod_ip.is_empty()
    {
        return CreateAction::WaitForReady;
    }
    if backend.pod_ip != probe.pod_ip || backend.pod_name != probe.pod_name {
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

/// A Claim never reports Ready while its bound Sandbox stays suspended, for
/// example after setup's no-Pod fence lost its `started` intent (#2328).
/// Waiting for readiness alone would never converge.
fn suspended_workspace_blocks_readiness(probe: &ProbeResult) -> bool {
    probe.claim_exists && !probe.claim_ready && probe.sandbox_suspended
}

fn create_action_requires_runtime_identity(action: CreateAction) -> bool {
    matches!(
        action,
        CreateAction::StoreBackend
            | CreateAction::MarkRunning
            | CreateAction::PublishSetup
            | CreateAction::Done
    )
}

pub(super) fn requires_running_runtime_identity(state: &str, desired_state: &str) -> bool {
    state == "running" && desired_state == "started"
}

// ── Worker sandbox config (the cfg slice the create path reads) ────────

/// `SANDBOX_WORKSPACE_IDENTITY_MODE` may only say `binding`, which is also
/// its default. Every commodity workspace is identity-free: an
/// environment-token workspace never serves SSH or the tailnet, so it could
/// never become access-ready (#2460), and a worker configured for one
/// refuses to start.
pub const WORKSPACE_IDENTITY_MODE_ENV: &str = "SANDBOX_WORKSPACE_IDENTITY_MODE";

pub fn workspace_identity_mode_supported(value: &str) -> bool {
    matches!(value.trim(), "" | "binding")
}

impl SandboxWorkerCfg {
    /// The support image this worker renders, which every resume and Pod
    /// replacement re-pins a Sandbox's daemon to.
    pub fn support_image(&self) -> &str {
        crate::sandbox::template::effective_support_image(&self.daemon_image)
    }

    /// Review L2: a commodity workspace binds through the binding Service in
    /// the orchestration namespace (`POD_NAMESPACE`), and its access grant
    /// names the coordinator or API URL. Without them
    /// `environment_template_opts` would render environment-token Pods, which
    /// never serve SSH or the tailnet, so a worker with a sandbox backend
    /// refuses to start instead, like an unsupported
    /// `SANDBOX_WORKSPACE_IDENTITY_MODE`.
    pub fn require_workspace_binding_config(&self) -> Result<(), String> {
        let mut missing = Vec::new();
        if self.pod_namespace.trim().is_empty() {
            missing.push("POD_NAMESPACE");
        }
        if self.coordinator_url.trim().is_empty() && self.api_base_url.trim().is_empty() {
            missing.push("CODEWIRE_COORDINATOR_URL or CODEWIRE_API_URL");
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "commodity workspace binding requires {}",
                missing.join(" and ")
            ))
        }
    }
}

/// The dedicated orchestration Service that serves only
/// `WorkspaceBindingService` (design §3.5).
pub const WORKSPACE_BINDING_SERVICE_NAME: &str = "codewire-orchestration-workspace-binding";

/// The DNS name of the workspace-binding listener in `server_namespace`: the
/// name workspace daemons verify and orchestration's internal leaf carries.
pub fn workspace_binding_tls_host(server_namespace: &str) -> String {
    format!("{WORKSPACE_BINDING_SERVICE_NAME}.{server_namespace}.svc.cluster.local")
}

/// The in-cluster URL a workspace daemon long-polls for its binding, over
/// TLS verified with the mounted internal roots.
pub fn workspace_binding_url(server_namespace: &str) -> String {
    format!(
        "https://{}:{}",
        workspace_binding_tls_host(server_namespace),
        codewire_daemon_proto::WORKSPACE_BINDING_PORT
    )
}

/// Runtime configuration consumed by the environment-create handler.
#[derive(Debug, Clone, Default)]
pub struct SandboxWorkerCfg {
    pub session_secret: String,
    pub sandbox_namespace: String,
    pub credential_runtime: Option<crate::sandbox::template::CredentialRuntimeTemplateConfig>,
    pub daemon_image: String,
    pub dind_image: String,
    pub runtime_profile: String,
    pub docker_mode: String,
    pub allow_diagnostic_runtime: bool,
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
    /// `SANDBOX_WARM_POOL_SHAPES` as configured (Program #2238 C2). Empty
    /// configures no warm pool; parsed by
    /// [`crate::sandbox::warm_pool::parse_warm_pool_shapes`].
    pub warm_pool_shapes: String,
    /// `SANDBOX_COORDINATOR_EXTRA_ROOTS=true` mounts the public
    /// `codewire-coordinator-extra-roots` bundle into identity-free workspaces
    /// so the daemon can verify a local cluster's coordinator. Dev and
    /// Production leave it off: their coordinator has a WebPKI certificate.
    pub coordinator_extra_roots: bool,
    /// The in-cluster ingress controller workspaces may reach on 80/443
    /// (`SANDBOX_INGRESS_NAMESPACE`, `SANDBOX_INGRESS_POD_NAME`). Empty keeps
    /// the RKE2 controller in `kube-system`.
    pub ingress_namespace: String,
    pub ingress_pod_name: String,
}

impl SandboxWorkerCfg {
    pub fn from_env() -> Self {
        let identity_mode = std::env::var(WORKSPACE_IDENTITY_MODE_ENV).unwrap_or_default();
        assert!(
            workspace_identity_mode_supported(&identity_mode),
            "{WORKSPACE_IDENTITY_MODE_ENV} must be binding: an environment-token workspace never serves SSH or the tailnet"
        );
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
        let sandbox_namespace = getenv("SANDBOX_NAMESPACE", &format!("{env_prefix}-sandboxes"));
        let credential_runtime =
            crate::sandbox::template::CredentialRuntimeTemplateConfig::from_env(&sandbox_namespace)
                .expect("platform credential runtime configuration must be complete and canonical");
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
            sandbox_namespace,
            credential_runtime,
            daemon_image: getenv(
                "SANDBOX_DAEMON_IMAGE",
                codewire_server_core::runtime_images::DEFAULT_DAEMON_IMAGE,
            ),
            dind_image: getenv("SANDBOX_DIND_IMAGE", ""),
            runtime_profile: std::env::var("SANDBOX_RUNTIME_PROFILE").unwrap_or_default(),
            docker_mode: getenv("SANDBOX_DOCKER_MODE", "profile-default"),
            allow_diagnostic_runtime: getenv("SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME", "false") == "true",
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
            warm_pool_shapes: std::env::var(crate::sandbox::warm_pool::WARM_POOL_SHAPES_ENV)
                .unwrap_or_default(),
            coordinator_extra_roots: getenv("SANDBOX_COORDINATOR_EXTRA_ROOTS", "false") == "true",
            ingress_namespace: getenv("SANDBOX_INGRESS_NAMESPACE", ""),
            ingress_pod_name: getenv("SANDBOX_INGRESS_POD_NAME", ""),
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

/// Mirrors `isFirstPartyWorkspaceImage`.
pub fn is_first_party_workspace_image(image_ref: &str) -> bool {
    image_ref.contains("codewiresh/workspace-")
        || image_ref.contains("codewiresh/base")
        || image_ref.contains("codewiresh/workspace")
}

/// Mirrors `environmentTemplateOpts`: the environment's identity on top of
/// the cluster and shape inputs of [`shape_template_opts`].
pub fn environment_template_opts(
    cfg: &SandboxWorkerCfg,
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    operation_generation: i64,
    daemon_auth_token: &str,
) -> anyhow::Result<TemplateOpts> {
    let env_id = env.id.as_str();
    anyhow::ensure!(
        operation_generation > 0 && env.operation_generation == operation_generation,
        "template metadata no longer matches operation authority"
    );
    let selection = env
        .projection_selection
        .as_ref()
        .map_err(|_| anyhow::anyhow!("invalid platform environment projection selection"))?;
    let projection_selection_sha256 = selection
        .as_ref()
        .map(|selection| selection.sha256())
        .transpose()?;
    let managed_credential_clients = *env
        .managed_credential_clients
        .as_ref()
        .map_err(|_| anyhow::anyhow!("invalid managed credential client selection"))?;
    managed_credential_clients
        .check_collisions(env.project_spec.environment.keys().map(String::as_str))?;
    // Without a profile, the only managed client is the creator's own GitHub
    // connection for a selected GitHub repository.
    let account_github = codewire_access::ManagedCredentialClients::from_profile_slots(["github"])?;
    anyhow::ensure!(
        managed_credential_clients == Default::default()
            || selection.as_ref().is_some_and(|selection| {
                selection.profile.is_some() || managed_credential_clients == account_github
            }),
        "managed credential clients require an exact selected profile"
    );
    anyhow::ensure!(
        projection_selection_sha256.is_none() || cfg.credential_runtime.is_some(),
        "selected environment sources require credential runtime trust"
    );
    let runtime_spec = match runtime_profile_for_isolation_tier(&env.isolation_tier)
        .expect("environment isolation tier is validated at creation")
    {
        Some(profile) => runtime_profile_spec(profile, &cfg.docker_mode, cfg.dind_enabled),
        None => standard_runtime_profile_spec(cfg),
    };
    let template_base = if is_canonical_workspace_runtime_image(image_ref) {
        CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME
    } else {
        template_base
    };
    let shape = WorkspaceShape {
        cpu_millicores: i64::from(env.cpu_millicores),
        memory_mib: i64::from(env.memory_mb),
        disk_gib: i64::from(env.disk_gb),
    };

    Ok(TemplateOpts {
        name: environment_template_name(template_base, env_id),
        environment_id: env_id.to_string(),
        organization_id: env.org_id.clone(),
        operation_generation,
        projection_selection_sha256,
        managed_credential_clients,
        daemon_auth_token: daemon_auth_token.to_string(),
        ..shape_template_opts(cfg, image_ref, &runtime_spec, shape)
    })
}

/// The cluster and shape inputs of a workspace rendering, with no environment
/// identity: images, runtime, resources, storage, transport and the identity
/// mode. A warm pool renders from these alone (Program #2238 C1); an
/// environment adds its identity in [`environment_template_opts`]. Every
/// field is listed, so a new one must be placed on one side or the other.
pub fn shape_template_opts(
    cfg: &SandboxWorkerCfg,
    image_ref: &str,
    runtime_spec: &RuntimeProfileSpec,
    shape: WorkspaceShape,
) -> TemplateOpts {
    // Codewire base images supervise the daemon beneath PID 1. Custom
    // images also retain a keepalive alongside that managed daemon.
    let image_command = if is_first_party_workspace_image(image_ref) {
        Vec::new()
    } else {
        vec!["sleep".to_string(), "infinity".to_string()]
    };

    let uses_runtime_transport_registry = !cfg.runtime_transport_zones_json.trim().is_empty();
    // Commodity workspaces are identity-free (design §13); confidential keeps
    // its measured environment-bound init-data until B2c. A Pod reaches the
    // binding listener only with the orchestration namespace and a
    // coordinator known, which a worker with a sandbox backend requires at
    // startup (`require_workspace_binding_config`).
    let binds = runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
        && !cfg.pod_namespace.trim().is_empty()
        && !(cfg.coordinator_url.trim().is_empty() && cfg.api_base_url.trim().is_empty());
    let workspace_identity = if binds {
        WorkspaceIdentity::Binding {
            binding_url: workspace_binding_url(cfg.pod_namespace.trim()),
        }
    } else {
        WorkspaceIdentity::EnvironmentToken
    };

    TemplateOpts {
        // Environment identity: none.
        name: String::new(),
        environment_id: String::new(),
        organization_id: String::new(),
        operation_generation: 0,
        projection_selection_sha256: None,
        managed_credential_clients: Default::default(),
        confidential_storage_manifest_uri: String::new(),
        daemon_auth_token: String::new(),
        // Cluster and shape.
        image: image_ref.to_string(),
        image_command,
        support_image: cfg.daemon_image.clone(),
        dind_image: cfg.dind_image.clone(),
        runtime_profile: runtime_spec.profile.clone(),
        docker_mode: runtime_spec.docker_mode.clone(),
        credential_runtime: cfg.credential_runtime.clone(),
        workspace_identity,
        api_base_url: cfg.api_base_url.clone(),
        coordinator_url: cfg.coordinator_url.clone(),
        server_namespace: cfg.pod_namespace.clone(),
        coordinator_extra_roots: cfg.coordinator_extra_roots,
        ingress_namespace: cfg.ingress_namespace.clone(),
        ingress_pod_name: cfg.ingress_pod_name.clone(),
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
        cpu_millicores: shape.cpu_millicores,
        memory_mib: shape.memory_mib,
        disk_gib: shape.disk_gib,
        workspace_storage_class: cfg.workspace_storage_class.clone(),
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

/// The runtime of a standard-tier environment: this process's configured
/// profile.
fn standard_runtime_profile_spec(cfg: &SandboxWorkerCfg) -> RuntimeProfileSpec {
    runtime_profile_spec(&cfg.runtime_profile, &cfg.docker_mode, cfg.dind_enabled)
}

/// The identity-free inputs of one warm-pool shape (Program #2238 C1): the
/// canonical workspace image on the standard tier, from the shape and this
/// process's configuration alone, never from an environment row. A
/// confidential runtime, a diagnostic runtime outside diagnostic clusters and
/// a configuration that cannot render identity-free workspaces render no
/// pool.
pub fn warm_pool_template_opts(
    cfg: &SandboxWorkerCfg,
    shape: WorkspaceShape,
) -> anyhow::Result<TemplateOpts> {
    let runtime_spec = standard_runtime_profile_spec(cfg);
    anyhow::ensure!(
        runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL,
        "confidential workspaces are never pooled"
    );
    validate_managed_runtime_profile(&runtime_spec, cfg.allow_diagnostic_runtime)
        .map_err(|error| anyhow::anyhow!("warm pool runtime profile: {error}"))?;
    let opts = shape_template_opts(cfg, CANONICAL_WORKSPACE_RUNTIME_IMAGE, &runtime_spec, shape);
    anyhow::ensure!(
        opts.identity_free(),
        "warm pools require identity-free workspaces (POD_NAMESPACE and a coordinator)"
    );
    Ok(opts)
}

/// Render one configured warm pool in the sandbox namespace. Only diagnostic
/// clusters may pool images that are not digest-pinned.
pub fn render_configured_warm_pool(
    cfg: &SandboxWorkerCfg,
    shape: WorkspaceShape,
    replicas: i32,
) -> anyhow::Result<WarmPoolObjects> {
    let opts = warm_pool_template_opts(cfg, shape)?;
    render_warm_pool(
        &cfg.sandbox_namespace,
        &opts,
        replicas,
        cfg.allow_diagnostic_runtime,
    )
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

/// Build the claim contract for one environment-specific template.
pub fn environment_claim_opts(
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    operation_generation: i64,
) -> ClaimOpts {
    let env_id = env.id.as_str();
    assert!(
        operation_generation > 0,
        "operation authority must be captured"
    );
    let template_base = if is_canonical_workspace_runtime_image(image_ref) {
        CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME
    } else {
        template_base
    };
    let template_ref = environment_template_name(template_base, env_id);
    ClaimOpts {
        environment_id: env_id.to_string(),
        org_id: env.org_id.clone(),
        operation_generation,
        warm_pool_ref: shadow_warm_pool_name(&template_ref),
        template_ref,
        additional_pod_labels: crate::sandbox::runtime_identity_labels(
            env_id,
            &env.org_id,
            operation_generation,
            "workspace",
        ),
        ..Default::default()
    }
}

pub fn environment_per_env_template_name(
    image_ref: &str,
    template_base: &str,
    env_id: &str,
) -> String {
    let template_base = if is_canonical_workspace_runtime_image(image_ref) {
        CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME
    } else {
        template_base
    };
    environment_template_name(template_base, env_id)
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

const RUNTIME_METADATA_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(30);
const CREATE_MUTATION_STATES: &[&str] = &["pending", "creating", "starting"];

pub(super) fn ready_timeout_for_isolation(isolation_tier: &str) -> Duration {
    if isolation_tier == "confidential" {
        CONFIDENTIAL_WORKSPACE_READY_TIMEOUT
    } else {
        WORKSPACE_READY_TIMEOUT
    }
}

fn validate_template_metadata(env: &EnvironmentRow, opts: &TemplateOpts) -> anyhow::Result<()> {
    let digest = env
        .projection_selection
        .as_ref()
        .map_err(|_| AuthorityLost)?
        .as_ref()
        .map(|selection| selection.sha256())
        .transpose()
        .map_err(|_| AuthorityLost)?;
    let clients = *env
        .managed_credential_clients
        .as_ref()
        .map_err(|_| AuthorityLost)?;
    clients
        .check_collisions(env.project_spec.environment.keys().map(String::as_str))
        .map_err(|_| AuthorityLost)?;
    if env.id != opts.environment_id
        || env.org_id != opts.organization_id
        || env.operation_generation <= 0
        || env.operation_generation != opts.operation_generation
        || digest != opts.projection_selection_sha256
        || clients != opts.managed_credential_clients
    {
        return Err(AuthorityLost.into());
    }
    Ok(())
}

/// Publish only the selection captured for this same lifecycle operation.
/// Source replacement and publication serialize on the existing environment
/// row; immutable profile revisions need no separate lifecycle generation.
pub(super) async fn run_template_mutation<F, T>(
    authority: &ActivityAuthority,
    opts: &TemplateOpts,
    states: &[&str],
    mutation: F,
) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    if opts.environment_id != authority.environment_id()
        || opts.operation_generation != authority.operation_generation()
    {
        return Err(AuthorityLost.into());
    }
    let mut guard = authority.begin_external_mutation(states).await?;
    let result = await_external_mutation(async {
        let current = load_environment_in(guard.transaction(), authority.environment_id()).await?;
        validate_template_metadata(&current, opts)?;
        mutation.await
    })
    .await?;
    guard.commit().await?;
    Ok(result)
}

pub(super) async fn authorize_confidential_runtime(
    ctx: &WorkerContext,
    opts: &TemplateOpts,
    authority: &ActivityAuthority,
    authoritative_states: &[&str],
) -> anyhow::Result<()> {
    if opts.runtime_profile_spec().profile != RUNTIME_PROFILE_CONFIDENTIAL || opts.disk_gib <= 0 {
        return Ok(());
    }
    let storage = ctx
        .confidential_storage
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("confidential storage providers are not configured"))?;
    let init_data = confidential_init_data(opts)?;
    run_template_mutation(
        authority,
        opts,
        authoritative_states,
        storage.authorize_init_data(
            &opts.environment_id,
            &opts.confidential_storage_manifest_uri,
            init_data.as_bytes(),
        ),
    )
    .await?;
    Ok(())
}

pub(super) async fn load_environment_template_opts(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    operation_generation: i64,
) -> anyhow::Result<TemplateOpts> {
    let (image, base) =
        load_sandbox_template_config(&ctx.pool, env.preset_id.as_deref().unwrap_or_default())
            .await?;
    let daemon_auth_token =
        issue_environment_daemon_token(&ctx.sandbox_cfg.session_secret, &env.id)?;
    environment_template_opts(
        &ctx.sandbox_cfg,
        &image,
        &base,
        env,
        operation_generation,
        &daemon_auth_token,
    )
}

/// The allocated Sandbox, not only its template, owns the next Pod's immutable
/// bootstrap. The caller first observes completed suspension and Pod absence.
pub(super) async fn refresh_workspace_bootstrap(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    backend: &BackendRow,
    opts: &TemplateOpts,
    suspended: &WorkspaceSandboxIdentity,
    authority: &ActivityAuthority,
    states: &[&str],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        env.id == authority.environment_id(),
        "bootstrap authority mismatch"
    );
    let client = require_client(ctx, &backend.namespace)?;
    let mut guard = authority.begin_external_mutation(states).await?;
    await_external_mutation(async {
        let current = load_environment_in(guard.transaction(), &env.id).await?;
        validate_template_metadata(&current, opts)?;
        let (namespace, claim_name, claim_uid): (String, String, String) = sqlx::query_as(
            "SELECT namespace, sandbox_claim_name, sandbox_claim_uid
             FROM sandbox_environment_backend WHERE environment_id=$1",
        )
        .bind(&env.id)
        .fetch_one(&mut **guard.transaction())
        .await?;
        anyhow::ensure!(
            namespace == backend.namespace
                && claim_name == backend.claim_name
                && claim_uid == backend.claim_uid
                && !claim_uid.is_empty(),
            "bootstrap backend association changed"
        );
        client
            .reconcile_workspace_bootstrap(opts, &claim_name, &claim_uid, suspended)
            .await
    })
    .await?;
    guard.commit().await
}

pub(super) async fn confidential_runtime_template_opts(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    confidential_storage_manifest_uri: &str,
    operation_generation: i64,
) -> anyhow::Result<TemplateOpts> {
    anyhow::ensure!(
        env.isolation_tier == "confidential",
        "environment is not confidential"
    );
    let env_id = env.id.as_str();
    let preset_id = env
        .preset_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("confidential environment has no preset id"))?;
    let (image_ref, template_base) = load_sandbox_template_config(&ctx.pool, preset_id).await?;
    let cfg = &ctx.sandbox_cfg;
    let expected_template = environment_per_env_template_name(&image_ref, &template_base, env_id);
    let daemon_auth_token = issue_environment_daemon_token(&cfg.session_secret, env_id)?;
    let mut template_opts = environment_template_opts(
        cfg,
        &image_ref,
        &template_base,
        env,
        operation_generation,
        &daemon_auth_token,
    )?;
    template_opts.confidential_storage_manifest_uri = confidential_storage_manifest_uri.to_owned();
    if template_opts.name != expected_template {
        anyhow::bail!("confidential runtime template identity is inconsistent");
    }
    validate_managed_runtime_profile(
        &template_opts.runtime_profile_spec(),
        cfg.allow_diagnostic_runtime,
    )
    .map_err(|error| anyhow::anyhow!("runtime profile: {error}"))?;
    Ok(template_opts)
}

pub(super) async fn authorize_confidential_runtime_for_environment(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    confidential_storage_manifest_uri: &str,
    authority: &ActivityAuthority,
    authoritative_states: &[&str],
) -> anyhow::Result<()> {
    if env.isolation_tier != "confidential" {
        return Ok(());
    }
    let template_opts = confidential_runtime_template_opts(
        ctx,
        env,
        confidential_storage_manifest_uri,
        authority.operation_generation(),
    )
    .await?;
    authorize_confidential_runtime(ctx, &template_opts, authority, authoritative_states).await
}

pub(super) async fn reconcile_confidential_runtime_before_replacement(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    confidential_storage_manifest_uri: &str,
    authority: &ActivityAuthority,
    authoritative_states: &[&str],
    client: &SandboxClient,
    stale: &WorkspacePodIdentity,
) -> anyhow::Result<()> {
    if env.isolation_tier != "confidential" {
        return Ok(());
    }
    let env_id = env.id.as_str();
    let template_opts = confidential_runtime_template_opts(
        ctx,
        env,
        confidential_storage_manifest_uri,
        authority.operation_generation(),
    )
    .await?;
    authorize_confidential_runtime(ctx, &template_opts, authority, authoritative_states).await?;

    let kernel_params = run_template_mutation(
        authority,
        &template_opts,
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
    let mut bootstrap_recovered = false;
    let mut workspace_resumed = false;
    let mut reconciled_runtime: Option<ReconciledRuntime> = None;
    // Program #2238 C3: after a pool-born Claim failed its first bind and
    // was re-claimed, this attempt claims cold.
    let mut reclaimed_cold = false;

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
        // A confidential workspace cannot bind until B2c, and only a bound
        // daemon serves SSH and the tailnet (#2460): the API refuses these,
        // and a create that still arrives fails with the same reason.
        if env.isolation_tier == "confidential" {
            let reason = crate::confidential_storage::CONFIDENTIAL_ISOLATION_UNAVAILABLE;
            record_error(&svc, authority, env_id, reason).await?;
            anyhow::bail!(reason);
        }

        let profile = start_profile(cfg, &env.isolation_tier);
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
        let start_path = StartPath::from_launch_type(Some(probe.launch_type.as_str()));
        let mut action = next_create_action(&env.state, backend.as_ref(), setup_complete, &probe);
        if action == CreateAction::ResumeWorkspace && workspace_resumed {
            // One resume per attempt. A Sandbox suspended again meanwhile must
            // not loop here; the bounded readiness wait records the failure.
            action = CreateAction::WaitForReady;
        }
        tracing::info!(env = env_id, state = env.state, action = %action, "create loop");

        if create_action_requires_runtime_identity(action) {
            let backend = backend.as_ref().expect("ready runtime requires backend");
            let observed = ReconciledRuntime::observe(&env, backend, &probe);
            if reconciled_runtime.as_ref() != Some(&observed) {
                reconciled_runtime = None;
                match reconcile_or_refresh_runtime_identity(
                    ctx,
                    &env,
                    backend,
                    authority,
                    &[env.state.as_str()],
                    &probe,
                    !bootstrap_recovered,
                )
                .await
                {
                    Ok(true) => {
                        bootstrap_recovered = true;
                        // The old probe must not overwrite the replacement's backend
                        // association or let setup act on the retired incarnation.
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        if reclaim_cold(ctx, &env, authority, &error).await {
                            reclaimed_cold = true;
                            continue;
                        }
                        return Err(error);
                    }
                }
                reconciled_runtime = Some(observed);
            }
        } else {
            reconciled_runtime = None;
        }

        match action {
            CreateAction::Done => return Ok(()),

            CreateAction::ResumeWorkspace => {
                let backend = backend.as_ref().expect("resume_workspace requires backend");
                if let Err(e) = resume_suspended_workspace(ctx, &env, backend, authority).await {
                    record_error(
                        &svc,
                        authority,
                        env_id,
                        &format!("resume suspended workspace: {e:#}"),
                    )
                    .await?;
                    return Err(e);
                }
                workspace_resumed = true;
                // The next probe observes the resumed Sandbox and waits for
                // its Claim through the ordinary readiness path.
            }

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
                if let Err(e) = wait_with_early_bind(
                    ctx,
                    &env,
                    authority,
                    CREATE_MUTATION_STATES,
                    authority.run_while_authoritative_for_states(
                        CREATE_MUTATION_STATES,
                        readiness_wait(client.wait_for_ready(
                            env_id,
                            ready_timeout_for_isolation(&env.isolation_tier),
                        )),
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
                    if reclaim_cold(ctx, &env, authority, &e).await {
                        reclaimed_cold = true;
                        continue;
                    }
                    record_error(
                        &svc,
                        authority,
                        env_id,
                        &format!("wait for sandbox ready: {e:#}"),
                    )
                    .await?;
                    return Err(e);
                }
                let elapsed = started.elapsed();
                emit_authoritative_environment_log_for_states(
                    authority,
                    CREATE_MUTATION_STATES,
                    "wait_for_ready",
                    "completed",
                    "",
                    elapsed_meta(elapsed),
                )
                .await?;
                observe_create_stage(StartStage::WaitForReady, start_path, profile, elapsed);
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

            // `create_claim` measures creating the environment-scoped
            // template, shadow pool, claim and gateway objects. The readiness
            // wait that follows is its own `access_ready` stage; earlier
            // `create_claim` samples included that wait.
            CreateAction::CreateClaim => {
                let started = std::time::Instant::now();
                emit_create_log(authority, "create_claim", "started", "", None).await?;
                if env.state == "pending"
                    && let Err(e) = svc.transition(env_id, "pending", "creating").await
                {
                    authority.ensure().await?;
                    tracing::warn!(error = %e, "CAS to creating failed");
                }
                let mut confidential_storage_manifest_uri = None;
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
                    match authority
                        .run_external_mutation(
                            CREATE_MUTATION_STATES,
                            storage.ensure_ready(env_id, env.disk_gb),
                        )
                        .await
                    {
                        Ok(uri) => confidential_storage_manifest_uri = Some(uri),
                        Err(error) => {
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
                let daemon_auth_token =
                    match issue_environment_daemon_token(&cfg.session_secret, env_id) {
                        Ok(token) => token,
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
                                &format!("environment capabilities: {e:#}"),
                            )
                            .await?;
                            return Err(e);
                        }
                    };
                let mut template_opts = environment_template_opts(
                    cfg,
                    &image_ref,
                    &template_base,
                    &env,
                    authority.operation_generation(),
                    &daemon_auth_token,
                )?;
                template_opts.confidential_storage_manifest_uri =
                    confidential_storage_manifest_uri.unwrap_or_default();
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
                if let Err(e) = authorize_confidential_runtime(
                    ctx,
                    &template_opts,
                    authority,
                    CREATE_MUTATION_STATES,
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
                    record_error(
                        &svc,
                        authority,
                        env_id,
                        &format!("init-data authorization: {e:#}"),
                    )
                    .await?;
                    return Err(e);
                }
                let mut claim_opts = environment_claim_opts(
                    &image_ref,
                    &template_base,
                    &env,
                    authority.operation_generation(),
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

                // Program #2238 C3: claim from a shared warm pool only when
                // every routing condition holds; otherwise cold, unchanged. A
                // pool Claim carries only `warmPoolRef` and the identity
                // labels, and the shared template is never written for one
                // environment.
                let route = pool_route::route(
                    cfg,
                    &env,
                    &image_ref,
                    &template_opts,
                    &client,
                    reclaimed_cold,
                )
                .await;
                let claim_path = match &route {
                    pool_route::Route::Pool { name } => {
                        tracing::info!(env = env_id, pool = %name, "create: claiming from a warm pool");
                        claim_opts.warm_pool_ref = name.clone();
                        claim_opts.template_ref = name.clone();
                        StartPath::Warm
                    }
                    pool_route::Route::Cold(_) => StartPath::Cold,
                };
                if claim_path == StartPath::Cold {
                    if claim_opts.template_ref != template_opts.name {
                        let error = anyhow::anyhow!(
                            "claim template does not match environment-scoped daemon template"
                        );
                        emit_create_log(
                            authority,
                            "create_claim",
                            "failed",
                            &error.to_string(),
                            duration_meta(started),
                        )
                        .await?;
                        record_error(&svc, authority, env_id, &error.to_string()).await?;
                        return Err(error);
                    }
                    let ensured_template = template_opts.name.clone();
                    let ensured_shadow_pool = if claim_opts.warm_pool_ref.is_empty() {
                        shadow_warm_pool_name(&ensured_template)
                    } else {
                        claim_opts.warm_pool_ref.clone()
                    };
                    if let Err(e) = run_template_mutation(
                        authority,
                        &template_opts,
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
                            client.ensure_shadow_pool(
                                &ensured_shadow_pool,
                                &ensured_template,
                                env_id,
                            ),
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
                        record_error(&svc, authority, env_id, &format!("shadow pool: {e:#}"))
                            .await?;
                        return Err(e);
                    }
                }
                let claim_result = async {
                    let mut guard = authority
                        .begin_external_mutation(CREATE_MUTATION_STATES)
                        .await?;
                    let current = load_environment_in(guard.transaction(), env_id).await?;
                    validate_template_metadata(&current, &template_opts)?;
                    let (created_claim_name, claim_uid) = await_external_mutation(
                        client.create_sandbox_claim(&backend.namespace, &claim_opts),
                    )
                    .await?;
                    await_external_mutation(client.reconcile_claim_runtime_identity(
                        &claim_opts,
                        &created_claim_name,
                        &claim_uid,
                    ))
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
                        // The Kubernetes create may already have succeeded even when
                        // bookkeeping fails. Keep its environment-scoped dependencies so
                        // an idempotent retry can adopt the claim; destroy owns their final
                        // removal if the environment is abandoned.
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
                if let Err(e) = run_template_mutation(
                    authority,
                    &template_opts,
                    CREATE_MUTATION_STATES,
                    client.ensure_access_stack(&template_opts),
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
                let claim_elapsed = started.elapsed();
                emit_create_log(
                    authority,
                    "create_claim",
                    "completed",
                    "",
                    elapsed_meta(claim_elapsed),
                )
                .await?;
                observe_create_stage(StartStage::CreateClaim, claim_path, profile, claim_elapsed);

                // The gateway serves readiness only after it reaches the
                // workspace daemon, so this wait covers the workspace cold
                // start up to the daemon listening. An identity-free daemon
                // listens once bound, and `bind_before_ready` records that
                // binding beside this wait as soon as the Pod's containers
                // have started (design §10, amended), so the daemon is
                // reachable before Docker is ready and the next pass may still
                // wait for the claim (`wait_for_ready`). Same metadata shape as
                // the restart path, less the Pod IP, which the backend row
                // records once a probe sees it.
                let gateway_started = std::time::Instant::now();
                emit_create_log(
                    authority,
                    "access_ready",
                    "started",
                    ACCESS_READY_STARTED_MESSAGE,
                    None,
                )
                .await?;
                let gateway_result = wait_with_early_bind(
                    ctx,
                    &env,
                    authority,
                    CREATE_MUTATION_STATES,
                    authority.run_while_authoritative_for_states(
                        CREATE_MUTATION_STATES,
                        readiness_wait(client.wait_for_workspace_access_ready(
                            env_id,
                            ready_timeout_for_isolation(&env.isolation_tier),
                            &RecordedHostKeys(&ctx.pool),
                        )),
                    ),
                )
                .await;
                let gateway_elapsed = gateway_started.elapsed();
                let gateway_meta = Some(serde_json::json!({
                    "duration_ms": duration_ms(gateway_elapsed),
                    "namespace": backend.namespace,
                }));
                if let Err(e) = gateway_result {
                    emit_create_log(
                        authority,
                        "access_ready",
                        "failed",
                        &format!("{e:#}"),
                        gateway_meta,
                    )
                    .await?;
                    if reclaim_cold(ctx, &env, authority, &e).await {
                        reclaimed_cold = true;
                        continue;
                    }
                    record_error(&svc, authority, env_id, &format!("gateway stack: {e:#}")).await?;
                    return Err(e);
                }
                emit_create_log(authority, "access_ready", "completed", "", gateway_meta).await?;
                // A pool Claim's Sandbox is warm only when the controller
                // adopted a member; with none ready it was created cold.
                let gateway_path = match claim_path {
                    StartPath::Warm => client
                        .probe_environment(env_id)
                        .await
                        .map(|probe| StartPath::from_launch_type(Some(probe.launch_type.as_str())))
                        .unwrap_or(StartPath::Cold),
                    StartPath::Cold => StartPath::Cold,
                };
                observe_create_stage(
                    StartStage::AccessReady,
                    gateway_path,
                    profile,
                    gateway_elapsed,
                );
            }

            CreateAction::StoreBackend => {
                update_backend_pod_info(authority, &probe.pod_ip, &probe.pod_name).await?;
                emit_create_log(authority, "store_backend", "completed", "", None).await?;
            }

            CreateAction::MarkRunning => {
                let entered_running = match svc.transition(env_id, &env.state, "running").await {
                    Ok(()) => true,
                    Err(e) => {
                        authority.ensure().await?;
                        tracing::warn!(env = env_id, from = env.state, error = %e, "CAS to running failed");
                        false
                    }
                };
                if let Err(e) = svc.mark_started(env_id).await {
                    authority.ensure().await?;
                    tracing::warn!(env = env_id, error = %e, "mark started failed");
                }
                if entered_running {
                    if let Some(reconciled) = reconciled_runtime.as_mut() {
                        reconciled.entered_running();
                    }
                    if records_pod_start_marks(action) {
                        record_pod_start_marks(ctx, authority, &probe, start_path, profile).await?;
                    }
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
    elapsed_meta(started.elapsed())
}

fn elapsed_meta(elapsed: Duration) -> Option<serde_json::Value> {
    Some(serde_json::json!({ "duration_ms": duration_ms(elapsed) }))
}

const ACCESS_READY_STARTED_MESSAGE: &str = "Waiting for SSH access";

/// What one runtime identity reconciliation in this create attempt checked:
/// the environment row it rendered from, the recorded Claim association, and
/// the exact Pod incarnation and address the probe observed.
///
/// Every ready action (`store_backend`, `mark_running`, `publish_setup`,
/// `done`) needs a reconciled runtime. A cold create reaches two or three of
/// them back to back on one Pod, and each repeat re-read the Claim, Sandbox,
/// Pod and bootstrap objects, re-applied the gateway stack and waited for
/// its readiness again: about 0.25 s on Dev, or 1.25 s when that readiness
/// poll missed once. A repeat now runs whenever any of these inputs changed.
/// The only change it allows is the `running` state this attempt's own
/// `mark_running` committed; every later write still checks authority for
/// its own states.
#[derive(Debug, Clone, PartialEq)]
struct ReconciledRuntime {
    environment: EnvironmentRow,
    namespace: String,
    claim_name: String,
    claim_uid: String,
    pod_name: String,
    pod_uid: String,
    pod_ip: String,
}

impl ReconciledRuntime {
    fn observe(environment: &EnvironmentRow, backend: &BackendRow, probe: &ProbeResult) -> Self {
        Self {
            environment: environment.clone(),
            namespace: backend.namespace.clone(),
            claim_name: backend.claim_name.clone(),
            claim_uid: backend.claim_uid.clone(),
            pod_name: probe.pod_name.clone(),
            pod_uid: probe.pod_uid.clone(),
            pod_ip: probe.pod_ip.clone(),
        }
    }

    /// Record the state transition this attempt itself just committed.
    fn entered_running(&mut self) {
        self.environment.state = "running".to_string();
    }
}

/// The create action whose committed transition records the workspace Pod's
/// own start marks: `mark_running`, the one action every create path takes.
/// `store_backend` cannot own this: the leader's sandbox liveness loop stores
/// `pod_name` and `pod_ip` for `creating` environments every few seconds, so
/// during the gateway readiness wait it usually stores the Pod first and
/// create goes straight from `create_claim` to `mark_running`.
fn records_pod_start_marks(action: CreateAction) -> bool {
    action == CreateAction::MarkRunning
}

/// Rows carry the Pod UID and are written once per Pod, even when an error
/// retry reaches `mark_running` again for the same Pod. They are not journal
/// checkpoints.
async fn record_pod_start_marks(
    ctx: &WorkerContext,
    authority: &ActivityAuthority,
    probe: &ProbeResult,
    path: StartPath,
    profile: StartProfile,
) -> anyhow::Result<()> {
    if probe.pod_uid.is_empty() {
        return Ok(());
    }
    let recorded = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
           SELECT 1 FROM environment_logs
            WHERE environment_id = $1
              AND phase = ANY($2)
              AND metadata->>'pod_uid' = $3
         )",
    )
    .bind(authority.environment_id())
    .bind(&POD_STAGE_PHASES[..])
    .bind(&probe.pod_uid)
    .fetch_one(&ctx.pool)
    .await;
    match recorded {
        Ok(false) => {}
        Ok(true) => return Ok(()),
        Err(error) => {
            // Timing is observational; a failed read must not fail create.
            tracing::warn!(
                environment_id = authority.environment_id(),
                error = %error,
                "create: skip Pod start marks after a failed recorded-marks read"
            );
            return Ok(());
        }
    }
    for timing in pod_stage_timings(&probe.pod_timeline) {
        emit_running_log(
            authority,
            timing.stage.as_str(),
            "completed",
            "",
            Some(timing.metadata(&probe.pod_uid)),
        )
        .await?;
        observe_create_stage(timing.stage, path, profile, timing.duration);
    }
    Ok(())
}

/// Observe a completed create stage after its durable log row committed.
fn observe_create_stage(
    stage: StartStage,
    path: StartPath,
    profile: StartProfile,
    elapsed: Duration,
) {
    start_metrics::observe_stage(stage, path, profile, elapsed);
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
    let confidential_storage_manifest_uri = if env.isolation_tier == "confidential" {
        let storage = ctx
            .confidential_storage
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("confidential storage providers are not configured"))?;
        authority
            .run_external_mutation(
                CREATE_MUTATION_STATES,
                storage.ensure_ready(env_id, env.disk_gb),
            )
            .await?
    } else {
        String::new()
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
            &confidential_storage_manifest_uri,
            authority,
            CREATE_MUTATION_STATES,
            client,
            &stale,
        )
        .await?;
        authority
            .run_external_mutation(
                CREATE_MUTATION_STATES,
                client.replace_workspace_pod_if_uid(
                    env_id,
                    &stale.name,
                    &stale.uid,
                    ctx.sandbox_cfg.support_image(),
                ),
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

/// Resume the exact Claim-owned Sandbox through the cold-bootstrap path Start
/// uses: request suspension again, observe the controller complete it with
/// every prior workspace Pod absent, refresh the bootstrap for this operation
/// generation, then resume only that observed incarnation. A resumed Pod runs
/// no setup command; a setup owner still re-fences its own Pod on takeover.
async fn resume_suspended_workspace(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    backend: &BackendRow,
    authority: &ActivityAuthority,
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    emit_create_log(authority, "resume_workspace", "started", "", None).await?;
    tracing::info!(
        env = env.id,
        "resuming suspended workspace Sandbox before waiting for claim readiness"
    );
    let result = async {
        let mut opts =
            load_environment_template_opts(ctx, env, authority.operation_generation()).await?;
        if env.isolation_tier == "confidential" {
            let storage = ctx.confidential_storage.as_ref().ok_or_else(|| {
                anyhow::anyhow!("confidential storage providers are not configured")
            })?;
            opts.confidential_storage_manifest_uri = authority
                .run_external_mutation(
                    CREATE_MUTATION_STATES,
                    storage.ensure_ready(&env.id, env.disk_gb),
                )
                .await?;
        }
        super::lifecycle::restart_workspace_bootstrap(
            ctx,
            env,
            backend,
            &opts,
            authority,
            CREATE_MUTATION_STATES,
        )
        .await
    }
    .await;
    match result {
        Ok(()) => {
            emit_create_log(
                authority,
                "resume_workspace",
                "completed",
                "",
                duration_meta(started),
            )
            .await
        }
        Err(error) => {
            emit_create_log(
                authority,
                "resume_workspace",
                "failed",
                &format!("{error:#}"),
                duration_meta(started),
            )
            .await?;
            Err(error)
        }
    }
}

async fn ensure_access_stack_for_environment(
    ctx: &WorkerContext,
    cfg: &SandboxWorkerCfg,
    env: &EnvironmentRow,
    env_id: &str,
    namespace: &str,
    authority: &ActivityAuthority,
    states: &[&str],
) -> anyhow::Result<()> {
    let preset_id = env.preset_id.clone().unwrap_or_default();
    let (image_ref, template_base) = load_sandbox_template_config(&ctx.pool, &preset_id).await?;
    let daemon_auth_token = issue_environment_daemon_token(&cfg.session_secret, env_id)?;
    let template_opts = environment_template_opts(
        cfg,
        &image_ref,
        &template_base,
        env,
        authority.operation_generation(),
        &daemon_auth_token,
    )?;
    let runtime_spec = template_opts.runtime_profile_spec();
    validate_managed_runtime_profile(&runtime_spec, cfg.allow_diagnostic_runtime)
        .map_err(|e| anyhow::anyhow!("runtime profile: {e}"))?;
    let client = require_client(ctx, namespace)?;
    run_template_mutation(
        authority,
        &template_opts,
        states,
        client.ensure_access_stack(&template_opts),
    )
    .await?;
    authority
        .run_while_authoritative_for_states(
            states,
            client.wait_for_workspace_access_ready(
                env_id,
                ready_timeout_for_isolation(&env.isolation_tier),
                &RecordedHostKeys(&ctx.pool),
            ),
        )
        .await
}

/// Recover one exactly owned, stale-bootstrap runtime through the same cold
/// start path. A second mismatch, any ownership error or authority loss fails
/// this attempt; no relabel-only fallback and no unbounded retry loop.
pub(super) async fn reconcile_or_refresh_runtime_identity(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    backend: &BackendRow,
    authority: &ActivityAuthority,
    states: &[&str],
    probe: &ProbeResult,
    allow_recovery: bool,
) -> anyhow::Result<bool> {
    let expected = WorkspacePodIdentity {
        name: probe.pod_name.clone(),
        uid: probe.pod_uid.clone(),
    };
    match reconcile_runtime_identity_for_pod(ctx, env, backend, authority, states, Some(&expected))
        .await
    {
        Ok(()) => {
            publish_backend_probe(authority, states, probe).await?;
            return Ok(false);
        }
        Err(error) if allow_recovery && error.is::<WorkspaceBootstrapMismatch>() => {}
        Err(error) => return Err(error),
    }
    let mut opts =
        load_environment_template_opts(ctx, env, authority.operation_generation()).await?;
    if env.isolation_tier == "confidential" {
        let storage = ctx
            .confidential_storage
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("confidential storage providers are not configured"))?;
        opts.confidential_storage_manifest_uri = authority
            .run_external_mutation(states, storage.ensure_ready(&env.id, env.disk_gb))
            .await?;
    }
    super::lifecycle::restart_workspace_bootstrap(ctx, env, backend, &opts, authority, states)
        .await?;
    let client = require_client(ctx, &backend.namespace)?;
    let deadline = tokio::time::Instant::now() + ready_timeout_for_isolation(&env.isolation_tier);
    let probe = authority
        .run_while_authoritative_for_states(
            states,
            super::lifecycle::within_workspace_deadline(deadline, async {
                loop {
                    let probe = client.probe_environment(&env.id).await?;
                    if super::lifecycle::start_runtime_is_ready(&probe) {
                        return Ok(probe);
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }),
        )
        .await?;
    // Verify the actual replacement tuple before publishing its address. The
    // strict second call intentionally cannot start another recovery.
    let expected = WorkspacePodIdentity {
        name: probe.pod_name.clone(),
        uid: probe.pod_uid.clone(),
    };
    reconcile_runtime_identity_for_pod(ctx, env, backend, authority, states, Some(&expected))
        .await?;
    publish_backend_probe(authority, states, &probe).await?;
    Ok(true)
}

pub(super) async fn publish_backend_probe(
    authority: &ActivityAuthority,
    states: &[&str],
    probe: &ProbeResult,
) -> anyhow::Result<()> {
    authority
        .execute_for_states(
            states,
            sqlx::query(
                "UPDATE sandbox_environment_backend SET pod_ip=$1, pod_name=$2
                 WHERE environment_id=$3",
            )
            .bind(&probe.pod_ip)
            .bind(&probe.pod_name)
            .bind(authority.environment_id()),
        )
        .await?;
    Ok(())
}

/// Reconcile labels for an already-observed live runtime using only the
/// activity's existing generation. The Claim write and DB association read
/// share its row fence; controller convergence never holds that SQL lock.
pub(super) async fn reconcile_runtime_identity(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    backend: &BackendRow,
    authority: &ActivityAuthority,
    states: &[&str],
) -> anyhow::Result<()> {
    reconcile_runtime_identity_for_pod(ctx, env, backend, authority, states, None).await
}

/// Run `wait` (the gateway or Claim Ready wait of create and start) while
/// [`bind_before_ready`] records an identity-free Pod's binding as soon as its
/// chain is bind-ready (design §10, amended). The wait decides the outcome:
/// a recorded or skipped bind lets it continue, a refused bind fails it, and
/// the bind is dropped once the wait ends. The post-ready runtime-identity
/// reconcile still binds, idempotently, before MarkRunning and setup. A
/// recorded warm bind gets its warm-member bridge (#2434) at once, after the
/// binding committed, so the gateway's connects need not wait for the
/// relabelled member's new Cilium identity.
pub(super) async fn wait_with_early_bind<T>(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    authority: &ActivityAuthority,
    states: &[&str],
    wait: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let Some(kube) = ctx.kube.as_ref() else {
        return wait.await;
    };
    let bind = bind_before_ready(kube, Some(&ctx.sandbox_cfg), authority, states);
    tokio::pin!(wait);
    tokio::pin!(bind);
    let mut binding = true;
    loop {
        tokio::select! {
            result = &mut wait => return result,
            result = &mut bind, if binding => {
                binding = false;
                if let Some(recorded) = result? {
                    if matches!(env.state.as_str(), "creating" | "starting") {
                        observe_create_stage(
                            StartStage::WorkspaceBind,
                            recorded.path,
                            start_profile(&ctx.sandbox_cfg, &env.isolation_tier),
                            recorded.elapsed,
                        );
                    }
                    warm_bridge::bridge_warm_member(ctx, env, authority, states, &recorded)
                        .await?;
                }
            }
        }
    }
}

pub(super) async fn reconcile_runtime_identity_for_pod(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    backend: &BackendRow,
    authority: &ActivityAuthority,
    states: &[&str],
    expected_pod: Option<&WorkspacePodIdentity>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        env.id == authority.environment_id(),
        "runtime identity authority does not match environment"
    );
    let client = require_client(ctx, &backend.namespace)?;
    let template_opts =
        load_environment_template_opts(ctx, env, authority.operation_generation()).await?;
    let opts = ClaimOpts {
        environment_id: env.id.clone(),
        org_id: env.org_id.clone(),
        operation_generation: authority.operation_generation(),
        ..Default::default()
    };
    let mut guard = authority.begin_external_mutation(states).await?;
    let (namespace, claim_name, claim_uid, organization): (String, String, String, String) =
        sqlx::query_as(
            "SELECT b.namespace, b.sandbox_claim_name, b.sandbox_claim_uid, e.org_id
           FROM sandbox_environment_backend b JOIN environments e ON e.id = b.environment_id
          WHERE b.environment_id = $1",
        )
        .bind(&env.id)
        .fetch_one(&mut **guard.transaction())
        .await?;
    anyhow::ensure!(
        organization == env.org_id
            && namespace == backend.namespace
            && claim_name == backend.claim_name
            && claim_uid == backend.claim_uid
            && !namespace.is_empty()
            && !claim_uid.is_empty(),
        "runtime identity backend association changed"
    );
    let observation = await_external_mutation(async {
        let current = load_environment_in(guard.transaction(), &env.id).await?;
        validate_template_metadata(&current, &template_opts)?;
        let observation = client
            .observe_claim_runtime_identity(&opts, &claim_name, &claim_uid)
            .await?;
        anyhow::ensure!(
            expected_pod.is_none_or(|expected| observation.pod() == expected),
            "workspace Pod changed after the ready observation"
        );
        let binding = live_environment_binding(&mut **guard.transaction(), &env.id).await?;
        if !workspace_bootstrap_current(
            &client,
            &template_opts,
            &claim_name,
            &claim_uid,
            observation.pod(),
            binding.as_ref(),
        )
        .await?
        {
            return Err(WorkspaceBootstrapMismatch.into());
        }
        client
            .reconcile_claim_runtime_identity(&opts, &claim_name, &claim_uid)
            .await?;
        Ok(observation)
    })
    .await?;
    guard.commit().await?;

    // Design §10: Claim Ready with converged labels, then the binding, then
    // the gateway. An identity-free daemon listens only once bound and the
    // gateway reaches it only after that, so the gateway wait comes last.
    // Under the amended trigger the binding usually happened during an
    // earlier wait; this wait binds early too, for a start whose Claim showed
    // a stale Ready and a replacement Pod that is still starting Docker.
    wait_with_early_bind(
        ctx,
        env,
        authority,
        states,
        authority.run_while_authoritative_for_states(
            states,
            client.wait_for_claim_runtime_identity(
                &opts,
                &claim_name,
                &claim_uid,
                &observation,
                ready_timeout_for_isolation(&env.isolation_tier),
            ),
        ),
    )
    .await?;
    let kube = ctx
        .kube
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox backend is not configured"))?;
    if let Some(recorded) = bind_workspace_runtime(
        kube,
        Some(&ctx.sandbox_cfg),
        env,
        backend,
        authority,
        states,
        &observation,
    )
    .await?
    {
        if matches!(env.state.as_str(), "creating" | "starting") {
            observe_create_stage(
                StartStage::WorkspaceBind,
                recorded.path,
                start_profile(&ctx.sandbox_cfg, &env.isolation_tier),
                recorded.elapsed,
            );
        }
        // The early bind lost the race to the Claim Ready wait: bridge now,
        // still before the access wait below.
        warm_bridge::bridge_warm_member(ctx, env, authority, states, &recorded).await?;
    }

    // Create's `access_ready` stage (A0a) is the CreateClaim wait, which the
    // early bind lets finish while Docker starts; here SSH access is
    // normally ready already.
    ensure_access_stack_for_environment(
        ctx,
        &ctx.sandbox_cfg,
        env,
        &env.id,
        &namespace,
        authority,
        states,
    )
    .await?;
    authority.ensure_for_states(states).await
}

/// Stale-bootstrap check for the observed Pod (design §12). A bound Pod-scope
/// runtime compares the binding row's captured generation, digest and
/// clients; a legacy environment-scope Pod compares the environment it was
/// rendered with, as before; an identity-free Pod that is not bound yet is
/// current by construction, because its binding captures the current
/// environment row under the same fence.
async fn workspace_bootstrap_current(
    client: &SandboxClient,
    template_opts: &TemplateOpts,
    claim_name: &str,
    claim_uid: &str,
    pod: &WorkspacePodIdentity,
    binding: Option<&EnvironmentBinding>,
) -> anyhow::Result<bool> {
    let live_pod = client
        .get_workspace_pod(&pod.name)
        .await?
        .filter(|live| live.metadata.uid.as_deref() == Some(pod.uid.as_str()))
        .ok_or_else(|| anyhow::anyhow!("workspace bootstrap Pod was replaced"))?;
    match credential_scope(&live_pod) {
        Some(WorkspaceCredentialScope::Environment) => {
            client
                .workspace_bootstrap_matches(template_opts, claim_name, claim_uid, pod)
                .await
        }
        Some(WorkspaceCredentialScope::Pod) => Ok(binding
            .filter(|binding| binding.pod_uid == pod.uid)
            .is_none_or(|binding| binding_bootstrap_current(binding, template_opts))),
        None => anyhow::bail!("workspace credential scope is ambiguous"),
    }
}

/// How long a cold re-claim waits for the pool-born Claim to be gone.
const RECLAIM_TIMEOUT: Duration = Duration::from_secs(60);

/// A create's readiness wait expired or failed before its Sandbox bound
/// (review M3). It reads exactly as the wait's own error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct ReadinessWaitFailed(anyhow::Error);

/// Mark a readiness wait's failure, so a never-bound pool-born Claim that
/// never became Ready can be re-claimed cold. Authority loss is checked
/// outside this wait and is never marked.
async fn readiness_wait<T>(
    wait: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    wait.await.map_err(|error| {
        if crate::worker::activity_authority::is_authority_lost(&error) {
            error
        } else {
            ReadinessWaitFailed(error).into()
        }
    })
}

/// Whether a create failure may re-claim cold: a definitive bind-check
/// refusal, or a readiness wait that failed (review M3).
fn reclaim_eligible(error: &anyhow::Error) -> bool {
    definitive_refusal(error)
        || (error.downcast_ref::<ReadinessWaitFailed>().is_some()
            && !crate::worker::activity_authority::is_authority_lost(error))
}

/// Program #2238 C3: a definitive bind-check failure, or a readiness wait
/// that failed (review M3), on a pool-born Claim whose Sandbox nothing ever
/// bound deletes that Claim and its Sandbox, each by UID, so the create loop
/// claims cold. A Sandbox any environment ever bound may hold tenant data
/// and is never deleted here; a member is never handed back to its pool.
/// `false` leaves the original error to the caller's ordinary failure path:
/// a failure inside the re-claim is logged and counted, never returned in
/// its place (review L3).
async fn reclaim_cold(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    authority: &ActivityAuthority,
    error: &anyhow::Error,
) -> bool {
    if !reclaim_eligible(error) || !matches!(env.state.as_str(), "pending" | "creating") {
        return false;
    }
    match try_reclaim_cold(ctx, env, authority).await {
        Ok(reclaimed) => reclaimed,
        Err(reclaim_error) => {
            pool_route::record_reclaim("failed");
            tracing::warn!(
                env = %env.id,
                error = %format!("{reclaim_error:#}"),
                original = %format!("{error:#}"),
                "create: cold re-claim failed; keeping the original failure"
            );
            false
        }
    }
}

async fn try_reclaim_cold(
    ctx: &WorkerContext,
    env: &EnvironmentRow,
    authority: &ActivityAuthority,
) -> anyhow::Result<bool> {
    let Some(kube) = ctx.kube.as_ref() else {
        return Ok(false);
    };
    let backend = load_backend_row(&ctx.pool, &env.id).await?;
    if backend.namespace.is_empty() || backend.claim_uid.is_empty() {
        return Ok(false);
    }
    let client = SandboxClient::new(kube.clone(), &backend.namespace);
    let Some(observed) = client.pool_born_claim(&env.id, &backend.claim_uid).await? else {
        return Ok(false);
    };
    if let Some((_, sandbox_uid)) = &observed.sandbox
        && sandbox_bound_by_any(&ctx.pool, sandbox_uid).await?
    {
        pool_route::record_reclaim("refused_bound");
        return Ok(false);
    }
    let started = std::time::Instant::now();
    // A never-bound member never had a warm-member bridge (#2434); removing
    // any name-addressed residue keeps the cold re-claim from inheriting one.
    authority
        .run_external_mutation(CREATE_MUTATION_STATES, async {
            client.delete_warm_member_bridge(&env.id).await?;
            client
                .delete_pool_born_claim(&env.id, &observed, RECLAIM_TIMEOUT)
                .await
        })
        .await?;
    emit_create_log(
        authority,
        "reclaim_cold",
        "completed",
        "the pool-born Claim never bound; claiming cold",
        duration_meta(started),
    )
    .await?;
    pool_route::record_reclaim("reclaimed");
    tracing::warn!(env = %env.id, pool = %observed.pool, "create: re-claiming cold after a pool-born bind failure");
    Ok(true)
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

    fn identity_mode_env() -> EnvironmentRow {
        EnvironmentRow {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "creating".into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 2000,
            memory_mb: 4096,
            disk_gb: 10,
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        }
    }

    /// Review L2: a worker with a sandbox backend refuses to start without
    /// the binding Service namespace or a coordinator/API URL, instead of
    /// silently rendering legacy Pods.
    #[test]
    fn missing_binding_configuration_fails_startup() {
        let complete = SandboxWorkerCfg {
            pod_namespace: "dev".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            ..Default::default()
        };
        assert_eq!(complete.require_workspace_binding_config(), Ok(()));
        let coordinator_only = SandboxWorkerCfg {
            api_base_url: String::new(),
            coordinator_url: "http://codewire-coordinator.dev.svc.cluster.local:8090".into(),
            ..complete.clone()
        };
        assert_eq!(coordinator_only.require_workspace_binding_config(), Ok(()));
        for (cfg, missing) in [
            (
                SandboxWorkerCfg {
                    pod_namespace: " ".into(),
                    ..complete.clone()
                },
                "POD_NAMESPACE",
            ),
            (
                SandboxWorkerCfg {
                    api_base_url: String::new(),
                    ..complete.clone()
                },
                "CODEWIRE_COORDINATOR_URL or CODEWIRE_API_URL",
            ),
        ] {
            let error = cfg.require_workspace_binding_config().unwrap_err();
            assert!(error.contains(missing), "{error}");
        }
    }

    /// Commodity Pods always render identity-free, and only `binding` (or
    /// nothing) is a supported `SANDBOX_WORKSPACE_IDENTITY_MODE`: an
    /// environment-token commodity workspace could never become
    /// access-ready. Confidential keeps its rendered token until B2c; a
    /// configuration without the orchestration namespace or a coordinator,
    /// which a sandbox worker refuses at startup, renders one too.
    #[test]
    fn commodity_workspaces_always_render_identity_free() {
        for supported in ["", "binding", " binding "] {
            assert!(
                workspace_identity_mode_supported(supported),
                "{supported:?}"
            );
        }
        for refused in ["environment-token", "Binding", "token", "legacy", "pod"] {
            assert!(!workspace_identity_mode_supported(refused), "{refused}");
        }
        let cfg = SandboxWorkerCfg {
            runtime_profile: "commodity".into(),
            pod_namespace: "dev".into(),
            api_base_url: "https://codewire-dev.sh".into(),
            ..Default::default()
        };
        let render = |cfg: &SandboxWorkerCfg, env: &EnvironmentRow| {
            environment_template_opts(
                cfg,
                "ghcr.io/codewiresh/workspace:1",
                "base",
                env,
                7,
                "daemon-tok",
            )
            .unwrap()
            .workspace_identity
        };
        let env = identity_mode_env();
        assert_eq!(
            render(&cfg, &env),
            WorkspaceIdentity::Binding {
                binding_url:
                    "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087"
                        .into()
            }
        );
        // Confidential keeps its rendered token.
        let no_namespace = SandboxWorkerCfg {
            pod_namespace: String::new(),
            ..cfg.clone()
        };
        assert_eq!(
            render(&no_namespace, &env),
            WorkspaceIdentity::EnvironmentToken
        );
        let no_coordinator = SandboxWorkerCfg {
            api_base_url: String::new(),
            coordinator_url: String::new(),
            ..cfg.clone()
        };
        assert_eq!(
            render(&no_coordinator, &env),
            WorkspaceIdentity::EnvironmentToken
        );
        let confidential = EnvironmentRow {
            isolation_tier: "confidential".into(),
            ..identity_mode_env()
        };
        assert_eq!(
            render(&cfg, &confidential),
            WorkspaceIdentity::EnvironmentToken
        );
    }

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
            pod_name: if ip.is_empty() {
                String::new()
            } else {
                "sandbox-env".into()
            },
            pod_ip: ip.into(),
            setup_complete,
            ..Default::default()
        }
    }

    fn probe(exists: bool, ready: bool) -> ProbeResult {
        ProbeResult {
            claim_exists: exists,
            claim_ready: ready,
            pod_exists: ready,
            pod_phase: if ready { "Running" } else { "" }.into(),
            pod_name: if ready { "sandbox-env" } else { "" }.into(),
            pod_uid: if ready { "pod-uid" } else { "" }.into(),
            pod_ip: if ready { "10.0.0.5" } else { "" }.into(),
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
        // Replacement identity must be stored before the new Pod is exposed.
        let mut replaced = probe(true, true);
        replaced.pod_name = "replacement".into();
        replaced.pod_uid = "replacement-uid".into();
        replaced.pod_ip = "10.0.0.6".into();
        assert_eq!(
            next_create_action("creating", Some(&b), false, &replaced),
            CreateAction::StoreBackend
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

    fn environment(state: &str) -> EnvironmentRow {
        EnvironmentRow {
            id: "env-1".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: state.into(),
            desired_state: "started".into(),
            isolation_tier: "standard".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 1000,
            memory_mb: 2048,
            disk_gb: 10,
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        }
    }

    /// Walk the create policy the way the activity loop does, applying each
    /// action's durable effect. Returns the actions taken and how many
    /// runtime identity reconciliations they needed.
    /// `liveness_stores_pod` reproduces Dev on 2026-09-30: the leader's
    /// sandbox liveness loop stored the Pod's name and IP during the gateway
    /// readiness wait, so create never took `store_backend`.
    fn walk_create(start_state: &str, liveness_stores_pod: bool) -> (Vec<CreateAction>, usize) {
        let ready = probe(true, true);
        let mut state = start_state.to_string();
        let mut stored: Option<BackendRow> = None;
        let mut claim_exists = false;
        let mut actions = Vec::new();
        let mut reconciled: Option<ReconciledRuntime> = None;
        let mut reconciliations = 0;
        loop {
            let observed = if claim_exists {
                ready.clone()
            } else {
                probe(false, false)
            };
            let action = next_create_action(&state, stored.as_ref(), false, &observed);
            actions.push(action);
            assert!(actions.len() <= 8, "create did not converge: {actions:?}");
            if create_action_requires_runtime_identity(action) {
                let runtime = ReconciledRuntime::observe(
                    &environment(&state),
                    stored.as_ref().unwrap(),
                    &observed,
                );
                if reconciled.as_ref() != Some(&runtime) {
                    reconciliations += 1;
                    reconciled = Some(runtime);
                }
            } else {
                reconciled = None;
            }
            match action {
                CreateAction::EnsureNamespace => stored = Some(backend("ns", "", "", false)),
                CreateAction::CreateClaim => {
                    let row = stored.as_mut().unwrap();
                    claim_exists = true;
                    row.claim_name = "sandbox-env".into();
                    state = "creating".into();
                    if liveness_stores_pod {
                        row.pod_name = ready.pod_name.clone();
                        row.pod_ip = ready.pod_ip.clone();
                    }
                }
                CreateAction::StoreBackend => {
                    let row = stored.as_mut().unwrap();
                    row.pod_name = ready.pod_name.clone();
                    row.pod_ip = ready.pod_ip.clone();
                }
                CreateAction::MarkRunning => {
                    state = "running".into();
                    reconciled.as_mut().unwrap().entered_running();
                }
                CreateAction::PublishSetup => return (actions, reconciliations),
                other => panic!("unexpected create action {other}"),
            }
        }
    }

    #[test]
    fn pod_start_marks_are_recorded_on_the_path_dev_takes() {
        use CreateAction::*;
        // Dev: create_claim, then straight to mark_running.
        let (dev, dev_reconciliations) = walk_create("pending", true);
        assert_eq!(
            dev,
            [EnsureNamespace, CreateClaim, MarkRunning, PublishSetup]
        );
        let (create_stores_pod, store_reconciliations) = walk_create("pending", false);
        assert_eq!(
            create_stores_pod,
            [
                EnsureNamespace,
                CreateClaim,
                StoreBackend,
                MarkRunning,
                PublishSetup
            ]
        );
        // Every path takes the recording action exactly once;
        // `store_backend` is optional and so cannot own the Pod marks.
        for actions in [&dev, &create_stores_pod] {
            assert_eq!(
                actions
                    .iter()
                    .filter(|action| records_pod_start_marks(**action))
                    .count(),
                1,
                "{actions:?}"
            );
        }
        assert!(!records_pod_start_marks(StoreBackend));
        // One Pod, one reconciliation: the ready actions that follow it in
        // the same attempt reuse it.
        assert_eq!((dev_reconciliations, store_reconciliations), (1, 1));
    }

    #[test]
    fn a_ready_action_reconciles_again_after_any_observed_change() {
        let stored = backend("ns", "sandbox-env", "10.0.0.5", false);
        let ready = probe(true, true);
        let running = environment("running");
        let mut reconciled = ReconciledRuntime::observe(&environment("creating"), &stored, &ready);
        // Only this attempt's own committed `mark_running` may advance state.
        assert_ne!(
            reconciled,
            ReconciledRuntime::observe(&running, &stored, &ready)
        );
        reconciled.entered_running();
        assert_eq!(
            reconciled,
            ReconciledRuntime::observe(&running, &stored, &ready)
        );

        let probed = |change: fn(&mut ProbeResult)| {
            let mut probe = ready.clone();
            change(&mut probe);
            ReconciledRuntime::observe(&running, &stored, &probe)
        };
        let recorded = |change: fn(&mut BackendRow)| {
            let mut backend = stored.clone();
            change(&mut backend);
            ReconciledRuntime::observe(&running, &backend, &ready)
        };
        let loaded = |change: fn(&mut EnvironmentRow)| {
            let mut environment = running.clone();
            change(&mut environment);
            ReconciledRuntime::observe(&environment, &stored, &ready)
        };
        let changes = [
            (
                "replaced Pod",
                probed(|p| p.pod_uid = "replacement-uid".into()),
            ),
            ("renamed Pod", probed(|p| p.pod_name = "replacement".into())),
            ("new Pod address", probed(|p| p.pod_ip = "10.0.0.6".into())),
            (
                "new Claim",
                recorded(|b| b.claim_uid = "claim-uid-2".into()),
            ),
            ("new namespace", recorded(|b| b.namespace = "ns-2".into())),
            (
                "state moved elsewhere",
                loaded(|e| e.state = "error".into()),
            ),
            (
                "desired stop",
                loaded(|e| e.desired_state = "stopped".into()),
            ),
            ("new generation", loaded(|e| e.operation_generation = 8)),
            (
                "new managed clients",
                loaded(|e| {
                    e.managed_credential_clients =
                        codewire_access::ManagedCredentialClients::from_profile_slots(["github"])
                            .map_err(|_| codewire_project::PlatformProjectionSelectionError)
                }),
            ),
            (
                "invalid selection",
                loaded(|e| {
                    e.projection_selection = Err(codewire_project::PlatformProjectionSelectionError)
                }),
            ),
            ("resized", loaded(|e| e.memory_mb = 4096)),
        ];
        for (change, observed) in changes {
            assert_ne!(reconciled, observed, "{change}");
        }
        // Backend Pod fields are what `store_backend` writes, not an input.
        assert_eq!(
            reconciled,
            recorded(|b| {
                b.pod_ip.clear();
                b.pod_name.clear();
            })
        );
    }

    #[test]
    fn ready_create_actions_including_retry_fast_paths_require_runtime_identity() {
        for action in [
            CreateAction::Done,
            CreateAction::StoreBackend,
            CreateAction::MarkRunning,
            CreateAction::PublishSetup,
        ] {
            assert!(create_action_requires_runtime_identity(action));
        }
        for action in [
            CreateAction::WaitForReady,
            CreateAction::ResumeWorkspace,
            CreateAction::EnsureNamespace,
            CreateAction::CreateClaim,
        ] {
            assert!(!create_action_requires_runtime_identity(action));
        }
    }

    /// #2328: setup's no-Pod fence left the Sandbox suspended while desired
    /// state stayed `started`. Every pending-create retry then waited for a
    /// Claim that cannot become Ready while its Sandbox is suspended.
    #[test]
    fn pending_retry_resumes_a_suspended_sandbox_instead_of_waiting_for_readiness() {
        let b = backend("ns", "sandbox-env", "10.0.0.5", false);
        let suspended = ProbeResult {
            claim_exists: true,
            claim_reason: "SandboxSuspended".into(),
            sandbox_suspended: true,
            ..Default::default()
        };
        assert_eq!(
            next_create_action("pending", Some(&b), false, &suspended),
            CreateAction::ResumeWorkspace
        );
        assert_eq!(
            CreateAction::ResumeWorkspace.to_string(),
            "resume_workspace"
        );
        // Only an explicit retry resumes. A first create waits for its own new
        // Claim, and start/running paths own their Sandbox operating mode.
        for state in ["creating", "starting", "running"] {
            assert_eq!(
                next_create_action(state, Some(&b), false, &suspended),
                CreateAction::WaitForReady,
                "{state}"
            );
        }
        // An unbound Claim reads zero replicas without being suspended.
        let unbound = ProbeResult {
            sandbox_suspended: false,
            claim_reason: String::new(),
            ..suspended.clone()
        };
        assert_eq!(
            next_create_action("pending", Some(&b), false, &unbound),
            CreateAction::WaitForReady
        );
        // A Ready Claim proceeds through runtime identity, never a resume.
        let ready = ProbeResult {
            sandbox_suspended: true,
            ..probe(true, true)
        };
        assert_eq!(
            next_create_action("pending", Some(&b), false, &ready),
            CreateAction::MarkRunning
        );
    }

    #[test]
    fn running_identity_reconciliation_never_resumes_stopped_or_destroying_environments() {
        assert!(requires_running_runtime_identity("running", "started"));
        for (state, desired) in [
            ("running", "stopped"),
            ("running", "destroyed"),
            ("stopped", "started"),
            ("destroying", "started"),
            ("resizing", "resized"),
        ] {
            assert!(!requires_running_runtime_identity(state, desired));
        }
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
    fn claim_opts_always_use_an_environment_scoped_template_and_shadow_pool() {
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
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        };
        // Even the canonical image uses an environment-scoped template: the
        // daemon credential must be present before the workspace process starts.
        let opts = environment_claim_opts(
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
            "tmpl-base",
            &env,
            7,
        );
        assert_eq!(opts.template_ref, "workspace-env-1");
        assert_eq!(opts.warm_pool_ref, "shadow-pool-workspace-env-1");
        assert!(opts.env_overrides.is_empty());
        assert_eq!(opts.operation_generation, 7);
        assert_eq!(
            opts.additional_pod_labels,
            crate::sandbox::runtime_identity_labels("env-1", "org-1", 7, "workspace")
        );

        // Isolation tier and requested size never select a shared template.
        let mut confidential = env.clone();
        confidential.isolation_tier = "confidential".into();
        confidential.cpu_millicores = 8000;
        let opts = environment_claim_opts(
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
            "tmpl-base",
            &confidential,
            7,
        );
        assert_eq!(opts.template_ref, "workspace-env-1");
        assert_eq!(opts.warm_pool_ref, "shadow-pool-workspace-env-1");
        assert_eq!(
            environment_per_env_template_name(
                "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
                "tmpl-base",
                "env-1",
            ),
            "workspace-env-1"
        );

        // Custom image → per-env template from the preset base name.
        let opts = environment_claim_opts("ghcr.io/acme/custom:1", "tmpl-base", &env, 7);
        assert_eq!(opts.template_ref, "tmpl-base-env-1");
        assert_eq!(opts.warm_pool_ref, "shadow-pool-tmpl-base-env-1");
        assert!(opts.env_overrides.is_empty());
    }

    #[test]
    fn long_per_environment_pool_cleanup_cannot_target_another_claim() {
        let env = EnvironmentRow {
            id: "unused".into(),
            org_id: "org-1".into(),
            preset_id: None,
            env_type: "sandbox".into(),
            state: "pending".into(),
            desired_state: "started".into(),
            isolation_tier: "confidential".into(),
            external_cleanup_completed_at: None,
            cpu_millicores: 2000,
            memory_mb: 16384,
            disk_gb: 50,
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        };
        let template_base = "codewiresh-workspace-sha256-2058b7f1fd76f6f77b1dba";
        let first_id = "3d6bb495-efac-419f-bf3a-91696e7c7ca4";
        let second_id = "76169e1f-3bbf-46be-96e0-cac68e0ac910";

        let first_env = EnvironmentRow {
            id: first_id.to_owned(),
            ..env.clone()
        };
        let second_env = EnvironmentRow {
            id: second_id.to_owned(),
            ..env.clone()
        };
        let first_claim = environment_claim_opts(
            "ghcr.io/codewiresh/workspace@sha256:2058b7f1fd76f6f77b1dba596a9b54c698c049380e5ace6a0493f10a9d41e1b4",
            template_base,
            &first_env,
            7,
        );
        let second_claim = environment_claim_opts(
            "ghcr.io/codewiresh/workspace@sha256:2058b7f1fd76f6f77b1dba596a9b54c698c049380e5ace6a0493f10a9d41e1b4",
            template_base,
            &second_env,
            7,
        );
        let first_cleanup_template = environment_per_env_template_name(
            "ghcr.io/codewiresh/workspace@sha256:2058b7f1fd76f6f77b1dba596a9b54c698c049380e5ace6a0493f10a9d41e1b4",
            template_base,
            first_id,
        );

        assert_eq!(
            first_claim.warm_pool_ref,
            shadow_warm_pool_name(&first_cleanup_template)
        );
        assert_ne!(first_claim.warm_pool_ref, second_claim.warm_pool_ref);
        assert_ne!(
            shadow_warm_pool_name(&first_cleanup_template),
            second_claim.warm_pool_ref
        );
    }

    #[test]
    fn template_opts_use_only_the_runtime_profile() {
        let cfg = SandboxWorkerCfg {
            daemon_image: "daemon:1".into(),
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
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
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        };
        // First-party image: no image command; canonical name swap.
        let opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
            "preset-base",
            &env,
            7,
            "daemon-tok",
        )
        .unwrap();
        assert!(opts.image_command.is_empty());
        assert_eq!(opts.name, "workspace-env-1");
        assert_eq!(opts.organization_id, "org-1");
        assert_eq!(opts.operation_generation, 7);
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
        // Custom image: sleep infinity + preset-derived name.
        let opts = environment_template_opts(
            &cfg,
            "ghcr.io/acme/img:1",
            "preset-base",
            &env,
            7,
            "daemon-tok",
        )
        .unwrap();
        assert_eq!(
            opts.image_command,
            vec!["sleep".to_string(), "infinity".to_string()]
        );
        assert_eq!(opts.name, "preset-base-env-1");
    }

    #[test]
    fn confidential_tier_coexists_with_commodity_process_default() {
        let cfg = SandboxWorkerCfg {
            runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
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
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
        };

        let standard_opts = environment_template_opts(
            &cfg,
            "ghcr.io/codewiresh/workspace:golden",
            "workspace",
            &standard,
            7,
            "daemon-tok",
        )
        .unwrap();
        assert_eq!(
            standard_opts.runtime_profile,
            crate::sandbox::template::RUNTIME_PROFILE_COMMODITY
        );
        assert_eq!(
            standard_opts.runtime_profile_spec().runtime_class_name,
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
            7,
            "daemon-tok",
        )
        .unwrap();
        assert_eq!(
            confidential_opts.runtime_profile,
            crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL
        );
        assert_eq!(
            confidential_opts.runtime_profile_spec().runtime_class_name,
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
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
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
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
            "workspace",
            &env,
            7,
            "daemon-tok",
        )
        .unwrap();

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
            7,
            "daemon-tok",
        )
        .unwrap();
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
            ttl_seconds: None,
            project_spec: codewire_project::ProjectSpec::default(),
            operation_generation: 7,
            projection_selection: Ok(None),
            managed_credential_clients: Ok(Default::default()),
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
            "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff",
            "workspace",
            &env,
            7,
            "daemon-tok",
        )
        .unwrap();

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
