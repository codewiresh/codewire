//! #3628 PR 8b moved workspace rendering behind the driver: orchestration
//! states a [`RenderingIntent`] and the driver renders it with its own
//! [`KubernetesRenderConfig`]. Today's builders are frozen below, exactly as
//! they were on `e4833ff34`, and every case renders the same options both
//! ways, or fails with the same error.

use super::*;
use crate::sandbox::canonical_workspace_runtime_image;
use crate::sandbox::template::{
    CpuSharingRatio, CredentialRuntimeTemplateConfig, DOCKER_MODE_LOCAL_DIND_DIRECT,
    RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_RUNC, RuntimeProfileSpec, TemplateOpts,
    runtime_profile_spec, validate_managed_runtime_profile,
};
use codewire_project::PlatformProjectionSelection;

// ── Frozen: the builders as they were before PR 8b ─────────────────────

/// Mirrors `isFirstPartyWorkspaceImage`.
fn is_first_party_workspace_image(image_ref: &str) -> bool {
    image_ref.contains("codewiresh/workspace-")
        || image_ref.contains("codewiresh/base")
        || image_ref.contains("codewiresh/workspace")
}

/// Mirrors `environmentTemplateOpts`: the environment's identity on top of
/// the cluster and shape inputs of [`before_shape_template_opts`].
fn before_environment_template_opts(
    cfg: &SandboxWorkerCfg,
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    operation_generation: i64,
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
        None => before_standard_runtime_profile_spec(cfg),
    };
    // A confidential claim is the guest-encrypted raw Block volume of its own
    // class; without one the environment is refused, never given the
    // commodity class.
    anyhow::ensure!(
        runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
            || !cfg.confidential_workspace_storage_class.is_empty(),
        "confidential workspace storage has no StorageClass: set {}",
        crate::sandbox::template::CONFIDENTIAL_WORKSPACE_STORAGE_CLASS_ENV
    );
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
    // A confidential workspace measures the roots its daemon trusts (B2c);
    // without them no confidential rendering exists.
    anyhow::ensure!(
        runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
            || !cfg.confidential_binding_roots_pem.trim().is_empty(),
        "confidential workspaces need orchestration's internal TLS roots to measure"
    );

    let opts = TemplateOpts {
        name: environment_template_name(template_base, env_id),
        environment_id: env_id.to_string(),
        organization_id: env.org_id.clone(),
        operation_generation,
        projection_selection_sha256,
        managed_credential_clients,
        codex_login_check_period_seconds: cfg.codex_login_check_period_seconds,
        workspace_source_snapshot: env
            .source_snapshot_id
            .as_deref()
            .map(crate::sandbox::snapshots::kept_snapshot_name),
        ..before_shape_template_opts(cfg, image_ref, &runtime_spec, shape)
    };
    let opts = if env.dedicated_cpu {
        TemplateOpts {
            cpu_sharing: crate::sandbox::template::CpuSharingRatio::NONE,
            ..opts
        }
    } else {
        opts
    };
    // Its binding listener is one of the measured anchors: a confidential
    // rendering without one is refused here, never rendered.
    anyhow::ensure!(
        runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
            || !opts.workspace_binding_url.trim().is_empty(),
        "confidential workspaces need the workspace binding listener to measure"
    );
    Ok(opts)
}

/// The cluster and shape inputs of a workspace rendering, with no environment
/// identity: images, runtime, resources, storage, transport and the identity
/// mode. A warm pool renders from these alone (Program #2238 C1); an
/// environment adds its identity in [`before_environment_template_opts`]. Every
/// field is listed, so a new one must be placed on one side or the other.
fn before_shape_template_opts(
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
        crate::sandbox::template::WORKSPACE_KEEPALIVE_COMMAND
            .map(str::to_owned)
            .to_vec()
    };

    let uses_runtime_transport_registry = !cfg.runtime_transport_zones_json.trim().is_empty();
    // Every hosted workspace is identity-free (design §13), confidential too
    // (B2c), which also measures its binding anchors. A Pod reaches the
    // binding listener only with the orchestration namespace and a
    // coordinator known, which a worker with a sandbox backend requires at
    // startup (`require_workspace_binding_config`).
    let has_coordinator =
        !(cfg.coordinator_url.trim().is_empty() && cfg.api_base_url.trim().is_empty());
    let binds = !cfg.pod_namespace.trim().is_empty() && has_coordinator;
    let measured_binding_roots = if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        cfg.confidential_binding_roots_pem.clone()
    } else {
        String::new()
    };
    let workspace_binding_url = if binds {
        workspace_binding_url(cfg.pod_namespace.trim())
    } else {
        String::new()
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
        // Cluster and shape.
        measured_binding_roots,
        image: image_ref.to_string(),
        image_command,
        support_image: cfg.daemon_image.clone(),
        dind_image: cfg.dind_image.clone(),
        runtime_profile: runtime_spec.profile.clone(),
        docker_mode: runtime_spec.docker_mode.clone(),
        credential_runtime: cfg.credential_runtime.clone(),
        workspace_binding_url,
        api_base_url: cfg.api_base_url.clone(),
        coordinator_url: cfg.coordinator_url.clone(),
        server_namespace: cfg.pod_namespace.clone(),
        coordinator_extra_roots: cfg.coordinator_extra_roots,
        ingress_namespace: cfg.ingress_namespace.clone(),
        ingress_pod_name: cfg.ingress_pod_name.clone(),
        egress_bandwidth: cfg.egress_bandwidth.clone(),
        // Kind's test deployment only, and the same as an environment's own
        // rendering: a pool member must render exactly as the environment that
        // adopts it, or every create of its shape routes cold (#3852). Kind's
        // pool template admission names the variable; no other deployment's
        // build reads it.
        codex_login_check_period_seconds: cfg.codex_login_check_period_seconds,
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
        udp_relay_bind_addrs: if uses_runtime_transport_registry {
            String::new()
        } else {
            cfg.udp_relay_bind_addrs.clone()
        },
        udp_relay_allocator_egress_enabled: uses_runtime_transport_registry,
        cpu_millicores: shape.cpu_millicores,
        // Nothing has measured a confidential VM under sharing.
        cpu_sharing: if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
            crate::sandbox::template::CpuSharingRatio::NONE
        } else {
            cfg.cpu_sharing_ratio
        },
        memory_mib: shape.memory_mib,
        disk_gib: shape.disk_gib,
        workspace_source_snapshot: None,
        workspace_storage_class: if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
            cfg.confidential_workspace_storage_class.clone()
        } else {
            cfg.workspace_storage_class.clone()
        },
        workspace_subfolder: cfg.workspace_subfolder,
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
fn before_standard_runtime_profile_spec(cfg: &SandboxWorkerCfg) -> RuntimeProfileSpec {
    runtime_profile_spec(&cfg.runtime_profile, &cfg.docker_mode, cfg.dind_enabled)
}

/// The identity-free inputs of one warm-pool shape (Program #2238 C1): the
/// canonical workspace image on the standard tier, from the shape and this
/// process's configuration alone, never from an environment row. A
/// confidential runtime, a diagnostic runtime outside diagnostic clusters and
/// a configuration that cannot render identity-free workspaces render no
/// pool.
fn before_warm_pool_template_opts(
    cfg: &SandboxWorkerCfg,
    shape: WorkspaceShape,
) -> anyhow::Result<TemplateOpts> {
    let runtime_spec = before_standard_runtime_profile_spec(cfg);
    anyhow::ensure!(
        runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL,
        "confidential workspaces are never pooled"
    );
    validate_managed_runtime_profile(&runtime_spec, cfg.allow_diagnostic_runtime)
        .map_err(|error| anyhow::anyhow!("warm pool runtime profile: {error}"))?;
    let opts = before_shape_template_opts(
        cfg,
        canonical_workspace_runtime_image(),
        &runtime_spec,
        shape,
    );
    anyhow::ensure!(
        !opts.workspace_binding_url.is_empty(),
        "warm pools require identity-free workspaces (POD_NAMESPACE and a coordinator)"
    );
    Ok(opts)
}

// ── The cases ──────────────────────────────────────────────────────────

const CUSTOM_IMAGE: &str = "registry.example.invalid/team/app@sha256:4444444444444444444444444444444444444444444444444444444444444444";
const FIRST_PARTY_IMAGE: &str = "registry.example.invalid/codewiresh/workspace-node@sha256:5555555555555555555555555555555555555555555555555555555555555555";

/// A Dev-shaped commodity configuration with synthetic values.
fn base_cfg() -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        sandbox_namespace: "dev-sandboxes".into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes")),
        daemon_image: "registry.example.invalid/codewire/daemon@sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
        dind_image: "docker.io/library/docker:29.7.1-dind@sha256:3333333333333333333333333333333333333333333333333333333333333333".into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        docker_mode: crate::sandbox::template::DOCKER_MODE_PROFILE_DEFAULT.into(),
        workspace_storage_class: "linstor-local".into(),
        network_policy_management: "Managed".into(),
        kata_agent_policy_enabled: true,
        api_base_url: "https://codewire-dev.sh".into(),
        coordinator_url: "http://codewire-coordinator.dev.svc.cluster.local:8090".into(),
        pod_namespace: "dev".into(),
        ..Default::default()
    }
}

/// The confidential tier enabled beside commodity.
fn confidential_cfg() -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        kata_coco_init_data_enabled: true,
        kata_coco_kbs_url: "https://kbs.example.invalid:8080".into(),
        kata_coco_kbs_ca_pem: "-----BEGIN CERTIFICATE-----\nkbs\n-----END CERTIFICATE-----\n"
            .into(),
        kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
        kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
        kata_coco_test_resource_path: "/run/test-resource".into(),
        confidential_workspace_storage_class: "linstor-confidential".into(),
        confidential_binding_roots_pem:
            "-----BEGIN CERTIFICATE-----\nroots\n-----END CERTIFICATE-----\n".into(),
        ..base_cfg()
    }
}

/// Every deployment setting a rendering reads, each away from its default.
fn configurations() -> Vec<(&'static str, SandboxWorkerCfg)> {
    vec![
        ("base", base_cfg()),
        ("confidential", confidential_cfg()),
        (
            "transport and relays",
            SandboxWorkerCfg {
                derp_host: "derp.example.invalid".into(),
                derp_port: "8443".into(),
                stun_host: "stun.example.invalid".into(),
                stun_port: "3479".into(),
                stun_servers: "stun.example.invalid:3479".into(),
                direct_udp_lb_enabled: true,
                direct_udp_lb_ip: "192.0.2.10".into(),
                direct_udp_lb_port_start: "40000".into(),
                direct_udp_lb_port_end: "40100".into(),
                direct_udp_lb_class: "io.cilium/l2".into(),
                direct_udp_lb_sharing_key: "workspaces".into(),
                direct_udp_transport_zone: "zone-a".into(),
                udp_relay_allocator_url: "https://relay.example.invalid".into(),
                udp_relay_bind_addrs: "0.0.0.0:3478".into(),
                ..confidential_cfg()
            },
        ),
        (
            "transport registry and bad ports",
            SandboxWorkerCfg {
                derp_port: "not-a-port".into(),
                stun_port: "-1".into(),
                direct_udp_lb_enabled: true,
                direct_udp_lb_port_start: "70000".into(),
                direct_udp_lb_port_end: "0".into(),
                udp_relay_allocator_url: "https://relay.example.invalid".into(),
                udp_relay_bind_addrs: "0.0.0.0:3478".into(),
                runtime_transport_zones_json: r#"{"zone-a":{}}"#.into(),
                ..confidential_cfg()
            },
        ),
        (
            "every other setting",
            SandboxWorkerCfg {
                coordinator_extra_roots: true,
                codex_login_check_period_seconds: Some(30),
                ingress_namespace: "ingress".into(),
                ingress_pod_name: "ingress-controller".into(),
                egress_bandwidth: "100M".into(),
                cpu_sharing_ratio: CpuSharingRatio::parse(Some("4")).unwrap(),
                workspace_subfolder: true,
                network_policy_management: "Unmanaged".into(),
                kata_agent_policy_enabled: false,
                debug_tailnet: true,
                ..confidential_cfg()
            },
        ),
        (
            "dind",
            SandboxWorkerCfg {
                docker_mode: DOCKER_MODE_LOCAL_DIND_DIRECT.into(),
                dind_enabled: true,
                ..confidential_cfg()
            },
        ),
        (
            "diagnostic runtime",
            SandboxWorkerCfg {
                runtime_profile: RUNTIME_PROFILE_RUNC.into(),
                ..confidential_cfg()
            },
        ),
        (
            "diagnostic runtime allowed",
            SandboxWorkerCfg {
                runtime_profile: RUNTIME_PROFILE_RUNC.into(),
                allow_diagnostic_runtime: true,
                ..confidential_cfg()
            },
        ),
        (
            "confidential standard profile",
            SandboxWorkerCfg {
                runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
                ..confidential_cfg()
            },
        ),
        (
            "no credential runtime",
            SandboxWorkerCfg {
                credential_runtime: None,
                ..confidential_cfg()
            },
        ),
        (
            "no confidential storage class",
            SandboxWorkerCfg {
                confidential_workspace_storage_class: String::new(),
                ..confidential_cfg()
            },
        ),
        (
            "no measured roots",
            SandboxWorkerCfg {
                confidential_binding_roots_pem: " \n".into(),
                ..confidential_cfg()
            },
        ),
        (
            "no binding namespace",
            SandboxWorkerCfg {
                pod_namespace: " ".into(),
                ..confidential_cfg()
            },
        ),
        (
            "no coordinator",
            SandboxWorkerCfg {
                coordinator_url: String::new(),
                api_base_url: " ".into(),
                ..confidential_cfg()
            },
        ),
    ]
}

fn environment() -> EnvironmentRow {
    EnvironmentRow {
        id: "3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
        org_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        state: "creating".into(),
        desired_state: "started".into(),
        isolation_tier: "standard".into(),
        dedicated_cpu: false,
        never_ran: false,
        external_cleanup_completed_at: None,
        cpu_millicores: 2000,
        memory_mb: 8192,
        disk_gb: 80,
        source_snapshot_id: None,
        ttl_seconds: None,
        project_spec: codewire_project::ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    }
}

fn selection(profile: bool) -> PlatformProjectionSelection {
    PlatformProjectionSelection {
        creator: "synthetic-creator".into(),
        organization: "synthetic-org".into(),
        organization_selected: true,
        project_id: None,
        user_selected: false,
        profile: profile.then(|| ("synthetic-profile".into(), 3)),
        ordinary_keys: ["APP_MODE".into()].into(),
        reserved_keys: codewire_project::platform_projection_reserved_keys([]).unwrap(),
    }
}

/// Every environment input a rendering reads, plus each check that refuses.
fn environments() -> Vec<(&'static str, EnvironmentRow)> {
    let github = codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap();
    vec![
        ("standard", environment()),
        (
            "confidential",
            EnvironmentRow {
                isolation_tier: "confidential".into(),
                ..environment()
            },
        ),
        (
            "dedicated",
            EnvironmentRow {
                dedicated_cpu: true,
                ..environment()
            },
        ),
        (
            "confidential dedicated",
            EnvironmentRow {
                isolation_tier: "confidential".into(),
                dedicated_cpu: true,
                ..environment()
            },
        ),
        (
            "small",
            EnvironmentRow {
                cpu_millicores: 1000,
                memory_mb: 2048,
                disk_gb: 10,
                ..environment()
            },
        ),
        (
            "restored",
            EnvironmentRow {
                source_snapshot_id: Some("snapshot-1".into()),
                ..environment()
            },
        ),
        (
            "selected",
            EnvironmentRow {
                projection_selection: Ok(Some(selection(false))),
                managed_credential_clients: Ok(github),
                ..environment()
            },
        ),
        (
            "selected with a profile",
            EnvironmentRow {
                projection_selection: Ok(Some(selection(true))),
                managed_credential_clients: Ok(github),
                ..environment()
            },
        ),
        (
            "clients without a profile",
            EnvironmentRow {
                managed_credential_clients: Ok(github),
                ..environment()
            },
        ),
        (
            "invalid selection",
            EnvironmentRow {
                projection_selection: Err(codewire_project::PlatformProjectionSelectionError),
                ..environment()
            },
        ),
        (
            "invalid clients",
            EnvironmentRow {
                managed_credential_clients: Err(codewire_project::PlatformProjectionSelectionError),
                ..environment()
            },
        ),
        (
            "another generation",
            EnvironmentRow {
                operation_generation: 8,
                ..environment()
            },
        ),
    ]
}

fn images() -> [(&'static str, &'static str); 3] {
    [
        (canonical_workspace_runtime_image(), "workspace"),
        (CUSTOM_IMAGE, "preset-base"),
        (FIRST_PARTY_IMAGE, "node-base"),
    ]
}

fn outcome<T>(result: anyhow::Result<T>) -> Result<T, String> {
    result.map_err(|error| format!("{error:#}"))
}

/// Each environment renders the same options, or fails with the same error,
/// under each configuration; and its runtime is checked the same way.
#[test]
fn every_environment_renders_as_before() {
    let mut compared = 0;
    for (cfg_case, cfg) in configurations() {
        let config = KubernetesRenderConfig::from(&cfg);
        for (env_case, env) in environments() {
            for (image, base) in images() {
                let case = format!("{cfg_case} / {env_case} / {base}");
                let before = outcome(before_environment_template_opts(&cfg, image, base, &env, 7));
                let intent = environment_rendering_intent(image, base, &env, 7);
                let after = outcome(
                    intent
                        .as_ref()
                        .map_err(|error| anyhow::anyhow!("{error:#}"))
                        .and_then(|intent| config.environment(intent)),
                );
                assert!(before == after, "{case}: {before:?}\n != {after:?}");
                if let (Ok(before), Ok(intent)) = (&before, &intent) {
                    assert_eq!(
                        validate_managed_runtime_profile(
                            &before.runtime_profile_spec(),
                            cfg.allow_diagnostic_runtime
                        ),
                        config.check_runtime_profile(intent),
                        "{case}: runtime profile check"
                    );
                }
                compared += 1;
            }
        }
    }
    // Some of each outcome, so a case list that fails everything can't pass.
    assert_eq!(compared, 14 * 12 * 3);
}

/// Each pool shape renders the same options, or fails the same way.
#[test]
fn every_pool_renders_as_before() {
    let shapes = [
        WorkspaceShape {
            cpu_millicores: 1000,
            memory_mib: 4096,
            disk_gib: 10,
        },
        WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 8192,
            disk_gib: 80,
        },
        WorkspaceShape {
            cpu_millicores: 500,
            memory_mib: 1024,
            disk_gib: 5,
        },
    ];
    for (cfg_case, cfg) in configurations() {
        let config = KubernetesRenderConfig::from(&cfg);
        for shape in shapes {
            let before = outcome(before_warm_pool_template_opts(&cfg, shape));
            let after = outcome(config.pool(shape));
            assert!(
                before == after,
                "{cfg_case} / {shape:?}: {before:?}\n != {after:?}"
            );
        }
    }
}

/// The cases above reach both success and every refusal, so equal outcomes
/// mean something.
#[test]
fn the_cases_reach_every_outcome() {
    let mut outcomes = std::collections::BTreeSet::new();
    for (_, cfg) in configurations() {
        for (_, env) in environments() {
            for (image, base) in images() {
                outcomes.insert(
                    match before_environment_template_opts(&cfg, image, base, &env, 7) {
                        Ok(opts) => format!("ok {}", opts.runtime_profile),
                        Err(error) => format!("{error:#}"),
                    },
                );
            }
        }
    }
    let outcomes: Vec<_> = outcomes.into_iter().collect();
    for expected in [
        "ok commodity",
        "ok confidential",
        "ok runc",
        "template metadata no longer matches operation authority",
        "invalid platform environment projection selection",
        "invalid managed credential client selection",
        "managed credential clients require an exact selected profile",
        "selected environment sources require credential runtime trust",
        "confidential workspaces need orchestration's internal TLS roots to measure",
        "confidential workspaces need the workspace binding listener to measure",
    ] {
        assert!(
            outcomes.iter().any(|outcome| outcome == expected),
            "{expected} not reached: {outcomes:#?}"
        );
    }
    assert!(
        outcomes.iter().any(
            |outcome| outcome.starts_with("confidential workspace storage has no StorageClass")
        ),
        "{outcomes:#?}"
    );
}
