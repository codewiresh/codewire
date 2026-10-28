//! Warm-pool rendering from cluster configuration and a shape alone
//! (Program #2238 C1).

use super::*;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_RUNC,
    render_sandbox_template,
};
use codewire_project::{PlatformProjectionSelection, ProjectSpec};
use serde_json::Value;

const SANDBOX_NAMESPACE: &str = "dev-sandboxes";
const SYNTHETIC_WORKSPACE_IMAGE: &str = "registry.example.invalid/codewire/workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// A Dev-shaped commodity configuration (the hosted Dev overlay's values) with
/// synthetic digests.
fn dev_cfg() -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        sandbox_namespace: SANDBOX_NAMESPACE.into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(SANDBOX_NAMESPACE)),
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

fn shapes() -> [WorkspaceShape; 2] {
    [
        WorkspaceShape {
            cpu_millicores: 1000,
            memory_mib: 4096,
            disk_gib: 10,
        },
        WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 8192,
            disk_gib: 10,
        },
    ]
}

fn environment(shape: WorkspaceShape) -> EnvironmentRow {
    EnvironmentRow {
        id: "3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
        org_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        state: "creating".into(),
        desired_state: "started".into(),
        isolation_tier: "standard".into(),
        external_cleanup_completed_at: None,
        cpu_millicores: i32::try_from(shape.cpu_millicores).unwrap(),
        memory_mb: i32::try_from(shape.memory_mib).unwrap(),
        disk_gb: i32::try_from(shape.disk_gib).unwrap(),
        ttl_seconds: None,
        project_spec: ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    }
}

/// An environment with a selected GitHub repository: a projection digest and
/// the creator's own managed GitHub client.
fn environment_with_selection(shape: WorkspaceShape) -> EnvironmentRow {
    EnvironmentRow {
        projection_selection: Ok(Some(PlatformProjectionSelection {
            creator: "synthetic-creator".into(),
            organization: "synthetic-org".into(),
            organization_selected: true,
            project_id: None,
            user_selected: false,
            profile: None,
            ordinary_keys: ["APP_MODE".into()].into(),
            reserved_keys: codewire_project::platform_projection_reserved_keys([]).unwrap(),
        })),
        managed_credential_clients: Ok(
            codewire_access::ManagedCredentialClients::from_profile_slots(["github"]).unwrap(),
        ),
        ..environment(shape)
    }
}

fn environment_opts(cfg: &SandboxWorkerCfg, env: &EnvironmentRow) -> TemplateOpts {
    environment_template_opts(
        cfg,
        canonical_workspace_runtime_image(),
        "workspace",
        env,
        7,
    )
    .unwrap()
}

fn load_golden(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/sandbox/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("golden file missing")).unwrap()
}

/// Enabling the confidential tier alongside commodity (the Dev confidential
/// activation profile: CoCo init-data, the KBS contract and the confidential
/// StorageClass) leaves every commodity warm pool byte-identical, so
/// activating it neither drains nor recreates the pools (codewire#2321).
#[test]
fn confidential_tier_settings_leave_commodity_pools_unchanged() {
    let confidential_enabled = SandboxWorkerCfg {
        kata_coco_init_data_enabled: true,
        kata_coco_kbs_url: "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080"
            .into(),
        kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
        kata_coco_test_resource_uri: "kbs:///default/codewire/runtime-test-resource".into(),
        confidential_workspace_storage_class: "linstor-confidential".into(),
        ..dev_cfg()
    };
    // Dev's configured shapes, plus the 80 GiB hosted default (#3571).
    let hosted_default = WorkspaceShape {
        cpu_millicores: 2000,
        memory_mib: 8192,
        disk_gib: 80,
    };
    for shape in shapes().into_iter().chain([hosted_default]) {
        let commodity_only = render_configured_warm_pool(&dev_cfg(), shape, 2).unwrap();
        let with_confidential =
            render_configured_warm_pool(&confidential_enabled, shape, 2).unwrap();
        // The revision is what the reconciler compares: equal, no Recreate.
        assert_eq!(with_confidential.revision, commodity_only.revision);
        assert_eq!(with_confidential.name, commodity_only.name);
        assert_eq!(with_confidential, commodity_only);
    }
}

#[test]
fn pool_template_equals_the_environment_rendering_of_its_shape() {
    let cfg = dev_cfg();
    for shape in shapes() {
        let pool = render_configured_warm_pool(&cfg, shape, 2).unwrap();
        for env in [environment(shape), environment_with_selection(shape)] {
            let opts = environment_opts(&cfg, &env);
            assert!(!opts.workspace_binding_url.is_empty());
            let rendered = render_sandbox_template(SANDBOX_NAMESPACE, &opts);
            assert_eq!(
                rendered["spec"],
                crate::sandbox::warm_pool::without_revision_marker(&pool.template["spec"]),
                "{shape:?}"
            );
        }
    }
}

/// The environment rendering is exactly the shape rendering plus the
/// environment's identity: every other field comes from the shape side.
#[test]
fn environment_opts_are_the_shape_opts_plus_identity() {
    let cfg = SandboxWorkerCfg {
        direct_udp_lb_enabled: true,
        direct_udp_lb_ip: "203.0.113.36".into(),
        direct_udp_lb_port_start: "33000".into(),
        direct_udp_lb_port_end: "33010".into(),
        derp_host: "derp.codewire-dev.sh".into(),
        stun_host: "stun.codewire-dev.sh".into(),
        udp_relay_allocator_url: "http://relay".into(),
        ..dev_cfg()
    };
    for shape in shapes() {
        let env = environment_with_selection(shape);
        let opts = environment_opts(&cfg, &env);
        assert_eq!(opts.name, format!("workspace-{}", env.id));
        assert_eq!(opts.environment_id, env.id);
        assert_eq!(opts.organization_id, env.org_id);
        assert_eq!(opts.operation_generation, 7);
        assert!(opts.projection_selection_sha256.is_some());
        let without_identity = TemplateOpts {
            name: String::new(),
            environment_id: String::new(),
            organization_id: String::new(),
            operation_generation: 0,
            projection_selection_sha256: None,
            managed_credential_clients: Default::default(),
            ..opts
        };
        let shape_opts = shape_template_opts(
            &cfg,
            canonical_workspace_runtime_image(),
            &standard_runtime_profile_spec(&cfg),
            shape,
        );
        assert_eq!(format!("{without_identity:?}"), format!("{shape_opts:?}"));
        assert_eq!(
            format!("{shape_opts:?}"),
            format!("{:?}", warm_pool_template_opts(&cfg, shape).unwrap())
        );
    }
}

#[test]
fn pool_opts_use_the_canonical_image_and_carry_no_identity() {
    let cfg = dev_cfg();
    let opts = warm_pool_template_opts(&cfg, shapes()[0]).unwrap();
    assert_eq!(opts.image, canonical_workspace_runtime_image());
    assert!(!opts.workspace_binding_url.is_empty());
    assert!(opts.name.is_empty() && opts.environment_id.is_empty());
    assert!(opts.organization_id.is_empty() && opts.operation_generation == 0);
    assert!(opts.projection_selection_sha256.is_none());
    let objects = render_configured_warm_pool(&cfg, shapes()[0], 2).unwrap();
    assert!(objects.name.starts_with("cw-pool-1000m-4096mi-10gi-"));
    assert_eq!(objects.template["metadata"]["namespace"], SANDBOX_NAMESPACE);
}

#[test]
fn confidential_is_never_pooled() {
    let cfg = SandboxWorkerCfg {
        runtime_profile: RUNTIME_PROFILE_CONFIDENTIAL.into(),
        ..dev_cfg()
    };
    for shape in shapes() {
        let error = warm_pool_template_opts(&cfg, shape).unwrap_err();
        assert!(error.to_string().contains("confidential"), "{error}");
        assert!(render_configured_warm_pool(&cfg, shape, 2).is_err());
    }
}

#[test]
fn unbindable_and_unmanaged_runtimes_render_no_pool() {
    let shape = shapes()[0];
    let no_binding_listener = SandboxWorkerCfg {
        pod_namespace: String::new(),
        ..dev_cfg()
    };
    assert!(warm_pool_template_opts(&no_binding_listener, shape).is_err());

    // A diagnostic runtime pools only on a diagnostic cluster, which may
    // also use side-loaded tagged images.
    let diagnostic = SandboxWorkerCfg {
        runtime_profile: RUNTIME_PROFILE_RUNC.into(),
        daemon_image: "git.example.com/codewire/daemon:local".into(),
        ..dev_cfg()
    };
    assert!(warm_pool_template_opts(&diagnostic, shape).is_err());
    let diagnostic_cluster = SandboxWorkerCfg {
        allow_diagnostic_runtime: true,
        ..diagnostic
    };
    assert!(render_configured_warm_pool(&diagnostic_cluster, shape, 1).is_ok());

    // A managed cluster pools only digest-pinned images.
    let tagged = SandboxWorkerCfg {
        daemon_image: "registry.example.invalid/codewire/daemon:main-4b5b65d-1783969421".into(),
        ..dev_cfg()
    };
    let error = render_configured_warm_pool(&tagged, shape, 2).unwrap_err();
    assert!(error.to_string().contains("digest-pinned"), "{error}");
}

#[test]
fn warm_pool_matches_golden_files() {
    let cfg = dev_cfg();
    let opts = shape_template_opts(
        &cfg,
        SYNTHETIC_WORKSPACE_IMAGE,
        &standard_runtime_profile_spec(&cfg),
        shapes()[0],
    );
    let objects = render_warm_pool(&cfg.sandbox_namespace, &opts, 2, false).unwrap();
    assert_eq!(
        objects.template,
        load_golden("warm-pool-sandboxtemplate.golden.json")
    );
    assert_eq!(
        objects.pool,
        load_golden("warm-pool-sandboxwarmpool.golden.json")
    );
}

/// The CEL list literal a policy variable or overlay value carries.
fn cel_names(literal: &str) -> Vec<String> {
    literal
        .trim()
        .trim_matches('"')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|name| name.trim().trim_matches('\'').to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

/// The template admission policy's volume rule, here for ConfigMaps: a
/// rendered pool template mounts only the policy's public roots ConfigMaps,
/// each only as its `ca.crt` (Kind e2e also admits its coordinator's extra
/// roots). A renderer that mounts another ConfigMap, or more of one, fails
/// here before a cluster denies every pool.
#[test]
fn rendered_pool_templates_pass_the_admission_volume_rule() {
    let manifests = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");
    let policy = std::fs::read_to_string(format!(
        "{manifests}deployments/k8s/orchestration/warm-pool-authz.yaml"
    ))
    .unwrap();
    let base = policy
        .split_once("- name: rootsConfigMaps\n")
        .and_then(|(_, rest)| rest.lines().next())
        .and_then(|line| line.trim().strip_prefix("expression: "))
        .map(cel_names)
        .expect("the template policy names its roots ConfigMaps");
    let kind =
        std::fs::read_to_string(format!("{manifests}tests/e2e/kind/kustomization.yaml")).unwrap();
    let kind = kind
        .split_once("path: /spec/variables/2/expression\n")
        .and_then(|(_, rest)| rest.lines().next())
        .and_then(|line| line.trim().strip_prefix("value: "))
        .map(cel_names)
        .expect("the Kind e2e overlay names its roots ConfigMaps");
    assert_eq!(base, ["codewire-orchestration-internal-roots"]);
    assert_eq!(
        kind,
        [
            "codewire-orchestration-internal-roots",
            codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_CONFIGMAP
        ]
    );
    for (cfg, allowed, mounted) in [
        (dev_cfg(), &base, 1),
        (
            SandboxWorkerCfg {
                coordinator_extra_roots: true,
                ..dev_cfg()
            },
            &kind,
            2,
        ),
    ] {
        for shape in shapes() {
            let rendered = render_configured_warm_pool(&cfg, shape, 1).unwrap();
            let volumes = rendered.template["spec"]["podTemplate"]["spec"]["volumes"]
                .as_array()
                .unwrap();
            let config_maps: Vec<&Value> = volumes
                .iter()
                .filter_map(|volume| volume.get("configMap"))
                .collect();
            assert_eq!(config_maps.len(), mounted);
            for config_map in config_maps {
                let fields = config_map.as_object().unwrap();
                assert!(
                    fields
                        .keys()
                        .all(|key| ["name", "items", "defaultMode"].contains(&key.as_str())),
                    "{config_map}"
                );
                assert!(
                    allowed
                        .iter()
                        .any(|name| config_map["name"] == name.as_str()),
                    "the policy refuses ConfigMap {}",
                    config_map["name"]
                );
                assert_eq!(
                    config_map["items"],
                    serde_json::json!([{ "key": "ca.crt", "path": "ca.crt" }])
                );
            }
        }
    }
}
