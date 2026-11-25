//! Warm-pool rendering from cluster configuration and a shape alone
//! (Program #2238 C1).

use super::*;
use crate::sandbox::canonical_workspace_runtime_image;
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
        dedicated_cpu: false,
        systemd_workspace: false,
        systemd_environments_enabled: false,
        runtime_profile: "commodity".into(),
        never_ran: false,
        external_cleanup_completed_at: None,
        cpu_millicores: i32::try_from(shape.cpu_millicores).unwrap(),
        memory_mb: i32::try_from(shape.memory_mib).unwrap(),
        disk_gb: i32::try_from(shape.disk_gib).unwrap(),
        source_snapshot_id: None,
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
    // Kind's test deployment also sets the Codex login check period (#3852).
    for (ratio, codex_period) in [("1", None), ("2", None), ("1", Some(30))] {
        let cfg = SandboxWorkerCfg {
            cpu_sharing_ratio: crate::sandbox::template::CpuSharingRatio::parse(Some(ratio))
                .unwrap(),
            codex_login_check_period_seconds: codex_period,
            ..dev_cfg()
        };
        for shape in shapes() {
            let pool = render_configured_warm_pool(&cfg, shape, 2).unwrap();
            for env in [environment(shape), environment_with_selection(shape)] {
                let opts = environment_opts(&cfg, &env);
                assert!(!opts.workspace_binding_url.is_empty());
                let rendered = render_sandbox_template(SANDBOX_NAMESPACE, &opts);
                assert_eq!(
                    rendered["spec"],
                    crate::sandbox::warm_pool::without_revision_marker(&pool.template["spec"]),
                    "{shape:?} at {ratio}:1, Codex login period {codex_period:?}"
                );
            }
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

/// codewire#3626 condition 4: the template admits orchestration to a
/// member's 7777 and 2222 from birth, which is safe only while nothing in an
/// unbound member listens. So every pool renders exactly the canonical
/// first-party image under the managed supervisor, beside at most the
/// platform keepalive (this test configuration's canonical repository, like
/// Dev's and Production's, is not a `codewiresh/` one, so it renders the
/// keepalive), and a workload entrypoint is refused outright.
#[test]
fn every_warm_pool_runs_only_the_canonical_image_and_the_platform_keepalive() {
    let keepalive = crate::sandbox::template::WORKSPACE_KEEPALIVE_COMMAND.map(str::to_owned);
    let diagnostic = SandboxWorkerCfg {
        runtime_profile: RUNTIME_PROFILE_RUNC.into(),
        allow_diagnostic_runtime: true,
        ..dev_cfg()
    };
    let mut rendered = 0;
    for cfg in [dev_cfg(), diagnostic] {
        for shape in shapes() {
            let opts = warm_pool_template_opts(&cfg, shape).unwrap();
            assert_eq!(opts.image, canonical_workspace_runtime_image());
            assert!(
                opts.image_command.is_empty() || opts.image_command == keepalive,
                "{shape:?}: {:?}",
                opts.image_command
            );
            let objects = render_configured_warm_pool(&cfg, shape, 1).unwrap();
            let containers = objects.template["spec"]["podTemplate"]["spec"]["containers"]
                .as_array()
                .unwrap()
                .clone();
            let workspace = containers
                .iter()
                .find(|container| container["name"] == "workspace")
                .unwrap();
            assert_eq!(workspace["image"], canonical_workspace_runtime_image());
            let command = workspace["command"][2].as_str().unwrap();
            assert!(command.contains("/codewire/bin/cw __hosted-daemon"));
            if opts.image_command.is_empty() {
                assert!(!command.contains("workload_pid"), "{shape:?}: {command}");
            } else {
                assert!(
                    command.contains("(exec 'sleep' 'infinity')"),
                    "{shape:?}: {command}"
                );
            }
            rendered += 1;
        }
    }
    assert_eq!(rendered, 4);

    // A custom image never pools, and neither does any workload entrypoint.
    let cfg = dev_cfg();
    let custom = shape_template_opts(
        &cfg,
        "registry.example.invalid/custom/workspace@sha256:4444444444444444444444444444444444444444444444444444444444444444",
        &standard_runtime_profile_spec(&cfg),
        shapes()[0],
    );
    assert_eq!(custom.image_command, keepalive);
    for command in [
        vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "nc -l 2222".to_owned(),
        ],
        vec!["sleep".to_owned()],
        vec!["sleep".to_owned(), "infinity".to_owned(), "&".to_owned()],
        vec!["/usr/sbin/sshd".to_owned(), "-D".to_owned()],
    ] {
        let entrypoint = TemplateOpts {
            image_command: command.clone(),
            ..warm_pool_template_opts(&cfg, shapes()[0]).unwrap()
        };
        let error = render_warm_pool(&cfg.sandbox_namespace, &entrypoint, 1, false).unwrap_err();
        assert!(
            error.to_string().contains("never a workload entrypoint"),
            "{command:?}: {error}"
        );
    }
}

/// Hosted egress as a Dev-shaped deployment sets it (#4000), with neutral
/// gateway names; the broker golden and the admission proof use these values.
fn broker_egress() -> crate::sandbox::template::HostedEgressTemplate {
    crate::egress::gateway_check::assume_verified();
    crate::sandbox::template::HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: "2".into(),
        gateway: crate::sandbox::template::GatewayPeer {
            namespace: "gateway-proxies".into(),
            gateway_name: "public".into(),
            gateway_namespace: "gateway".into(),
            port: 10443,
        },
        derp_tls_port: 8443,
        gateway_addr: "10.44.0.43:443".into(),
        derp_addr: "derp.codewire-dev.sh=10.44.0.84:8443".into(),
        cluster_dns_ip: "10.44.0.10".into(),
    }
}

/// The broker-mode pool template (#4000 P5): what the warm-pool template
/// admission policy's broker arm admits. The scratch Kind proof of that
/// policy applies this file.
#[test]
fn a_broker_mode_warm_pool_matches_its_golden_file() {
    let cfg = dev_cfg();
    let mut opts = shape_template_opts(
        &cfg,
        SYNTHETIC_WORKSPACE_IMAGE,
        &standard_runtime_profile_spec(&cfg),
        shapes()[0],
    );
    opts.hosted_egress = Some(broker_egress());
    let objects = render_warm_pool(&cfg.sandbox_namespace, &opts, 2, false).unwrap();
    crate::test_golden::assert_golden(
        "warm-pool-broker-sandboxtemplate.golden.json",
        &objects.template,
    );
}

/// The template admission policy's broker arm (#4000) names exactly what the
/// broker rendering adds: its two workspace variables, the egress token's
/// audience, the TUN init's command and every egress peer with its Pod labels
/// and port. A renderer change on either side fails here before a cluster
/// denies every broker pool.
#[test]
fn the_admission_policy_names_the_broker_rendering() {
    let manifests = concat!(env!("CARGO_MANIFEST_DIR"), "/../../");
    let policy = std::fs::read_to_string(format!(
        "{manifests}deployments/k8s/orchestration/warm-pool-authz.yaml"
    ))
    .unwrap();
    let literal = |name: &str| {
        policy
            .split_once(&format!("- name: {name}\n"))
            .and_then(|(_, rest)| rest.lines().next())
            .and_then(|line| line.trim().strip_prefix("expression: "))
            .map(cel_names)
            .unwrap_or_else(|| panic!("the template policy names {name}"))
    };
    let cfg = dev_cfg();
    let mut opts = shape_template_opts(
        &cfg,
        SYNTHETIC_WORKSPACE_IMAGE,
        &standard_runtime_profile_spec(&cfg),
        shapes()[0],
    );
    let server = opts.server_namespace.clone();
    let today = render_warm_pool(&cfg.sandbox_namespace, &opts, 2, false).unwrap();
    opts.hosted_egress = Some(broker_egress());
    let broker = render_warm_pool(&cfg.sandbox_namespace, &opts, 2, false).unwrap();
    let pod = |template: &Value| template["spec"]["podTemplate"]["spec"].clone();
    let workspace_env = |template: &Value| -> Vec<String> {
        pod(template)["containers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|container| container["name"] == "workspace")
            .flat_map(|container| container["env"].as_array().cloned().unwrap_or_default())
            .map(|variable| variable["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let before = workspace_env(&today.template);
    let added: Vec<String> = workspace_env(&broker.template)
        .into_iter()
        .filter(|name| !before.contains(name))
        .collect();
    assert_eq!(literal("brokerEnvironment"), added);
    assert_eq!(
        literal("brokerAudiences"),
        [codewire_daemon_proto::EGRESS_TOKEN_AUDIENCE]
    );
    assert!(policy.contains(&format!(
        "c.command == [{}]",
        crate::sandbox::template::HOSTED_EGRESS_TUN_COMMAND
            .iter()
            .map(|part| format!("'{part}'"))
            .collect::<Vec<_>>()
            .join(", ")
    )));
    assert!(policy.contains(&format!(
        "c.name != '{}'",
        crate::sandbox::template::HOSTED_EGRESS_TUN_CONTAINER
    )));
    // The netstack is the only nameserver, as rendered.
    let dns = &pod(&broker.template)["dnsConfig"];
    assert_eq!(pod(&broker.template)["dnsPolicy"], "None");
    assert_eq!(dns["searches"], serde_json::json!([]));
    assert!(policy.contains(&format!(
        "variables.pod.dnsConfig.nameservers == ['{}']",
        dns["nameservers"][0].as_str().unwrap()
    )));
    assert_eq!(dns["nameservers"].as_array().unwrap().len(), 1);
    // Each rendered egress peer is one line of the policy's peer list: its
    // port and each of its Pod labels, and no other label.
    let rules = broker.template["spec"]["networkPolicy"]["egress"]
        .as_array()
        .unwrap()
        .clone();
    assert!(!rules.is_empty());
    for rule in &rules {
        for peer in rule["to"].as_array().unwrap() {
            let namespace = peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                .as_str()
                .unwrap();
            let labels = peer["podSelector"]["matchLabels"].as_object().unwrap();
            for port in rule["ports"].as_array().unwrap() {
                let port = format!("'{}/{}'", port["protocol"].as_str().unwrap(), port["port"]);
                let line = if namespace == server {
                    policy
                        .lines()
                        .find(|line| {
                            line.contains("[variables.serverNamespace, ") && line.contains(&port)
                        })
                        .unwrap_or_else(|| panic!("the policy has no server peer on {port}"))
                        .to_owned()
                } else {
                    // The gateway's proxies come from the deployment's param.
                    assert_eq!(namespace, "gateway-proxies");
                    assert_eq!(port, "'TCP/10443'");
                    continue;
                };
                assert_eq!(line.matches("=").count(), labels.len(), "{line}");
                for (key, value) in labels {
                    assert!(
                        line.contains(&format!("'{key}={}'", value.as_str().unwrap())),
                        "{line} lacks {key}"
                    );
                }
            }
        }
    }
    // The gateway peer's two label keys are the renderer's.
    let gateway = rules
        .iter()
        .flat_map(|rule| rule["to"].as_array().unwrap().clone())
        .find(|peer| {
            peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                == "gateway-proxies"
        })
        .expect("the gateway peer");
    for key in gateway["podSelector"]["matchLabels"]
        .as_object()
        .unwrap()
        .keys()
    {
        assert!(
            policy.contains(&format!("'{key}=' + string(params.data[")),
            "{key}"
        );
    }
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
    crate::test_golden::assert_golden("warm-pool-sandboxtemplate.golden.json", &objects.template);
    crate::test_golden::assert_golden("warm-pool-sandboxwarmpool.golden.json", &objects.pool);
    // Policy drift runs main's trusted Pod builder, which still lists this
    // golden. It stays, the same template, until that builder stops naming
    // it (#4026).
    crate::test_golden::assert_golden(
        "warm-pool-subfolder-sandboxtemplate.golden.json",
        &objects.template,
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

/// A pool member's Pod spec: its golden template as stored, plus the
/// workspace claim the controller adds, and the pool rendering it came from.
fn golden_member() -> (Value, TemplateOpts) {
    let cfg = dev_cfg();
    let rendering = shape_template_opts(
        &cfg,
        SYNTHETIC_WORKSPACE_IMAGE,
        &standard_runtime_profile_spec(&cfg),
        shapes()[0],
    );
    let path = format!(
        "{}/tests/fixtures/sandbox/warm-pool-sandboxtemplate.golden.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let template: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut spec = template["spec"]["podTemplate"]["spec"].clone();
    spec["volumes"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "name": "workspace",
            "persistentVolumeClaim": { "claimName": "workspace-sandbox-a" },
        }));
    (spec, rendering)
}

fn container_index(spec: &Value, field: &str, name: &str) -> usize {
    spec[field]
        .as_array()
        .unwrap()
        .iter()
        .position(|container| container["name"] == name)
        .unwrap()
}

/// #3628 PR 5c, cw-confidential's condition 3: the golden pool member is
/// isolated as rendered, and each property the check guards, broken alone,
/// is refused with its path, whatever the driver's pool verdict.
#[test]
fn a_pool_member_is_isolated_exactly_as_its_rendering() {
    use crate::worker::workspace_binding::checks::pool_member_isolated;
    use serde_json::json;

    let (golden, wanted) = golden_member();
    assert_eq!(pool_member_isolated(&golden, &wanted), Ok(()));
    let volumes = golden["volumes"].as_array().unwrap().len();
    let token = golden["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|volume| volume["name"] == "workspace-binding-identity")
        .unwrap();
    let workspace = container_index(&golden, "containers", "workspace");
    let dind = container_index(&golden, "containers", "dind");
    let mount = container_index(&golden, "initContainers", "mount-workspace");
    type Break = Box<dyn Fn(&mut Value)>;
    let set = |path: &'static str, value: Value| -> Break {
        Box::new(move |spec: &mut Value| *spec.pointer_mut(path).unwrap() = value.clone())
    };
    let insert = |key: &'static str, value: Value| -> Break {
        Box::new(move |spec: &mut Value| spec[key] = value.clone())
    };
    let volume = |value: Value| -> Break {
        Box::new(move |spec: &mut Value| {
            spec["volumes"].as_array_mut().unwrap().push(value.clone())
        })
    };
    let context = |field: &'static str, index: usize, key: &'static str, value: Value| -> Break {
        Box::new(move |spec: &mut Value| {
            spec[field][index]["securityContext"][key] = value.clone();
        })
    };
    let cases: Vec<(&str, Break, String)> = vec![
        (
            "another runtime class",
            set("/runtimeClassName", json!("runc")),
            "/runtimeClassName".into(),
        ),
        (
            "no runtime class",
            Box::new(|spec: &mut Value| {
                spec.as_object_mut().unwrap().remove("runtimeClassName");
            }),
            "/runtimeClassName".into(),
        ),
        (
            "an automounted token",
            set("/automountServiceAccountToken", json!(true)),
            "/automountServiceAccountToken".into(),
        ),
        (
            "service links",
            set("/enableServiceLinks", json!(true)),
            "/enableServiceLinks".into(),
        ),
        (
            "host network",
            insert("hostNetwork", json!(true)),
            "/hostNetwork".into(),
        ),
        (
            "host PID",
            insert("hostPID", json!(true)),
            "/hostPID".into(),
        ),
        (
            "host IPC",
            insert("hostIPC", json!(true)),
            "/hostIPC".into(),
        ),
        (
            "a shared process namespace",
            insert("shareProcessNamespace", json!(true)),
            "/shareProcessNamespace".into(),
        ),
        (
            "an ephemeral container",
            insert("ephemeralContainers", json!([{"name": "debug"}])),
            "/ephemeralContainers".into(),
        ),
        (
            "a root Pod",
            set("/securityContext/runAsUser", json!(0)),
            "/securityContext/runAsUser".into(),
        ),
        (
            "a root file group",
            set("/securityContext/fsGroup", json!(0)),
            "/securityContext/fsGroup".into(),
        ),
        (
            "a root supplemental group",
            Box::new(|spec: &mut Value| {
                spec["securityContext"]["supplementalGroups"] = json!([0]);
            }),
            "/securityContext/supplementalGroups".into(),
        ),
        (
            "a sysctl",
            Box::new(|spec: &mut Value| {
                spec["securityContext"]["sysctls"] =
                    json!([{"name": "kernel.msgmax", "value": "1"}]);
            }),
            "/securityContext/sysctls".into(),
        ),
        (
            "a secret volume",
            volume(json!({"name": "s", "secret": {"secretName": "x"}})),
            format!("/volumes/{volumes}/secret"),
        ),
        (
            "a host path",
            volume(json!({"name": "h", "hostPath": {"path": "/"}})),
            format!("/volumes/{volumes}/hostPath"),
        ),
        (
            "an inline CSI volume",
            volume(json!({"name": "c", "csi": {"driver": "x"}})),
            format!("/volumes/{volumes}/csi"),
        ),
        (
            "an ephemeral volume",
            volume(json!({"name": "e", "ephemeral": {}})),
            format!("/volumes/{volumes}/ephemeral"),
        ),
        (
            "another image",
            volume(
                json!({"name": "i", "image": {"reference": "registry.example.invalid/other@sha256:9"}}),
            ),
            format!("/volumes/{volumes}/image"),
        ),
        (
            "two sources",
            volume(json!({"name": "t", "emptyDir": {}, "configMap": {"name": "x"}})),
            format!("/volumes/{volumes}"),
        ),
        (
            "another claim",
            volume(json!({"name": "other", "persistentVolumeClaim": {"claimName": "x"}})),
            format!("/volumes/{volumes}/persistentVolumeClaim"),
        ),
        (
            "a projected secret",
            Box::new(move |spec: &mut Value| {
                spec["volumes"][token]["projected"]["sources"] = json!([{"secret": {"name": "x"}}]);
            }),
            format!("/volumes/{token}/projected/sources/0"),
        ),
        (
            "a token of another audience",
            Box::new(move |spec: &mut Value| {
                spec["volumes"][token]["projected"]["sources"][0]["serviceAccountToken"]["audience"] =
                    json!("https://kubernetes.default.svc");
            }),
            format!("/volumes/{token}/projected/sources/0"),
        ),
        (
            "a privileged workspace",
            context("containers", workspace, "privileged", json!(true)),
            format!("/containers/{workspace}/securityContext"),
        ),
        (
            "a root workspace",
            context("containers", workspace, "runAsUser", json!(0)),
            format!("/containers/{workspace}/securityContext"),
        ),
        (
            "DinD renamed",
            Box::new(move |spec: &mut Value| {
                spec["containers"][dind]["name"] = json!("helper");
            }),
            format!("/containers/{dind}/securityContext"),
        ),
        (
            "another image as DinD",
            Box::new(move |spec: &mut Value| {
                spec["containers"][dind]["image"] = json!(SYNTHETIC_WORKSPACE_IMAGE);
            }),
            format!("/containers/{dind}/securityContext"),
        ),
        (
            "another image as mount-workspace",
            Box::new(move |spec: &mut Value| {
                spec["initContainers"][mount]["image"] = json!(SYNTHETIC_WORKSPACE_IMAGE);
            }),
            format!("/initContainers/{mount}/securityContext"),
        ),
        (
            "an added capability",
            context(
                "containers",
                workspace,
                "capabilities",
                json!({"add": ["NET_ADMIN"]}),
            ),
            format!("/containers/{workspace}/securityContext/capabilities/add"),
        ),
        (
            "privilege escalation",
            context(
                "containers",
                workspace,
                "allowPrivilegeEscalation",
                json!(true),
            ),
            format!("/containers/{workspace}/securityContext/allowPrivilegeEscalation"),
        ),
        (
            "an unmasked proc",
            context("containers", workspace, "procMount", json!("Unmasked")),
            format!("/containers/{workspace}/securityContext/procMount"),
        ),
        (
            "a host port",
            Box::new(move |spec: &mut Value| {
                spec["containers"][workspace]["ports"] =
                    json!([{"containerPort": 2222, "hostPort": 2222}]);
            }),
            format!("/containers/{workspace}/ports/0/hostPort"),
        ),
        (
            "a token mounted into DinD",
            Box::new(move |spec: &mut Value| {
                spec["containers"][dind]["volumeMounts"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": "workspace-binding-identity", "mountPath": "/t"}));
            }),
            format!(
                "/containers/{dind}/volumeMounts/{}",
                golden["containers"][dind]["volumeMounts"]
                    .as_array()
                    .unwrap()
                    .len()
            ),
        ),
    ];
    for (label, change, path) in cases {
        let mut spec = golden.clone();
        change(&mut spec);
        assert_eq!(pool_member_isolated(&spec, &wanted), Err(path), "{label}");
    }

    // A confidential pool is never one, whatever its member looks like.
    // Its member carries the confidential class, so only the profile check
    // can refuse it.
    let mut confidential = wanted.clone();
    confidential.runtime_profile = crate::sandbox::template::RUNTIME_PROFILE_CONFIDENTIAL.into();
    let mut member = golden.clone();
    member["runtimeClassName"] = json!(confidential.runtime_profile_spec().runtime_class_name);
    assert_eq!(
        pool_member_isolated(&member, &confidential),
        Err("/runtimeClassName".to_owned())
    );
}

/// #4000: a broker-mode pool member, rendered as its pool stores it, is
/// isolated. Its TUN init container and egress token are admitted only while
/// hosted egress is on, the TUN container only as root from the support image,
/// and the egress token only into the workspace container.
#[test]
fn a_broker_mode_pool_member_is_admitted_only_with_hosted_egress() {
    use crate::sandbox::template::{HOSTED_EGRESS_TUN_CONTAINER, render_sandbox_template};
    use crate::worker::workspace_binding::checks::pool_member_isolated;
    use serde_json::json;

    let (_, mut wanted) = golden_member();
    wanted.hosted_egress = Some(broker_egress());
    let template = render_sandbox_template("dev-sandboxes", &wanted);
    let mut spec = template["spec"]["podTemplate"]["spec"].clone();
    spec["volumes"].as_array_mut().unwrap().push(json!({
        "name": "workspace",
        "persistentVolumeClaim": { "claimName": "workspace-sandbox-a" },
    }));
    assert_eq!(pool_member_isolated(&spec, &wanted), Ok(()));

    // The same member against a rendering without hosted egress: its egress
    // token is the first thing refused.
    let off = TemplateOpts {
        hosted_egress: None,
        ..wanted.clone()
    };
    let refused = pool_member_isolated(&spec, &off).unwrap_err();
    assert!(refused.starts_with("/volumes/"), "{refused}");

    // The TUN container runs as root only from the support image.
    let tun = container_index(&spec, "initContainers", HOSTED_EGRESS_TUN_CONTAINER);
    let mut other_image = spec.clone();
    other_image["initContainers"][tun]["image"] = json!("registry.example.invalid/other:tag");
    assert_eq!(
        pool_member_isolated(&other_image, &wanted),
        Err(format!("/initContainers/{tun}/securityContext"))
    );
    // ...with its one command, nothing appended, and nothing mounted over the
    // image's own `cw`, such as the daemon volume the workspace can write.
    for (key, value) in [
        (
            "command",
            json!(["/codewire/bin/cw", "__hosted-egress-tun"]),
        ),
        ("args", json!(["--owner-uid", "0"])),
        (
            "volumeMounts",
            json!([{ "name": "codewire-bin", "mountPath": "/usr/local/bin" }]),
        ),
        ("env", json!([{ "name": "LD_PRELOAD", "value": "/x.so" }])),
    ] {
        let mut changed = spec.clone();
        changed["initContainers"][tun][key] = value;
        assert_eq!(
            pool_member_isolated(&changed, &wanted),
            Err(format!("/initContainers/{tun}/securityContext")),
            "{key}"
        );
    }
    // ...and one more mount beside the TUN device's is refused too.
    let mut extra = spec.clone();
    extra["initContainers"][tun]["volumeMounts"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "name": "codewire-bin", "mountPath": "/codewire" }));
    assert_eq!(
        pool_member_isolated(&extra, &wanted),
        Err(format!("/initContainers/{tun}/securityContext"))
    );
    // The TUN device's volume is memory-backed exactly as rendered: a node
    // written to a disk-backed emptyDir would sit on the node's filesystem.
    let devnet = spec["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|volume| volume["name"] == "egress-devnet")
        .expect("the TUN device's volume");
    for shape in [
        json!({}),
        json!({ "medium": "Memory" }),
        json!({ "medium": "Memory", "sizeLimit": "1Gi" }),
    ] {
        let mut disk = spec.clone();
        disk["volumes"][devnet]["emptyDir"] = shape.clone();
        assert_eq!(
            pool_member_isolated(&disk, &wanted),
            Err(format!("/volumes/{devnet}")),
            "{shape}"
        );
    }
    // It is mounted at exactly /dev/net, by the workspace container and the
    // TUN init only.
    let workspace = container_index(&spec, "containers", "workspace");
    let mount = spec["containers"][workspace]["volumeMounts"]
        .as_array()
        .unwrap()
        .iter()
        .position(|mount| mount["name"] == "egress-devnet")
        .expect("the workspace's TUN device mount");
    for changed_mount in [
        json!({ "name": "egress-devnet", "mountPath": "/dev/net", "subPath": "x" }),
        json!({ "name": "egress-devnet", "mountPath": "/dev" }),
        json!({ "name": "egress-devnet", "mountPath": "/dev/net", "mountPropagation": "HostToContainer" }),
    ] {
        let mut changed = spec.clone();
        changed["containers"][workspace]["volumeMounts"][mount] = changed_mount.clone();
        assert_eq!(
            pool_member_isolated(&changed, &wanted),
            Err(format!("/containers/{workspace}/volumeMounts/{mount}")),
            "{changed_mount}"
        );
    }
    let dind = container_index(&spec, "containers", "dind");
    let mut shared = spec.clone();
    let position = shared["containers"][dind]["volumeMounts"]
        .as_array()
        .map_or(0, Vec::len);
    shared["containers"][dind]["volumeMounts"] = json!(
        shared["containers"][dind]["volumeMounts"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .chain([json!({ "name": "egress-devnet", "mountPath": "/dev/net" })])
            .collect::<Vec<_>>()
    );
    assert_eq!(
        pool_member_isolated(&shared, &wanted),
        Err(format!("/containers/{dind}/volumeMounts/{position}"))
    );
    // ...and only as an init container.
    let mut moved = spec.clone();
    let container = moved["initContainers"].as_array_mut().unwrap().remove(tun);
    let position = moved["containers"].as_array().unwrap().len();
    moved["containers"].as_array_mut().unwrap().push(container);
    assert_eq!(
        pool_member_isolated(&moved, &wanted),
        Err(format!("/containers/{position}/securityContext"))
    );
    // Hosted egress on a runtime that is not a VM is refused outright.
    let runc = TemplateOpts {
        runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_RUNC.into(),
        ..wanted.clone()
    };
    assert_eq!(
        pool_member_isolated(&spec, &runc),
        Err("/runtimeClassName".to_owned())
    );

    // The egress token reaches the workspace container only.
    let dind = container_index(&spec, "containers", "dind");
    let mut leaked = spec.clone();
    let mounts = leaked["containers"][dind]["volumeMounts"]
        .as_array_mut()
        .unwrap();
    let position = mounts.len();
    mounts.push(json!({ "name": "workspace-egress-identity", "mountPath": "/t" }));
    assert_eq!(
        pool_member_isolated(&leaked, &wanted),
        Err(format!("/containers/{dind}/volumeMounts/{position}"))
    );
}

/// #6070, cw-security's amendment 1: a pool member's first bind admits the
/// broker additions only when its own Sandbox is whole broker, judged by the
/// pool rendered in that mode, with the switch on or off. A direct or hollow
/// member with any one of them is refused either way.
#[test]
fn a_members_broker_additions_follow_its_own_mode_whatever_the_switch_says() {
    use crate::egress::own_mode::{HostedEgress, SandboxMode};
    use crate::runtime::kubernetes::rendering::KubernetesRenderConfig;
    use crate::sandbox::template::{
        HOSTED_EGRESS_DEVNET_VOLUME, HOSTED_EGRESS_TUN_CONTAINER, render_sandbox_template,
    };
    use crate::worker::workspace_binding::checks::pool_member_isolated;
    use serde_json::json;

    let shape = shapes()[0];
    let config = |enabled| KubernetesRenderConfig {
        hosted_egress: HostedEgress {
            enabled,
            broker: Some(broker_egress()),
        },
        ..KubernetesRenderConfig::from(&dev_cfg())
    };
    let member_spec = |opts: &TemplateOpts| {
        let mut spec =
            render_sandbox_template(SANDBOX_NAMESPACE, opts)["spec"]["podTemplate"]["spec"].clone();
        spec["volumes"].as_array_mut().unwrap().push(json!({
            "name": "workspace",
            "persistentVolumeClaim": { "claimName": "workspace-sandbox-a" },
        }));
        spec
    };
    let broker_spec = member_spec(&config(true).pool(shape).unwrap());
    let direct_spec = member_spec(&config(false).pool(shape).unwrap());
    let mode = |broker| SandboxMode {
        name: "cw-pool-member".into(),
        broker,
    };
    // Each broker addition alone, on a direct member's spec.
    let tun = container_index(&broker_spec, "initContainers", HOSTED_EGRESS_TUN_CONTAINER);
    let mut with_tun = direct_spec.clone();
    with_tun["initContainers"]
        .as_array_mut()
        .unwrap()
        .push(broker_spec["initContainers"][tun].clone());
    let mut with_devnet = direct_spec.clone();
    with_devnet["volumes"].as_array_mut().unwrap().push(
        broker_spec["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|volume| volume["name"] == HOSTED_EGRESS_DEVNET_VOLUME)
            .unwrap()
            .clone(),
    );
    let mut with_token = direct_spec.clone();
    with_token["volumes"].as_array_mut().unwrap().push(json!({
        "name": "egress-token",
        "projected": { "sources": [{ "serviceAccountToken": {
            "audience": codewire_daemon_proto::EGRESS_TOKEN_AUDIENCE,
            "expirationSeconds": 3600,
            "path": "token",
        }}]},
    }));
    for enabled in [true, false] {
        let config = config(enabled);
        let whole = config.pool_of(shape, &mode(true)).unwrap();
        assert_eq!(whole.hosted_egress, Some(broker_egress()), "{enabled}");
        assert_eq!(
            pool_member_isolated(&broker_spec, &whole),
            Ok(()),
            "{enabled}"
        );
        let direct = config.pool_of(shape, &mode(false)).unwrap();
        assert_eq!(direct.hosted_egress, None, "{enabled}");
        assert_eq!(
            pool_member_isolated(&direct_spec, &direct),
            Ok(()),
            "{enabled}"
        );
        for (what, spec) in [
            ("every addition", &broker_spec),
            ("the TUN init", &with_tun),
            ("the TUN volume", &with_devnet),
            ("the egress token", &with_token),
        ] {
            assert!(
                pool_member_isolated(spec, &direct).is_err(),
                "{enabled}: a direct member with {what} was admitted"
            );
        }
    }
    // Without the broker settings a broker member is refused, never judged
    // direct.
    let error = KubernetesRenderConfig::from(&dev_cfg())
        .pool_of(shape, &mode(true))
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<crate::egress::own_mode::BrokerSettingsAbsent>()
            .is_some(),
        "{error:#}"
    );
}

/// A Dev-shaped `standard` configuration whose disk boots the canonical
/// workspace image (#5602).
fn standard_cfg() -> SandboxWorkerCfg {
    let (_, digest) = canonical_workspace_runtime_image()
        .rsplit_once('@')
        .unwrap();
    SandboxWorkerCfg {
        runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_STANDARD.into(),
        hosted_egress: crate::egress::own_mode::HostedEgress::on(broker_egress()),
        standard_runtime: crate::sandbox::template::StandardRuntime::parse(
            "registry.example.invalid/codewire/pod-runtime@sha256:4444444444444444444444444444444444444444444444444444444444444444",
            &format!(
                "registry.example.invalid/codewire/workspace-disk@sha256:5555555555555555555555555555555555555555555555555555555555555555 \
                 6666666666666666666666666666666666666666666666666666666666666666 \
                 77777777777777777777777777777777 \
                 registry.example.invalid/codewire/workspace@{digest}"
            ),
        )
        .unwrap(),
        ..dev_cfg()
    }
}

/// #5602, cw-security's conditions on a `standard` member's first bind: it
/// is admitted exactly as its pool renders it, with its workspace disk as its
/// one image volume; a disk of another reference, a second disk, a support
/// image volume, or the same member against a `commodity` rendering is
/// refused.
#[test]
fn a_standard_pool_member_is_admitted_only_with_its_exact_disk() {
    use crate::worker::workspace_binding::checks::pool_member_isolated;
    use serde_json::json;

    let cfg = standard_cfg();
    let wanted = warm_pool_template_opts(&cfg, shapes()[0]).unwrap();
    assert_eq!(wanted.runtime_profile_spec().runtime_class_name, "standard");
    let template = render_sandbox_template(SANDBOX_NAMESPACE, &wanted);
    let mut spec = template["spec"]["podTemplate"]["spec"].clone();
    spec["volumes"].as_array_mut().unwrap().push(json!({
        "name": "workspace",
        "persistentVolumeClaim": { "claimName": "workspace-sandbox-a" },
    }));
    assert_eq!(pool_member_isolated(&spec, &wanted), Ok(()));

    let volumes = spec["volumes"].as_array().unwrap().clone();
    let disk = volumes
        .iter()
        .position(|volume| volume.get("image").is_some())
        .expect("the workspace disk");
    // Exactly the configured reference, and only as rendered.
    for (pointer, value) in [
        (
            "/image/reference",
            json!(
                "registry.example.invalid/codewire/workspace-disk@sha256:8888888888888888888888888888888888888888888888888888888888888888"
            ),
        ),
        ("/image/pullPolicy", json!("Always")),
        ("/name", json!("other-disk")),
    ] {
        let mut changed = spec.clone();
        *changed["volumes"][disk].pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            pool_member_isolated(&changed, &wanted),
            Err(format!("/volumes/{disk}/image")),
            "{pointer}"
        );
    }
    // It is the only image volume: neither a second copy of it nor the
    // support image's volume, which other profiles mount, is admitted.
    let mut twice = spec.clone();
    twice["volumes"]
        .as_array_mut()
        .unwrap()
        .push(volumes[disk].clone());
    assert_eq!(
        pool_member_isolated(&twice, &wanted),
        Err(format!("/volumes/{}", volumes.len()))
    );
    let mut support = spec.clone();
    support["volumes"].as_array_mut().unwrap().push(json!({
        "name": "codewire-bin",
        "image": { "reference": wanted.effective_support_image(), "pullPolicy": "IfNotPresent" },
    }));
    assert_eq!(
        pool_member_isolated(&support, &wanted),
        Err(format!("/volumes/{}/image", volumes.len()))
    );
    // Against a `commodity` rendering, its class is the first refusal.
    let commodity = warm_pool_template_opts(&dev_cfg(), shapes()[0]).unwrap();
    assert_eq!(
        pool_member_isolated(&spec, &commodity),
        Err("/runtimeClassName".to_owned())
    );
}

/// The `standard` pool template (#5602): what the warm-pool template
/// admission policy's standard arm admits. The scratch Kind proof of that
/// policy applies this file.
#[test]
fn a_standard_warm_pool_matches_its_golden_file() {
    let cfg = standard_cfg();
    let opts = warm_pool_template_opts(&cfg, shapes()[0]).unwrap();
    let objects = render_warm_pool(&cfg.sandbox_namespace, &opts, 2, false).unwrap();
    // A standard pool serves only the canonical workspace image, so its
    // rendering names the published pin, and its revision and name hash it.
    // The file names a synthetic digest and a zero revision instead, so a pin
    // bump changes no golden.
    let (_, canonical) = canonical_workspace_runtime_image()
        .rsplit_once('@')
        .unwrap();
    let (_, synthetic) = SYNTHETIC_WORKSPACE_IMAGE.rsplit_once('@').unwrap();
    let revision = objects.template["metadata"]["annotations"]["codewire.sh/pool-revision"]
        .as_str()
        .unwrap()
        .to_owned();
    let name = objects.template["metadata"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    let (shape, _) = name.rsplit_once('-').unwrap();
    let template: Value = serde_json::from_str(
        &serde_json::to_string(&objects.template)
            .unwrap()
            .replace(canonical, synthetic)
            .replace(&revision, &"0".repeat(64))
            .replace(&name, &format!("{shape}-00000000")),
    )
    .unwrap();
    crate::test_golden::assert_golden("warm-pool-standard-sandboxtemplate.golden.json", &template);
}

/// The template admission policy's standard pool arm (#5602) names exactly
/// the VM settings the standard pool rendering adds to the broker pool's
/// workspace. A renderer change on either side fails here before a cluster
/// denies every standard pool.
#[test]
fn the_admission_policy_names_the_standard_pool_rendering() {
    let policy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deployments/k8s/orchestration/warm-pool-authz.yaml"
    ))
    .unwrap();
    let mut named = policy
        .split_once("- name: standardPoolEnvironment\n")
        .and_then(|(_, rest)| rest.lines().next())
        .and_then(|line| line.trim().strip_prefix("expression: "))
        .map(cel_names)
        .expect("the template policy names standardPoolEnvironment");
    let workspace_env = |template: &Value| -> Vec<String> {
        template["spec"]["podTemplate"]["spec"]["containers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|container| container["name"] == "workspace")
            .flat_map(|container| container["env"].as_array().cloned().unwrap_or_default())
            .map(|variable| variable["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let cfg = standard_cfg();
    let standard = render_warm_pool(
        &cfg.sandbox_namespace,
        &warm_pool_template_opts(&cfg, shapes()[0]).unwrap(),
        2,
        false,
    )
    .unwrap();
    let mut broker_opts = shape_template_opts(
        &dev_cfg(),
        SYNTHETIC_WORKSPACE_IMAGE,
        &standard_runtime_profile_spec(&dev_cfg()),
        shapes()[0],
    );
    broker_opts.hosted_egress = Some(broker_egress());
    let broker = render_warm_pool(&cfg.sandbox_namespace, &broker_opts, 2, false).unwrap();
    let before = workspace_env(&broker.template);
    let mut added: Vec<String> = workspace_env(&standard.template)
        .into_iter()
        .filter(|name| !before.contains(name))
        .collect();
    named.sort();
    added.sort();
    assert_eq!(named, added);
}

/// #5602: a `standard` deployment pools only while its disk boots the
/// canonical image, since otherwise its canonical creates go to `commodity`
/// and adopt no member.
#[test]
fn a_standard_pool_needs_a_disk_of_the_canonical_image() {
    let mut cfg = standard_cfg();
    assert!(warm_pool_template_opts(&cfg, shapes()[0]).is_ok());
    cfg.standard_runtime = crate::sandbox::template::StandardRuntime::parse(
        "registry.example.invalid/codewire/pod-runtime@sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "registry.example.invalid/codewire/workspace-disk@sha256:5555555555555555555555555555555555555555555555555555555555555555 \
         6666666666666666666666666666666666666666666666666666666666666666 \
         77777777777777777777777777777777 \
         registry.example.invalid/codewire/workspace@sha256:9999999999999999999999999999999999999999999999999999999999999999",
    )
    .unwrap();
    let refused = warm_pool_template_opts(&cfg, shapes()[0])
        .unwrap_err()
        .to_string();
    assert!(refused.contains("does not boot the canonical"), "{refused}");
}
