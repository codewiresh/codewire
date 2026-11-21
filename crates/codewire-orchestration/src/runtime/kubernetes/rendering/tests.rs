use super::*;
use crate::runtime::RenderingIdentity;

const NAMESPACE: &str = "dev-sandboxes";
const ENVIRONMENT: &str = "3d6bb495-efac-419f-bf3a-91696e7c7ca4";

/// A deployment with every setting the workspace NetworkPolicy reads.
fn config() -> KubernetesRenderConfig {
    KubernetesRenderConfig {
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        server_namespace: "dev".into(),
        workspace_binding_url: "https://binding.dev.svc.cluster.local:8443".into(),
        ingress_namespace: "ingress".into(),
        ingress_pod_name: "ingress-nginx".into(),
        stun_host: "derp.example.invalid".into(),
        stun_port: 3478,
        direct_udp_lb_enabled: true,
        direct_udp_lb_ip: "192.0.2.10".into(),
        direct_udp_lb_port_start: 32000,
        direct_udp_lb_port_end: 32999,
        uses_runtime_transport_registry: true,
        network_policy_management: "Managed".into(),
        kata_coco_kbs_url: "https://kbs.example.invalid:8080".into(),
        confidential_workspace_storage_class: "confidential".into(),
        confidential_binding_roots_pem:
            "-----BEGIN CERTIFICATE-----\nroots\n-----END CERTIFICATE-----\n".into(),
        ..Default::default()
    }
}

fn intent(isolation: Isolation) -> RenderingIntent {
    RenderingIntent {
        image: "registry.example.invalid/custom/image:1".into(),
        template_base: "workspace".into(),
        isolation,
        dedicated_cpu: true,
        shape: WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 8192,
            disk_gib: 80,
        },
        identity: RenderingIdentity {
            environment_id: ENVIRONMENT.into(),
            organization_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
            operation_generation: 7,
            projection_selection_sha256: None,
            managed_credential_clients: Default::default(),
            source_snapshot_id: None,
            confidential_storage_manifest_uri: String::new(),
        },
    }
}

#[test]
fn the_policy_the_lockdown_check_expects_is_the_one_the_access_stack_applies() {
    for (config, isolation) in [
        (config(), Isolation::Standard),
        (config(), Isolation::Confidential),
        (
            KubernetesRenderConfig {
                direct_udp_lb_enabled: false,
                stun_host: String::new(),
                ..config()
            },
            Isolation::Standard,
        ),
    ] {
        // What `ensure_access_stack` renders: the environment's own options,
        // with the direct UDP port it allocates where the LoadBalancer is on.
        let mut applied = config.environment(&intent(isolation)).unwrap();
        if applied.direct_udp_lb_enabled {
            applied.direct_udp_lb_port = 32417;
        }
        assert_eq!(
            config.workspace_network_policy(NAMESPACE, ENVIRONMENT, isolation),
            Some(render_workspace_daemon_network_policy(NAMESPACE, &applied)),
            "{isolation:?}"
        );
    }
}

const SANDBOX_UID: &str = "51c208bf-0e29-452b-8d74-06d77da367a9";

#[test]
fn the_bridge_the_lockdown_check_expects_is_the_one_a_warm_claim_applies() {
    for (config, isolation) in [
        (config(), Isolation::Standard),
        (config(), Isolation::Confidential),
        (
            KubernetesRenderConfig {
                direct_udp_lb_enabled: false,
                stun_host: String::new(),
                ..config()
            },
            Isolation::Standard,
        ),
    ] {
        // What `ensure_warm_member_bridge` renders for a claimed member: the
        // environment's own options and the Sandbox UID its binding recorded.
        let mut applied = config.environment(&intent(isolation)).unwrap();
        if applied.direct_udp_lb_enabled {
            applied.direct_udp_lb_port = 32417;
        }
        let expected = render_warm_member_bridge(NAMESPACE, &applied, SANDBOX_UID).unwrap();
        let bridge = config
            .warm_member_bridge(NAMESPACE, ENVIRONMENT, isolation, SANDBOX_UID)
            .unwrap()
            .unwrap();
        assert_eq!(bridge, expected, "{isolation:?}");
        // cw-security, #4000: the bridge may add nothing to the environment's
        // own policy. It is that policy's ingress, exactly, and no egress.
        let own = config
            .workspace_network_policy(NAMESPACE, ENVIRONMENT, isolation)
            .unwrap();
        assert_eq!(
            bridge["spec"]["ingress"], own["spec"]["ingress"],
            "{isolation:?}"
        );
        assert_eq!(
            bridge["spec"]["policyTypes"],
            serde_json::json!(["Ingress"])
        );
        assert!(bridge["spec"].get("egress").is_none(), "{isolation:?}");
    }
}

#[test]
fn no_bridge_is_rendered_without_a_recorded_sandbox_or_managed_policies() {
    assert_eq!(
        config()
            .warm_member_bridge(NAMESPACE, ENVIRONMENT, Isolation::Standard, "")
            .unwrap(),
        None
    );
    let unmanaged = KubernetesRenderConfig {
        network_policy_management: "Unmanaged".into(),
        ..config()
    };
    assert_eq!(
        unmanaged
            .warm_member_bridge(NAMESPACE, ENVIRONMENT, Isolation::Standard, SANDBOX_UID)
            .unwrap(),
        None
    );
    assert!(
        config()
            .warm_member_bridge(NAMESPACE, ENVIRONMENT, Isolation::Standard, "not-a-uid")
            .is_err()
    );
}

#[test]
fn a_deployment_that_does_not_manage_network_policies_renders_none_to_compare() {
    let unmanaged = KubernetesRenderConfig {
        network_policy_management: "Unmanaged".into(),
        ..config()
    };
    assert_eq!(
        unmanaged.workspace_network_policy(NAMESPACE, ENVIRONMENT, Isolation::Standard),
        None
    );
}

/// The template policy the lockdown check expects (#4964) is the one a pool's
/// or an environment's template makes: its rules read only this configuration
/// and the runtime profile, never the shape or the environment.
#[test]
fn the_template_policy_the_lockdown_check_expects_is_every_templates() {
    const HASH: &str = "2f9c41ab";
    let config = config();
    let pool = config
        .pool(WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
        })
        .unwrap();
    assert_eq!(
        config.template_network_policy(Isolation::Standard, HASH),
        Some(render_template_network_policy(&pool, HASH))
    );
    for isolation in [Isolation::Standard, Isolation::Confidential] {
        let environment = config.environment(&intent(isolation)).unwrap();
        assert_eq!(
            config.template_network_policy(isolation, HASH),
            Some(render_template_network_policy(&environment, HASH)),
            "{isolation:?}"
        );
    }
    let unmanaged = KubernetesRenderConfig {
        network_policy_management: "Unmanaged".into(),
        ..config
    };
    assert_eq!(
        unmanaged.template_network_policy(Isolation::Standard, HASH),
        None
    );
}

fn broker(fence_revision: &str) -> HostedEgressTemplate {
    crate::egress::gateway_check::assume_verified();
    HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: fence_revision.into(),
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

fn fence_of(template: &serde_json::Value) -> Option<&str> {
    template
        .pointer("/spec/podTemplate/metadata/annotations/codewire.sh~1egress-fence-revision")
        .and_then(serde_json::Value::as_str)
}

/// With hosted egress on (#4000, item 3), every template on a VM runtime is
/// broker-mode, and the fence revision the deployment configures is the one
/// every pool and environment template carries.
#[test]
fn hosted_egress_on_makes_every_vm_template_broker_mode_with_the_configured_fence() {
    use crate::sandbox::template::render_sandbox_template;
    for revision in ["2", "3"] {
        let config = KubernetesRenderConfig {
            hosted_egress: Some(broker(revision)),
            ..config()
        };
        let pool = config
            .pool(WorkspaceShape {
                cpu_millicores: 2000,
                memory_mib: 4096,
                disk_gib: 20,
            })
            .unwrap();
        assert_eq!(pool.hosted_egress, Some(broker(revision)));
        assert_eq!(
            fence_of(&render_sandbox_template(NAMESPACE, &pool)),
            Some(revision)
        );
        for isolation in [Isolation::Standard, Isolation::Confidential] {
            let environment = config.environment(&intent(isolation)).unwrap();
            environment.validate_hosted_egress().unwrap();
            assert_eq!(
                fence_of(&render_sandbox_template(NAMESPACE, &environment)),
                Some(revision),
                "{isolation:?}"
            );
        }
    }
    // Off, nothing is broker-mode.
    let pool = config()
        .pool(WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
        })
        .unwrap();
    assert_eq!(pool.hosted_egress, None);
    assert_eq!(fence_of(&render_sandbox_template(NAMESPACE, &pool)), None);
}

#[test]
fn a_runtime_that_is_not_a_vm_never_renders_broker_mode() {
    let config = KubernetesRenderConfig {
        hosted_egress: Some(broker("2")),
        runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_RUNC.into(),
        allow_diagnostic_runtime: true,
        ..config()
    };
    let opts = config.shape(
        crate::sandbox::canonical_workspace_runtime_image(),
        &config.runtime_spec(Isolation::Standard),
        WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
        },
    );
    assert_eq!(opts.hosted_egress, None);
}

/// `SPEC.md` section 4: a deployment on `standard` runs the workspace image
/// its disk was built from in its own VM runtime; an environment that names
/// any other image is created on `commodity`; and `standard` renders no warm
/// pool yet.
#[test]
fn a_standard_deployment_runs_the_disks_workspace_image_on_standard_and_any_other_on_commodity() {
    let canonical = crate::sandbox::canonical_workspace_runtime_image();
    let (_, digest) = canonical.rsplit_once('@').unwrap();
    let runtime = crate::sandbox::template::StandardRuntime::parse(
        "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        &format!(
            "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 \
             3333333333333333333333333333333333333333333333333333333333333333 \
             44444444444444444444444444444444 \
             registry.example.invalid/codewire/workspace@{digest}"
        ),
    )
    .unwrap();
    let config = KubernetesRenderConfig {
        runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
        hosted_egress: Some(broker("2")),
        standard_runtime: runtime.clone(),
        ..config()
    };
    // The disk names its workspace image at another registry than the one
    // environments name it at; the digest decides.
    let workspace = config
        .environment(&RenderingIntent {
            image: canonical.into(),
            ..intent(Isolation::Standard)
        })
        .unwrap();
    assert_eq!(
        workspace.runtime_profile_spec().runtime_class_name,
        "standard"
    );
    assert_eq!(workspace.standard_runtime, runtime);
    assert!(
        config
            .check_runtime_profile(&intent(Isolation::Standard))
            .is_ok()
    );

    // A workspace pin moved on without the disk republished: the VM would
    // boot the old image, so the environment goes to commodity.
    let stale_disk = KubernetesRenderConfig {
        standard_runtime: crate::sandbox::template::StandardRuntime::parse(
            "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 \
             3333333333333333333333333333333333333333333333333333333333333333 \
             44444444444444444444444444444444 \
             registry.example.invalid/codewire/workspace@sha256:5555555555555555555555555555555555555555555555555555555555555555",
        )
        .unwrap(),
        ..config.clone()
    }
    .environment(&RenderingIntent {
        image: canonical.into(),
        ..intent(Isolation::Standard)
    })
    .unwrap();
    assert_eq!(
        stale_disk.runtime_profile_spec().profile,
        RUNTIME_PROFILE_COMMODITY
    );
    assert_eq!(stale_disk.standard_runtime, None);

    let own_image = config.environment(&intent(Isolation::Standard)).unwrap();
    assert_eq!(
        own_image.runtime_profile_spec().profile,
        RUNTIME_PROFILE_COMMODITY
    );
    assert_eq!(own_image.standard_runtime, None);
    assert!(own_image.hosted_egress.is_some());

    assert!(
        config
            .pool(WorkspaceShape {
                cpu_millicores: 2000,
                memory_mib: 4096,
                disk_gib: 20,
            })
            .is_err()
    );
    // Without hosted egress, a standard environment is refused, never
    // rendered without a network.
    assert!(
        KubernetesRenderConfig {
            hosted_egress: None,
            ..config.clone()
        }
        .environment(&RenderingIntent {
            image: crate::sandbox::canonical_workspace_runtime_image().into(),
            ..intent(Isolation::Standard)
        })
        .is_err()
    );
}
