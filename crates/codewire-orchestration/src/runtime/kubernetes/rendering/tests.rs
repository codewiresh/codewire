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
        systemd_workspace: false,
        systemd_opted_in: false,
        runtime_profile: "commodity".into(),
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
            earlier_projection_selection_sha256: Vec::new(),
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
            hosted_egress: HostedEgress::on(broker(revision)),
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
    // Off with the broker settings kept (#6070): a create still renders
    // direct, a pool and an environment alike.
    let kept = KubernetesRenderConfig {
        hosted_egress: HostedEgress {
            enabled: false,
            broker: Some(broker("2")),
        },
        ..config()
    };
    let pool = kept
        .pool(WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
        })
        .unwrap();
    assert_eq!(pool.hosted_egress, None);
    for isolation in [Isolation::Standard, Isolation::Confidential] {
        let environment = kept.environment(&intent(isolation)).unwrap();
        assert_eq!(environment.hosted_egress, None, "{isolation:?}");
    }
}

#[test]
fn a_runtime_that_is_not_a_vm_never_renders_broker_mode() {
    let config = KubernetesRenderConfig {
        hosted_egress: HostedEgress::on(broker("2")),
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
/// any other image is created on `commodity`; and its warm pool renders the
/// standard Pod its canonical creates adopt, but none on a disk that does
/// not boot the canonical image (#5602).
/// A standard runtime whose disk was built from a workspace image other than
/// the canonical one.
fn stale_disk_runtime() -> Option<crate::sandbox::template::StandardRuntime> {
    crate::sandbox::template::StandardRuntime::parse(
        "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 \
         3333333333333333333333333333333333333333333333333333333333333333 \
         44444444444444444444444444444444 \
         registry.example.invalid/codewire/workspace@sha256:5555555555555555555555555555555555555555555555555555555555555555",
    )
    .unwrap()
}

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
        hosted_egress: HostedEgress::on(broker("2")),
        standard_runtime: runtime.clone(),
        ..config()
    };
    // An environment its create recorded on `standard` (whose choice
    // `sandbox::standard_move` tests). The disk names its workspace image at
    // another registry than the one environments name it at.
    let workspace = config
        .environment(&RenderingIntent {
            image: canonical.into(),
            runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
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

    // One recorded on `commodity`, as a create of any other image is.
    let own_image = config.environment(&intent(Isolation::Standard)).unwrap();
    assert_eq!(
        own_image.runtime_profile_spec().profile,
        RUNTIME_PROFILE_COMMODITY
    );
    assert_eq!(own_image.standard_runtime, None);
    assert!(own_image.hosted_egress.is_some());

    let shape = WorkspaceShape {
        cpu_millicores: 2000,
        memory_mib: 4096,
        disk_gib: 20,
    };
    let member = config.pool(shape).unwrap();
    let adopter = config
        .environment(&RenderingIntent {
            image: canonical.into(),
            shape,
            runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
            ..intent(Isolation::Standard)
        })
        .unwrap();
    assert_eq!(
        member.runtime_profile_spec(),
        adopter.runtime_profile_spec()
    );
    assert_eq!(member.runtime_profile_spec().runtime_class_name, "standard");
    assert_eq!(member.standard_runtime, runtime);
    assert_eq!(member.image, adopter.image);
    // A disk that boots another image: canonical creates go to `commodity`,
    // so a standard member would never be adopted.
    let stale = KubernetesRenderConfig {
        standard_runtime: stale_disk_runtime(),
        ..config.clone()
    };
    let refused = stale.pool(shape).unwrap_err().to_string();
    assert!(refused.contains("does not boot the canonical"), "{refused}");
    // Without hosted egress, a standard environment is refused, never
    // rendered without a network.
    assert!(
        KubernetesRenderConfig {
            hosted_egress: HostedEgress::default(),
            ..config.clone()
        }
        .environment(&RenderingIntent {
            image: crate::sandbox::canonical_workspace_runtime_image().into(),
            runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
            ..intent(Isolation::Standard)
        })
        .is_err()
    );
}

#[test]
fn an_environment_renders_on_its_recorded_profile_whatever_disk_or_default_the_deployment_has() {
    // The deployment's disk holds another image, as after a republish.
    let standard = KubernetesRenderConfig {
        runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
        hosted_egress: HostedEgress::on(broker("2")),
        standard_runtime: stale_disk_runtime(),
        ..config()
    };
    let profile = |config: &KubernetesRenderConfig, systemd_workspace, recorded: &str| {
        config
            .environment_spec(&RenderingIntent {
                image: crate::sandbox::canonical_workspace_runtime_image().into(),
                systemd_workspace,
                runtime_profile: recorded.into(),
                ..intent(Isolation::Standard)
            })
            .profile
    };
    for systemd_workspace in [true, false] {
        // Created on `standard`: it stays there though the disk no longer
        // boots its image, and a systemd one needs no opt-in.
        assert_eq!(
            profile(&standard, systemd_workspace, "standard"),
            RUNTIME_PROFILE_STANDARD
        );
        // Created on `commodity`: it stays there on a `standard` default.
        assert_eq!(
            profile(&standard, systemd_workspace, "commodity"),
            RUNTIME_PROFILE_COMMODITY
        );
        // A moved organization's environment on a `commodity` default
        // stays on `standard`.
        assert_eq!(
            profile(&config(), systemd_workspace, "standard"),
            RUNTIME_PROFILE_STANDARD
        );
    }
    // Once the deployment no longer has `standard`, its start is refused,
    // never rendered onto another profile.
    let refused = config()
        .environment(&RenderingIntent {
            image: crate::sandbox::canonical_workspace_runtime_image().into(),
            runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
            ..intent(Isolation::Standard)
        })
        .unwrap_err()
        .to_string();
    assert!(refused.contains("no longer makes available"), "{refused}");
}

#[test]
fn a_diagnostic_record_on_a_managed_deployment_is_refused_on_every_write() {
    // A `runc` record on a `commodity` deployment that allows no diagnostic
    // runtime: a create's write and an existing environment's are refused.
    let managed = KubernetesRenderConfig {
        allow_diagnostic_runtime: false,
        ..config()
    };
    let recorded = RenderingIntent {
        runtime_profile: "runc".into(),
        ..intent(Isolation::Standard)
    };
    for refused in [
        managed.environment(&recorded),
        managed.existing(&recorded, None),
        managed.existing(&recorded, Some(&sandbox_mode(false))),
    ] {
        assert!(refused.is_err(), "{refused:?}");
    }
    // A diagnostic deployment that allows it still renders it.
    let diagnostic = KubernetesRenderConfig {
        runtime_profile: "runc".into(),
        allow_diagnostic_runtime: true,
        ..config()
    };
    assert!(diagnostic.environment(&recorded).is_ok());
}

/// A pool claim renders the recorded profile (#5602): the claim compares the
/// environment's own rendering with the member's revision, so an environment
/// recorded `standard` never adopts a `commodity` pool's member, and one
/// recorded `commodity` still does.
#[test]
fn a_standard_record_never_adopts_a_commodity_pool_member() {
    let canonical = crate::sandbox::canonical_workspace_runtime_image();
    let (_, digest) = canonical.rsplit_once('@').unwrap();
    let config = KubernetesRenderConfig {
        hosted_egress: HostedEgress::on(broker("2")),
        standard_runtime: crate::sandbox::template::StandardRuntime::parse(
            "registry.example.invalid/codewire/pod-runtime@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            &format!(
                "registry.example.invalid/codewire/workspace-disk@sha256:2222222222222222222222222222222222222222222222222222222222222222 \
                 3333333333333333333333333333333333333333333333333333333333333333 \
                 44444444444444444444444444444444 \
                 registry.example.invalid/codewire/workspace@{digest}"
            ),
        )
        .unwrap(),
        ..config()
    };
    let shape = WorkspaceShape {
        cpu_millicores: 2000,
        memory_mib: 4096,
        disk_gib: 20,
    };
    let revision = |opts: &TemplateOpts| {
        crate::sandbox::warm_pool::pool_revision(
            &crate::sandbox::template::render_sandbox_template(NAMESPACE, opts)["spec"],
        )
    };
    let member = config.pool(shape).unwrap();
    assert_eq!(
        member.runtime_profile_spec().profile,
        RUNTIME_PROFILE_COMMODITY
    );
    let claim = |recorded: &str| {
        config
            .environment(&RenderingIntent {
                image: canonical.into(),
                shape,
                runtime_profile: recorded.into(),
                ..intent(Isolation::Standard)
            })
            .unwrap()
    };
    assert_eq!(
        revision(&claim(RUNTIME_PROFILE_COMMODITY)),
        revision(&member)
    );
    assert_ne!(
        revision(&claim(RUNTIME_PROFILE_STANDARD)),
        revision(&member)
    );

    // Conversely, overriding the warm pool's runtime profile to `standard` on
    // a `commodity` deployment makes `standard` environments adopt the pool
    // while `commodity` environments start cold.
    let standard_pool = KubernetesRenderConfig {
        warm_pool_runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
        ..config
    };
    let standard_member = standard_pool.pool(shape).unwrap();
    assert_eq!(
        standard_member.runtime_profile_spec().profile,
        RUNTIME_PROFILE_STANDARD
    );
    let standard_claim = |recorded: &str| {
        standard_pool
            .environment(&RenderingIntent {
                image: canonical.into(),
                shape,
                runtime_profile: recorded.into(),
                ..intent(Isolation::Standard)
            })
            .unwrap()
    };
    assert_eq!(
        revision(&standard_claim(RUNTIME_PROFILE_STANDARD)),
        revision(&standard_member)
    );
    assert_ne!(
        revision(&standard_claim(RUNTIME_PROFILE_COMMODITY)),
        revision(&standard_member)
    );
}

#[test]
fn a_systemd_workspace_renders_from_its_record_and_only_while_it_is_offered() {
    // An image from any repository renders as a plain custom image unless the
    // environment's create recorded it as a systemd workspace.
    let plain = config().environment(&intent(Isolation::Standard)).unwrap();
    assert!(!plain.systemd_workspace);
    // Recorded as one, on a deployment that does not offer it (no repository
    // set, as here): refused, never rendered as a plain custom image.
    let recorded = RenderingIntent {
        systemd_workspace: true,
        ..intent(Isolation::Standard)
    };
    let error = config().environment(&recorded).unwrap_err();
    assert_eq!(
        error.to_string(),
        "this deployment does not offer systemd workspaces"
    );
}

/// A Sandbox of `name` with the whole broker shape when `broker`, and the
/// broker label alone otherwise.
fn sandbox_mode(broker: bool) -> SandboxMode {
    let mut template = serde_json::json!({
        "metadata": {"labels": {"codewire.sh/egress": "broker"}},
        "spec": {"runtimeClassName": "commodity", "containers": []},
    });
    if broker {
        template["metadata"]["annotations"] =
            serde_json::json!({"codewire.sh/egress-fence-revision": "2"});
        template["spec"]["initContainers"] = serde_json::json!([{"name": "hosted-egress-tun"}]);
    }
    SandboxMode::of(
        "sandbox-a",
        &serde_json::json!({"spec": {"podTemplate": template}}),
    )
}

/// #6070: with the switch on or off, an existing broker Sandbox renders
/// broker mode, and its access stack's policy is exactly the one the
/// lockdown check expects; a direct or hollow one renders direct, which the
/// check never takes for a broker guest's.
#[test]
fn an_existing_sandbox_renders_its_own_mode_and_the_check_expects_the_broker_one() {
    for enabled in [false, true] {
        let config = KubernetesRenderConfig {
            hosted_egress: HostedEgress {
                enabled,
                broker: Some(broker("2")),
            },
            ..config()
        };
        for isolation in [Isolation::Standard, Isolation::Confidential] {
            let expected = config
                .workspace_network_policy(NAMESPACE, ENVIRONMENT, isolation)
                .unwrap();
            let mut whole = config
                .existing(&intent(isolation), Some(&sandbox_mode(true)))
                .unwrap();
            assert_eq!(whole.hosted_egress, Some(broker("2")));
            whole.direct_udp_lb_port = 32417;
            assert_eq!(
                render_workspace_daemon_network_policy(NAMESPACE, &whole),
                expected,
                "{enabled} {isolation:?}"
            );
            let mut hollow = config
                .existing(&intent(isolation), Some(&sandbox_mode(false)))
                .unwrap();
            assert_eq!(hollow.hosted_egress, None);
            hollow.direct_udp_lb_port = 32417;
            assert_ne!(
                render_workspace_daemon_network_policy(NAMESPACE, &hollow),
                expected,
                "{enabled} {isolation:?}"
            );
            // No Sandbox yet: a create, which the switch decides.
            assert_eq!(
                config
                    .existing(&intent(isolation), None)
                    .unwrap()
                    .hosted_egress
                    .is_some(),
                enabled
            );
        }
        // The template policy a broker member's template makes is the
        // broker one too.
        let pool = KubernetesRenderConfig {
            hosted_egress: HostedEgress::on(broker("2")),
            ..config.clone()
        }
        .pool(WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 4096,
            disk_gib: 20,
        })
        .unwrap();
        assert_eq!(
            config.template_network_policy(Isolation::Standard, "2f9c41ab"),
            Some(render_template_network_policy(&pool, "2f9c41ab"))
        );
    }
    // Without the settings a broker Sandbox is refused, never direct.
    let error = config()
        .existing(&intent(Isolation::Standard), Some(&sandbox_mode(true)))
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<crate::egress::own_mode::BrokerSettingsAbsent>()
            .is_some(),
        "{error:#}"
    );
}

#[test]
fn may_have_standard_pods_includes_per_org_standard_on_commodity_default() {
    assert!(!config().may_have_standard_pods());
    let per_org = KubernetesRenderConfig {
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        standard_runtime: stale_disk_runtime(),
        ..config()
    };
    assert!(per_org.may_have_standard_pods());
    let default_standard = KubernetesRenderConfig {
        runtime_profile: RUNTIME_PROFILE_STANDARD.into(),
        standard_runtime: None,
        ..config()
    };
    assert!(default_standard.may_have_standard_pods());
}
