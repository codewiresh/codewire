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
