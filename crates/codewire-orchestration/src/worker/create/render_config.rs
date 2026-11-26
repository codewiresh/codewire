use super::*;

/// The deployment-wide half of every workspace rendering, which the driver
/// holds (#3628 PR 8b).
impl From<&SandboxWorkerCfg> for KubernetesRenderConfig {
    fn from(cfg: &SandboxWorkerCfg) -> Self {
        Self {
            credential_runtime: cfg.credential_runtime.clone(),
            daemon_image: cfg.daemon_image.clone(),
            dind_image: cfg.dind_image.clone(),
            runtime_profile: cfg.runtime_profile.clone(),
            warm_pool_runtime_profile: cfg.warm_pool_runtime_profile.clone(),
            docker_mode: cfg.docker_mode.clone(),
            dind_enabled: cfg.dind_enabled,
            allow_diagnostic_runtime: cfg.allow_diagnostic_runtime,
            workspace_storage_class: cfg.workspace_storage_class.clone(),
            confidential_workspace_storage_class: cfg.confidential_workspace_storage_class.clone(),
            confidential_binding_roots_pem: cfg.confidential_binding_roots_pem.clone(),
            workspace_binding_url: if workspace_binding_configured(cfg) {
                workspace_binding_url(cfg.pod_namespace.trim())
            } else {
                String::new()
            },
            api_base_url: cfg.api_base_url.clone(),
            coordinator_url: cfg.coordinator_url.clone(),
            server_namespace: cfg.pod_namespace.clone(),
            coordinator_extra_roots: cfg.coordinator_extra_roots,
            codex_login_check_period_seconds: cfg.codex_login_check_period_seconds,
            ingress_namespace: cfg.ingress_namespace.clone(),
            ingress_pod_name: cfg.ingress_pod_name.clone(),
            egress_bandwidth: cfg.egress_bandwidth.clone(),
            derp_host: cfg.derp_host.clone(),
            hosted_egress: cfg.hosted_egress.clone(),
            standard_runtime: cfg.standard_runtime.clone(),
            derp_port: parse_derp_port(&cfg.derp_port),
            stun_host: cfg.stun_host.clone(),
            stun_port: parse_stun_port(&cfg.stun_port),
            stun_servers: cfg.stun_servers.clone(),
            direct_udp_lb_enabled: cfg.direct_udp_lb_enabled,
            direct_udp_lb_ip: cfg.direct_udp_lb_ip.clone(),
            direct_udp_lb_port_start: parse_udp_lb_port_bound(&cfg.direct_udp_lb_port_start),
            direct_udp_lb_port_end: parse_udp_lb_port_bound(&cfg.direct_udp_lb_port_end),
            direct_udp_lb_class: cfg.direct_udp_lb_class.clone(),
            direct_udp_lb_sharing_key: cfg.direct_udp_lb_sharing_key.clone(),
            direct_udp_transport_zone: cfg.direct_udp_transport_zone.clone(),
            udp_relay_allocator_url: cfg.udp_relay_allocator_url.clone(),
            udp_relay_bind_addrs: cfg.udp_relay_bind_addrs.clone(),
            uses_runtime_transport_registry: !cfg.runtime_transport_zones_json.trim().is_empty(),
            cpu_sharing_ratio: cfg.cpu_sharing_ratio,
            network_policy_management: cfg.network_policy_management.clone(),
            kata_agent_policy_enabled: cfg.kata_agent_policy_enabled,
            kata_coco_init_data_enabled: cfg.kata_coco_init_data_enabled,
            kata_coco_kbs_url: cfg.kata_coco_kbs_url.clone(),
            kata_coco_kbs_ca_pem: cfg.kata_coco_kbs_ca_pem.clone(),
            kata_coco_kbs_peer: cfg.kata_coco_kbs_peer.clone(),
            kata_coco_image_registry_auth_uri: cfg.kata_coco_image_registry_auth_uri.clone(),
            kata_coco_test_resource_uri: cfg.kata_coco_test_resource_uri.clone(),
            kata_coco_test_resource_path: cfg.kata_coco_test_resource_path.clone(),
            debug_tailnet: cfg.debug_tailnet,
        }
    }
}
