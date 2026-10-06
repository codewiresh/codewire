//! Workspace network-policy rendering. The environment's SSH server and
//! tailnet peer live in its workspace daemon (design §5): only orchestration
//! reaches the daemon, previews and SSH, and only the world sends to the
//! tailnet UDP port, through the environment's direct-UDP LoadBalancer.

use serde_json::{Map, Value, json};

use super::naming::{
    direct_udp_service_name, warm_member_daemon_bridge_name, warm_member_selector,
    workspace_daemon_network_policy_name, workspace_selector,
};
use super::runtime_policy::RUNTIME_PROFILE_CONFIDENTIAL;
use super::{APP_PREVIEW_MAX_PORT, APP_PREVIEW_MIN_PORT, TemplateOpts, WORKSPACE_DAEMON_PORT};

/// Private, loopback, link-local and carrier-grade NAT ranges: every cluster
/// and Pod network a Codewire cluster uses. The world is everything else.
const NON_WORLD_IPV4: [&str; 6] = [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
];

fn world_peers() -> Value {
    json!([
        { "ipBlock": { "cidr": "0.0.0.0/0", "except": NON_WORLD_IPV4 } },
        { "ipBlock": { "cidr": "::/0", "except": ["fc00::/7"] } },
    ])
}

/// The daemon's tailnet reach beyond the public internet rule (design §5):
/// STUN on the DERP servers and the public UDP relay's data plane. Traffic to
/// their public LoadBalancers is delivered to these Pods, so the rules name
/// them, on those public ports only: never DERP's TLS port, the relay's
/// allocator or any other server-namespace Pod.
fn workspace_tailnet_egress_rules(opts: &TemplateOpts) -> Vec<Value> {
    if opts.server_namespace.is_empty() {
        return Vec::new();
    }
    let server_pods = |component: &str| {
        json!([{
            "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
            "podSelector": { "matchLabels": { "app.kubernetes.io/component": component } },
        }])
    };
    let mut egress = vec![json!({
        "to": server_pods("derp"),
        "ports": [ { "protocol": "UDP", "port": i64::from(codewire_gateway_proto::DERP_STUN_PORT) } ],
    })];
    if opts.udp_relay_allocator_egress_enabled || !opts.udp_relay_allocator_url.trim().is_empty() {
        egress.push(json!({
            "to": server_pods("udp-relay"),
            "ports": [ { "protocol": "UDP", "port": i64::from(codewire_gateway_proto::UDP_RELAY_DATA_PORT) } ],
        }));
    }
    egress
}

pub(super) fn workspace_egress_rules(opts: &TemplateOpts) -> Vec<Value> {
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
        ingress_controller_egress_rule(opts),
    ];
    egress.extend(workspace_tailnet_egress_rules(opts));
    if let Some(rule) = kata_coco_kbs_egress_rule(&opts.kata_coco_kbs_url) {
        egress.push(rule);
    }
    egress
}

/// HTTP and HTTPS to the cluster's ingress controller: RKE2's in
/// `kube-system` unless orchestration names another (a local cluster's
/// ingress-nginx, which fronts its coordinator for the daemon).
fn ingress_controller_egress_rule(opts: &TemplateOpts) -> Value {
    let namespace = match opts.ingress_namespace.trim() {
        "" => "kube-system",
        namespace => namespace,
    };
    let pod_name = match opts.ingress_pod_name.trim() {
        "" => "rke2-ingress-nginx",
        pod_name => pod_name,
    };
    json!({
        "to": [
            {
                "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": namespace } },
                "podSelector": { "matchLabels": { "app.kubernetes.io/name": pod_name } },
            },
        ],
        "ports": [
            { "protocol": "TCP", "port": 443 },
            { "protocol": "TCP", "port": 80 },
        ],
    })
}

/// The shared template egress of an identity-free workspace (design §3.5,
/// §13): today's rules, TCP 8087 to orchestration Pods in the server
/// namespace, and the daemon's tailnet reach, so a warm member's tailnet peer
/// starts at bind without waiting for its environment's own policy.
pub(super) fn identity_free_workspace_egress_rules(opts: &TemplateOpts) -> Vec<Value> {
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
        ingress_controller_egress_rule(opts),
        json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "orchestration" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": i64::from(codewire_gateway_proto::WORKSPACE_BINDING_PORT) },
            ],
        }),
    ];
    egress.extend(workspace_tailnet_egress_rules(opts));
    if let Some(rule) = kata_coco_kbs_egress_rule(&opts.kata_coco_kbs_url) {
        egress.push(rule);
    }
    egress
}

fn kata_coco_kbs_egress_rule(kbs_url: &str) -> Option<Value> {
    let parsed = url::Url::parse(kbs_url.trim()).ok()?;
    let host = parsed.host_str()?.trim_end_matches('.');
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2] != "svc" {
        return None;
    }

    let port = parsed.port_or_known_default()? as i64;
    // A Service DNS name does not identify its backing Pod labels. Select the
    // dedicated KBS namespace and exact port; the destination's own ingress
    // policy remains responsible for admitting only confidential callers.
    Some(json!({
        "to": [
            {
                "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": parts[1] } },
            },
        ],
        "ports": [
            { "protocol": "TCP", "port": port },
        ],
    }))
}

/// Who may reach a workspace (design §5): orchestration in the server
/// namespace on the daemon, preview and SSH ports, and the world, never a
/// cluster or Pod address (N1), on the tailnet UDP port.
fn workspace_daemon_ingress_rules(opts: &TemplateOpts) -> Vec<Value> {
    let mut ingress = Vec::new();
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
                { "protocol": "TCP", "port": i64::from(codewire_gateway_proto::WORKSPACE_SSH_PORT) },
                {
                    "protocol": "TCP",
                    "port": APP_PREVIEW_MIN_PORT,
                    "endPort": APP_PREVIEW_MAX_PORT,
                },
            ],
        }));
    }
    if tailnet_udp_listener_enabled(opts) {
        ingress.push(json!({
            "from": world_peers(),
            "ports": [ { "protocol": "UDP", "port": i64::from(codewire_gateway_proto::WORKSPACE_TAILNET_UDP_PORT) } ],
        }));
    }
    ingress
}

pub fn render_workspace_daemon_network_policy(namespace: &str, opts: &TemplateOpts) -> Value {
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
            "ingress": workspace_daemon_ingress_rules(opts),
            "egress": workspace_egress_rules(opts),
        },
    })
}

pub(super) fn tailnet_udp_listener_enabled(opts: &TemplateOpts) -> bool {
    direct_udp_ingress_enabled(opts)
        || direct_udp_endpoint(opts).is_some()
        || !opts.udp_relay_allocator_url.trim().is_empty()
        || !opts.udp_relay_bind_addrs.trim().is_empty()
}

fn direct_udp_ingress_enabled(opts: &TemplateOpts) -> bool {
    !opts.stun_host.trim().is_empty() || !opts.stun_servers.trim().is_empty()
}

fn direct_udp_endpoint(opts: &TemplateOpts) -> Option<String> {
    if !opts.direct_udp_lb_enabled {
        return None;
    }
    let ip = opts.direct_udp_lb_ip.trim();
    if ip.is_empty() || opts.direct_udp_lb_port <= 0 || opts.direct_udp_lb_port > 65535 {
        return None;
    }
    Some(format!("{ip}:{}", opts.direct_udp_lb_port))
}

/// The environment's direct-UDP LoadBalancer (design §5): its shared IP and
/// allocated port, selecting the workspace Pod's tailnet peer.
pub fn render_direct_udp_service(namespace: &str, opts: &TemplateOpts) -> Option<Value> {
    let _endpoint = direct_udp_endpoint(opts)?;
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

    let mut labels = json!({
        "codewire.sh/environment-id": opts.environment_id,
        "codewire.sh/org-id": opts.organization_id,
        (super::super::LABEL_OPERATION_GENERATION): opts.operation_generation.to_string(),
        "app.kubernetes.io/name": "codewire-workspace",
        "app.kubernetes.io/component": "direct-udp",
        "app.kubernetes.io/managed-by": "codewire",
    });
    let labels_obj = labels.as_object_mut().expect("labels object");
    if opts.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL {
        labels_obj.insert("codewire.sh/isolation-tier".into(), "confidential".into());
    }
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
        "selector": workspace_selector(opts),
        "ports": [
            {
                "name": "tailnet-udp",
                "protocol": "UDP",
                "port": opts.direct_udp_lb_port,
                "targetPort": i64::from(codewire_gateway_proto::WORKSPACE_TAILNET_UDP_PORT),
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
            "name": direct_udp_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": spec,
    }))
}

/// Program #2238 C6 (#2434): the bridge for one adopted warm-pool member.
///
/// A member gains `codewire.sh/environment-id` only when its claim relabels
/// it, and Cilium drops traffic to it until the relabelled Pod has a new
/// security identity. `cw-daemon-warm-<env>` selects the member by the label
/// the fork stamped at its birth, `agents.x-k8s.io/sandbox-uid`, together
/// with the workspace type, so the existing identity is admitted at once. It
/// grants exactly what `cw-daemon-net-<env>` grants beyond the shared
/// template: ingress from orchestration and, for the tailnet, from the world.
///
/// The caller applies it only after the warm binding that recorded
/// `sandbox_uid` committed. A Pod without the label is never selected, so
/// until the fork stamps it the bridge is inert and the environment policies
/// behave exactly as before. There is no gateway half: the gateway is gone.
pub fn render_warm_member_bridge(
    namespace: &str,
    opts: &TemplateOpts,
    sandbox_uid: &str,
) -> anyhow::Result<Value> {
    anyhow::ensure!(
        canonical_uuid(&opts.environment_id),
        "warm member bridge: the environment ID is not a canonical UUID"
    );
    anyhow::ensure!(
        canonical_uuid(sandbox_uid),
        "warm member bridge: the recorded Sandbox UID is not a canonical UUID"
    );
    let member = warm_member_selector(sandbox_uid);
    let labels = json!({
        "app.kubernetes.io/name": "codewire-warm-member-bridge",
        "app.kubernetes.io/component": "warm-member-bridge",
        "app.kubernetes.io/managed-by": "codewire",
        "codewire.sh/environment-id": opts.environment_id,
    });
    Ok(bridge_policy(
        namespace,
        &warm_member_daemon_bridge_name(&opts.environment_id),
        labels,
        member,
        workspace_daemon_ingress_rules(opts),
        Vec::new(),
    ))
}

/// A bridge declares only the directions it grants, so it never isolates a
/// direction that no other policy already isolates.
fn bridge_policy(
    namespace: &str,
    name: &str,
    labels: Value,
    selector: Value,
    ingress: Vec<Value>,
    egress: Vec<Value>,
) -> Value {
    let mut policy_types = Vec::new();
    let mut spec = json!({ "podSelector": { "matchLabels": selector } });
    if !ingress.is_empty() {
        policy_types.push("Ingress");
        spec["ingress"] = Value::Array(ingress);
    }
    if !egress.is_empty() {
        policy_types.push("Egress");
        spec["egress"] = Value::Array(egress);
    }
    spec["policyTypes"] = json!(policy_types);
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
        },
        "spec": spec,
    })
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
