//! Workspace and gateway network-policy rendering.

use serde_json::{Value, json};

use super::CREDENTIAL_GATEWAY_HTTPS_PORT;
use super::gateway::tailnet_udp_listener_enabled;
use super::naming::{
    gateway_labels, gateway_network_policy_name, gateway_selector, warm_member_daemon_bridge_name,
    warm_member_gateway_bridge_name, warm_member_selector, workspace_daemon_network_policy_name,
    workspace_selector,
};
use super::{
    APP_PREVIEW_MAX_PORT, APP_PREVIEW_MIN_PORT, DEFAULT_GATEWAY_READYZ_PORT,
    DEFAULT_GATEWAY_SSH_PORT, GATEWAY_TAILNET_UDP_PORT, INTERNAL_DERP_STUN_PORT,
    INTERNAL_DERP_TLS_PORT, TemplateOpts, WORKSPACE_DAEMON_PORT,
};

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
        json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/name": "rke2-ingress-nginx" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": 443 },
                { "protocol": "TCP", "port": 80 },
            ],
        }),
    ];
    egress.extend(workspace_gateway_https_egress_rule(opts));
    if let Some(rule) = kata_coco_kbs_egress_rule(&opts.kata_coco_kbs_url) {
        egress.push(rule);
    }
    egress
}

/// A workspace's egress to its own environment's credential gateway on 8443,
/// present only with the platform credential runtime.
fn workspace_gateway_https_egress_rule(opts: &TemplateOpts) -> Option<Value> {
    opts.credential_runtime.as_ref().map(|_| {
        json!({
            "to":[{"podSelector":{"matchLabels":gateway_selector(opts)}}],
            "ports":[{"protocol":"TCP","port":CREDENTIAL_GATEWAY_HTTPS_PORT}],
        })
    })
}

/// The shared template egress of an identity-free workspace (design §3.5,
/// §13): today's rules without the environment's own gateway on 8443, which
/// `cw-daemon-net-<env>` keeps and applies once labels converge, plus exactly
/// one new rule, TCP 8087 to orchestration Pods in the server namespace.
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
        json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/name": "rke2-ingress-nginx" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": 443 },
                { "protocol": "TCP", "port": 80 },
            ],
        }),
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

/// Who may reach a workspace's daemon and preview ports: its own
/// environment's gateway, and orchestration in the server namespace.
fn workspace_daemon_ingress_rules(opts: &TemplateOpts) -> Vec<Value> {
    let mut ingress = vec![json!({
        "from": [ { "podSelector": { "matchLabels": gateway_selector(opts) } } ],
        "ports": [
            { "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT },
            { "protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT },
        ],
    })];
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
                {
                    "protocol": "TCP",
                    "port": APP_PREVIEW_MIN_PORT,
                    "endPort": APP_PREVIEW_MAX_PORT,
                },
            ],
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

/// A gateway's egress to the daemon and preview ports of the workspace Pods
/// `workspace` selects.
fn gateway_workspace_egress_rule(workspace: Value) -> Value {
    json!({
        "to": [ { "podSelector": { "matchLabels": workspace } } ],
        "ports": [
            { "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT },
            { "protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT },
        ],
    })
}

/// A gateway's credential HTTPS ingress from the workspace Pods `workspace`
/// selects.
fn gateway_https_ingress_rule(workspace: Value) -> Value {
    json!({
        "from":[{"podSelector":{"matchLabels":workspace}}],
        "ports":[{"protocol":"TCP","port":CREDENTIAL_GATEWAY_HTTPS_PORT}],
    })
}

pub fn render_gateway_network_policy(namespace: &str, opts: &TemplateOpts) -> Value {
    let mut egress = vec![
        gateway_workspace_egress_rule(workspace_selector(opts)),
        json!({
            "to": [
                { "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "kube-system" } } },
            ],
            "ports": [
                { "protocol": "UDP", "port": 53 },
                { "protocol": "TCP", "port": 53 },
            ],
        }),
        json!({
            "to": [
                { "ipBlock": { "cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"] } },
                { "ipBlock": { "cidr": "::/0", "except": ["fc00::/7"] } },
            ],
            "ports": [
                { "protocol": "TCP", "port": 443 },
                { "protocol": "UDP", "port": INTERNAL_DERP_STUN_PORT },
                { "protocol": "UDP", "port": GATEWAY_TAILNET_UDP_PORT },
            ],
        }),
    ];
    if !opts.server_namespace.is_empty() {
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "orchestration" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": 8084 },
                { "protocol": "TCP", "port": 8085 },
            ],
        }));
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "coordinator" } },
                },
            ],
            "ports": [ { "protocol": "TCP", "port": 8090 } ],
        }));
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "derp" } },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": INTERNAL_DERP_TLS_PORT },
                { "protocol": "UDP", "port": INTERNAL_DERP_STUN_PORT },
            ],
        }));
        if opts.udp_relay_allocator_egress_enabled
            || !opts.udp_relay_allocator_url.trim().is_empty()
        {
            egress.push(json!({
                "to": [
                    {
                        "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                        "podSelector": { "matchLabels": { "app.kubernetes.io/component": "udp-relay" } },
                    },
                ],
                "ports": [
                    { "protocol": "TCP", "port": 8095 },
                    { "protocol": "UDP", "port": 41641 },
                ],
            }));
        }
        egress.push(json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/name": "codewire-mesh" } },
                },
            ],
            "ports": [ { "protocol": "TCP", "port": 8080 } ],
        }));
    }
    if let Some(rule) = kata_coco_kbs_egress_rule(&opts.kata_coco_kbs_url) {
        egress.push(rule);
    }

    let mut ingress = vec![json!({
        "ports": [ { "protocol": "TCP", "port": DEFAULT_GATEWAY_READYZ_PORT } ],
    })];
    if let Some(config) = &opts.credential_runtime {
        config.assert_namespace(namespace);
        ingress.push(gateway_https_ingress_rule(workspace_selector(opts)));
        egress.push(json!({
            "to":[{
                "namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":config.broker_namespace()}},
                "podSelector":{"matchLabels":{"app.kubernetes.io/name":"codewire","app.kubernetes.io/component":"credential-service"}},
            }],
            "ports":[{"protocol":"TCP","port":9443}],
        }));
    }
    if !opts.server_namespace.is_empty() {
        ingress.push(json!({
            "from": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": opts.server_namespace } },
                    "podSelector": { "matchLabels": { "app.kubernetes.io/component": "orchestration" } },
                },
            ],
            "ports": [ { "protocol": "TCP", "port": DEFAULT_GATEWAY_SSH_PORT } ],
        }));
    }
    if tailnet_udp_listener_enabled(opts) {
        ingress.push(json!({
            "ports": [ { "protocol": "UDP", "port": GATEWAY_TAILNET_UDP_PORT } ],
        }));
    }

    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": gateway_network_policy_name(&opts.environment_id),
            "namespace": namespace,
            "labels": gateway_labels(opts),
        },
        "spec": {
            "podSelector": { "matchLabels": gateway_selector(opts) },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": ingress,
            "egress": egress,
        },
    })
}

/// Program #2238 C6 (#2434): the bridge for one adopted warm-pool member.
///
/// A member gains `codewire.sh/environment-id` only when its claim relabels
/// it, and Cilium drops the gateway's traffic until the relabelled Pod has a
/// new security identity. These two policies select the member by the label
/// the fork stamped at its birth, `agents.x-k8s.io/sandbox-uid`, together
/// with the workspace type, so the existing identity is admitted at once:
///
/// - `cw-daemon-warm-<env>` selects the member and grants exactly what
///   `cw-daemon-net-<env>` grants beyond the shared template: ingress from
///   this environment's gateway and from orchestration, and egress to the
///   gateway's credential port.
/// - `cw-gw-warm-<env>` selects this environment's gateway and grants
///   exactly the workspace rules of `cw-gw-net-<env>`, toward the member:
///   egress to its daemon and preview ports, and credential ingress from it.
///
/// The caller applies them only after the warm binding that recorded
/// `sandbox_uid` committed. A Pod without the label is never selected, so
/// until the fork stamps it the bridge is inert and the environment policies
/// behave exactly as before.
pub fn render_warm_member_bridge(
    namespace: &str,
    opts: &TemplateOpts,
    sandbox_uid: &str,
) -> anyhow::Result<[Value; 2]> {
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
    let daemon = bridge_policy(
        namespace,
        &warm_member_daemon_bridge_name(&opts.environment_id),
        labels.clone(),
        member.clone(),
        workspace_daemon_ingress_rules(opts),
        workspace_gateway_https_egress_rule(opts)
            .into_iter()
            .collect(),
    );
    let mut gateway_ingress = Vec::new();
    if let Some(config) = &opts.credential_runtime {
        config.assert_namespace(namespace);
        gateway_ingress.push(gateway_https_ingress_rule(member.clone()));
    }
    let gateway = bridge_policy(
        namespace,
        &warm_member_gateway_bridge_name(&opts.environment_id),
        labels,
        gateway_selector(opts),
        gateway_ingress,
        vec![gateway_workspace_egress_rule(member)],
    );
    Ok([daemon, gateway])
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
