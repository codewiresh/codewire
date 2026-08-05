//! Workspace and gateway network-policy rendering.

use serde_json::{Value, json};

use super::gateway::tailnet_udp_listener_enabled;
use super::naming::{
    gateway_labels, gateway_network_policy_name, gateway_selector,
    workspace_daemon_network_policy_name, workspace_selector,
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
    Some(json!({
        "to": [
            {
                "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": parts[1] } },
                "podSelector": { "matchLabels": { "app.kubernetes.io/name": parts[0] } },
            },
        ],
        "ports": [
            { "protocol": "TCP", "port": port },
        ],
    }))
}

pub fn render_workspace_daemon_network_policy(namespace: &str, opts: &TemplateOpts) -> Value {
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
            "ingress": ingress,
            "egress": workspace_egress_rules(opts),
        },
    })
}

pub fn render_gateway_network_policy(namespace: &str, opts: &TemplateOpts) -> Value {
    let mut egress = vec![
        json!({
            "to": [ { "podSelector": { "matchLabels": workspace_selector(opts) } } ],
            "ports": [
                { "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT },
                { "protocol": "TCP", "port": APP_PREVIEW_MIN_PORT, "endPort": APP_PREVIEW_MAX_PORT },
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
