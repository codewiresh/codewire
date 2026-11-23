//! Broker mode's lockdown (#4000 P5, infra#1822): the policies a broker-mode
//! workspace is selected by name only the reviewed peers, each by selector and
//! its one port, with no address range and no DNS. Kubernetes NetworkPolicies
//! add up, so the bound workspace's policy and the warm template's are held to
//! the same list.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;

const NAMESPACE: &str = "dev-sandboxes";
const SERVER: &str = "dev";
const KBS_URL: &str = "http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080";
/// A confidential workspace renders only with measured binding roots (B2c);
/// a synthetic, public bundle, as the template tests use.
const MEASURED_BINDING_ROOTS: &str =
    "-----BEGIN CERTIFICATE-----\nMIIBsynthetic\n-----END CERTIFICATE-----\n";
const MEASURED_BINDING_URL: &str =
    "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";

fn egress_template() -> HostedEgressTemplate {
    crate::egress::gateway_check::assume_verified();
    HostedEgressTemplate {
        stream_addr: "10.44.0.89:8089".into(),
        binding_addr: "10.44.0.87:8087".into(),
        fence_revision: "2".into(),
        gateway: GatewayPeer {
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

fn opts(profile: &str, relay: bool, egress: Option<HostedEgressTemplate>) -> TemplateOpts {
    let confidential = profile == RUNTIME_PROFILE_CONFIDENTIAL;
    TemplateOpts {
        workspace_binding_url: if confidential {
            MEASURED_BINDING_URL.into()
        } else {
            String::new()
        },
        measured_binding_roots: if confidential {
            MEASURED_BINDING_ROOTS.into()
        } else {
            String::new()
        },
        name: "tmpl-broker".into(),
        environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
        image: "ghcr.io/codewiresh/workspace:golden".into(),
        support_image: "registry.example.invalid/codewire/daemon:test".into(),
        runtime_profile: profile.into(),
        kata_coco_kbs_url: KBS_URL.into(),
        api_base_url: "https://codewire-dev.sh".into(),
        server_namespace: SERVER.into(),
        udp_relay_allocator_egress_enabled: relay,
        cpu_millicores: 1000,
        memory_mib: 2048,
        hosted_egress: egress,
        ..Default::default()
    }
}

/// Both policies a broker-mode workspace is selected by: its environment's,
/// and the warm template's, which governs identity-free members.
fn egress_policies(opts: &TemplateOpts) -> Vec<(&'static str, Vec<Value>)> {
    let bound = network::render_workspace_daemon_network_policy(NAMESPACE, opts);
    let template = render_sandbox_template(NAMESPACE, opts);
    vec![
        (
            "environment policy",
            bound["spec"]["egress"].as_array().unwrap().clone(),
        ),
        (
            "warm template",
            template["spec"]["networkPolicy"]["egress"]
                .as_array()
                .unwrap()
                .clone(),
        ),
    ]
}

fn server(component: &str) -> Value {
    json!({
        "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": SERVER } },
        "podSelector": { "matchLabels": {
            "app.kubernetes.io/name": "codewire",
            "app.kubernetes.io/component": component,
        } },
    })
}

/// Each allowed (peer, protocol, port), as the reviewed list on #4000 names it.
fn expected(confidential: bool, relay: bool) -> BTreeSet<String> {
    let gateway = json!({
        "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "gateway-proxies" } },
        "podSelector": { "matchLabels": {
            "gateway.envoyproxy.io/owning-gateway-name": "public",
            "gateway.envoyproxy.io/owning-gateway-namespace": "gateway",
        } },
    });
    let mut out: BTreeSet<String> = [
        (server("egress"), "TCP", 8089),
        (server("orchestration"), "TCP", 8087),
        (server("derp"), "TCP", 8443),
        (gateway, "TCP", 10443),
    ]
    .into_iter()
    .map(|(peer, protocol, port)| format!("{peer} {protocol}/{port}"))
    .collect();
    if relay {
        out.insert(format!("{} UDP/41641", server("udp-relay")));
    }
    if confidential {
        let kbs = json!({ "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "codewire-trustee" } } });
        out.insert(format!("{kbs} TCP/8080"));
    }
    out
}

/// Every (peer, protocol, port) the rules allow. A rule without `to` or
/// without `ports` would allow every peer or every port; it is listed as such
/// so it never matches the expected set.
fn allowed(rules: &[Value]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rule in rules {
        let peers = rule["to"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![json!("every peer")]);
        let ports = rule["ports"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![json!("every port")]);
        for peer in &peers {
            for port in &ports {
                out.insert(
                    match (
                        port["protocol"].as_str(),
                        port["port"].as_i64(),
                        port.get("endPort"),
                    ) {
                        (Some(protocol), Some(number), None) => {
                            format!("{peer} {protocol}/{number}")
                        }
                        _ => format!("{peer} {port}"),
                    },
                );
            }
        }
    }
    out
}

#[test]
fn broker_mode_names_only_the_reviewed_peers() {
    for (profile, confidential) in [
        (RUNTIME_PROFILE_COMMODITY, false),
        (RUNTIME_PROFILE_CONFIDENTIAL, true),
    ] {
        for relay in [false, true] {
            let opts = opts(profile, relay, Some(egress_template()));
            for (policy, rules) in egress_policies(&opts) {
                assert_eq!(
                    allowed(&rules),
                    expected(confidential, relay),
                    "{policy}, profile {profile:?}, relay {relay}"
                );
            }
        }
    }
}

/// With the key broker at an address (#4000), a confidential broker-mode
/// workspace reaches the key broker's labelled Pods and nothing else in its
/// namespace: the namespace-only rule is gone from both policies.
#[test]
fn an_address_kbs_url_names_the_key_brokers_pods() {
    let peer = KbsPeer::parse(
        "codewire-trustee:app=kbs,app.kubernetes.io/instance=codewire-trustee,app.kubernetes.io/name=trustee",
    )
    .unwrap();
    let kbs_pods = json!({
        "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "codewire-trustee" } },
        "podSelector": { "matchLabels": {
            "app": "kbs",
            "app.kubernetes.io/instance": "codewire-trustee",
            "app.kubernetes.io/name": "trustee",
        } },
    });
    let namespace_only = json!({ "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "codewire-trustee" } } });
    for relay in [false, true] {
        let mut opts = opts(RUNTIME_PROFILE_CONFIDENTIAL, relay, Some(egress_template()));
        opts.kata_coco_kbs_url = "https://10.44.0.45:8080".into();
        opts.kata_coco_kbs_peer = Some(peer.clone());
        let mut want = expected(true, relay);
        assert!(want.remove(&format!("{namespace_only} TCP/8080")));
        want.insert(format!("{kbs_pods} TCP/8080"));
        for (policy, rules) in egress_policies(&opts) {
            assert_eq!(allowed(&rules), want, "{policy}, relay {relay}");
        }
    }
}

/// Without a peer, an address URL names no namespace, so the template gets no
/// path to the key broker at all; startup refuses that configuration
/// (`KbsSettings::from_env`).
#[test]
fn an_address_kbs_url_without_a_peer_opens_nothing() {
    let mut opts = opts(RUNTIME_PROFILE_CONFIDENTIAL, false, Some(egress_template()));
    opts.kata_coco_kbs_url = "https://10.44.0.45:8080".into();
    let mut want = expected(true, false);
    want.retain(|entry| !entry.contains("codewire-trustee"));
    for (policy, rules) in egress_policies(&opts) {
        assert_eq!(allowed(&rules), want, "{policy}");
    }
}

#[test]
fn broker_mode_has_no_address_range_and_no_dns() {
    for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
        let opts = opts(profile, true, Some(egress_template()));
        for (policy, rules) in egress_policies(&opts) {
            let text = Value::Array(rules.clone()).to_string();
            assert!(
                !text.contains("ipBlock"),
                "{policy} has an address range: {text}"
            );
            for rule in &rules {
                for port in rule["ports"].as_array().unwrap() {
                    assert_ne!(port["port"], json!(53), "{policy} opens DNS: {rule}");
                    assert!(
                        port.get("endPort").is_none(),
                        "{policy} opens a port range: {rule}"
                    );
                }
                assert!(
                    rule.get("to").is_some(),
                    "{policy} has a rule open to every peer: {rule}"
                );
            }
        }
    }
}

#[test]
fn the_gateway_peer_is_its_proxies_and_nothing_behind_it() {
    // cw-security's condition (#4901): the gateway applies header stripping
    // and rate limits, so the workspace must reach the proxies only, never a
    // service behind them on its own port.
    let opts = opts(RUNTIME_PROFILE_COMMODITY, true, Some(egress_template()));
    for (policy, rules) in egress_policies(&opts) {
        for rule in &rules {
            for peer in rule["to"].as_array().unwrap() {
                let labels = &peer["podSelector"]["matchLabels"];
                if peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
                    == "gateway-proxies"
                {
                    assert_eq!(
                        labels["gateway.envoyproxy.io/owning-gateway-name"], "public",
                        "{policy}: {rule}"
                    );
                    assert_eq!(
                        rule["ports"],
                        json!([{ "protocol": "TCP", "port": 10443 }]),
                        "{policy}: {rule}"
                    );
                }
                if labels["app.kubernetes.io/component"] == "orchestration" {
                    // The binding, and none of orchestration's API ports.
                    assert_eq!(
                        rule["ports"],
                        json!([{ "protocol": "TCP", "port": 8087 }]),
                        "{policy}: {rule}"
                    );
                }
                let component = labels["app.kubernetes.io/component"]
                    .as_str()
                    .unwrap_or_default();
                assert!(
                    ![
                        "coordinator",
                        "billing",
                        "idp",
                        "dashboard",
                        "credential-service",
                        "mesh"
                    ]
                    .contains(&component),
                    "{policy} names a service behind the gateway: {rule}"
                );
            }
        }
    }
}

#[test]
fn hosted_egress_off_leaves_todays_policies() {
    for profile in ["", RUNTIME_PROFILE_CONFIDENTIAL] {
        let off = opts(profile, true, None);
        for (policy, rules) in egress_policies(&off) {
            let text = Value::Array(rules).to_string();
            // Today's workspace reaches the world outside the private ranges,
            // and cluster DNS.
            assert!(
                text.contains("\"cidr\":\"0.0.0.0/0\""),
                "{policy} lost the world rule"
            );
            assert!(text.contains("\"port\":53"), "{policy} lost cluster DNS");
            assert!(
                !text.contains("owning-gateway-name"),
                "{policy} gained a broker peer"
            );
        }
        let template = render_sandbox_template(NAMESPACE, &off);
        let pod = &template["spec"]["podTemplate"]["metadata"];
        assert!(
            pod["labels"]
                .get(crate::egress::admission::EGRESS_MODE_LABEL)
                .is_none()
        );
        assert!(
            pod["annotations"]
                .get(hosted_egress::FENCE_REVISION_ANNOTATION)
                .is_none()
        );
    }
}

#[test]
fn broker_pods_carry_the_label_and_fence_revision_from_creation() {
    // The warm template is what creates identity-free members, so the fence
    // selects them from their first packet.
    let template = render_sandbox_template(
        NAMESPACE,
        &opts(RUNTIME_PROFILE_COMMODITY, false, Some(egress_template())),
    );
    let pod = &template["spec"]["podTemplate"]["metadata"];
    assert_eq!(
        pod["labels"][crate::egress::admission::EGRESS_MODE_LABEL],
        crate::egress::admission::EGRESS_MODE_BROKER
    );
    assert_eq!(
        pod["annotations"][hosted_egress::FENCE_REVISION_ANNOTATION],
        "2"
    );
}

#[test]
fn the_tun_init_runs_the_images_own_cw_and_mounts_nothing() {
    // cw-security (#4955): in emptyDir mode the workspace can write the
    // daemon volume's `cw`, so the privileged init must never run or mount it.
    let opts = opts(RUNTIME_PROFILE_COMMODITY, false, Some(egress_template()));
    let template = render_sandbox_template(NAMESPACE, &opts);
    let spec = &template["spec"]["podTemplate"]["spec"];
    let tun = spec["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|container| container["name"] == hosted_egress::TUN_INIT_CONTAINER)
        .expect("the TUN init container");
    assert_eq!(tun["image"], opts.support_image.as_str());
    assert_eq!(
        tun["command"],
        json!([
            "/usr/local/bin/cw",
            "__hosted-egress-tun",
            "--owner-uid",
            "1000"
        ])
    );
    for key in ["args", "env", "envFrom", "volumeDevices"] {
        assert!(tun.get(key).is_none(), "the TUN init sets {key}: {tun}");
    }
    // Its one mount is the TUN device's memory-backed volume.
    let devnet = json!({ "name": "egress-devnet", "mountPath": "/dev/net" });
    assert_eq!(tun["volumeMounts"], json!([devnet]));
    let volumes: Vec<&Value> = spec["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|volume| volume["name"] == "egress-devnet")
        .collect();
    assert_eq!(
        volumes,
        [&json!({
            "name": "egress-devnet",
            "emptyDir": { "medium": "Memory", "sizeLimit": "1Mi" },
        })]
    );
    // Mounted by the TUN init and the workspace container, and nothing else.
    let mounters: Vec<&str> = spec["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .chain(spec["containers"].as_array().unwrap())
        .filter(|container| {
            container["volumeMounts"]
                .as_array()
                .is_some_and(|mounts| mounts.iter().any(|mount| mount["name"] == "egress-devnet"))
        })
        .map(|container| container["name"].as_str().unwrap())
        .collect();
    assert_eq!(mounters, [hosted_egress::TUN_INIT_CONTAINER, "workspace"]);
    let workspace = spec["containers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|container| container["name"] == "workspace")
        .unwrap();
    assert!(
        workspace["volumeMounts"]
            .as_array()
            .unwrap()
            .contains(&devnet),
        "{workspace}"
    );
    assert!(
        spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|container| container["name"] != hosted_egress::TUN_INIT_CONTAINER)
    );
}

#[test]
fn hosted_egress_renders_only_on_a_vm_runtime() {
    // The TUN init is privileged, which is root only inside a guest VM.
    for profile in ["", RUNTIME_PROFILE_NONE, RUNTIME_PROFILE_RUNC] {
        let refused = opts(profile, false, Some(egress_template()));
        assert!(
            refused.validate_hosted_egress().is_err(),
            "profile {profile:?}"
        );
        assert!(opts(profile, false, None).validate_hosted_egress().is_ok());
    }
    for profile in [RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL] {
        assert!(
            opts(profile, false, Some(egress_template()))
                .validate_hosted_egress()
                .is_ok(),
            "profile {profile:?}"
        );
    }
}

/// The lockdown check holds a template's controller-made policy to
/// `render_template_network_policy` (#4964): the controller copies the
/// template's `networkPolicy` rules under its own selector and both types, so
/// that rendering must carry exactly the rules the template does, with hosted
/// egress on or off.
#[test]
fn the_template_policy_the_lockdown_check_expects_carries_the_templates_rules() {
    for (profile, egress) in [
        (RUNTIME_PROFILE_COMMODITY, None),
        (RUNTIME_PROFILE_COMMODITY, Some(egress_template())),
        (RUNTIME_PROFILE_CONFIDENTIAL, Some(egress_template())),
    ] {
        let opts = opts(profile, true, egress.clone());
        let rules = render_sandbox_template(NAMESPACE, &opts)["spec"]["networkPolicy"].clone();
        let policy = render_template_network_policy(&opts, "2f9c41ab");
        assert_eq!(
            policy["spec"]["podSelector"],
            json!({"matchLabels": {"agents.x-k8s.io/sandbox-template-ref-hash": "2f9c41ab"}})
        );
        assert_eq!(policy["spec"]["policyTypes"], json!(["Ingress", "Egress"]));
        assert_eq!(
            policy["spec"]["egress"],
            rules["egress"],
            "{profile} {}",
            egress.is_some()
        );
        assert_eq!(
            policy["spec"]["ingress"],
            rules.get("ingress").cloned().unwrap_or_else(|| json!([])),
            "{profile} {}",
            egress.is_some()
        );
    }
}
