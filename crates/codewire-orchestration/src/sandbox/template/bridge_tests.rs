//! The warm-member bridge (Program #2238 C6, #2434): goldens, the exact
//! mirror of the environment policies, and label matching against
//! Dev-shaped Pods.

use serde_json::{Value, json};

use super::*;

const NAMESPACE: &str = "dev-sandboxes";
const ENV: &str = "be31063a-8ec8-46d5-aa17-75cda1729370";
const OTHER_ENV: &str = "3d6bb495-efac-419f-bf3a-91696e7c7ca4";
/// The bound member's Sandbox UID, as its warm binding recorded it.
const BOUND_SANDBOX: &str = "0b6f4a52-5d1e-4c2a-9a4e-3f1d2c7b8e90";
const UNBOUND_SANDBOX: &str = "5e2d8c41-7a3b-4f90-b6e1-2c9d0a8f7b34";
const OTHER_SANDBOX: &str = "7c3e9d10-2b4a-4f6e-8d1c-5a9b0e2f4c61";
/// One 32-bit FNV-1a name hash shared by three Sandboxes: the collision a
/// name-hash selector could not tell apart.
const COLLIDING_NAME_HASH: &str = "d0258436";

fn bridge_opts() -> TemplateOpts {
    TemplateOpts {
        name: "tmpl-golden-bridge".into(),
        image: "ghcr.io/codewiresh/workspace:golden".into(),
        support_image: "git.example.invalid/codewire/gateway:golden".into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        environment_id: ENV.into(),
        organization_id: "org-golden-bridge".into(),
        operation_generation: 7,
        gateway_token: "gw-token-golden-bridge".into(),
        daemon_auth_token: "daemon-token-golden-bridge".into(),
        server_namespace: "dev".into(),
        stun_host: "stun.codewire-dev.sh".into(),
        workspace_identity: WorkspaceIdentity::Binding {
            binding_url: "https://codewire-orchestration.dev.svc.cluster.local:8087".into(),
        },
        gateway_daemon_credential_from_binding: true,
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NAMESPACE)),
        ..Default::default()
    }
}

fn bridge(opts: &TemplateOpts) -> Value {
    render_warm_member_bridge(NAMESPACE, opts, BOUND_SANDBOX).unwrap()
}

fn load_golden(name: &str) -> Value {
    let path = format!(
        "{}/tests/fixtures/sandbox/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("Rust-owned golden file missing"))
        .unwrap()
}

#[test]
fn warm_member_bridge_matches_golden_files() {
    assert_eq!(
        bridge(&bridge_opts()),
        load_golden("warm-member-bridge-daemon-networkpolicy.golden.json")
    );
}

#[test]
fn warm_member_bridge_names_are_per_environment_and_dns_safe() {
    let daemon = bridge(&bridge_opts());
    assert_eq!(daemon["metadata"]["name"], format!("cw-daemon-warm-{ENV}"));
    assert_eq!(
        warm_member_daemon_bridge_name(ENV),
        format!("cw-daemon-warm-{ENV}")
    );
    // Only cleanup still names the gateway half an environment bound before
    // the gateway's removal may own.
    assert_eq!(
        warm_member_gateway_bridge_name(ENV),
        format!("cw-gw-warm-{ENV}")
    );
    assert!(daemon["metadata"]["name"].as_str().unwrap().len() <= 63);
    assert_eq!(daemon["metadata"]["namespace"], NAMESPACE);
    assert_eq!(
        daemon["metadata"]["labels"]["codewire.sh/environment-id"],
        ENV
    );
}

/// The bridge grants exactly the ingress of `cw-daemon-net-<env>`, nothing
/// more: the same sources and ports, with only the member selector changed.
#[test]
fn warm_member_bridge_mirrors_the_environment_policy_exactly() {
    for opts in [
        bridge_opts(),
        TemplateOpts {
            credential_runtime: None,
            ..bridge_opts()
        },
        TemplateOpts {
            server_namespace: String::new(),
            stun_host: "stun.example.test".into(),
            ..bridge_opts()
        },
    ] {
        let daemon = bridge(&opts);
        let daemon_net = render_workspace_daemon_network_policy(NAMESPACE, &opts);
        // The member needs no egress beyond the shared template.
        assert_eq!(
            daemon["spec"]["podSelector"],
            json!({"matchLabels": {SANDBOX_UID_LABEL: BOUND_SANDBOX, "codewire.sh/type": "workspace"}})
        );
        assert_eq!(daemon["spec"]["ingress"], daemon_net["spec"]["ingress"]);
        assert!(daemon["spec"].get("egress").is_none());
        assert_eq!(daemon["spec"]["policyTypes"], json!(["Ingress"]));
    }
}

#[test]
fn warm_member_bridge_refuses_anything_but_canonical_uuids() {
    let opts = bridge_opts();
    for sandbox_uid in [
        "",
        COLLIDING_NAME_HASH,
        "0B6F4A52-5D1E-4C2A-9A4E-3F1D2C7B8E90",
        "0b6f4a525d1e4c2a9a4e3f1d2c7b8e90",
        "0b6f4a52-5d1e-4c2a-9a4e-3f1d2c7b8e90,codewire.sh/type=gateway",
    ] {
        assert!(
            render_warm_member_bridge(NAMESPACE, &opts, sandbox_uid).is_err(),
            "{sandbox_uid:?} was accepted"
        );
    }
    let named = TemplateOpts {
        environment_id: "env-golden-commodity".into(),
        ..bridge_opts()
    };
    assert!(render_warm_member_bridge(NAMESPACE, &named, BOUND_SANDBOX).is_err());
}

// ------------------------------------------------- label matching on Dev

/// `matchLabels` semantics: every pair present. An empty selector would
/// select every Pod, which no bridge selector may be.
fn selects(selector: &Value, labels: &Value) -> bool {
    let selector = selector["matchLabels"].as_object().unwrap();
    assert!(!selector.is_empty(), "an empty selector selects every Pod");
    selector
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

/// A pool member before adoption, with the fork's birth labels.
fn unbound_member(sandbox_uid: &str, name_hash: &str) -> Value {
    json!({
        "agents.x-k8s.io/sandbox-name-hash": name_hash,
        "agents.x-k8s.io/sandbox-template-ref-hash": "8c41d0e7",
        "agents.x-k8s.io/warm-pool-sandbox": "1b7e93d4",
        SANDBOX_UID_LABEL: sandbox_uid,
        "codewire.sh/type": "workspace",
    })
}

/// The adopted member once its claim relabelled it.
fn relabelled_member(environment: &str, sandbox_uid: &str) -> Value {
    json!({
        "agents.x-k8s.io/claim-uid": "c0ffee00-9dad-11d1-80b4-00c04fd430c8",
        "agents.x-k8s.io/launch-type": "warm",
        "agents.x-k8s.io/sandbox-name-hash": COLLIDING_NAME_HASH,
        "agents.x-k8s.io/sandbox-template-ref-hash": "8c41d0e7",
        SANDBOX_UID_LABEL: sandbox_uid,
        "codewire.sh/environment-id": environment,
        "codewire.sh/org-id": "org-golden-bridge",
        "codewire.sh/type": "workspace",
    })
}

/// A Pod an environment's gateway Deployment ran before the gateway's
/// removal; a lingering one must never be selected or admitted.
fn gateway_pod(environment: &str) -> Value {
    json!({
        "app.kubernetes.io/component": "gateway",
        "app.kubernetes.io/managed-by": "codewire",
        "app.kubernetes.io/name": "codewire-gateway",
        "codewire.sh/environment-id": environment,
        "codewire.sh/org-id": "org-golden-bridge",
        "codewire.sh/type": "gateway",
        "pod-template-hash": "7d9c8b6f5",
    })
}

fn image_cache_pod() -> Value {
    json!({
        "app.kubernetes.io/component": "image-cache",
        "app.kubernetes.io/managed-by": "codewire",
        "app.kubernetes.io/name": "cw-image-cache",
        "app.kubernetes.io/part-of": "codewire",
        "controller-revision-hash": "6b8f7c9d5",
        "pod-template-generation": "3",
    })
}

/// Dev-shaped Pods a bridge must never select or admit as a member.
fn foreign_pods() -> Vec<(&'static str, Value)> {
    vec![
        (
            "an unbound member",
            unbound_member(UNBOUND_SANDBOX, "5f0c2a91"),
        ),
        (
            "an unbound member with the bound member's name hash",
            unbound_member(UNBOUND_SANDBOX, COLLIDING_NAME_HASH),
        ),
        (
            "another environment's member with the same name hash",
            relabelled_member(OTHER_ENV, OTHER_SANDBOX),
        ),
        ("this environment's gateway Pod", gateway_pod(ENV)),
        ("another environment's gateway Pod", gateway_pod(OTHER_ENV)),
        ("an image-cache Pod", image_cache_pod()),
    ]
}

#[test]
fn warm_member_bridge_selects_exactly_the_bound_member() {
    let selector = bridge(&bridge_opts())["spec"]["podSelector"].clone();
    // Before and after the claim's relabel.
    let mut before = unbound_member(BOUND_SANDBOX, COLLIDING_NAME_HASH);
    before
        .as_object_mut()
        .unwrap()
        .remove("agents.x-k8s.io/warm-pool-sandbox");
    assert!(selects(&selector, &before));
    assert!(selects(&selector, &relabelled_member(ENV, BOUND_SANDBOX)));
    for (label, pod) in foreign_pods() {
        assert!(!selects(&selector, &pod), "member selector chose {label}");
    }
    // Before the fork stamps the label, the bridge selects nothing and the
    // environment policy keeps working as it does today.
    let mut unstamped = relabelled_member(ENV, BOUND_SANDBOX);
    unstamped.as_object_mut().unwrap().remove(SANDBOX_UID_LABEL);
    assert!(!selects(&selector, &unstamped));
    assert!(selects(
        &render_workspace_daemon_network_policy(NAMESPACE, &bridge_opts())["spec"]["podSelector"],
        &unstamped
    ));
}

#[test]
fn warm_member_bridge_admits_orchestration_and_the_world_only() {
    let opts = TemplateOpts {
        stun_host: "stun.example.test".into(),
        ..bridge_opts()
    };
    let daemon = bridge(&opts);
    let ingress = daemon["spec"]["ingress"].as_array().unwrap();
    assert_eq!(ingress.len(), 2, "{ingress:?}");
    for rule in ingress {
        for peer in rule["from"].as_array().unwrap() {
            if let Some(block) = peer.get("ipBlock") {
                // The tailnet UDP port, from the world only (N1).
                assert_eq!(
                    rule["ports"],
                    json!([{"protocol": "UDP", "port": codewire_gateway_proto::WORKSPACE_TAILNET_UDP_PORT}])
                );
                assert!(
                    block["except"]
                        .as_array()
                        .is_some_and(|except| !except.is_empty()),
                    "{block}"
                );
                continue;
            }
            // No same-namespace peer: no gateway, no other workspace.
            assert_eq!(
                peer["namespaceSelector"],
                json!({"matchLabels": {"kubernetes.io/metadata.name": "dev"}})
            );
            assert_eq!(
                peer["podSelector"],
                json!({"matchLabels": {"app.kubernetes.io/name": "codewire", "app.kubernetes.io/component": "orchestration"}})
            );
        }
    }
}
