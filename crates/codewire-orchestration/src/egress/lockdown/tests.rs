use serde_json::{Value, json};

use super::*;
use crate::sandbox::LABEL_TYPE;
use crate::sandbox::template::{SANDBOX_UID_LABEL, warm_member_daemon_bridge_name};

const ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";
const ANOTHER: &str = "9d2a4b7c-51f3-4e0a-8b66-2a7c1e5f3d08";
/// The guest's template hash, and another template's.
const HASH: &str = "2f9c41ab";
const ANOTHER_HASH: &str = "77d0e3c5";
const TEMPLATE_POLICY: &str = "warm-2000m-4096mi-20gi-r7-network-policy";
/// The Sandbox UID the guest's warm binding recorded, and another Sandbox's.
const SANDBOX_UID: &str = "51c208bf-0e29-452b-8d74-06d77da367a9";
const ANOTHER_SANDBOX_UID: &str = "c3a1e7d2-6f4b-4b9a-9e2d-7a5f0c1b8e44";

fn guest(labels: &[(&str, &str)]) -> MemberFacts {
    MemberFacts {
        name: Some("cw-guest".to_owned()),
        namespace: Some("dev-sandboxes".to_owned()),
        uid: Some("6bf8d155-e84c-4fc5-b479-b17022fe41dd".to_owned()),
        terminating: false,
        service_account: None,
        controllers: Vec::new(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        has_spec: true,
        volumes: Vec::new(),
        containers: Vec::new(),
        init_containers: Vec::new(),
        image_ids: Vec::new(),
        ip: String::new(),
        ips: Vec::new(),
        phase: Some("Running".to_owned()),
        node_name: None,
        spec_json: serde_json::Value::Null,
    }
}

fn bound() -> MemberFacts {
    guest(&[
        (LABEL_ENV_ID, ENVIRONMENT),
        (LABEL_TYPE, "workspace"),
        (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
        (TEMPLATE_REF_HASH_LABEL, HASH),
    ])
}

/// A policy shaped like the one orchestration renders for `ENVIRONMENT`.
fn rendered() -> NetworkPolicyFacts {
    NetworkPolicyFacts {
        spec: json!({
            "podSelector": {"matchLabels": {LABEL_ENV_ID: ENVIRONMENT, LABEL_TYPE: "workspace"}},
            "policyTypes": ["Ingress", "Egress"],
            "egress": [{
                "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                "ports": [{"protocol": "UDP", "port": 53}],
            }],
        }),
    }
}

/// The controller's policy for the guest's template, shaped like the one
/// orchestration renders for a broker-mode template.
fn template() -> NetworkPolicyFacts {
    template_for(HASH)
}

fn template_for(hash: &str) -> NetworkPolicyFacts {
    NetworkPolicyFacts {
        spec: json!({
            "podSelector": {"matchLabels": {TEMPLATE_REF_HASH_LABEL: hash}},
            "policyTypes": ["Ingress", "Egress"],
            "egress": [{
                "to": [{"podSelector": {"matchLabels": {"app": "cw-egress"}}}],
                "ports": [{"protocol": "TCP", "port": 8089}],
            }],
        }),
    }
}

/// The controller's default for a template with no `networkPolicy`: every
/// public address. A template made before hosted egress has this.
fn wide_template() -> NetworkPolicyFacts {
    NetworkPolicyFacts {
        spec: json!({
            "podSelector": {"matchLabels": {TEMPLATE_REF_HASH_LABEL: HASH}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "sandbox-router"}}}]}],
            "egress": [{"to": [
                {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]}},
                {"ipBlock": {"cidr": "::/0", "except": ["fc00::/7", "fe80::/10"]}},
            ]}],
        }),
    }
}

fn named(name: &str, facts: NetworkPolicyFacts) -> NamedNetworkPolicy {
    NamedNetworkPolicy {
        name: name.to_owned(),
        facts,
    }
}

fn own(facts: NetworkPolicyFacts) -> NamedNetworkPolicy {
    named(&policy_name(ENVIRONMENT), facts)
}

fn live(edit: impl FnOnce(&mut Value)) -> NetworkPolicyFacts {
    let mut policy = rendered();
    edit(&mut policy.spec);
    policy
}

fn check(guest: &MemberFacts, live: &[NamedNetworkPolicy]) -> Result<(), LockdownRefusal> {
    lockdown_applied(
        guest,
        ENVIRONMENT,
        Some(&rendered()),
        Some(&template()),
        Some(&bridge_for(SANDBOX_UID)),
        live,
    )
}

fn differs(policy: &str) -> Result<(), LockdownRefusal> {
    Err(LockdownRefusal::PolicyDiffers {
        policy: policy.to_owned(),
    })
}

#[test]
fn a_bound_broker_pod_under_exactly_the_rendered_policy_passes() {
    assert_eq!(
        policy_name(ENVIRONMENT),
        workspace_daemon_network_policy_name(ENVIRONMENT)
    );
    assert_eq!(check(&bound(), &[own(rendered())]), Ok(()));
    assert_eq!(
        check(
            &bound(),
            &[own(rendered()), named(TEMPLATE_POLICY, template())]
        ),
        Ok(())
    );
}

#[test]
fn a_bound_pod_is_checked_whatever_its_labels_say() {
    let stripped = guest(&[
        (LABEL_TYPE, "workspace"),
        (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
    ]);
    let relabelled = guest(&[
        (LABEL_ENV_ID, ANOTHER),
        (LABEL_TYPE, "workspace"),
        (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
    ]);
    for guest in [stripped, relabelled] {
        assert_eq!(
            check(&guest, &[own(rendered())]),
            Err(LockdownRefusal::NotLabelledForItsBinding)
        );
    }
    let not_broker = guest(&[(LABEL_ENV_ID, ENVIRONMENT), (LABEL_TYPE, "workspace")]);
    assert_eq!(
        check(&not_broker, &[own(rendered())]),
        Err(LockdownRefusal::NotBrokerMode)
    );
}

#[test]
fn any_difference_from_the_rendered_policy_fails_closed() {
    assert_eq!(check(&bound(), &[]), Err(LockdownRefusal::PolicyMissing));
    assert_eq!(
        check(&bound(), &[named(TEMPLATE_POLICY, template())]),
        Err(LockdownRefusal::PolicyMissing)
    );
    assert_eq!(
        lockdown_applied(&bound(), ENVIRONMENT, None, None, None, &[own(rendered())]),
        Err(LockdownRefusal::PolicyUnmanaged)
    );
    let allow_all = live(|spec| spec["egress"] = json!([{}]));
    let extra_rule = live(|spec| {
        spec["egress"]
            .as_array_mut()
            .unwrap()
            .push(json!({"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}));
    });
    let no_rules = live(|spec| {
        spec.as_object_mut().unwrap().remove("egress");
    });
    let ingress_only = live(|spec| spec["policyTypes"] = json!(["Ingress"]));
    let every_pod = live(|spec| spec["podSelector"] = json!({}));
    let another_environment =
        live(|spec| spec["podSelector"]["matchLabels"][LABEL_ENV_ID] = json!(ANOTHER));
    for different in [
        allow_all,
        extra_rule,
        no_rules,
        ingress_only,
        every_pod,
        another_environment,
    ] {
        assert_eq!(
            check(&bound(), &[own(different.clone())]),
            differs(&policy_name(ENVIRONMENT)),
            "{}",
            different.spec
        );
    }
}

#[test]
fn the_rendered_policy_must_select_the_pod() {
    let untyped = guest(&[
        (LABEL_ENV_ID, ENVIRONMENT),
        (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
    ]);
    assert_eq!(
        check(&untyped, &[own(rendered())]),
        Err(LockdownRefusal::PolicyDoesNotSelect)
    );
    for unselective in [
        json!({"podSelector": {}}),
        json!({"podSelector": {"matchLabels": {}}}),
        json!({"podSelector": {
            "matchLabels": {LABEL_ENV_ID: ENVIRONMENT},
            "matchExpressions": [{"key": LABEL_TYPE, "operator": "Exists"}],
        }}),
    ] {
        let policy = NetworkPolicyFacts { spec: unselective };
        assert_eq!(
            lockdown_applied(
                &bound(),
                ENVIRONMENT,
                Some(&policy),
                None,
                None,
                &[own(policy.clone())]
            ),
            Err(LockdownRefusal::PolicyDoesNotSelect),
            "{}",
            policy.spec
        );
    }
}

#[test]
fn a_wide_template_policy_beside_an_exact_environment_policy_fails_closed() {
    // #4964: a template made before hosted egress keeps the controller's
    // default, which adds every public address to what the Pod may reach.
    assert_eq!(
        check(
            &bound(),
            &[own(rendered()), named(TEMPLATE_POLICY, wide_template())]
        ),
        differs(TEMPLATE_POLICY)
    );
    // The template's form under another name is not the controller's policy.
    assert_eq!(
        check(
            &bound(),
            &[own(rendered()), named("copied-policy", template())]
        ),
        differs("copied-policy")
    );
    // A Pod without a template hash has no template policy to accept.
    let unhashed = guest(&[
        (LABEL_ENV_ID, ENVIRONMENT),
        (LABEL_TYPE, "workspace"),
        (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
    ]);
    let any_hash = NetworkPolicyFacts {
        spec: json!({
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
        }),
    };
    assert_eq!(
        lockdown_applied(
            &unhashed,
            ENVIRONMENT,
            Some(&rendered()),
            None,
            None,
            &[own(rendered()), named(TEMPLATE_POLICY, any_hash)]
        ),
        differs(TEMPLATE_POLICY)
    );
}

#[test]
fn another_templates_policy_does_not_select_the_pod() {
    assert_eq!(
        check(
            &bound(),
            &[
                own(rendered()),
                named("warm-other-network-policy", template_for(ANOTHER_HASH))
            ]
        ),
        Ok(())
    );
}

#[test]
fn any_other_policy_with_a_rule_that_selects_the_pod_fails_closed() {
    let wide = |selector: Value| NetworkPolicyFacts {
        spec: json!({
            "podSelector": selector,
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
        }),
    };
    for selector in [
        json!({}),
        json!({"matchLabels": {LABEL_TYPE: "workspace"}}),
        json!({"matchExpressions": [{"key": LABEL_TYPE, "operator": "In", "values": ["workspace", "other"]}]}),
        json!({"matchExpressions": [{"key": LABEL_TYPE, "operator": "NotIn", "values": ["other"]}]}),
        json!({"matchExpressions": [{"key": "absent", "operator": "DoesNotExist"}]}),
        json!({"matchExpressions": [{"key": LABEL_ENV_ID, "operator": "Exists"}]}),
        // One this cannot read counts as selecting.
        json!({"matchExpressions": [{"key": LABEL_TYPE, "operator": "Gt", "values": ["1"]}]}),
    ] {
        assert_eq!(
            check(
                &bound(),
                &[own(rendered()), named("extra", wide(selector.clone()))]
            ),
            differs("extra"),
            "{selector}"
        );
    }
    // A selector the Pod does not match is someone else's policy.
    for selector in [
        json!({"matchLabels": {LABEL_TYPE: "other"}}),
        json!({"matchExpressions": [{"key": LABEL_TYPE, "operator": "In", "values": ["other"]}]}),
        json!({"matchExpressions": [{"key": LABEL_TYPE, "operator": "NotIn", "values": ["workspace"]}]}),
        json!({"matchExpressions": [{"key": "absent", "operator": "Exists"}]}),
        json!({"matchExpressions": [{"key": LABEL_TYPE, "operator": "DoesNotExist"}]}),
    ] {
        assert_eq!(
            check(
                &bound(),
                &[own(rendered()), named("elsewhere", wide(selector.clone()))]
            ),
            Ok(()),
            "{selector}"
        );
    }
}

#[test]
fn a_policy_with_no_rules_allows_nothing_and_passes() {
    // cw-security on #4964: zero rules in both directions, whatever the types.
    for allow_free in [
        json!({"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}),
        json!({"podSelector": {}, "policyTypes": ["Egress"], "egress": []}),
        json!({"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [], "egress": []}),
    ] {
        assert_eq!(
            check(
                &bound(),
                &[
                    own(rendered()),
                    named(
                        "default-deny",
                        NetworkPolicyFacts {
                            spec: allow_free.clone()
                        }
                    )
                ]
            ),
            Ok(()),
            "{allow_free}"
        );
    }
    // One empty rule allows everything in its direction.
    for allow_all in [
        json!({"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{}]}),
        json!({"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]}),
    ] {
        assert_eq!(
            check(
                &bound(),
                &[
                    own(rendered()),
                    named(
                        "allow-all",
                        NetworkPolicyFacts {
                            spec: allow_all.clone()
                        }
                    )
                ]
            ),
            differs("allow-all"),
            "{allow_all}"
        );
    }
}

/// The adopted warm member's bridge (#2434), shaped like the one orchestration
/// renders for `ENVIRONMENT`'s member `uid`: ingress only, by Sandbox UID.
fn bridge_for(uid: &str) -> NetworkPolicyFacts {
    NetworkPolicyFacts {
        spec: json!({
            "podSelector": {"matchLabels": {SANDBOX_UID_LABEL: uid, LABEL_TYPE: "workspace"}},
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "dev"}},
                    "podSelector": {"matchLabels": {"app.kubernetes.io/component": "orchestration"}},
                }],
                "ports": [{"protocol": "TCP", "port": 7777}],
            }],
        }),
    }
}

fn claimed() -> MemberFacts {
    guest(&[
        (LABEL_ENV_ID, ENVIRONMENT),
        (LABEL_TYPE, "workspace"),
        (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
        (TEMPLATE_REF_HASH_LABEL, HASH),
        (SANDBOX_UID_LABEL, SANDBOX_UID),
    ])
}

#[test]
fn a_claimed_warm_member_under_its_rendered_bridge_passes() {
    // Dev, 2026-11-21 (#4000): a pooled create's member carried its own
    // policy, its template's and its bridge, each as orchestration rendered
    // it, and was refused `policy_differs` on the bridge.
    assert_eq!(
        check(
            &claimed(),
            &[
                own(rendered()),
                named(TEMPLATE_POLICY, template()),
                named(
                    &warm_member_daemon_bridge_name(ENVIRONMENT),
                    bridge_for(SANDBOX_UID)
                ),
            ]
        ),
        Ok(())
    );
}

#[test]
fn a_bridge_that_is_not_exactly_the_rendered_one_fails_closed() {
    let name = warm_member_daemon_bridge_name(ENVIRONMENT);
    let bridge = |edit: fn(&mut Value)| {
        let mut policy = bridge_for(SANDBOX_UID);
        edit(&mut policy.spec);
        policy
    };
    for (live_name, live_policy) in [
        // One rule added to it.
        (
            name.clone(),
            bridge(|spec| {
                spec["ingress"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}));
            }),
        ),
        // A render from other settings: an older revision's.
        (
            name.clone(),
            bridge(|spec| spec["ingress"][0]["ports"][0]["port"] = json!(7778)),
        ),
        // The same name, with egress added.
        (
            name.clone(),
            bridge(|spec| {
                spec["policyTypes"] = json!(["Ingress", "Egress"]);
                spec["egress"] = json!([{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]);
            }),
        ),
        // Another environment's bridge, selecting this member.
        (
            warm_member_daemon_bridge_name(ANOTHER),
            bridge_for(SANDBOX_UID),
        ),
        // The rendered content under another name.
        ("copied-bridge".to_owned(), bridge_for(SANDBOX_UID)),
    ] {
        assert_eq!(
            check(
                &claimed(),
                &[own(rendered()), named(&live_name, live_policy.clone())]
            ),
            differs(&live_name),
            "{live_name}: {}",
            live_policy.spec
        );
    }
    // With no rendered bridge (a binding that recorded no Sandbox UID), a
    // live one is not accepted either.
    assert_eq!(
        lockdown_applied(
            &claimed(),
            ENVIRONMENT,
            Some(&rendered()),
            Some(&template()),
            None,
            &[own(rendered()), named(&name, bridge_for(SANDBOX_UID))]
        ),
        differs(&name)
    );
}

#[test]
fn a_bridge_for_another_sandbox_does_not_select_the_member() {
    // Rendered for the binding's Sandbox, a bridge naming another Sandbox's
    // UID selects another Pod, so it neither passes nor fails this one.
    assert_eq!(
        check(
            &claimed(),
            &[
                own(rendered()),
                named(
                    &warm_member_daemon_bridge_name(ENVIRONMENT),
                    bridge_for(ANOTHER_SANDBOX_UID)
                ),
            ]
        ),
        Ok(())
    );
}
