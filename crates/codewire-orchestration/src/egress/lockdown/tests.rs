use serde_json::{Value, json};

use super::*;
use crate::sandbox::LABEL_TYPE;

const ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";
const ANOTHER: &str = "9d2a4b7c-51f3-4e0a-8b66-2a7c1e5f3d08";

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

fn live(edit: impl FnOnce(&mut Value)) -> NetworkPolicyFacts {
    let mut policy = rendered();
    edit(&mut policy.spec);
    policy
}

fn check(guest: &MemberFacts, live: Option<&NetworkPolicyFacts>) -> Result<(), LockdownRefusal> {
    lockdown_applied(guest, ENVIRONMENT, Some(&rendered()), live)
}

#[test]
fn a_bound_broker_pod_under_exactly_the_rendered_policy_passes() {
    assert_eq!(
        policy_name(ENVIRONMENT),
        workspace_daemon_network_policy_name(ENVIRONMENT)
    );
    assert_eq!(check(&bound(), Some(&rendered())), Ok(()));
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
            check(&guest, Some(&rendered())),
            Err(LockdownRefusal::NotLabelledForItsBinding)
        );
    }
    let not_broker = guest(&[(LABEL_ENV_ID, ENVIRONMENT), (LABEL_TYPE, "workspace")]);
    assert_eq!(
        check(&not_broker, Some(&rendered())),
        Err(LockdownRefusal::NotBrokerMode)
    );
}

#[test]
fn any_difference_from_the_rendered_policy_fails_closed() {
    assert_eq!(check(&bound(), None), Err(LockdownRefusal::PolicyMissing));
    assert_eq!(
        lockdown_applied(&bound(), ENVIRONMENT, None, Some(&rendered())),
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
            check(&bound(), Some(&different)),
            Err(LockdownRefusal::PolicyDiffers),
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
        check(&untyped, Some(&rendered())),
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
            lockdown_applied(&bound(), ENVIRONMENT, Some(&policy), Some(&policy)),
            Err(LockdownRefusal::PolicyDoesNotSelect),
            "{}",
            policy.spec
        );
    }
}
