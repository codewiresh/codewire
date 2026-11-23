use super::*;

const PEER: &str = "codewire-trustee:app=kbs,app.kubernetes.io/instance=codewire-trustee,app.kubernetes.io/name=trustee";

#[test]
fn a_peer_is_a_namespace_and_its_labels() {
    let peer = KbsPeer::parse(PEER).unwrap();
    assert_eq!(peer.namespace, "codewire-trustee");
    assert_eq!(
        peer.labels,
        BTreeMap::from([
            ("app".to_string(), "kbs".to_string()),
            (
                "app.kubernetes.io/instance".to_string(),
                "codewire-trustee".to_string()
            ),
            ("app.kubernetes.io/name".to_string(), "trustee".to_string()),
        ])
    );
}

#[test]
fn a_malformed_peer_is_refused() {
    for value in [
        "",
        "codewire-trustee",
        "codewire-trustee:",
        ":app=kbs",
        "Codewire-Trustee:app=kbs",
        "codewire-trustee:app",
        "codewire-trustee:app=",
        "codewire-trustee:app=kbs,app=other",
        "codewire-trustee:-app=kbs",
        "codewire-trustee:app=kbs,",
        "codewire-trustee:bad..prefix/name=kbs",
    ] {
        assert!(KbsPeer::parse(value).is_err(), "{value:?} parsed");
    }
}

#[test]
fn the_rule_admits_only_pods_with_the_labels_in_the_namespace() {
    // cw-security's condition (#4000): a Pod in the key broker's namespace
    // without its labels is not reachable through this rule. One peer with
    // both selectors is an AND; two peers would admit the whole namespace.
    let rule = KbsPeer::parse(PEER)
        .unwrap()
        .egress_rule("https://10.44.0.45:8080")
        .unwrap();
    assert_eq!(
        rule,
        json!({
            "to": [
                {
                    "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": "codewire-trustee" } },
                    "podSelector": { "matchLabels": {
                        "app": "kbs",
                        "app.kubernetes.io/instance": "codewire-trustee",
                        "app.kubernetes.io/name": "trustee",
                    } },
                },
            ],
            "ports": [{ "protocol": "TCP", "port": 8080 }],
        })
    );
}

#[test]
fn the_rule_takes_its_port_from_the_url_and_needs_one() {
    let peer = KbsPeer::parse(PEER).unwrap();
    assert_eq!(
        peer.egress_rule("https://10.44.0.45").unwrap()["ports"],
        json!([{ "protocol": "TCP", "port": 443 }])
    );
    assert_eq!(peer.egress_rule("not a url"), None);
}

#[test]
fn an_address_url_needs_a_peer() {
    let peer = KbsPeer::parse(PEER).unwrap();
    for url in ["https://10.44.0.45:8080", "https://[fd00::45]:8080"] {
        assert!(require_peer_for_address(url, None).is_err(), "{url}");
        require_peer_for_address(url, Some(&peer)).unwrap();
    }
    for url in [
        "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080",
        "",
    ] {
        require_peer_for_address(url, None).unwrap();
    }
}

#[test]
#[should_panic(expected = "must name the key broker's Pods")]
fn settings_refuse_an_address_without_a_peer() {
    let getenv = |key: &str, default: &str| match key {
        "SANDBOX_KATA_COCO_KBS_URL" => "https://10.44.0.45:8080".to_string(),
        _ => default.to_string(),
    };
    KbsSettings::from_env(&getenv);
}

#[test]
fn settings_read_the_url_and_the_peer() {
    let getenv = |key: &str, default: &str| match key {
        "SANDBOX_KATA_COCO_KBS_URL" => "https://10.44.0.45:8080".to_string(),
        KBS_PEER_ENV => PEER.to_string(),
        _ => default.to_string(),
    };
    let settings = KbsSettings::from_env(&getenv);
    assert_eq!(settings.url, "https://10.44.0.45:8080");
    assert_eq!(settings.ca_pem, "");
    assert_eq!(settings.peer, Some(KbsPeer::parse(PEER).unwrap()));
}

#[test]
fn settings_without_a_peer_keep_todays_url_fallback() {
    let getenv = |key: &str, default: &str| match key {
        "CONFIDENTIAL_STORAGE_KBS_URL" => {
            "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080".to_string()
        }
        _ => default.to_string(),
    };
    let settings = KbsSettings::from_env(&getenv);
    assert_eq!(
        settings.url,
        "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080"
    );
    assert_eq!(settings.peer, None);
}
