use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
const OTHER_PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
const PUBLIC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

fn request(
    address: IpAddr,
    port: u16,
    hostname: Option<&str>,
    route_class: RouteClass,
) -> EgressRequest {
    EgressRequest::tcp(address, port, hostname, route_class).unwrap()
}

fn rule(id: &str, action: PolicyAction) -> PolicyRule {
    PolicyRule {
        id: id.to_string(),
        action,
        protocols: vec![EgressProtocol::Tcp],
        ports: vec![443],
        cidrs: vec!["0.0.0.0/0".to_string()],
        destinations: Vec::new(),
        route_classes: vec![RouteClass::General],
    }
}

fn document(rules: Vec<PolicyRule>) -> PolicyDocument {
    PolicyDocument {
        version: POLICY_SCHEMA_VERSION,
        default: PolicyAction::Deny,
        rules,
    }
}

#[test]
fn developer_baseline_allows_public_general_dns_and_tcp_only() {
    let policy = CompiledPolicy::developer_baseline();
    assert_eq!(policy.digest().to_hex(), DEVELOPER_BASELINE_DIGEST);
    for address in [PUBLIC_V4, PUBLIC_V6] {
        let decision = policy.evaluate(&request(address, 443, None, RouteClass::General));
        assert!(decision.is_allowed(), "public address {address} was denied");
        assert_eq!(decision.reason, DecisionReason::RuleAllow);
        assert_eq!(decision.rule_id.as_deref(), Some("developer-public-tcp"));
    }

    let query = EgressRequest::dns_query("registry.npmjs.org", RouteClass::General).unwrap();
    assert!(policy.evaluate(&query).is_allowed());
    let answer =
        EgressRequest::dns_answer("registry.npmjs.org", PUBLIC_V4, RouteClass::General).unwrap();
    assert!(policy.evaluate(&answer).is_allowed());

    let credential = request(PUBLIC_V4, 443, None, RouteClass::Credential);
    let mesh = request(PUBLIC_V4, 443, None, RouteClass::Mesh);
    let uncurated_port = request(PUBLIC_V4, 25, None, RouteClass::General);
    assert_eq!(
        policy.evaluate(&credential).reason,
        DecisionReason::DefaultDeny
    );
    assert_eq!(policy.evaluate(&mesh).reason, DecisionReason::DefaultDeny);
    assert_eq!(
        policy.evaluate(&uncurated_port).reason,
        DecisionReason::DefaultDeny
    );
}

#[test]
fn protected_addresses_override_an_explicit_public_allow() {
    let policy = CompiledPolicy::developer_baseline();
    let cases = [
        ("0.0.0.1", AddressClass::Unspecified),
        ("10.0.0.1", AddressClass::Private),
        ("100.64.0.1", AddressClass::Shared),
        ("127.0.0.1", AddressClass::Loopback),
        ("169.254.169.254", AddressClass::LinkLocal),
        ("172.16.1.1", AddressClass::Private),
        ("192.168.1.1", AddressClass::Private),
        ("192.0.2.1", AddressClass::Documentation),
        ("198.18.0.1", AddressClass::Benchmark),
        ("198.51.100.1", AddressClass::Documentation),
        ("203.0.113.1", AddressClass::Documentation),
        ("224.0.0.1", AddressClass::Multicast),
        ("240.0.0.1", AddressClass::Reserved),
        ("::", AddressClass::Unspecified),
        ("::1", AddressClass::Loopback),
        ("::ffff:127.0.0.1", AddressClass::Mapped),
        ("::127.0.0.1", AddressClass::Mapped),
        ("64:ff9b::7f00:1", AddressClass::Mapped),
        ("64:ff9b:1::7f00:1", AddressClass::Mapped),
        ("fc00::1", AddressClass::Private),
        ("fe80::1", AddressClass::LinkLocal),
        ("fec0::1", AddressClass::Reserved),
        ("ff02::1", AddressClass::Multicast),
        ("2001:db8::1", AddressClass::Documentation),
        ("2001:2::1", AddressClass::Benchmark),
        ("2002::1", AddressClass::Reserved),
        ("3fff::1", AddressClass::Reserved),
        ("5f00::1", AddressClass::Reserved),
    ];
    for (address, class) in cases {
        let address = address.parse().unwrap();
        let decision = policy.evaluate(&request(address, 443, None, RouteClass::General));
        assert_eq!(
            decision.reason,
            DecisionReason::ProtectedAddress(class),
            "wrong classification for {address}"
        );
        assert_eq!(decision.rule_id, None);
    }
}

#[test]
fn protected_names_override_dns_and_tcp_allows() {
    let policy = CompiledPolicy::developer_baseline();
    let cases = [
        ("localhost", NameClass::Localhost),
        ("api.localhost", NameClass::Localhost),
        ("printer.local", NameClass::Local),
        ("service.internal", NameClass::Internal),
        ("router.home.arpa", NameClass::Home),
        ("anything.invalid", NameClass::Reserved),
        ("fixture.test", NameClass::Reserved),
    ];
    for (name, class) in cases {
        let query = EgressRequest::dns_query(name, RouteClass::General).unwrap();
        assert_eq!(
            policy.evaluate(&query).reason,
            DecisionReason::ProtectedName(class),
            "wrong classification for {name}"
        );
        let tcp = request(PUBLIC_V4, 443, Some(name), RouteClass::General);
        assert_eq!(
            policy.evaluate(&tcp).reason,
            DecisionReason::ProtectedName(class)
        );
    }
}

#[test]
fn dns_answers_are_rechecked_against_the_address_boundary() {
    let policy = CompiledPolicy::developer_baseline();
    let query = EgressRequest::dns_query("registry.npmjs.org", RouteClass::General).unwrap();
    assert!(policy.evaluate(&query).is_allowed());

    let rebound = EgressRequest::dns_answer(
        "registry.npmjs.org",
        "169.254.169.254".parse().unwrap(),
        RouteClass::General,
    )
    .unwrap();
    assert_eq!(
        policy.evaluate(&rebound).reason,
        DecisionReason::ProtectedAddress(AddressClass::LinkLocal)
    );
}

#[test]
fn explicit_deny_wins_independent_of_rule_order() {
    let allow = rule("z-allow", PolicyAction::Allow);
    let deny = rule("a-deny", PolicyAction::Deny);
    for rules in [
        vec![allow.clone(), deny.clone()],
        vec![deny.clone(), allow.clone()],
    ] {
        let policy = CompiledPolicy::compile(document(rules)).unwrap();
        let decision = policy.evaluate(&request(PUBLIC_V4, 443, None, RouteClass::General));
        assert_eq!(decision.action, DecisionAction::Deny);
        assert_eq!(decision.reason, DecisionReason::RuleDeny);
        assert_eq!(decision.rule_id.as_deref(), Some("a-deny"));
    }
}

#[test]
fn rule_categories_are_and_ed_while_values_within_them_are_or_ed() {
    let policy = CompiledPolicy::compile(document(vec![PolicyRule {
        id: "named-web".to_string(),
        action: PolicyAction::Allow,
        protocols: vec![EgressProtocol::Tcp],
        ports: vec![443, 8443],
        cidrs: vec!["8.0.0.0/8".to_string(), "93.0.0.0/8".to_string()],
        destinations: vec![
            "api.example.com".to_string(),
            "*.packages.example.com".to_string(),
        ],
        route_classes: vec![RouteClass::General],
    }]))
    .unwrap();

    assert!(
        policy
            .evaluate(&request(
                PUBLIC_V4,
                443,
                Some("api.example.com"),
                RouteClass::General,
            ))
            .is_allowed()
    );
    assert!(
        policy
            .evaluate(&request(
                OTHER_PUBLIC_V4,
                8443,
                Some("deep.packages.example.com"),
                RouteClass::General,
            ))
            .is_allowed()
    );
    for denied in [
        request(PUBLIC_V4, 80, Some("api.example.com"), RouteClass::General),
        request(PUBLIC_V4, 443, Some("example.com"), RouteClass::General),
        request(
            PUBLIC_V4,
            443,
            Some("api.example.com"),
            RouteClass::Credential,
        ),
        request(
            "1.1.1.1".parse().unwrap(),
            443,
            Some("api.example.com"),
            RouteClass::General,
        ),
    ] {
        assert_eq!(policy.evaluate(&denied).reason, DecisionReason::DefaultDeny);
    }
}

#[test]
fn canonical_digest_ignores_rule_and_selector_order_but_not_semantics() {
    let mut first = rule("second", PolicyAction::Allow);
    first.ports = vec![8443, 443];
    first.cidrs = vec!["93.0.0.0/8".to_string(), "8.0.0.0/8".to_string()];
    let second = rule("first", PolicyAction::Deny);

    let mut reordered_first = first.clone();
    reordered_first.ports.reverse();
    reordered_first.cidrs.reverse();
    let left = CompiledPolicy::compile(document(vec![first, second.clone()])).unwrap();
    let right = CompiledPolicy::compile(document(vec![second, reordered_first.clone()])).unwrap();
    assert_eq!(left.digest(), right.digest());
    assert_eq!(
        left.canonical_json().unwrap(),
        right.canonical_json().unwrap()
    );
    assert_eq!(left.digest().to_hex().len(), 64);

    reordered_first.action = PolicyAction::Deny;
    let changed = CompiledPolicy::compile(document(vec![reordered_first])).unwrap();
    assert_ne!(left.digest(), changed.digest());
}

#[test]
fn yaml_parser_is_strict_and_normalizes_names() {
    let policy = PolicyDocument::parse_yaml(
        br#"
version: 1
default: deny
rules:
  - id: named
    action: allow
    protocols: [tcp]
    ports: [443]
    cidrs: [93.0.0.0/8]
    destinations: [API.Example.COM.]
    route_classes: [general]
"#,
    )
    .unwrap();
    assert_eq!(
        policy.canonical_document().rules[0].destinations,
        ["api.example.com"]
    );

    let unknown = b"version: 1\ndefault: deny\nrules: []\nunknown: true\n";
    assert!(matches!(
        PolicyDocument::parse_yaml(unknown),
        Err(PolicyError::Yaml(_))
    ));
}

#[test]
fn malformed_policy_documents_fail_closed() {
    let invalid = [
        PolicyDocument {
            version: 2,
            default: PolicyAction::Deny,
            rules: Vec::new(),
        },
        PolicyDocument {
            version: 1,
            default: PolicyAction::Allow,
            rules: Vec::new(),
        },
        document(vec![PolicyRule {
            id: "Bad Id".to_string(),
            ..rule("valid", PolicyAction::Allow)
        }]),
        document(vec![
            rule("duplicate", PolicyAction::Allow),
            rule("duplicate", PolicyAction::Deny),
        ]),
        document(vec![PolicyRule {
            id: "duplicate-port".to_string(),
            ports: vec![443, 443],
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "no-protocol".to_string(),
            protocols: Vec::new(),
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "no-route".to_string(),
            route_classes: Vec::new(),
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "no-destination".to_string(),
            cidrs: Vec::new(),
            destinations: Vec::new(),
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "zero-port".to_string(),
            ports: vec![0],
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "host-bits".to_string(),
            cidrs: vec!["10.0.0.1/8".to_string()],
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "bad-name".to_string(),
            destinations: vec!["*bad.example.com".to_string()],
            ..rule("ignored", PolicyAction::Allow)
        }]),
        document(vec![PolicyRule {
            id: "dns-without-name".to_string(),
            protocols: vec![EgressProtocol::Dns],
            destinations: Vec::new(),
            ..rule("ignored", PolicyAction::Allow)
        }]),
    ];
    for document in invalid {
        assert!(CompiledPolicy::compile(document).is_err());
    }
}

#[test]
fn document_rule_and_selector_limits_are_enforced() {
    let oversized = vec![b'x'; MAX_POLICY_DOCUMENT_BYTES + 1];
    assert!(matches!(
        PolicyDocument::parse_yaml(&oversized),
        Err(PolicyError::DocumentTooLarge { .. })
    ));

    let too_many_rules = (0..=MAX_POLICY_RULES)
        .map(|index| rule(&format!("rule-{index}"), PolicyAction::Deny))
        .collect();
    assert!(matches!(
        CompiledPolicy::compile(document(too_many_rules)),
        Err(PolicyError::TooManyRules { .. })
    ));

    let mut selector_heavy = rule("selector-heavy", PolicyAction::Allow);
    selector_heavy.ports = (1..=(MAX_RULE_SELECTORS as u16)).collect();
    assert!(matches!(
        CompiledPolicy::compile(document(vec![selector_heavy])),
        Err(PolicyError::TooManySelectors { .. })
    ));
}

#[test]
fn invalid_runtime_requests_are_rejected_before_evaluation() {
    assert!(matches!(
        EgressRequest::tcp(PUBLIC_V4, 0, None, RouteClass::General),
        Err(PolicyError::InvalidRequest { field: "port", .. })
    ));
    for hostname in ["", "127.0.0.1", "bad_name.example"] {
        assert!(matches!(
            EgressRequest::dns_query(hostname, RouteClass::General),
            Err(PolicyError::InvalidRequest {
                field: "hostname",
                ..
            })
        ));
    }
}

#[test]
fn decisions_expose_only_bounded_reason_rule_and_digest() {
    let policy = CompiledPolicy::developer_baseline();
    let decision = policy.evaluate(&request(
        "10.0.0.1".parse().unwrap(),
        443,
        Some("sensitive-user-input.example.com"),
        RouteClass::General,
    ));
    assert_eq!(decision.action, DecisionAction::Deny);
    assert_eq!(
        decision.reason,
        DecisionReason::ProtectedAddress(AddressClass::Private)
    );
    assert_eq!(decision.rule_id, None);
    assert_eq!(decision.policy_digest, policy.digest());
    assert_eq!(decision.reason_code(), "protected-address-private");
}

#[test]
fn builtin_policies_have_stable_names_ids_bytes_and_digests() {
    // `open` is `codewire-developer-v1`: its bytes and digest never change.
    assert_eq!(
        DEVELOPER_BASELINE_YAML,
        b"version: 1\ndefault: deny\nrules:\n  - id: developer-public-dns\n    action: allow\n    protocols: [dns]\n    ports: [53]\n    destinations: [\"*\"]\n    route_classes: [general]\n  - id: developer-public-tcp\n    action: allow\n    protocols: [tcp]\n    ports: [22, 80, 443]\n    cidrs: [0.0.0.0/0, \"::/0\"]\n    route_classes: [general]\n"
    );
    assert_eq!(
        DEVELOPER_BASELINE_DIGEST,
        "fab8151c7bffd0d0fe6ca1a9397ae6b60fa1e0ae650a967f9c9445ac3dd4189f"
    );
    assert_eq!(
        LOCKED_POLICY_YAML,
        b"version: 1\ndefault: deny\nrules: []\n"
    );
    assert_eq!(
        LOCKED_POLICY_DIGEST,
        "145641138b37aaf7724fb49bc3dd5f59c515ff34e60a2cfbdc7d51d4da9b16ca"
    );

    assert_eq!(
        BuiltinPolicy::ALL,
        [BuiltinPolicy::Open, BuiltinPolicy::Locked]
    );
    for (builtin, name, id, digest) in [
        (
            BuiltinPolicy::Open,
            "open",
            "codewire-developer-v1",
            DEVELOPER_BASELINE_DIGEST,
        ),
        (
            BuiltinPolicy::Locked,
            "locked",
            "codewire-locked-v1",
            LOCKED_POLICY_DIGEST,
        ),
    ] {
        assert_eq!(builtin.name(), name);
        assert_eq!(builtin.to_string(), name);
        assert_eq!(builtin.id(), id);
        assert_eq!(builtin.digest_hex(), digest);
        assert_eq!(builtin.compile().digest().to_hex(), digest);
        assert_eq!(BuiltinPolicy::from_name(name), Some(builtin));
    }
    assert_eq!(
        CompiledPolicy::developer_baseline().digest().to_hex(),
        DEVELOPER_BASELINE_DIGEST
    );
    assert_eq!(
        CompiledPolicy::locked().digest().to_hex(),
        LOCKED_POLICY_DIGEST
    );
    assert_eq!(BuiltinPolicy::from_name("Open"), None);
    assert_eq!(BuiltinPolicy::from_name("work"), None);
}

#[test]
fn builtin_names_are_reserved_in_any_letter_case() {
    for name in ["open", "OPEN", "Open", "locked", "LOCKED", "lOcKeD"] {
        assert!(is_reserved_policy_name(name), "{name} is not reserved");
    }
    for name in ["work", "opened", "unlocked", "open-1", ""] {
        assert!(!is_reserved_policy_name(name), "{name} is reserved");
    }
}

#[test]
fn locked_admits_no_workload_egress() {
    let policy = CompiledPolicy::locked();
    assert!(policy.canonical_document().rules.is_empty());
    for route_class in [
        RouteClass::General,
        RouteClass::Credential,
        RouteClass::Mesh,
    ] {
        let query = EgressRequest::dns_query("github.com", route_class).unwrap();
        assert_eq!(policy.evaluate(&query).reason, DecisionReason::DefaultDeny);
        for address in [PUBLIC_V4, PUBLIC_V6] {
            for port in [22, 80, 443] {
                let decision = policy.evaluate(&request(address, port, None, route_class));
                assert_eq!(decision.reason, DecisionReason::DefaultDeny);
                assert_eq!(decision.policy_digest.to_hex(), LOCKED_POLICY_DIGEST);
            }
        }
    }
}

#[test]
fn locked_is_the_empty_typed_policy_and_open_is_outside_the_subset() {
    let empty = typed::TypedPolicy::new([]).unwrap();
    assert_eq!(empty.compile().digest().to_hex(), LOCKED_POLICY_DIGEST);
    assert_eq!(
        typed::TypedPolicy::from_document(CompiledPolicy::locked().canonical_document()).unwrap(),
        empty
    );
    let open = typed::TypedPolicy::from_document(
        CompiledPolicy::developer_baseline().canonical_document(),
    )
    .unwrap_err();
    assert_eq!(
        open.to_string(),
        "egress policy rule developer-public-dns is outside the supported subset: its id is not a .dns or .tcp allow rule id"
    );
}

#[test]
fn protected_overlap_finds_any_shared_address() {
    for (network, class) in [
        ("0.0.0.0/0", Some(AddressClass::Unspecified)),
        ("8.0.0.0/5", Some(AddressClass::Private)),
        ("10.20.0.0/16", Some(AddressClass::Private)),
        ("100.96.0.0/11", Some(AddressClass::Shared)),
        ("192.0.0.0/8", Some(AddressClass::Private)),
        ("192.0.2.0/24", Some(AddressClass::Documentation)),
        ("8.8.8.8/32", None),
        ("8.0.0.0/8", None),
        ("93.0.0.0/8", None),
        ("::/0", Some(AddressClass::Unspecified)),
        ("2000::/3", Some(AddressClass::Documentation)),
        ("2606:4700:4700::1111/128", None),
        ("fe80::/64", Some(AddressClass::LinkLocal)),
    ] {
        assert_eq!(
            protected_overlap(cidr::IpNetwork::parse(network).unwrap()),
            class,
            "{network}"
        );
    }
}
