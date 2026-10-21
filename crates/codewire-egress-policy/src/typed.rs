//! The typed rule subset a user policy may contain (#2537).
//!
//! A user policy is default deny plus allow rules. Each rule selects one
//! exact DNS name, one descendant-domain pattern (every descendant, never the
//! apex) or one public CIDR, plus a finite set of TCP ports. Its content is
//! still one version 1 document, in a canonical form this module writes and
//! reads, so the brokers evaluate it with the same [`CompiledPolicy`] as any
//! other document and its digest does not depend on rule order.
//!
//! In that form a name rule is two version 1 rules: `<id>.dns` lets the name
//! resolve and `<id>.tcp` lets its leased addresses be dialed on the rule's
//! ports. A CIDR rule is `<id>.tcp` alone. The id is derived from the target.
//! `locked` is the empty set; `open` is outside the subset.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::cidr::IpNetwork;
use crate::hostname::{canonical_hostname, protected_name};
use crate::{
    CompiledPolicy, EgressProtocol, POLICY_SCHEMA_VERSION, PolicyAction, PolicyDocument,
    PolicyError, PolicyRule, RouteClass, protected_overlap,
};

/// Admission limit on rules in one user policy.
pub const MAX_ALLOW_RULES: usize = 64;
/// Admission limit on ports in one rule.
pub const MAX_ALLOW_RULE_PORTS: usize = 32;

const RULE_ID_DOMAIN: &[u8] = b"codewire.egress-policy/allow-rule/v1\0";
const DNS_SUFFIX: &str = ".dns";
const TCP_SUFFIX: &str = ".tcp";
const DNS_PORT: u16 = 53;

/// How a rule's target matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AllowTargetKind {
    /// Exactly one DNS name.
    Name,
    /// Every descendant of a domain, excluding the domain itself.
    Descendants,
    /// One public address range.
    Cidr,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Target {
    Name(String),
    Descendants(String),
    Cidr(IpNetwork),
}

/// A validated rule target. It can only be built by [`AllowTarget::parse`],
/// so it is never a protected name, a protected range or a wildcard that
/// matches everything.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllowTarget(Target);

impl AllowTarget {
    /// Parse `github.com`, `*.npmjs.org`, a CIDR such as `8.0.0.0/8`, or a single
    /// address. Errors do not repeat the input.
    pub fn parse(value: &str) -> Result<Self, TypedPolicyError> {
        if value.contains("://") {
            return Err(TypedPolicyError::InvalidTarget(
                "a URL is not a host name; allow its host",
            ));
        }
        if value.contains('/') {
            let network = IpNetwork::parse(value).map_err(|_| {
                TypedPolicyError::InvalidTarget(
                    "paths are not supported; use a host name or an address/prefix CIDR",
                )
            })?;
            return Self::cidr(network);
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            let network = IpNetwork::parse(&format!("{address}/{prefix}"))
                .map_err(|_| TypedPolicyError::InvalidTarget("the address is invalid"))?;
            return Self::cidr(network);
        }
        if value == "*" {
            return Err(TypedPolicyError::InvalidTarget(
                "an unrestricted wildcard is not allowed",
            ));
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            let suffix = name(suffix)?;
            if !suffix.contains('.') {
                return Err(TypedPolicyError::InvalidTarget(
                    "a wildcard needs a domain of at least two labels",
                ));
            }
            return Ok(Self(Target::Descendants(suffix)));
        }
        if value.contains('*') {
            return Err(TypedPolicyError::InvalidTarget(
                "a wildcard must be the whole leftmost label, as in *.example.com",
            ));
        }
        Ok(Self(Target::Name(name(value)?)))
    }

    fn cidr(network: IpNetwork) -> Result<Self, TypedPolicyError> {
        if protected_overlap(network).is_some() {
            return Err(TypedPolicyError::InvalidTarget(
                "the range includes protected addresses",
            ));
        }
        Ok(Self(Target::Cidr(network)))
    }

    pub fn kind(&self) -> AllowTargetKind {
        match self.0 {
            Target::Name(_) => AllowTargetKind::Name,
            Target::Descendants(_) => AllowTargetKind::Descendants,
            Target::Cidr(_) => AllowTargetKind::Cidr,
        }
    }

    fn is_named(&self) -> bool {
        !matches!(self.0, Target::Cidr(_))
    }

    /// The version 1 rule id prefix for this target.
    fn rule_id(&self) -> String {
        let (tag, value): (&[u8], String) = match &self.0 {
            Target::Name(name) => (b"name", name.clone()),
            Target::Descendants(suffix) => (b"descendants", suffix.clone()),
            Target::Cidr(network) => (b"cidr", network.to_string()),
        };
        let mut hasher = Sha256::new();
        hasher.update(RULE_ID_DOMAIN);
        hasher.update(tag);
        hasher.update(b"\0");
        hasher.update(value.as_bytes());
        let digest = hasher.finalize();
        let mut id = String::from("allow-");
        for byte in &digest[..8] {
            id.push_str(&format!("{byte:02x}"));
        }
        id
    }
}

impl fmt::Display for AllowTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Target::Name(name) => formatter.write_str(name),
            Target::Descendants(suffix) => write!(formatter, "*.{suffix}"),
            Target::Cidr(network) => network.fmt(formatter),
        }
    }
}

fn name(value: &str) -> Result<String, TypedPolicyError> {
    let name = canonical_hostname(value).map_err(|_| {
        TypedPolicyError::InvalidTarget("not a host name, a *.domain pattern or a CIDR")
    })?;
    if protected_name(&name).is_some() {
        return Err(TypedPolicyError::InvalidTarget(
            "protected names cannot be allowed",
        ));
    }
    Ok(name)
}

/// One allow rule: a target and the TCP ports it may be dialed on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllowRule {
    target: AllowTarget,
    ports: Vec<u16>,
}

impl AllowRule {
    /// Ports must be non-zero and distinct, at least one and at most
    /// [`MAX_ALLOW_RULE_PORTS`].
    pub fn new(
        target: AllowTarget,
        ports: impl IntoIterator<Item = u16>,
    ) -> Result<Self, TypedPolicyError> {
        let ports: Vec<u16> = ports.into_iter().collect();
        let invalid = |detail| TypedPolicyError::InvalidRule {
            target: target.to_string(),
            detail,
        };
        if ports.is_empty() {
            return Err(invalid("at least one TCP port is required"));
        }
        if ports.len() > MAX_ALLOW_RULE_PORTS {
            return Err(invalid("a rule allows at most 32 ports"));
        }
        if ports.contains(&0) {
            return Err(invalid("port zero is invalid"));
        }
        let unique: BTreeSet<u16> = ports.iter().copied().collect();
        if unique.len() != ports.len() {
            return Err(invalid("a port is listed more than once"));
        }
        Ok(Self {
            target,
            ports: unique.into_iter().collect(),
        })
    }

    pub fn target(&self) -> &AllowTarget {
        &self.target
    }

    /// Ascending and distinct.
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    fn rules(&self) -> Vec<PolicyRule> {
        let id = self.target.rule_id();
        let (cidrs, destinations) = match &self.target.0 {
            Target::Cidr(network) => (vec![network.to_string()], Vec::new()),
            Target::Name(_) | Target::Descendants(_) => (Vec::new(), vec![self.target.to_string()]),
        };
        let mut rules = Vec::with_capacity(2);
        if self.target.is_named() {
            rules.push(PolicyRule {
                id: format!("{id}{DNS_SUFFIX}"),
                action: PolicyAction::Allow,
                protocols: vec![EgressProtocol::Dns],
                ports: vec![DNS_PORT],
                cidrs: Vec::new(),
                destinations: destinations.clone(),
                route_classes: vec![RouteClass::General],
            });
        }
        rules.push(PolicyRule {
            id: format!("{id}{TCP_SUFFIX}"),
            action: PolicyAction::Allow,
            protocols: vec![EgressProtocol::Tcp],
            ports: self.ports.clone(),
            cidrs,
            destinations,
            route_classes: vec![RouteClass::General],
        });
        rules
    }
}

/// A user policy in the supported subset: default deny plus allow rules,
/// each target at most once, at most [`MAX_ALLOW_RULES`] rules.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TypedPolicy {
    rules: Vec<AllowRule>,
}

impl TypedPolicy {
    pub fn new(rules: impl IntoIterator<Item = AllowRule>) -> Result<Self, TypedPolicyError> {
        let mut rules: Vec<AllowRule> = rules.into_iter().collect();
        if rules.len() > MAX_ALLOW_RULES {
            return Err(TypedPolicyError::TooManyRules {
                actual: rules.len(),
                maximum: MAX_ALLOW_RULES,
            });
        }
        rules.sort();
        if let Some(pair) = rules
            .windows(2)
            .find(|pair| pair[0].target == pair[1].target)
        {
            return Err(TypedPolicyError::DuplicateTarget(
                pair[0].target.to_string(),
            ));
        }
        let mut ids = BTreeSet::new();
        if let Some(rule) = rules.iter().find(|rule| !ids.insert(rule.target.rule_id())) {
            return Err(TypedPolicyError::InvalidRule {
                target: rule.target.to_string(),
                detail: "its rule id collides with another rule's",
            });
        }
        Ok(Self { rules })
    }

    /// Read a version 1 document that is in the subset's canonical form.
    /// Errors name the offending rule id.
    pub fn from_document(document: &PolicyDocument) -> Result<Self, TypedPolicyError> {
        let compiled = CompiledPolicy::compile(document.clone())?;
        let canonical = compiled.canonical_document();
        let mut rules = Vec::new();
        for rule in &canonical.rules {
            if rule.id.ends_with(DNS_SUFFIX) {
                continue;
            }
            let unsupported = |detail| TypedPolicyError::UnsupportedRule {
                rule_id: rule.id.clone(),
                detail,
            };
            if !rule.id.ends_with(TCP_SUFFIX) {
                return Err(unsupported("its id is not a .dns or .tcp allow rule id"));
            }
            if rule.action != PolicyAction::Allow {
                return Err(unsupported("only allow rules are supported"));
            }
            if rule.protocols != [EgressProtocol::Tcp] {
                return Err(unsupported("a .tcp rule allows TCP only"));
            }
            if rule.route_classes != [RouteClass::General] {
                return Err(unsupported("only the general route class is supported"));
            }
            let target = match (rule.cidrs.as_slice(), rule.destinations.as_slice()) {
                ([cidr], []) => AllowTarget::parse(cidr),
                ([], [destination]) => AllowTarget::parse(destination),
                _ => {
                    return Err(unsupported(
                        "a rule selects exactly one name, pattern or CIDR",
                    ));
                }
            }
            .map_err(|error| TypedPolicyError::UnsupportedRule {
                rule_id: rule.id.clone(),
                detail: error.detail(),
            })?;
            rules.push(
                AllowRule::new(target, rule.ports.iter().copied()).map_err(|error| {
                    TypedPolicyError::UnsupportedRule {
                        rule_id: rule.id.clone(),
                        detail: error.detail(),
                    }
                })?,
            );
        }
        let typed = Self::new(rules)?;
        let expected = typed.to_document().rules;
        let mut expected_rules = expected.iter();
        for rule in &canonical.rules {
            if expected_rules.next() != Some(rule) {
                return Err(TypedPolicyError::UnsupportedRule {
                    rule_id: rule.id.clone(),
                    detail: "it is not in the canonical form of its allow rule",
                });
            }
        }
        if let Some(missing) = expected_rules.next() {
            return Err(TypedPolicyError::UnsupportedRule {
                rule_id: missing.id.clone(),
                detail: "the matching rule of its allow rule is missing",
            });
        }
        Ok(typed)
    }

    /// Ascending by target.
    pub fn rules(&self) -> &[AllowRule] {
        &self.rules
    }

    /// The allow rule a version 1 rule id from a decision belongs to.
    pub fn rule_for_id(&self, rule_id: &str) -> Option<&AllowRule> {
        let prefix = rule_id
            .strip_suffix(DNS_SUFFIX)
            .or_else(|| rule_id.strip_suffix(TCP_SUFFIX))?;
        self.rules
            .iter()
            .find(|rule| rule.target.rule_id() == prefix)
    }

    /// The canonical version 1 document, rules ascending by id.
    pub fn to_document(&self) -> PolicyDocument {
        let mut rules: Vec<PolicyRule> = self.rules.iter().flat_map(AllowRule::rules).collect();
        rules.sort_by(|left, right| left.id.cmp(&right.id));
        PolicyDocument {
            version: POLICY_SCHEMA_VERSION,
            default: PolicyAction::Deny,
            rules,
        }
    }

    pub fn compile(&self) -> CompiledPolicy {
        CompiledPolicy::compile(self.to_document())
            .expect("a typed egress policy always compiles within the library ceilings")
    }
}

#[derive(Debug, Error)]
pub enum TypedPolicyError {
    #[error("invalid allow target: {0}")]
    InvalidTarget(&'static str),
    #[error("allow rule {target} is invalid: {detail}")]
    InvalidRule {
        target: String,
        detail: &'static str,
    },
    #[error("allow rule {0} is listed more than once")]
    DuplicateTarget(String),
    #[error("network policy has {actual} allow rules; maximum is {maximum}")]
    TooManyRules { actual: usize, maximum: usize },
    #[error("egress policy rule {rule_id} is outside the supported subset: {detail}")]
    UnsupportedRule {
        rule_id: String,
        detail: &'static str,
    },
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

impl TypedPolicyError {
    fn detail(&self) -> &'static str {
        match self {
            Self::InvalidTarget(detail)
            | Self::InvalidRule { detail, .. }
            | Self::UnsupportedRule { detail, .. } => detail,
            Self::DuplicateTarget(_) => "its target is listed more than once",
            Self::TooManyRules { .. } => "the policy has too many rules",
            Self::Policy(_) => "it is not a valid egress policy rule",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{DecisionReason, EgressRequest};

    fn target(value: &str) -> AllowTarget {
        AllowTarget::parse(value).unwrap()
    }

    fn rule(value: &str, ports: &[u16]) -> AllowRule {
        AllowRule::new(target(value), ports.iter().copied()).unwrap()
    }

    fn sample() -> TypedPolicy {
        TypedPolicy::new([
            rule("GitHub.com.", &[443, 22]),
            rule("*.npmjs.org", &[443]),
            rule("8.0.0.0/8", &[22]),
        ])
        .unwrap()
    }

    #[test]
    fn targets_are_one_name_one_descendant_pattern_or_one_public_cidr() {
        for (value, kind, canonical) in [
            ("GitHub.com.", AllowTargetKind::Name, "github.com"),
            ("com", AllowTargetKind::Name, "com"),
            ("*.NPMJS.org", AllowTargetKind::Descendants, "*.npmjs.org"),
            ("8.0.0.0/8", AllowTargetKind::Cidr, "8.0.0.0/8"),
            ("93.184.216.34", AllowTargetKind::Cidr, "93.184.216.34/32"),
            ("2a01:4f8::1/128", AllowTargetKind::Cidr, "2a01:4f8::1/128"),
            (
                "2606:4700:4700::1111",
                AllowTargetKind::Cidr,
                "2606:4700:4700::1111/128",
            ),
        ] {
            let parsed = target(value);
            assert_eq!(parsed.kind(), kind, "{value}");
            assert_eq!(parsed.to_string(), canonical);
        }
        assert_ne!(target("example.org"), target("*.example.org"));
    }

    #[test]
    fn targets_outside_the_subset_are_refused_without_reflecting_input() {
        for (value, detail) in [
            ("*", "an unrestricted wildcard is not allowed"),
            ("*.com", "a wildcard needs a domain of at least two labels"),
            (
                "*.canary",
                "a wildcard needs a domain of at least two labels",
            ),
            (
                "foo.*.canary.org",
                "a wildcard must be the whole leftmost label, as in *.example.com",
            ),
            (
                "*canary.org",
                "a wildcard must be the whole leftmost label, as in *.example.com",
            ),
            (
                "https://canary.org",
                "a URL is not a host name; allow its host",
            ),
            (
                "canary.org/path",
                "paths are not supported; use a host name or an address/prefix CIDR",
            ),
            (
                "canary.org:443",
                "not a host name, a *.domain pattern or a CIDR",
            ),
            (
                "^canary\\.org$",
                "not a host name, a *.domain pattern or a CIDR",
            ),
            (
                "canary org",
                "not a host name, a *.domain pattern or a CIDR",
            ),
            ("", "not a host name, a *.domain pattern or a CIDR"),
            (
                "metadata.google.internal",
                "protected names cannot be allowed",
            ),
            ("canary.localhost", "protected names cannot be allowed"),
            ("*.google.internal", "protected names cannot be allowed"),
            ("*.home.arpa", "protected names cannot be allowed"),
            ("10.0.0.0/8", "the range includes protected addresses"),
            ("8.0.0.0/5", "the range includes protected addresses"),
            ("0.0.0.0/0", "the range includes protected addresses"),
            ("::/0", "the range includes protected addresses"),
            ("fe80::/10", "the range includes protected addresses"),
            ("127.0.0.1", "the range includes protected addresses"),
            ("::ffff:8.8.8.8", "the range includes protected addresses"),
            (
                "8.8.8.8/8",
                "paths are not supported; use a host name or an address/prefix CIDR",
            ),
        ] {
            let error = AllowTarget::parse(value).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("invalid allow target: {detail}"),
                "{value}"
            );
            assert!(!error.to_string().contains("canary"));
        }
    }

    #[test]
    fn ports_are_a_finite_non_empty_set_and_errors_name_the_rule() {
        assert_eq!(rule("github.com", &[443, 22, 80]).ports(), [22, 80, 443]);
        let many: Vec<u16> = (1..=MAX_ALLOW_RULE_PORTS as u16).collect();
        assert_eq!(
            rule("github.com", &many).ports().len(),
            MAX_ALLOW_RULE_PORTS
        );
        for (ports, detail) in [
            (vec![], "at least one TCP port is required"),
            (vec![0, 443], "port zero is invalid"),
            (vec![443, 443], "a port is listed more than once"),
            (
                (1..=MAX_ALLOW_RULE_PORTS as u16 + 1).collect(),
                "a rule allows at most 32 ports",
            ),
        ] {
            let error = AllowRule::new(target("*.github.com"), ports).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("allow rule *.github.com is invalid: {detail}")
            );
        }
    }

    #[test]
    fn a_policy_lists_each_target_once_and_at_most_sixty_four_rules() {
        let error =
            TypedPolicy::new([rule("github.com", &[443]), rule("GITHUB.com", &[22])]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "allow rule github.com is listed more than once"
        );
        let rules =
            |count: u8| (0..count).map(|index| rule(&format!("host-{index}.example.org"), &[443]));
        assert_eq!(
            TypedPolicy::new(rules(64)).unwrap().rules().len(),
            MAX_ALLOW_RULES
        );
        assert!(matches!(
            TypedPolicy::new(rules(65)),
            Err(TypedPolicyError::TooManyRules {
                actual: 65,
                maximum: MAX_ALLOW_RULES
            })
        ));
        // At the admission limits the document stays within the library's.
        let widest = TypedPolicy::new((0..64_u8).map(|index| {
            AllowRule::new(
                target(&format!(
                    "{}.example.org",
                    "a".repeat(40) + &index.to_string()
                )),
                1..=32,
            )
            .unwrap()
        }))
        .unwrap();
        assert!(serde_yaml::to_string(&widest.to_document()).unwrap().len() < 256 * 1024);
        widest.compile();
    }

    #[test]
    fn the_canonical_document_and_digest_do_not_depend_on_rule_order() {
        let forward = sample();
        let reverse = TypedPolicy::new([
            rule("8.0.0.0/8", &[22]),
            rule("*.npmjs.org", &[443]),
            rule("github.com", &[22, 443]),
        ])
        .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.compile().digest(), reverse.compile().digest());
        let document = forward.to_document();
        assert_eq!(document.rules.len(), 5);
        assert!(
            document
                .rules
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id)
        );
        for rule in &document.rules {
            assert!(
                rule.id.starts_with("allow-") && rule.id.len() == 26,
                "{}",
                rule.id
            );
        }
        let changed = TypedPolicy::new([rule("github.com", &[443])]).unwrap();
        assert_ne!(changed.compile().digest(), forward.compile().digest());
        // The rule id depends on the target alone, never on its ports.
        assert_eq!(
            changed.to_document().rules[0].id,
            TypedPolicy::new([rule("github.com", &[22])])
                .unwrap()
                .to_document()
                .rules[0]
                .id
        );
    }

    #[test]
    fn the_compiled_subset_allows_exactly_its_names_patterns_ranges_and_ports() {
        let policy = sample().compile();
        let general = RouteClass::General;
        let dns = |name| policy.evaluate(&EgressRequest::dns_query(name, general).unwrap());
        assert!(dns("github.com").is_allowed());
        assert!(dns("registry.npmjs.org").is_allowed());
        assert!(dns("deep.registry.npmjs.org").is_allowed());
        assert_eq!(dns("npmjs.org").reason, DecisionReason::DefaultDeny);
        assert_eq!(dns("api.github.com").reason, DecisionReason::DefaultDeny);

        let leased = "93.184.216.34".parse().unwrap();
        let tcp = |address, port, name: Option<&str>| {
            policy.evaluate(&EgressRequest::tcp(address, port, name, general).unwrap())
        };
        assert!(tcp(leased, 22, Some("github.com")).is_allowed());
        assert!(tcp(leased, 443, Some("github.com")).is_allowed());
        assert!(!tcp(leased, 80, Some("github.com")).is_allowed());
        assert!(tcp(leased, 443, Some("registry.npmjs.org")).is_allowed());
        assert!(!tcp(leased, 22, Some("registry.npmjs.org")).is_allowed());
        let range = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
        assert!(tcp(range, 22, None).is_allowed());
        assert!(!tcp(range, 443, None).is_allowed());
        assert!(
            !tcp(leased, 443, None).is_allowed(),
            "a raw address needs a lease"
        );
        let credential = EgressRequest::dns_query("github.com", RouteClass::Credential).unwrap();
        assert!(!policy.evaluate(&credential).is_allowed());

        let decision = tcp(leased, 443, Some("github.com"));
        let matched = sample();
        let rule = matched
            .rule_for_id(decision.rule_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(rule.target().to_string(), "github.com");
        assert_eq!(rule.ports(), [22, 443]);
        assert!(matched.rule_for_id("developer-public-tcp").is_none());
    }

    #[test]
    fn documents_round_trip_only_in_canonical_form_and_errors_name_the_rule() {
        let typed = sample();
        let document = typed.to_document();
        assert_eq!(TypedPolicy::from_document(&document).unwrap(), typed);
        let yaml = serde_yaml::to_string(&document).unwrap();
        let reparsed = PolicyDocument::parse_yaml(yaml.as_bytes()).unwrap();
        assert_eq!(
            TypedPolicy::from_document(reparsed.canonical_document()).unwrap(),
            typed
        );

        let tcp_index = document
            .rules
            .iter()
            .position(|rule| rule.destinations == ["github.com"] && rule.id.ends_with(".tcp"))
            .unwrap();
        let tcp_id = document.rules[tcp_index].id.clone();
        let mutate = |change: &dyn Fn(&mut PolicyDocument)| {
            let mut document = typed.to_document();
            change(&mut document);
            TypedPolicy::from_document(&document)
                .unwrap_err()
                .to_string()
        };
        let named = |detail: &str| {
            format!("egress policy rule {tcp_id} is outside the supported subset: {detail}")
        };
        assert_eq!(
            mutate(&|document| document.rules[tcp_index].action = PolicyAction::Deny),
            named("only allow rules are supported")
        );
        assert_eq!(
            mutate(&|document| document.rules[tcp_index]
                .route_classes
                .push(RouteClass::Mesh)),
            named("only the general route class is supported")
        );
        assert_eq!(
            mutate(&|document| document.rules[tcp_index]
                .protocols
                .push(EgressProtocol::Dns)),
            named("a .tcp rule allows TCP only")
        );
        assert_eq!(
            mutate(&|document| document.rules[tcp_index].destinations = vec!["*".into()]),
            named("an unrestricted wildcard is not allowed")
        );
        assert_eq!(
            mutate(&|document| {
                document.rules[tcp_index].cidrs = vec!["8.0.0.0/8".into()];
            }),
            named("a rule selects exactly one name, pattern or CIDR")
        );
        assert_eq!(
            mutate(&|document| document.rules[tcp_index].ports = (1..=33).collect()),
            named("a rule allows at most 32 ports")
        );
        assert_eq!(
            mutate(&|document| document.rules[tcp_index].destinations = vec!["db.internal".into()]),
            named("protected names cannot be allowed")
        );
        assert_eq!(
            mutate(&|document| document.rules[tcp_index].id = "custom".into()),
            "egress policy rule custom is outside the supported subset: its id is not a .dns or .tcp allow rule id"
        );
        assert_eq!(
            mutate(&|document| {
                document.rules[tcp_index].id = "allow-0000000000000000.tcp".into();
            }),
            "egress policy rule allow-0000000000000000.tcp is outside the supported subset: it is not in the canonical form of its allow rule"
        );
        // A name rule without its DNS half, or with a widened one.
        let dns_id = tcp_id.replace(".tcp", ".dns");
        assert_eq!(
            mutate(&|document| document.rules.retain(|rule| rule.id != dns_id)),
            named("it is not in the canonical form of its allow rule")
        );
        assert_eq!(
            mutate(&|document| {
                let dns = document
                    .rules
                    .iter_mut()
                    .find(|rule| rule.id == dns_id)
                    .unwrap();
                dns.destinations = vec!["*".into()];
            }),
            format!(
                "egress policy rule {dns_id} is outside the supported subset: it is not in the canonical form of its allow rule"
            )
        );
        // A trailing DNS-only rule.
        assert_eq!(
            mutate(&|document| {
                document.rules.push(PolicyRule {
                    id: "zz.dns".into(),
                    action: PolicyAction::Allow,
                    protocols: vec![EgressProtocol::Dns],
                    ports: vec![53],
                    cidrs: Vec::new(),
                    destinations: vec!["extra.example.org".into()],
                    route_classes: vec![RouteClass::General],
                });
            }),
            "egress policy rule zz.dns is outside the supported subset: it is not in the canonical form of its allow rule"
        );
    }
}
