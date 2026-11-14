//! Placement-neutral, I/O-free Codewire workload egress policy.
//!
//! This crate parses and normalizes bounded policy documents, computes a
//! canonical digest, and explains deny-first decisions. It deliberately owns
//! no resolver, socket, credential, process, audit sink, or platform adapter.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod builtin;
pub mod check;
mod cidr;
pub mod host_addresses;
mod hostname;
pub mod intercept;
pub mod lease;
pub mod record;
pub mod reference;
pub mod typed;

pub use builtin::{
    BuiltinPolicy, HOSTED_DEFAULT_DIGEST, HOSTED_DEFAULT_ID, HOSTED_DEFAULT_NAME,
    HOSTED_DEFAULT_YAML, LOCKED_ID, LOCKED_POLICY_DIGEST, LOCKED_POLICY_YAML,
    is_reserved_policy_name,
};
use cidr::IpNetwork;
use hostname::{NamePattern, canonical_hostname, protected_name};

pub const POLICY_SCHEMA_VERSION: u32 = 1;
pub const DEVELOPER_BASELINE_ID: &str = "codewire-developer-v1";
pub const DEVELOPER_BASELINE_DIGEST: &str =
    "fab8151c7bffd0d0fe6ca1a9397ae6b60fa1e0ae650a967f9c9445ac3dd4189f";
pub const DEVELOPER_BASELINE_YAML: &[u8] = include_bytes!("../policies/developer-v1.yaml");
pub const MAX_POLICY_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_POLICY_RULES: usize = 256;
pub const MAX_RULE_SELECTORS: usize = 128;
pub const MAX_RULE_ID_BYTES: usize = 64;

const DIGEST_DOMAIN: &[u8] = b"codewire.egress-policy/v1\0";

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("egress policy document is {actual} bytes; maximum is {maximum}")]
    DocumentTooLarge { actual: usize, maximum: usize },
    #[error("parse egress policy document: {0}")]
    Yaml(#[from] serde_saphyr::Error),
    #[error("unsupported egress policy schema version {0}")]
    UnsupportedSchema(u32),
    #[error("egress policy default action must be deny")]
    DefaultMustDeny,
    #[error("egress policy has {actual} rules; maximum is {maximum}")]
    TooManyRules { actual: usize, maximum: usize },
    #[error("egress policy rule id is invalid")]
    InvalidRuleId,
    #[error("egress policy rule id is duplicated: {0}")]
    DuplicateRuleId(String),
    #[error("egress policy rule {rule_id} has too many selectors: {actual}; maximum is {maximum}")]
    TooManySelectors {
        rule_id: String,
        actual: usize,
        maximum: usize,
    },
    #[error("egress policy rule {rule_id} has invalid {field}: {detail}")]
    InvalidRule {
        rule_id: String,
        field: &'static str,
        detail: String,
    },
    #[error("egress policy request has invalid {field}: {detail}")]
    InvalidRequest { field: &'static str, detail: String },
    #[error("serialize canonical egress policy: {0}")]
    CanonicalJson(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EgressProtocol {
    Dns,
    Tcp,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RouteClass {
    General,
    Credential,
    Mesh,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub version: u32,
    pub default: PolicyAction,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub action: PolicyAction,
    pub protocols: Vec<EgressProtocol>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub destinations: Vec<String>,
    pub route_classes: Vec<RouteClass>,
}

impl PolicyDocument {
    pub fn parse_yaml(bytes: &[u8]) -> Result<CompiledPolicy, PolicyError> {
        if bytes.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(PolicyError::DocumentTooLarge {
                actual: bytes.len(),
                maximum: MAX_POLICY_DOCUMENT_BYTES,
            });
        }
        let document = serde_saphyr::from_slice_with_options(bytes, yaml_options())?;
        CompiledPolicy::compile(document)
    }
}

/// How a policy document is read (#4278). It comes from users and is enforced,
/// so a value a YAML 1.1 reader would take differently is refused or kept a
/// string: only `true`/`false` are booleans; numbers with a leading zero or an
/// underscore stay strings; merge keys, duplicate keys and tags other than
/// YAML's own are refused. `codewire-project` reads codewire.yaml the same way.
fn yaml_options() -> serde_saphyr::Options {
    let mut options = serde_saphyr::Options::default();
    options.strict_booleans = true;
    options.leading_zero_numbers_as_strings = true;
    options.underscored_numbers_as_strings = true;
    options.merge_keys = serde_saphyr::MergeKeyPolicy::Error;
    options.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
    options.reject_unsupported_tags = true;
    options.with_snippet = false;
    options
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyDigest([u8; 32]);

impl PolicyDigest {
    /// A digest carried in a private bootstrap record. It names a policy; it
    /// never stands in for one, so a reader still compiles the document and
    /// compares.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for PolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    Unspecified,
    Loopback,
    Private,
    LinkLocal,
    Shared,
    Multicast,
    Documentation,
    Benchmark,
    Mapped,
    Reserved,
    /// One of the host's own interface addresses (#2614).
    HostInterface,
    /// A public address the host's network is seen from (#2614).
    NetworkPublic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameClass {
    Localhost,
    Local,
    Internal,
    Home,
    Metadata,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionAction {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionReason {
    RuleAllow,
    RuleDeny,
    DefaultDeny,
    ProtectedAddress(AddressClass),
    ProtectedName(NameClass),
    /// The name is bound for interception (#3999), and the policy refused
    /// its DNS only by default. Never a rule's decision, so no rule id.
    InterceptBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: DecisionAction,
    pub reason: DecisionReason,
    pub rule_id: Option<String>,
    pub policy_digest: PolicyDigest,
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        self.action == DecisionAction::Allow
    }

    pub fn reason_code(&self) -> &'static str {
        match self.reason {
            DecisionReason::RuleAllow => "rule-allow",
            DecisionReason::RuleDeny => "rule-deny",
            DecisionReason::DefaultDeny => "default-deny",
            DecisionReason::ProtectedAddress(AddressClass::Unspecified) => {
                "protected-address-unspecified"
            }
            DecisionReason::ProtectedAddress(AddressClass::Loopback) => {
                "protected-address-loopback"
            }
            DecisionReason::ProtectedAddress(AddressClass::Private) => "protected-address-private",
            DecisionReason::ProtectedAddress(AddressClass::LinkLocal) => {
                "protected-address-link-local"
            }
            DecisionReason::ProtectedAddress(AddressClass::Shared) => "protected-address-shared",
            DecisionReason::ProtectedAddress(AddressClass::Multicast) => {
                "protected-address-multicast"
            }
            DecisionReason::ProtectedAddress(AddressClass::Documentation) => {
                "protected-address-documentation"
            }
            DecisionReason::ProtectedAddress(AddressClass::Benchmark) => {
                "protected-address-benchmark"
            }
            DecisionReason::ProtectedAddress(AddressClass::Mapped) => "protected-address-mapped",
            DecisionReason::ProtectedAddress(AddressClass::HostInterface) => {
                "protected-address-host-interface"
            }
            DecisionReason::ProtectedAddress(AddressClass::NetworkPublic) => {
                "protected-address-network-public"
            }
            DecisionReason::ProtectedAddress(AddressClass::Reserved) => {
                "protected-address-reserved"
            }
            DecisionReason::ProtectedName(NameClass::Localhost) => "protected-name-localhost",
            DecisionReason::ProtectedName(NameClass::Local) => "protected-name-local",
            DecisionReason::ProtectedName(NameClass::Internal) => "protected-name-internal",
            DecisionReason::ProtectedName(NameClass::Home) => "protected-name-home",
            DecisionReason::ProtectedName(NameClass::Metadata) => "protected-name-metadata",
            DecisionReason::ProtectedName(NameClass::Reserved) => "protected-name-reserved",
            DecisionReason::InterceptBinding => "intercept-binding",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRequest {
    protocol: EgressProtocol,
    hostname: Option<String>,
    address: Option<IpAddr>,
    port: u16,
    route_class: RouteClass,
}

impl EgressRequest {
    /// Construct one TCP decision request.
    ///
    /// `hostname` is trusted policy evidence, not a guest-supplied label. A
    /// transport adapter must pass it only after validating and pinning the
    /// matching DNS answer; direct-IP requests must pass `None`.
    pub fn tcp(
        address: IpAddr,
        port: u16,
        hostname: Option<&str>,
        route_class: RouteClass,
    ) -> Result<Self, PolicyError> {
        if port == 0 {
            return Err(PolicyError::InvalidRequest {
                field: "port",
                detail: "TCP port must be non-zero".to_string(),
            });
        }
        let hostname = hostname
            .map(canonical_hostname)
            .transpose()
            .map_err(|detail| PolicyError::InvalidRequest {
                field: "hostname",
                detail,
            })?;
        Ok(Self {
            protocol: EgressProtocol::Tcp,
            hostname,
            address: Some(address),
            port,
            route_class,
        })
    }

    pub fn dns_query(name: &str, route_class: RouteClass) -> Result<Self, PolicyError> {
        Ok(Self {
            protocol: EgressProtocol::Dns,
            hostname: Some(canonical_hostname(name).map_err(|detail| {
                PolicyError::InvalidRequest {
                    field: "hostname",
                    detail,
                }
            })?),
            address: None,
            port: 53,
            route_class,
        })
    }

    pub fn dns_answer(
        name: &str,
        address: IpAddr,
        route_class: RouteClass,
    ) -> Result<Self, PolicyError> {
        let mut request = Self::dns_query(name, route_class)?;
        request.address = Some(address);
        Ok(request)
    }

    pub fn protocol(&self) -> EgressProtocol {
        self.protocol
    }

    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn route_class(&self) -> RouteClass {
        self.route_class
    }
}

#[derive(Clone, Debug)]
struct CompiledRule {
    id: String,
    action: PolicyAction,
    protocols: Vec<EgressProtocol>,
    ports: Vec<u16>,
    networks: Vec<IpNetwork>,
    destinations: Vec<NamePattern>,
    route_classes: Vec<RouteClass>,
}

impl CompiledRule {
    fn matches(&self, request: &EgressRequest) -> bool {
        (self.ports.is_empty() || self.ports.binary_search(&request.port).is_ok())
            && self.matches_any_port(request)
    }

    fn matches_any_port(&self, request: &EgressRequest) -> bool {
        self.matches_traffic(request)
            && (self.networks.is_empty()
                || request.address.is_some_and(|address| {
                    self.networks
                        .iter()
                        .any(|network| network.contains(address))
                }))
    }
}

impl CompiledRule {
    /// Whether the rule selects the request's protocol, route class and
    /// name, whatever its port and address.
    fn matches_traffic(&self, request: &EgressRequest) -> bool {
        self.protocols.binary_search(&request.protocol).is_ok()
            && self
                .route_classes
                .binary_search(&request.route_class)
                .is_ok()
            && (self.destinations.is_empty()
                || request.hostname.as_deref().is_some_and(|hostname| {
                    self.destinations
                        .iter()
                        .any(|pattern| pattern.matches(hostname))
                }))
    }

    fn matches_port(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.binary_search(&port).is_ok()
    }

    /// Whether the rule matches every address of both families, so an
    /// answer's address cannot change whether it applies.
    fn matches_every_address(&self) -> bool {
        self.networks.is_empty()
            || (self
                .networks
                .iter()
                .any(|network| matches!(network, IpNetwork::V4 { prefix: 0, .. }))
                && self
                    .networks
                    .iter()
                    .any(|network| matches!(network, IpNetwork::V6 { prefix: 0, .. })))
    }
}

/// How a policy judges a TCP dial to a name before its answers are known
/// (#2537 `cw policy check`). Rules that match whatever the answer decide it;
/// rules that also need the answer inside a network are reported apart,
/// because only the answer the guest dials decides them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NamedDial {
    /// The rule that decides the dial whatever the answer, and whether it
    /// allows it.
    pub(crate) decided_by: Option<(PolicyAction, String)>,
    /// A name rule allows the name on another port.
    pub(crate) allowed_on_another_port: bool,
    /// Networks that allow the dial when the answer is inside one.
    pub(crate) allowed_within: Vec<String>,
    /// Networks that refuse the dial when the answer is inside one.
    pub(crate) refused_within: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    document: PolicyDocument,
    rules: Vec<CompiledRule>,
    digest: PolicyDigest,
}

impl CompiledPolicy {
    pub fn compile(mut document: PolicyDocument) -> Result<Self, PolicyError> {
        if document.version != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedSchema(document.version));
        }
        if document.default != PolicyAction::Deny {
            return Err(PolicyError::DefaultMustDeny);
        }
        if document.rules.len() > MAX_POLICY_RULES {
            return Err(PolicyError::TooManyRules {
                actual: document.rules.len(),
                maximum: MAX_POLICY_RULES,
            });
        }

        let mut ids = BTreeSet::new();
        let mut compiled = Vec::with_capacity(document.rules.len());
        for rule in &mut document.rules {
            validate_rule_id(&rule.id)?;
            if !ids.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
            }
            let selector_count = rule.protocols.len()
                + rule.ports.len()
                + rule.cidrs.len()
                + rule.destinations.len()
                + rule.route_classes.len();
            if selector_count > MAX_RULE_SELECTORS {
                return Err(PolicyError::TooManySelectors {
                    rule_id: rule.id.clone(),
                    actual: selector_count,
                    maximum: MAX_RULE_SELECTORS,
                });
            }
            normalize_unique(&rule.id, "protocols", &mut rule.protocols)?;
            normalize_unique(&rule.id, "ports", &mut rule.ports)?;
            normalize_unique(&rule.id, "route_classes", &mut rule.route_classes)?;
            if rule.protocols.is_empty() {
                return invalid_rule(&rule.id, "protocols", "at least one protocol is required");
            }
            if rule.route_classes.is_empty() {
                return invalid_rule(
                    &rule.id,
                    "route_classes",
                    "at least one route class is required",
                );
            }
            if rule.ports.contains(&0) {
                return invalid_rule(&rule.id, "ports", "port zero is invalid");
            }
            if rule.cidrs.is_empty() && rule.destinations.is_empty() {
                return invalid_rule(
                    &rule.id,
                    "destinations",
                    "a CIDR or named destination is required",
                );
            }
            if rule.protocols.contains(&EgressProtocol::Dns) && rule.destinations.is_empty() {
                return invalid_rule(
                    &rule.id,
                    "destinations",
                    "DNS rules require a named destination",
                );
            }

            let mut networks = rule
                .cidrs
                .iter()
                .map(|value| {
                    IpNetwork::parse(value).map_err(|detail| PolicyError::InvalidRule {
                        rule_id: rule.id.clone(),
                        field: "cidrs",
                        detail: detail.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            networks.sort_unstable();
            reject_adjacent_duplicate(&rule.id, "cidrs", &networks)?;
            rule.cidrs = networks.iter().map(ToString::to_string).collect();

            let mut destinations = rule
                .destinations
                .iter()
                .map(|value| NamePattern::parse(value, &rule.id))
                .collect::<Result<Vec<_>, _>>()?;
            destinations.sort();
            reject_adjacent_duplicate(&rule.id, "destinations", &destinations)?;
            rule.destinations = destinations.iter().map(ToString::to_string).collect();

            compiled.push(CompiledRule {
                id: rule.id.clone(),
                action: rule.action,
                protocols: rule.protocols.clone(),
                ports: rule.ports.clone(),
                networks,
                destinations,
                route_classes: rule.route_classes.clone(),
            });
        }

        document.rules.sort_by(|left, right| left.id.cmp(&right.id));
        compiled.sort_by(|left, right| left.id.cmp(&right.id));
        let canonical = serde_json::to_vec(&document)?;
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(&canonical);
        let digest = PolicyDigest(hasher.finalize().into());
        Ok(Self {
            document,
            rules: compiled,
            digest,
        })
    }

    /// The built-in `open` policy, `codewire-developer-v1`.
    pub fn developer_baseline() -> Self {
        BuiltinPolicy::Open.compile()
    }

    /// The built-in `locked` policy: no rules, so no workload egress.
    pub fn locked() -> Self {
        BuiltinPolicy::Locked.compile()
    }

    /// `hosted-default`, `codewire-hosted-default-v1`: what a hosted Sandbox
    /// with no selection enforces.
    pub fn hosted_default() -> Self {
        PolicyDocument::parse_yaml(HOSTED_DEFAULT_YAML)
            .expect("the hosted default egress policy must remain valid")
    }

    pub fn digest(&self) -> PolicyDigest {
        self.digest
    }

    pub fn canonical_document(&self) -> &PolicyDocument {
        &self.document
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, PolicyError> {
        Ok(serde_json::to_vec(&self.document)?)
    }

    pub fn evaluate(&self, request: &EgressRequest) -> PolicyDecision {
        if let Some(hostname) = request.hostname.as_deref()
            && let Some(class) = protected_name(hostname)
        {
            return self.deny(DecisionReason::ProtectedName(class), None);
        }
        if let Some(address) = request.address
            && let Some(class) = classify_address(address)
        {
            return self.deny(DecisionReason::ProtectedAddress(class), None);
        }

        let mut allowed_by = None;
        for rule in &self.rules {
            if !rule.matches(request) {
                continue;
            }
            match rule.action {
                PolicyAction::Deny => {
                    return self.deny(DecisionReason::RuleDeny, Some(rule.id.clone()));
                }
                PolicyAction::Allow if allowed_by.is_none() => {
                    allowed_by = Some(rule.id.clone());
                }
                PolicyAction::Allow => {}
            }
        }
        if let Some(rule_id) = allowed_by {
            PolicyDecision {
                action: DecisionAction::Allow,
                reason: DecisionReason::RuleAllow,
                rule_id: Some(rule_id),
                policy_digest: self.digest,
            }
        } else {
            self.deny(DecisionReason::DefaultDeny, None)
        }
    }

    /// How this policy judges a TCP dial to `hostname` on `port` before the
    /// name's answers are known. Only rules that match every address decide
    /// it; deny wins, then the first allow rule, as in [`Self::evaluate`].
    pub(crate) fn judge_named_dial(
        &self,
        hostname: &str,
        port: u16,
        route_class: RouteClass,
    ) -> Result<NamedDial, PolicyError> {
        if port == 0 {
            return Err(PolicyError::InvalidRequest {
                field: "port",
                detail: "TCP port must be non-zero".to_string(),
            });
        }
        let mut request = EgressRequest::dns_query(hostname, route_class)?;
        request.protocol = EgressProtocol::Tcp;
        request.port = port;
        let mut dial = NamedDial {
            decided_by: None,
            allowed_on_another_port: false,
            allowed_within: Vec::new(),
            refused_within: Vec::new(),
        };
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.matches_traffic(&request))
        {
            let every_address = rule.matches_every_address();
            if !rule.matches_port(port) {
                dial.allowed_on_another_port |= rule.action == PolicyAction::Allow && every_address;
                continue;
            }
            match (rule.action, every_address) {
                (PolicyAction::Deny, true) => {
                    dial.decided_by = Some((PolicyAction::Deny, rule.id.clone()));
                    break;
                }
                (PolicyAction::Allow, true) => {
                    dial.decided_by
                        .get_or_insert_with(|| (PolicyAction::Allow, rule.id.clone()));
                }
                (PolicyAction::Allow, false) => dial
                    .allowed_within
                    .extend(rule.networks.iter().map(ToString::to_string)),
                (PolicyAction::Deny, false) => dial
                    .refused_within
                    .extend(rule.networks.iter().map(ToString::to_string)),
            }
        }
        for networks in [&mut dial.allowed_within, &mut dial.refused_within] {
            networks.sort();
            networks.dedup();
        }
        Ok(dial)
    }

    /// Whether some allow rule matches `request` on any port. It only
    /// classifies a refusal as "port not allowed"; it never admits anything.
    pub(crate) fn allows_on_another_port(&self, request: &EgressRequest) -> bool {
        if request
            .hostname
            .as_deref()
            .is_some_and(|hostname| protected_name(hostname).is_some())
            || request
                .address
                .is_some_and(|address| classify_address(address).is_some())
        {
            return false;
        }
        self.rules
            .iter()
            .any(|rule| rule.action == PolicyAction::Allow && rule.matches_any_port(request))
    }

    fn deny(&self, reason: DecisionReason, rule_id: Option<String>) -> PolicyDecision {
        PolicyDecision {
            action: DecisionAction::Deny,
            reason,
            rule_id,
            policy_digest: self.digest,
        }
    }
}

pub fn classify_address(address: IpAddr) -> Option<AddressClass> {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

/// The fixed IPv4 refusals, in classification order: the first match names
/// the class.
const PROTECTED_V4: [(u32, u8, AddressClass); 15] = [
    (0x0000_0000, 8, AddressClass::Unspecified),
    (0x0a00_0000, 8, AddressClass::Private),
    (0xac10_0000, 12, AddressClass::Private),
    (0xc0a8_0000, 16, AddressClass::Private),
    (0x6440_0000, 10, AddressClass::Shared),
    (0x7f00_0000, 8, AddressClass::Loopback),
    (0xa9fe_0000, 16, AddressClass::LinkLocal),
    (0xc000_0200, 24, AddressClass::Documentation),
    (0xc633_6400, 24, AddressClass::Documentation),
    (0xcb00_7100, 24, AddressClass::Documentation),
    (0xc612_0000, 15, AddressClass::Benchmark),
    (0xe000_0000, 4, AddressClass::Multicast),
    (0xc000_0000, 24, AddressClass::Reserved),
    (0xc058_6300, 24, AddressClass::Reserved),
    (0xf000_0000, 4, AddressClass::Reserved),
];

/// The fixed IPv6 refusals, in classification order. Each network is its
/// leading hexadecimal groups shifted into place.
const PROTECTED_V6: [(u128, u8, AddressClass); 17] = [
    (0, 128, AddressClass::Unspecified),
    (1, 128, AddressClass::Loopback),
    (0, 96, AddressClass::Mapped),
    (0xffff << 32, 96, AddressClass::Mapped),
    (0x0064_ff9b << 96, 96, AddressClass::Mapped),
    (0x0064_ff9b_0001 << 80, 48, AddressClass::Mapped),
    (0xfc00 << 112, 7, AddressClass::Private),
    (0xfe80 << 112, 10, AddressClass::LinkLocal),
    (0xfec0 << 112, 10, AddressClass::Reserved),
    (0xff00 << 112, 8, AddressClass::Multicast),
    (0x2001_0db8 << 96, 32, AddressClass::Documentation),
    (0x2001_0002 << 96, 48, AddressClass::Benchmark),
    (0x0100 << 112, 64, AddressClass::Reserved),
    (0x2001 << 112, 23, AddressClass::Reserved),
    (0x2002 << 112, 16, AddressClass::Reserved),
    (0x3fff << 112, 20, AddressClass::Reserved),
    (0x5f00 << 112, 16, AddressClass::Reserved),
];

fn classify_ipv4(address: Ipv4Addr) -> Option<AddressClass> {
    let raw = u32::from(address);
    PROTECTED_V4
        .iter()
        .find(|(network, prefix, _)| in_v4(raw, *network, *prefix))
        .map(|(_, _, class)| *class)
}

fn classify_ipv6(address: Ipv6Addr) -> Option<AddressClass> {
    let raw = u128::from(address);
    PROTECTED_V6
        .iter()
        .find(|(network, prefix, _)| in_v6(raw, *network, *prefix))
        .map(|(_, _, class)| *class)
}

/// The class of the first fixed refusal that shares any address with
/// `network`. Two prefixes overlap exactly when the shorter one contains the
/// other's network address.
pub(crate) fn protected_overlap(network: IpNetwork) -> Option<AddressClass> {
    match network {
        IpNetwork::V4 { network, prefix } => PROTECTED_V4
            .iter()
            .find(|(protected, protected_prefix, _)| {
                in_v4(*protected, network, prefix) || in_v4(network, *protected, *protected_prefix)
            })
            .map(|(_, _, class)| *class),
        IpNetwork::V6 { network, prefix } => PROTECTED_V6
            .iter()
            .find(|(protected, protected_prefix, _)| {
                in_v6(*protected, network, prefix) || in_v6(network, *protected, *protected_prefix)
            })
            .map(|(_, _, class)| *class),
    }
}

const fn in_v4(address: u32, network: u32, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    address & mask == network
}

const fn in_v6(address: u128, network: u128, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    address & mask == network
}

fn validate_rule_id(value: &str) -> Result<(), PolicyError> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if value.len() > MAX_RULE_ID_BYTES
        || !first.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(PolicyError::InvalidRuleId);
    }
    Ok(())
}

fn normalize_unique<T: Ord>(
    rule_id: &str,
    field: &'static str,
    values: &mut [T],
) -> Result<(), PolicyError> {
    values.sort();
    reject_adjacent_duplicate(rule_id, field, values)
}

fn reject_adjacent_duplicate<T: PartialEq>(
    rule_id: &str,
    field: &'static str,
    values: &[T],
) -> Result<(), PolicyError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return invalid_rule(rule_id, field, "duplicate selector");
    }
    Ok(())
}

fn invalid_rule<T>(rule_id: &str, field: &'static str, detail: &str) -> Result<T, PolicyError> {
    Err(PolicyError::InvalidRule {
        rule_id: rule_id.to_string(),
        field,
        detail: detail.to_string(),
    })
}

#[cfg(test)]
mod tests;
