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

mod cidr;
mod hostname;
pub mod lease;

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
    Yaml(#[from] serde_yaml::Error),
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
        let document = serde_yaml::from_slice(bytes)?;
        CompiledPolicy::compile(document)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyDigest([u8; 32]);

impl PolicyDigest {
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
            DecisionReason::ProtectedAddress(AddressClass::Reserved) => {
                "protected-address-reserved"
            }
            DecisionReason::ProtectedName(NameClass::Localhost) => "protected-name-localhost",
            DecisionReason::ProtectedName(NameClass::Local) => "protected-name-local",
            DecisionReason::ProtectedName(NameClass::Internal) => "protected-name-internal",
            DecisionReason::ProtectedName(NameClass::Home) => "protected-name-home",
            DecisionReason::ProtectedName(NameClass::Metadata) => "protected-name-metadata",
            DecisionReason::ProtectedName(NameClass::Reserved) => "protected-name-reserved",
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
        self.protocols.binary_search(&request.protocol).is_ok()
            && self
                .route_classes
                .binary_search(&request.route_class)
                .is_ok()
            && (self.ports.is_empty() || self.ports.binary_search(&request.port).is_ok())
            && (self.destinations.is_empty()
                || request.hostname.as_deref().is_some_and(|hostname| {
                    self.destinations
                        .iter()
                        .any(|pattern| pattern.matches(hostname))
                }))
            && (self.networks.is_empty()
                || request.address.is_some_and(|address| {
                    self.networks
                        .iter()
                        .any(|network| network.contains(address))
                }))
    }
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

    pub fn developer_baseline() -> Self {
        PolicyDocument::parse_yaml(DEVELOPER_BASELINE_YAML)
            .expect("the built-in developer egress policy must remain valid")
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

fn classify_ipv4(address: Ipv4Addr) -> Option<AddressClass> {
    let raw = u32::from(address);
    if in_v4(raw, 0x0000_0000, 8) {
        Some(AddressClass::Unspecified)
    } else if in_v4(raw, 0x0a00_0000, 8)
        || in_v4(raw, 0xac10_0000, 12)
        || in_v4(raw, 0xc0a8_0000, 16)
    {
        Some(AddressClass::Private)
    } else if in_v4(raw, 0x6440_0000, 10) {
        Some(AddressClass::Shared)
    } else if in_v4(raw, 0x7f00_0000, 8) {
        Some(AddressClass::Loopback)
    } else if in_v4(raw, 0xa9fe_0000, 16) {
        Some(AddressClass::LinkLocal)
    } else if in_v4(raw, 0xc000_0200, 24)
        || in_v4(raw, 0xc633_6400, 24)
        || in_v4(raw, 0xcb00_7100, 24)
    {
        Some(AddressClass::Documentation)
    } else if in_v4(raw, 0xc612_0000, 15) {
        Some(AddressClass::Benchmark)
    } else if in_v4(raw, 0xe000_0000, 4) {
        Some(AddressClass::Multicast)
    } else if in_v4(raw, 0xc000_0000, 24)
        || in_v4(raw, 0xc058_6300, 24)
        || in_v4(raw, 0xf000_0000, 4)
    {
        Some(AddressClass::Reserved)
    } else {
        None
    }
}

fn classify_ipv6(address: Ipv6Addr) -> Option<AddressClass> {
    let raw = u128::from(address);
    if address.is_unspecified() {
        Some(AddressClass::Unspecified)
    } else if address.is_loopback() {
        Some(AddressClass::Loopback)
    } else if in_v6(raw, 0x0000_0000_0000_0000_0000_0000_0000_0000, 96)
        || in_v6(raw, 0x0000_0000_0000_0000_0000_ffff_0000_0000, 96)
        || in_v6(raw, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96)
        || in_v6(raw, 0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48)
    {
        Some(AddressClass::Mapped)
    } else if in_v6(raw, 0xfc00_0000_0000_0000_0000_0000_0000_0000, 7) {
        Some(AddressClass::Private)
    } else if in_v6(raw, 0xfe80_0000_0000_0000_0000_0000_0000_0000, 10) {
        Some(AddressClass::LinkLocal)
    } else if in_v6(raw, 0xfec0_0000_0000_0000_0000_0000_0000_0000, 10) {
        Some(AddressClass::Reserved)
    } else if in_v6(raw, 0xff00_0000_0000_0000_0000_0000_0000_0000, 8) {
        Some(AddressClass::Multicast)
    } else if in_v6(raw, 0x2001_0db8_0000_0000_0000_0000_0000_0000, 32) {
        Some(AddressClass::Documentation)
    } else if in_v6(raw, 0x2001_0002_0000_0000_0000_0000_0000_0000, 48) {
        Some(AddressClass::Benchmark)
    } else if in_v6(raw, 0x0100_0000_0000_0000_0000_0000_0000_0000, 64)
        || in_v6(raw, 0x2001_0000_0000_0000_0000_0000_0000_0000, 23)
        || in_v6(raw, 0x2002_0000_0000_0000_0000_0000_0000_0000, 16)
        || in_v6(raw, 0x3fff_0000_0000_0000_0000_0000_0000_0000, 20)
        || in_v6(raw, 0x5f00_0000_0000_0000_0000_0000_0000_0000, 16)
    {
        Some(AddressClass::Reserved)
    } else {
        None
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
