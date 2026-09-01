//! Bounded, placement-neutral DNS lease and TCP admission state.
//!
//! Resolver and socket adapters remain outside this module. Callers provide a
//! validated resolver result and a monotonic instant; this state machine
//! applies policy, prevents TTL extension and rebinding to protected targets,
//! and attributes named TCP admission to an active DNS-to-IP lease.

use std::collections::BTreeSet;
use std::net::IpAddr;

use thiserror::Error;

use crate::hostname::{canonical_hostname, protected_name};
use crate::{CompiledPolicy, EgressRequest, PolicyDecision, PolicyDigest, PolicyError, RouteClass};

pub const MAX_CNAME_CHAIN: usize = 8;
pub const MAX_DNS_ADDRESSES: usize = 16;
pub const MAX_ACTIVE_DNS_LEASES: usize = 1_024;
pub const MAX_DNS_TTL_SECONDS: u32 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LeaseInstant(u64);

impl LeaseInstant {
    pub const ZERO: Self = Self(0);

    pub const fn from_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }

    fn checked_add_seconds(self, seconds: u32) -> Option<Self> {
        self.0
            .checked_add(u64::from(seconds).checked_mul(1_000)?)
            .map(Self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsAlias {
    name: String,
    ttl_seconds: u32,
}

impl DnsAlias {
    pub fn new(name: &str, ttl_seconds: u32) -> Result<Self, LeaseError> {
        if ttl_seconds == 0 {
            return Err(LeaseError::ZeroTtl);
        }
        let name = canonical_hostname(name).map_err(|_| LeaseError::InvalidAliasName)?;
        Ok(Self { name, ttl_seconds })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DnsAddress {
    address: IpAddr,
    ttl_seconds: u32,
}

impl DnsAddress {
    pub fn new(address: IpAddr, ttl_seconds: u32) -> Result<Self, LeaseError> {
        if ttl_seconds == 0 {
            return Err(LeaseError::ZeroTtl);
        }
        Ok(Self {
            address,
            ttl_seconds,
        })
    }

    pub fn address(self) -> IpAddr {
        self.address
    }

    pub fn ttl_seconds(self) -> u32 {
        self.ttl_seconds
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResolution {
    aliases: Vec<DnsAlias>,
    addresses: Vec<DnsAddress>,
}

impl DnsResolution {
    pub fn new(aliases: Vec<DnsAlias>, mut addresses: Vec<DnsAddress>) -> Result<Self, LeaseError> {
        if aliases.len() > MAX_CNAME_CHAIN {
            return Err(LeaseError::TooManyAliases {
                actual: aliases.len(),
                maximum: MAX_CNAME_CHAIN,
            });
        }
        if addresses.is_empty() {
            return Err(LeaseError::NoAddresses);
        }
        if addresses.len() > MAX_DNS_ADDRESSES {
            return Err(LeaseError::TooManyAddresses {
                actual: addresses.len(),
                maximum: MAX_DNS_ADDRESSES,
            });
        }

        let mut names = BTreeSet::new();
        if aliases
            .iter()
            .any(|alias| !names.insert(alias.name.clone()))
        {
            return Err(LeaseError::CnameCycle);
        }
        addresses.sort_unstable();
        if addresses
            .windows(2)
            .any(|pair| pair[0].address == pair[1].address)
        {
            return Err(LeaseError::DuplicateAddress);
        }
        Ok(Self { aliases, addresses })
    }

    pub fn aliases(&self) -> &[DnsAlias] {
        &self.aliases
    }

    pub fn addresses(&self) -> &[DnsAddress] {
        &self.addresses
    }

    fn effective_ttl_seconds(&self) -> u32 {
        self.aliases
            .iter()
            .map(DnsAlias::ttl_seconds)
            .chain(self.addresses.iter().copied().map(DnsAddress::ttl_seconds))
            .min()
            .expect("a DNS resolution always has at least one address")
            .min(MAX_DNS_TTL_SECONDS)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission<T> {
    Allowed(T),
    Denied(PolicyDecision),
}

impl<T> Admission<T> {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedDnsResolution {
    name: String,
    aliases: Vec<String>,
    addresses: Vec<IpAddr>,
    ttl_seconds: u32,
    expires_at: LeaseInstant,
    decision: PolicyDecision,
}

impl AdmittedDnsResolution {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    pub fn expires_at(&self) -> LeaseInstant {
        self.expires_at
    }

    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpAdmission {
    hostname: Option<String>,
    lease_expires_at: Option<LeaseInstant>,
    decision: PolicyDecision,
}

impl TcpAdmission {
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    pub fn lease_expires_at(&self) -> Option<LeaseInstant> {
        self.lease_expires_at
    }

    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }
}

#[derive(Clone, Debug)]
struct DnsLease {
    name: String,
    address: IpAddr,
    route_class: RouteClass,
    expires_at: LeaseInstant,
}

#[derive(Clone, Debug)]
pub struct EgressLeaseTable {
    policy: CompiledPolicy,
    leases: Vec<DnsLease>,
    maximum_leases: usize,
}

impl EgressLeaseTable {
    pub fn new(policy: CompiledPolicy) -> Self {
        Self {
            policy,
            leases: Vec::new(),
            maximum_leases: MAX_ACTIVE_DNS_LEASES,
        }
    }

    pub fn with_maximum_leases(
        policy: CompiledPolicy,
        maximum_leases: usize,
    ) -> Result<Self, LeaseError> {
        if !(1..=MAX_ACTIVE_DNS_LEASES).contains(&maximum_leases) {
            return Err(LeaseError::InvalidCapacity);
        }
        Ok(Self {
            policy,
            leases: Vec::new(),
            maximum_leases,
        })
    }

    pub fn policy_digest(&self) -> PolicyDigest {
        self.policy.digest()
    }

    /// Admit a resolver result and create bounded name-to-address leases.
    ///
    /// The caller owns DNS transport and supplies the complete canonical CNAME
    /// chain plus terminal addresses. Protected aliases and addresses are
    /// rejected or filtered before any lease is recorded. The returned TTL is
    /// the shortest observed TTL, capped by [`MAX_DNS_TTL_SECONDS`].
    pub fn admit_dns(
        &mut self,
        name: &str,
        route_class: RouteClass,
        resolution: DnsResolution,
        now: LeaseInstant,
    ) -> Result<Admission<AdmittedDnsResolution>, LeaseError> {
        let query = EgressRequest::dns_query(name, route_class)?;
        let query_decision = self.policy.evaluate(&query);
        if !query_decision.is_allowed() {
            return Ok(Admission::Denied(query_decision));
        }
        let name = query
            .hostname()
            .expect("a validated DNS query always carries its name")
            .to_string();

        for alias in &resolution.aliases {
            if alias.name == name {
                return Err(LeaseError::CnameCycle);
            }
            if protected_name(&alias.name).is_some() {
                let alias_request = EgressRequest::dns_query(&alias.name, route_class)?;
                return Ok(Admission::Denied(self.policy.evaluate(&alias_request)));
            }
        }

        let ttl_seconds = resolution.effective_ttl_seconds();
        let expires_at = now
            .checked_add_seconds(ttl_seconds)
            .ok_or(LeaseError::TimeOverflow)?;
        let mut admitted = Vec::with_capacity(resolution.addresses.len());
        let mut first_denial = None;
        for record in &resolution.addresses {
            let answer = EgressRequest::dns_answer(&name, record.address, route_class)?;
            let decision = self.policy.evaluate(&answer);
            if decision.is_allowed() {
                admitted.push(record.address);
            } else if first_denial.is_none() {
                first_denial = Some(decision);
            }
        }
        if admitted.is_empty() {
            return Ok(Admission::Denied(
                first_denial.expect("a non-empty DNS answer has a policy decision"),
            ));
        }

        self.purge_expired(now);
        let new_leases = admitted
            .iter()
            .filter(|address| {
                !self.leases.iter().any(|lease| {
                    lease.name == name
                        && lease.address == **address
                        && lease.route_class == route_class
                })
            })
            .count();
        if self.leases.len().saturating_add(new_leases) > self.maximum_leases {
            return Err(LeaseError::CapacityExhausted {
                maximum: self.maximum_leases,
            });
        }
        for address in &admitted {
            if let Some(existing) = self.leases.iter_mut().find(|lease| {
                lease.name == name && lease.address == *address && lease.route_class == route_class
            }) {
                // Never revoke a lease earlier than a TTL already returned to
                // a guest resolver, and never extend it beyond one admitted
                // result without observing another query.
                existing.expires_at = existing.expires_at.max(expires_at);
            } else {
                self.leases.push(DnsLease {
                    name: name.clone(),
                    address: *address,
                    route_class,
                    expires_at,
                });
            }
        }
        self.leases.sort_by(|left, right| {
            (left.address, left.route_class, left.name.as_str()).cmp(&(
                right.address,
                right.route_class,
                right.name.as_str(),
            ))
        });

        Ok(Admission::Allowed(AdmittedDnsResolution {
            name,
            aliases: resolution
                .aliases
                .iter()
                .map(|alias| alias.name.clone())
                .collect(),
            addresses: admitted,
            ttl_seconds,
            expires_at,
            decision: query_decision,
        }))
    }

    /// Admit one TCP destination using direct-IP policy or active DNS evidence.
    ///
    /// A CIDR rule that allows the direct IP is sufficient and is reported
    /// without hostname attribution. Otherwise, the first deterministic active
    /// hostname lease whose combined name/address request is allowed supplies
    /// the attribution. Because raw TCP carries no authenticated hostname, a
    /// named lease intentionally acknowledges shared-IP/vhost collateral; exact
    /// HTTP authority belongs in an explicit proxy or credential-broker route.
    pub fn admit_tcp(
        &mut self,
        address: IpAddr,
        port: u16,
        route_class: RouteClass,
        now: LeaseInstant,
    ) -> Result<Admission<TcpAdmission>, LeaseError> {
        self.purge_expired(now);
        let direct_request = EgressRequest::tcp(address, port, None, route_class)?;
        let direct_decision = self.policy.evaluate(&direct_request);
        if direct_decision.is_allowed() {
            return Ok(Admission::Allowed(TcpAdmission {
                hostname: None,
                lease_expires_at: None,
                decision: direct_decision,
            }));
        }

        for lease in &self.leases {
            if lease.address != address || lease.route_class != route_class {
                continue;
            }
            let named_request = EgressRequest::tcp(address, port, Some(&lease.name), route_class)?;
            let decision = self.policy.evaluate(&named_request);
            if decision.is_allowed() {
                return Ok(Admission::Allowed(TcpAdmission {
                    hostname: Some(lease.name.clone()),
                    lease_expires_at: Some(lease.expires_at),
                    decision,
                }));
            }
        }
        Ok(Admission::Denied(direct_decision))
    }

    pub fn active_leases(&mut self, now: LeaseInstant) -> usize {
        self.purge_expired(now);
        self.leases.len()
    }

    fn purge_expired(&mut self, now: LeaseInstant) {
        self.leases.retain(|lease| lease.expires_at > now);
    }
}

#[derive(Debug, Error)]
pub enum LeaseError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("DNS alias name is invalid")]
    InvalidAliasName,
    #[error("DNS TTL must be non-zero")]
    ZeroTtl,
    #[error("DNS result has {actual} aliases; maximum is {maximum}")]
    TooManyAliases { actual: usize, maximum: usize },
    #[error("DNS result has no addresses")]
    NoAddresses,
    #[error("DNS result has {actual} addresses; maximum is {maximum}")]
    TooManyAddresses { actual: usize, maximum: usize },
    #[error("DNS CNAME chain is cyclic or duplicated")]
    CnameCycle,
    #[error("DNS result has a duplicate address record")]
    DuplicateAddress,
    #[error("DNS lease capacity is invalid")]
    InvalidCapacity,
    #[error("DNS lease capacity is exhausted at {maximum}")]
    CapacityExhausted { maximum: usize },
    #[error("DNS lease expiry overflows the monotonic clock")]
    TimeOverflow,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::{DecisionReason, PolicyDocument};

    const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const OTHER_PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    const PUBLIC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

    fn named_policy() -> CompiledPolicy {
        PolicyDocument::parse_yaml(
            br#"
version: 1
default: deny
rules:
  - id: named-dns
    action: allow
    protocols: [dns]
    ports: [53]
    destinations: [allowed.example.com]
    route_classes: [general]
  - id: named-tcp
    action: allow
    protocols: [tcp]
    ports: [443]
    destinations: [allowed.example.com]
    route_classes: [general]
"#,
        )
        .unwrap()
    }

    fn address(address: IpAddr, ttl_seconds: u32) -> DnsAddress {
        DnsAddress::new(address, ttl_seconds).unwrap()
    }

    fn allowed<T>(admission: Admission<T>) -> T {
        match admission {
            Admission::Allowed(value) => value,
            Admission::Denied(decision) => panic!("unexpected denial: {decision:?}"),
        }
    }

    fn denied<T>(admission: Admission<T>) -> PolicyDecision {
        match admission {
            Admission::Allowed(_) => panic!("unexpected allow"),
            Admission::Denied(decision) => decision,
        }
    }

    #[test]
    fn named_tcp_requires_an_active_dns_lease() {
        let mut table = EgressLeaseTable::new(named_policy());
        let before = denied(
            table
                .admit_tcp(PUBLIC_V4, 443, RouteClass::General, LeaseInstant::ZERO)
                .unwrap(),
        );
        assert_eq!(before.reason, DecisionReason::DefaultDeny);

        let dns = allowed(
            table
                .admit_dns(
                    "Allowed.Example.COM.",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, 60)]).unwrap(),
                    LeaseInstant::from_millis(10_000),
                )
                .unwrap(),
        );
        assert_eq!(dns.name(), "allowed.example.com");
        assert_eq!(dns.addresses(), [PUBLIC_V4]);
        assert_eq!(dns.expires_at(), LeaseInstant::from_millis(70_000));

        let tcp = allowed(
            table
                .admit_tcp(
                    PUBLIC_V4,
                    443,
                    RouteClass::General,
                    LeaseInstant::from_millis(69_999),
                )
                .unwrap(),
        );
        assert_eq!(tcp.hostname(), Some("allowed.example.com"));
        assert_eq!(
            tcp.lease_expires_at(),
            Some(LeaseInstant::from_millis(70_000))
        );

        let expired = denied(
            table
                .admit_tcp(
                    PUBLIC_V4,
                    443,
                    RouteClass::General,
                    LeaseInstant::from_millis(70_000),
                )
                .unwrap(),
        );
        assert_eq!(expired.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn direct_ip_allow_does_not_claim_a_hostname_lease() {
        let mut table = EgressLeaseTable::new(CompiledPolicy::developer_baseline());
        let tcp = allowed(
            table
                .admit_tcp(PUBLIC_V4, 443, RouteClass::General, LeaseInstant::ZERO)
                .unwrap(),
        );
        assert_eq!(tcp.hostname(), None);
        assert_eq!(tcp.lease_expires_at(), None);
    }

    #[test]
    fn protected_answers_and_cname_targets_never_create_leases() {
        let mut table = EgressLeaseTable::new(named_policy());
        let rebound = denied(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(
                        vec![],
                        vec![address("169.254.169.254".parse().unwrap(), 30)],
                    )
                    .unwrap(),
                    LeaseInstant::ZERO,
                )
                .unwrap(),
        );
        assert!(matches!(
            rebound.reason,
            DecisionReason::ProtectedAddress(_)
        ));
        assert_eq!(table.active_leases(LeaseInstant::ZERO), 0);

        let protected_alias = denied(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(
                        vec![DnsAlias::new("metadata.google.internal", 30).unwrap()],
                        vec![address(PUBLIC_V4, 30)],
                    )
                    .unwrap(),
                    LeaseInstant::ZERO,
                )
                .unwrap(),
        );
        assert!(matches!(
            protected_alias.reason,
            DecisionReason::ProtectedName(_)
        ));
        assert_eq!(table.active_leases(LeaseInstant::ZERO), 0);
    }

    #[test]
    fn mixed_answers_filter_protected_targets_and_use_the_shortest_ttl() {
        let mut table = EgressLeaseTable::new(named_policy());
        let dns = allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(
                        vec![DnsAlias::new("edge.cdn.example.net", 45).unwrap()],
                        vec![
                            address(PUBLIC_V6, 120),
                            address("10.0.0.1".parse().unwrap(), 20),
                            address(PUBLIC_V4, 90),
                        ],
                    )
                    .unwrap(),
                    LeaseInstant::from_millis(1_000),
                )
                .unwrap(),
        );
        assert_eq!(dns.addresses(), [PUBLIC_V4, PUBLIC_V6]);
        assert_eq!(dns.aliases(), ["edge.cdn.example.net"]);
        assert_eq!(dns.ttl_seconds(), 20);
        assert_eq!(dns.expires_at(), LeaseInstant::from_millis(21_000));
        assert_eq!(table.active_leases(LeaseInstant::ZERO), 2);
    }

    #[test]
    fn ttl_is_never_extended_past_the_curated_maximum() {
        let mut table = EgressLeaseTable::new(named_policy());
        let dns = allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, MAX_DNS_TTL_SECONDS + 600)])
                        .unwrap(),
                    LeaseInstant::from_millis(5_000),
                )
                .unwrap(),
        );
        assert_eq!(dns.ttl_seconds(), MAX_DNS_TTL_SECONDS);
        assert_eq!(dns.expires_at(), LeaseInstant::from_millis(305_000));
    }

    #[test]
    fn a_refresh_does_not_revoke_a_ttl_already_returned_to_the_guest() {
        let mut table = EgressLeaseTable::new(named_policy());
        allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, 120)]).unwrap(),
                    LeaseInstant::ZERO,
                )
                .unwrap(),
        );
        let refreshed = allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, 5)]).unwrap(),
                    LeaseInstant::from_millis(10_000),
                )
                .unwrap(),
        );
        assert_eq!(refreshed.expires_at(), LeaseInstant::from_millis(15_000));
        let tcp = allowed(
            table
                .admit_tcp(
                    PUBLIC_V4,
                    443,
                    RouteClass::General,
                    LeaseInstant::from_millis(119_999),
                )
                .unwrap(),
        );
        assert_eq!(
            tcp.lease_expires_at(),
            Some(LeaseInstant::from_millis(120_000))
        );
    }

    #[test]
    fn shared_ip_attribution_is_explicit_and_deterministic() {
        let policy = PolicyDocument::parse_yaml(
            br#"
version: 1
default: deny
rules:
  - id: dns
    action: allow
    protocols: [dns]
    ports: [53]
    destinations: ["*.example.com"]
    route_classes: [general]
  - id: tcp
    action: allow
    protocols: [tcp]
    ports: [443]
    destinations: [a.example.com, b.example.com]
    route_classes: [general]
"#,
        )
        .unwrap();
        let mut table = EgressLeaseTable::new(policy);
        for name in ["b.example.com", "a.example.com"] {
            allowed(
                table
                    .admit_dns(
                        name,
                        RouteClass::General,
                        DnsResolution::new(vec![], vec![address(PUBLIC_V4, 60)]).unwrap(),
                        LeaseInstant::ZERO,
                    )
                    .unwrap(),
            );
        }
        let tcp = allowed(
            table
                .admit_tcp(PUBLIC_V4, 443, RouteClass::General, LeaseInstant::ZERO)
                .unwrap(),
        );
        assert_eq!(tcp.hostname(), Some("a.example.com"));
    }

    #[test]
    fn route_classes_do_not_share_dns_leases() {
        let mut table = EgressLeaseTable::new(named_policy());
        allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, 60)]).unwrap(),
                    LeaseInstant::ZERO,
                )
                .unwrap(),
        );
        let credential = denied(
            table
                .admit_tcp(PUBLIC_V4, 443, RouteClass::Credential, LeaseInstant::ZERO)
                .unwrap(),
        );
        assert_eq!(credential.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn rebinding_does_not_replace_an_unexpired_safe_lease() {
        let mut table = EgressLeaseTable::new(named_policy());
        allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, 60)]).unwrap(),
                    LeaseInstant::ZERO,
                )
                .unwrap(),
        );
        denied(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address("127.0.0.1".parse().unwrap(), 60)])
                        .unwrap(),
                    LeaseInstant::from_millis(1_000),
                )
                .unwrap(),
        );
        assert_eq!(table.active_leases(LeaseInstant::from_millis(1_000)), 1);
        assert!(
            table
                .admit_tcp(
                    PUBLIC_V4,
                    443,
                    RouteClass::General,
                    LeaseInstant::from_millis(1_000),
                )
                .unwrap()
                .is_allowed()
        );
    }

    #[test]
    fn malformed_results_and_capacity_exhaustion_fail_closed() {
        assert!(matches!(
            DnsAlias::new("bad_name.example.com", 1),
            Err(LeaseError::InvalidAliasName)
        ));
        assert!(matches!(
            DnsAddress::new(PUBLIC_V4, 0),
            Err(LeaseError::ZeroTtl)
        ));
        assert!(matches!(
            DnsResolution::new(vec![], vec![]),
            Err(LeaseError::NoAddresses)
        ));
        assert!(matches!(
            DnsResolution::new(vec![], vec![address(PUBLIC_V4, 1), address(PUBLIC_V4, 2)]),
            Err(LeaseError::DuplicateAddress)
        ));
        assert!(matches!(
            DnsResolution::new(
                vec![
                    DnsAlias::new("a.example.net", 1).unwrap(),
                    DnsAlias::new("a.example.net", 1).unwrap(),
                ],
                vec![address(PUBLIC_V4, 1)],
            ),
            Err(LeaseError::CnameCycle)
        ));

        let mut table = EgressLeaseTable::with_maximum_leases(named_policy(), 1).unwrap();
        allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    DnsResolution::new(vec![], vec![address(PUBLIC_V4, 60)]).unwrap(),
                    LeaseInstant::ZERO,
                )
                .unwrap(),
        );
        assert!(matches!(
            table.admit_dns(
                "allowed.example.com",
                RouteClass::General,
                DnsResolution::new(vec![], vec![address(OTHER_PUBLIC_V4, 60)]).unwrap(),
                LeaseInstant::ZERO,
            ),
            Err(LeaseError::CapacityExhausted { maximum: 1 })
        ));
        assert_eq!(table.active_leases(LeaseInstant::ZERO), 1);
    }

    #[test]
    fn result_and_table_limits_fail_closed() {
        let aliases = (0..=MAX_CNAME_CHAIN)
            .map(|index| DnsAlias::new(&format!("alias-{index}.example.net"), 1).unwrap())
            .collect();
        assert!(matches!(
            DnsResolution::new(aliases, vec![address(PUBLIC_V4, 1)]),
            Err(LeaseError::TooManyAliases {
                actual,
                maximum: MAX_CNAME_CHAIN,
            }) if actual == MAX_CNAME_CHAIN + 1
        ));

        let addresses = (1..=(MAX_DNS_ADDRESSES + 1))
            .map(|octet| address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, octet as u8)), 1))
            .collect();
        assert!(matches!(
            DnsResolution::new(vec![], addresses),
            Err(LeaseError::TooManyAddresses {
                actual,
                maximum: MAX_DNS_ADDRESSES,
            }) if actual == MAX_DNS_ADDRESSES + 1
        ));
        assert!(matches!(
            EgressLeaseTable::with_maximum_leases(named_policy(), 0),
            Err(LeaseError::InvalidCapacity)
        ));
        assert!(matches!(
            EgressLeaseTable::with_maximum_leases(named_policy(), MAX_ACTIVE_DNS_LEASES + 1,),
            Err(LeaseError::InvalidCapacity)
        ));
    }

    #[test]
    fn monotonic_expiry_overflow_fails_closed_without_a_lease() {
        let mut table = EgressLeaseTable::new(named_policy());
        assert!(matches!(
            table.admit_dns(
                "allowed.example.com",
                RouteClass::General,
                DnsResolution::new(vec![], vec![address(PUBLIC_V4, 1)]).unwrap(),
                LeaseInstant::from_millis(u64::MAX),
            ),
            Err(LeaseError::TimeOverflow)
        ));
        assert_eq!(table.active_leases(LeaseInstant::ZERO), 0);
    }

    #[test]
    fn query_name_repeated_in_the_cname_chain_is_rejected() {
        let mut table = EgressLeaseTable::new(named_policy());
        let result = table.admit_dns(
            "allowed.example.com",
            RouteClass::General,
            DnsResolution::new(
                vec![DnsAlias::new("allowed.example.com", 30).unwrap()],
                vec![address(PUBLIC_V4, 30)],
            )
            .unwrap(),
            LeaseInstant::ZERO,
        );
        assert!(matches!(result, Err(LeaseError::CnameCycle)));
        assert_eq!(table.active_leases(LeaseInstant::ZERO), 0);
    }
}
