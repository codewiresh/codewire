//! Bounded, placement-neutral DNS lease and TCP admission state.
//!
//! Resolver and socket adapters remain outside this module. Callers provide a
//! validated resolver result and a monotonic instant; this state machine
//! applies policy, prevents TTL extension and rebinding to protected targets,
//! and attributes named TCP admission to an active DNS-to-IP lease.
//!
//! Expired leases are kept for [`EXPIRED_LEASE_GRACE_SECONDS`], or until
//! capacity runs short, so a dial that finds only an expired lease can learn
//! the lease's own name and re-resolve it once ([`EgressLeaseTable::admit_tcp_or_expired`],
//! [`EgressLeaseTable::readmit_expired`]). [`EgressLeaseTable::replace_policy`]
//! swaps the policy in one call. Refusals are counted by reason.
//!
//! A name bound for interception (#3999) resolves even when no allow rule
//! names it, and a dial its lease attributes is answered
//! [`TcpVerdict::Intercepted`], never a dialable [`TcpAdmission`]. The set
//! is empty unless its owner replaces it, and an empty set changes nothing.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::host_addresses::HostAddressSet;
use crate::hostname::{canonical_hostname, protected_name};
use crate::intercept::InterceptSet;
use crate::{
    CompiledPolicy, DecisionAction, DecisionReason, EgressRequest, PolicyDecision, PolicyDigest,
    PolicyError, RouteClass,
};

pub const MAX_CNAME_CHAIN: usize = 8;
pub const MAX_DNS_ADDRESSES: usize = 16;
pub const MAX_ACTIVE_DNS_LEASES: usize = 1_024;
pub const MAX_DNS_TTL_SECONDS: u32 = 300;
/// The shortest lease the table grants a name-bound address; the guest
/// receives the lease lifetime as the answer's TTL (#2537).
pub const MIN_NAME_BOUND_LEASE_SECONDS: u32 = 60;
/// How long an expired lease is kept so a dial can re-resolve its name.
pub const EXPIRED_LEASE_GRACE_SECONDS: u32 = 600;

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
pub struct AdmittedDnsQuery {
    name: String,
    decision: PolicyDecision,
}

impl AdmittedDnsQuery {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
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

    /// The TTL to answer the guest with: the lease lifetime.
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

/// One admitted TCP flow. Its address, port, route class and attributed name
/// are the identity [`EgressLeaseTable::replace_policy`] judges it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpAdmission {
    address: IpAddr,
    port: u16,
    route_class: RouteClass,
    hostname: Option<String>,
    lease_expires_at: Option<LeaseInstant>,
    decision: PolicyDecision,
}

impl TcpAdmission {
    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn route_class(&self) -> RouteClass {
        self.route_class
    }

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

/// One TCP dial the table hands to the local receiver instead of dialling it
/// (#3999). It is a type of its own, not a [`TcpAdmission`], so a caller
/// cannot dial it without first matching [`TcpVerdict::Intercepted`]. Its
/// name is the bound name whose lease attributes the address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpInterception {
    address: IpAddr,
    port: u16,
    route_class: RouteClass,
    hostname: String,
    lease_expires_at: LeaseInstant,
    policy_digest: PolicyDigest,
}

impl TcpInterception {
    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn route_class(&self) -> RouteClass {
        self.route_class
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn lease_expires_at(&self) -> LeaseInstant {
        self.lease_expires_at
    }

    pub fn policy_digest(&self) -> PolicyDigest {
        self.policy_digest
    }
}

/// Why the table refused a DNS question or a dial. Only the owner sees it;
/// the guest gets NXDOMAIN or a reset whatever the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusalReason {
    /// The policy does not allow the name.
    NameNotAllowed,
    /// Every answer, or a name in its CNAME chain, is protected or local to
    /// the host.
    ProtectedAnswersOnly,
    /// The destination is allowed on other ports only.
    PortNotAllowed,
    /// No allowed name was resolved to the address and no CIDR rule allows
    /// it.
    AddressNotAllowed,
    /// The address is protected or local to the host.
    ProtectedAddress,
    /// The address's lease expired and its name no longer answers it.
    LeaseExpired,
    /// The dial is to a name bound for interception, and nothing receives
    /// intercepted connections yet (#3999).
    InterceptUnavailable,
}

impl RefusalReason {
    pub const ALL: [Self; 7] = [
        Self::NameNotAllowed,
        Self::ProtectedAnswersOnly,
        Self::PortNotAllowed,
        Self::AddressNotAllowed,
        Self::ProtectedAddress,
        Self::LeaseExpired,
        Self::InterceptUnavailable,
    ];

    /// The stable code logs and status report.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NameNotAllowed => "name_not_allowed",
            Self::ProtectedAnswersOnly => "protected_answers_only",
            Self::PortNotAllowed => "port_not_allowed",
            Self::AddressNotAllowed => "address_not_allowed",
            Self::ProtectedAddress => "protected_address",
            Self::LeaseExpired => "lease_expired",
            Self::InterceptUnavailable => "intercept_unavailable",
        }
    }

    /// The owner-facing wording.
    pub const fn description(self) -> &'static str {
        match self {
            Self::NameNotAllowed => "name not allowed",
            Self::ProtectedAnswersOnly => "answers only protected addresses",
            Self::PortNotAllowed => "port not allowed",
            Self::AddressNotAllowed => "address not allowed",
            Self::ProtectedAddress => "protected address",
            Self::LeaseExpired => "lease expired",
            Self::InterceptUnavailable => "interception unavailable",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::NameNotAllowed => 0,
            Self::ProtectedAnswersOnly => 1,
            Self::PortNotAllowed => 2,
            Self::AddressNotAllowed => 3,
            Self::ProtectedAddress => 4,
            Self::LeaseExpired => 5,
            Self::InterceptUnavailable => 6,
        }
    }
}

/// A snapshot of the refusal counters: one count per reason, never a name or
/// an address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefusalCounts([u64; RefusalReason::ALL.len()]);

impl RefusalCounts {
    pub fn get(&self, reason: RefusalReason) -> u64 {
        self.0[reason.index()]
    }

    pub fn total(&self) -> u64 {
        self.0
            .iter()
            .fold(0, |total, count| total.saturating_add(*count))
    }

    pub fn iter(&self) -> impl Iterator<Item = (RefusalReason, u64)> + '_ {
        RefusalReason::ALL
            .into_iter()
            .map(|reason| (reason, self.get(reason)))
    }
}

/// Counters a shared reference can bump, so the `&self` DNS question path
/// counts too.
#[derive(Debug, Default)]
struct RefusalCounters([AtomicU64; RefusalReason::ALL.len()]);

impl RefusalCounters {
    fn record(&self, reason: RefusalReason) {
        self.0[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> RefusalCounts {
        RefusalCounts(std::array::from_fn(|index| {
            self.0[index].load(Ordering::Relaxed)
        }))
    }
}

impl Clone for RefusalCounters {
    fn clone(&self) -> Self {
        let counts = self.snapshot();
        Self(std::array::from_fn(|index| AtomicU64::new(counts.0[index])))
    }
}

/// A refused DNS question or dial, with the decision the policy made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    reason: RefusalReason,
    decision: PolicyDecision,
}

impl Refusal {
    pub fn reason(&self) -> RefusalReason {
        self.reason
    }

    pub fn decision(&self) -> &PolicyDecision {
        &self.decision
    }
}

/// A dial whose address only an expired lease names. It carries that lease's
/// own name, so the broker re-resolves the name the table recorded, never a
/// guest-supplied one. Only the table creates it, and
/// [`EgressLeaseTable::readmit_expired`] consumes it.
#[derive(Debug, PartialEq, Eq)]
pub struct ExpiredLease {
    name: String,
    address: IpAddr,
    port: u16,
    route_class: RouteClass,
    decision: PolicyDecision,
}

impl ExpiredLease {
    /// The name to re-resolve.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The address the dial wants; the answer must contain it.
    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// The table's answer to one dial.
#[derive(Debug, PartialEq, Eq)]
pub enum TcpVerdict {
    Allowed(TcpAdmission),
    /// Hand the connection to the local receiver; never dial it (#3999).
    Intercepted(TcpInterception),
    Refused(Refusal),
    /// Re-resolve [`ExpiredLease::name`] once and pass the answer to
    /// [`EgressLeaseTable::readmit_expired`].
    LeaseExpired(ExpiredLease),
}

/// A dial [`EgressLeaseTable::readmit_expired`] admits once its name answers
/// the address again: to dial, or to intercept.
#[derive(Debug, PartialEq, Eq)]
pub enum Readmission {
    Allowed(TcpAdmission),
    Intercepted(TcpInterception),
}

/// An established flow the broker passes for judgement when the policy or
/// the interception bindings are replaced, as it was admitted.
#[derive(Clone, Copy, Debug)]
pub enum EstablishedFlow<'a> {
    Dialled(&'a TcpAdmission),
    Intercepted(&'a TcpInterception),
}

impl<'a> From<&'a TcpAdmission> for EstablishedFlow<'a> {
    fn from(admission: &'a TcpAdmission) -> Self {
        Self::Dialled(admission)
    }
}

impl<'a> From<&'a TcpInterception> for EstablishedFlow<'a> {
    fn from(interception: &'a TcpInterception) -> Self {
        Self::Intercepted(interception)
    }
}

/// What [`EgressLeaseTable::replace_intercepts`] changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterceptReplacement<K> {
    dropped_leases: usize,
    reset_flows: Vec<K>,
}

impl<K> InterceptReplacement<K> {
    /// Leases only a removed binding admitted, removed from the table.
    pub fn dropped_leases(&self) -> usize {
        self.dropped_leases
    }

    /// The keys of the passed flows whose outcome the new bindings change, in
    /// the order they were passed. The broker resets each of them.
    pub fn reset_flows(&self) -> &[K] {
        &self.reset_flows
    }

    pub fn into_reset_flows(self) -> Vec<K> {
        self.reset_flows
    }
}

/// What [`EgressLeaseTable::replace_policy`] changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyReplacement<K> {
    previous: PolicyDigest,
    current: PolicyDigest,
    dropped_leases: usize,
    refused_flows: Vec<K>,
}

impl<K> PolicyReplacement<K> {
    pub fn previous_digest(&self) -> PolicyDigest {
        self.previous
    }

    pub fn current_digest(&self) -> PolicyDigest {
        self.current
    }

    /// Leases the new revision refuses, removed from the table.
    pub fn dropped_leases(&self) -> usize {
        self.dropped_leases
    }

    /// The keys of the passed flows the new revision refuses, or would now
    /// treat otherwise (a dialled flow it would intercept, or an intercepted
    /// one it would not), in the order they were passed. The broker resets
    /// each of them.
    pub fn refused_flows(&self) -> &[K] {
        &self.refused_flows
    }

    pub fn into_refused_flows(self) -> Vec<K> {
        self.refused_flows
    }
}

#[derive(Clone, Debug)]
struct DnsLease {
    name: String,
    address: IpAddr,
    route_class: RouteClass,
    expires_at: LeaseInstant,
}

impl DnsLease {
    fn is_active(&self, now: LeaseInstant) -> bool {
        self.expires_at > now
    }

    fn is_retained(&self, now: LeaseInstant) -> bool {
        self.expires_at
            .checked_add_seconds(EXPIRED_LEASE_GRACE_SECONDS)
            .is_none_or(|end| end > now)
    }
}

#[derive(Clone, Debug)]
pub struct EgressLeaseTable {
    policy: CompiledPolicy,
    leases: Vec<DnsLease>,
    maximum_leases: usize,
    host_addresses: HostAddressSet,
    intercepts: InterceptSet,
    refusals: RefusalCounters,
}

impl EgressLeaseTable {
    /// A table whose name-bound leases live as long as the shortest TTL in
    /// the answer, clamped to [`MIN_NAME_BOUND_LEASE_SECONDS`] and
    /// [`MAX_DNS_TTL_SECONDS`]; the TTL returned to the guest equals the lease.
    pub fn new(policy: CompiledPolicy) -> Self {
        Self {
            policy,
            leases: Vec::new(),
            maximum_leases: MAX_ACTIVE_DNS_LEASES,
            host_addresses: HostAddressSet::default(),
            intercepts: InterceptSet::default(),
            refusals: RefusalCounters::default(),
        }
    }

    /// Replace the addresses local to the host this table's broker dials from
    /// (#2614). Every later TCP admission refuses them, and DNS admission
    /// leaves them out of answers.
    pub fn set_host_addresses(&mut self, addresses: HostAddressSet) {
        self.host_addresses = addresses;
    }

    pub fn with_maximum_leases(
        policy: CompiledPolicy,
        maximum_leases: usize,
    ) -> Result<Self, LeaseError> {
        if !(1..=MAX_ACTIVE_DNS_LEASES).contains(&maximum_leases) {
            return Err(LeaseError::InvalidCapacity);
        }
        Ok(Self {
            maximum_leases,
            ..Self::new(policy)
        })
    }

    pub fn policy_digest(&self) -> PolicyDigest {
        self.policy.digest()
    }

    /// The names bound for interception; empty unless replaced.
    pub fn intercepts(&self) -> &InterceptSet {
        &self.intercepts
    }

    /// Refusal counts since the table was made or last reset.
    pub fn refusal_counts(&self) -> RefusalCounts {
        self.refusals.snapshot()
    }

    /// Only the table's owner, holding it mutably, resets its counters.
    pub fn reset_refusal_counts(&mut self) {
        self.refusals = RefusalCounters::default();
    }

    /// Apply policy before invoking an external resolver.
    ///
    /// Allowed queries return the canonical name that a resolver adapter must
    /// use. A denial therefore cannot leak the requested name to DNS.
    pub fn authorize_dns_query(
        &self,
        name: &str,
        route_class: RouteClass,
    ) -> Result<Admission<AdmittedDnsQuery>, LeaseError> {
        let query = EgressRequest::dns_query(name, route_class)?;
        let decision = judge_dns(&self.policy, &self.intercepts, &query);
        if !decision.is_allowed() {
            self.refusals.record(RefusalReason::NameNotAllowed);
            return Ok(Admission::Denied(decision));
        }
        Ok(Admission::Allowed(AdmittedDnsQuery {
            name: query
                .hostname()
                .expect("a validated DNS query always carries its name")
                .to_string(),
            decision,
        }))
    }

    /// Admit a resolver result and create bounded name-to-address leases.
    ///
    /// The caller owns DNS transport and supplies the complete canonical CNAME
    /// chain plus terminal addresses. Protected aliases, protected addresses
    /// and addresses local to the host are rejected or filtered before any
    /// lease is recorded. The returned TTL is the lease lifetime: the
    /// shortest observed TTL within the table's bounds.
    pub fn admit_dns(
        &mut self,
        name: &str,
        route_class: RouteClass,
        resolution: DnsResolution,
        now: LeaseInstant,
    ) -> Result<Admission<AdmittedDnsResolution>, LeaseError> {
        Ok(
            match self.admit_resolution(name, route_class, resolution, now)? {
                Ok(admitted) => Admission::Allowed(admitted),
                Err(refusal) => Admission::Denied(refusal.decision),
            },
        )
    }

    fn admit_resolution(
        &mut self,
        name: &str,
        route_class: RouteClass,
        resolution: DnsResolution,
        now: LeaseInstant,
    ) -> Result<Result<AdmittedDnsResolution, Refusal>, LeaseError> {
        let query = match self.authorize_dns_query(name, route_class)? {
            Admission::Allowed(query) => query,
            Admission::Denied(decision) => {
                return Ok(Err(Refusal {
                    reason: RefusalReason::NameNotAllowed,
                    decision,
                }));
            }
        };
        let name = query.name;
        let query_decision = query.decision;

        for alias in &resolution.aliases {
            if alias.name == name {
                return Err(LeaseError::CnameCycle);
            }
            if protected_name(&alias.name).is_some() {
                let alias_request = EgressRequest::dns_query(&alias.name, route_class)?;
                let decision = self.policy.evaluate(&alias_request);
                return Ok(Err(
                    self.refuse(RefusalReason::ProtectedAnswersOnly, decision)
                ));
            }
        }

        let ttl_seconds = resolution
            .effective_ttl_seconds()
            .clamp(MIN_NAME_BOUND_LEASE_SECONDS, MAX_DNS_TTL_SECONDS);
        let expires_at = now
            .checked_add_seconds(ttl_seconds)
            .ok_or(LeaseError::TimeOverflow)?;
        let mut admitted = Vec::with_capacity(resolution.addresses.len());
        let mut first_denial = None;
        for record in &resolution.addresses {
            let decision = match self.host_addresses.classify(record.address) {
                Some(class) => self
                    .policy
                    .deny(DecisionReason::ProtectedAddress(class), None),
                None => judge_dns(
                    &self.policy,
                    &self.intercepts,
                    &EgressRequest::dns_answer(&name, record.address, route_class)?,
                ),
            };
            if decision.is_allowed() {
                admitted.push(record.address);
            } else if first_denial.is_none() {
                first_denial = Some(decision);
            }
        }
        if admitted.is_empty() {
            let decision = first_denial.expect("a non-empty DNS answer has a policy decision");
            let reason = match decision.reason {
                DecisionReason::ProtectedAddress(_) | DecisionReason::ProtectedName(_) => {
                    RefusalReason::ProtectedAnswersOnly
                }
                _ => RefusalReason::NameNotAllowed,
            };
            return Ok(Err(self.refuse(reason, decision)));
        }

        self.purge_expired(now);
        let matches = |lease: &DnsLease, address: IpAddr| {
            lease.name == name && lease.address == address && lease.route_class == route_class
        };
        let new_leases = admitted
            .iter()
            .filter(|address| !self.leases.iter().any(|lease| matches(lease, **address)))
            .count();
        let overflow = (self.leases.len() + new_leases).saturating_sub(self.maximum_leases);
        if overflow > 0 {
            // Capacity pressure ends the grace of the longest-expired leases
            // first; a lease this answer refreshes is never one of them.
            let mut evictable: Vec<(LeaseInstant, usize)> = self
                .leases
                .iter()
                .enumerate()
                .filter(|(_, lease)| {
                    !lease.is_active(now)
                        && !admitted.iter().any(|address| matches(lease, *address))
                })
                .map(|(index, lease)| (lease.expires_at, index))
                .collect();
            if evictable.len() < overflow {
                return Err(LeaseError::CapacityExhausted {
                    maximum: self.maximum_leases,
                });
            }
            evictable.sort_unstable();
            let evicted: BTreeSet<usize> = evictable[..overflow]
                .iter()
                .map(|(_, index)| *index)
                .collect();
            let mut index = 0;
            self.leases.retain(|_| {
                let keep = !evicted.contains(&index);
                index += 1;
                keep
            });
        }
        for address in &admitted {
            if let Some(existing) = self
                .leases
                .iter_mut()
                .find(|lease| matches(lease, *address))
            {
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

        Ok(Ok(AdmittedDnsResolution {
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
    ///
    /// When only an expired lease would admit the dial, the verdict is
    /// [`TcpVerdict::LeaseExpired`] and nothing is counted yet.
    ///
    /// A lease of a name bound on `port` for interception (#3999) is judged
    /// before any allow rule: an active one answers
    /// [`TcpVerdict::Intercepted`], an expired one [`TcpVerdict::LeaseExpired`],
    /// unless [`Self::deny_beats_interception`] refuses the dial.
    pub fn admit_tcp_or_expired(
        &mut self,
        address: IpAddr,
        port: u16,
        route_class: RouteClass,
        now: LeaseInstant,
    ) -> Result<TcpVerdict, LeaseError> {
        self.purge_expired(now);
        let direct_request = EgressRequest::tcp(address, port, None, route_class)?;
        // An address local to the host is refused whatever the rules or leases
        // say, like a private address.
        if let Some(class) = self.host_addresses.classify(address) {
            let decision = self
                .policy
                .deny(DecisionReason::ProtectedAddress(class), None);
            return Ok(TcpVerdict::Refused(
                self.refuse(RefusalReason::ProtectedAddress, decision),
            ));
        }
        let direct_decision = self.policy.evaluate(&direct_request);
        if matches!(direct_decision.reason, DecisionReason::ProtectedAddress(_)) {
            return Ok(TcpVerdict::Refused(
                self.refuse(RefusalReason::ProtectedAddress, direct_decision),
            ));
        }
        // Before the direct allow, so a broad CIDR rule cannot carry a dial
        // to a bound name past its interception.
        if let Some(verdict) = self.intercept_verdict(address, port, route_class, now)? {
            return Ok(verdict);
        }
        if direct_decision.is_allowed() {
            return Ok(TcpVerdict::Allowed(TcpAdmission {
                address,
                port,
                route_class,
                hostname: None,
                lease_expires_at: None,
                decision: direct_decision,
            }));
        }

        let mut expired = None;
        for lease in &self.leases {
            if lease.address != address || lease.route_class != route_class {
                continue;
            }
            let named_request = EgressRequest::tcp(address, port, Some(&lease.name), route_class)?;
            let decision = self.policy.evaluate(&named_request);
            if !decision.is_allowed() {
                continue;
            }
            if lease.is_active(now) {
                return Ok(TcpVerdict::Allowed(TcpAdmission {
                    address,
                    port,
                    route_class,
                    hostname: Some(lease.name.clone()),
                    lease_expires_at: Some(lease.expires_at),
                    decision,
                }));
            }
            if expired.is_none() {
                expired = Some(lease.name.clone());
            }
        }
        if let Some(name) = expired {
            return Ok(TcpVerdict::LeaseExpired(ExpiredLease {
                name,
                address,
                port,
                route_class,
                decision: direct_decision,
            }));
        }
        let reason = self.tcp_refusal_reason(&direct_request);
        Ok(TcpVerdict::Refused(self.refuse(reason, direct_decision)))
    }

    /// The verdict on a dial whose address a kept lease of a name bound on
    /// `port` attributes, or `None` when no bound name is in play. Bound names
    /// are tried in the table's name order; any active one intercepts.
    fn intercept_verdict(
        &self,
        address: IpAddr,
        port: u16,
        route_class: RouteClass,
        now: LeaseInstant,
    ) -> Result<Option<TcpVerdict>, LeaseError> {
        let bound: Vec<&DnsLease> = self
            .leases_at(address, route_class)
            .filter(|lease| self.intercepts.binds(&lease.name, port))
            .collect();
        let Some(first) = bound.first() else {
            return Ok(None);
        };
        if let Some((reason, decision)) = self.deny_beats_interception(
            address,
            port,
            route_class,
            bound.iter().map(|lease| lease.name.as_str()),
        )? {
            return Ok(Some(TcpVerdict::Refused(self.refuse(reason, decision))));
        }
        if let Some(lease) = bound.iter().find(|lease| lease.is_active(now)) {
            return Ok(Some(TcpVerdict::Intercepted(TcpInterception {
                address,
                port,
                route_class,
                hostname: lease.name.clone(),
                lease_expires_at: lease.expires_at,
                policy_digest: self.policy.digest(),
            })));
        }
        // The decision a lapsed re-resolve is refused with: no rule decides an
        // intercepted dial, and a CIDR allow must not be reported.
        Ok(Some(TcpVerdict::LeaseExpired(ExpiredLease {
            name: first.name.clone(),
            address,
            port,
            route_class,
            decision: self.policy.deny(DecisionReason::InterceptBinding, None),
        })))
    }

    /// Whether a user's deny rule refuses a dial that a bound name would
    /// otherwise intercept (#3999). A deny rule beats interception: one that
    /// matches the direct request, or the named request for any of the bound
    /// names at the address, refuses the dial with that rule's decision. Only
    /// a rule deny counts; the absence of an allow rule never does. This is
    /// the one place that precedence is decided.
    fn deny_beats_interception<'n>(
        &self,
        address: IpAddr,
        port: u16,
        route_class: RouteClass,
        bound_names: impl IntoIterator<Item = &'n str>,
    ) -> Result<Option<(RefusalReason, PolicyDecision)>, LeaseError> {
        let direct = self
            .policy
            .evaluate(&EgressRequest::tcp(address, port, None, route_class)?);
        if direct.reason == DecisionReason::RuleDeny {
            return Ok(Some((RefusalReason::AddressNotAllowed, direct)));
        }
        for name in bound_names {
            let named =
                self.policy
                    .evaluate(&EgressRequest::tcp(address, port, Some(name), route_class)?);
            if named.reason == DecisionReason::RuleDeny {
                return Ok(Some((RefusalReason::NameNotAllowed, named)));
            }
        }
        Ok(None)
    }

    /// Refuse a dial the table answered [`TcpVerdict::Intercepted`], counted
    /// as [`RefusalReason::InterceptUnavailable`]. The broker calls it while
    /// nothing receives intercepted connections; it consumes the interception
    /// so it cannot be handed on as well.
    pub fn refuse_interception(&self, interception: TcpInterception) -> Refusal {
        self.refuse(
            RefusalReason::InterceptUnavailable,
            PolicyDecision {
                action: DecisionAction::Deny,
                reason: DecisionReason::InterceptBinding,
                rule_id: None,
                policy_digest: interception.policy_digest,
            },
        )
    }

    /// Finish a dial that found only an expired lease, with the answer the
    /// broker got by re-resolving [`ExpiredLease::name`] once, or `None` when
    /// that lookup produced no addresses or failed.
    ///
    /// The answer goes through the same admission as a guest lookup under the
    /// current policy, so protected addresses and addresses local to the host
    /// are refused again and the leases are refreshed. The dial is then
    /// admitted, to dial or to intercept, only if the answer still contains
    /// its address.
    pub fn readmit_expired(
        &mut self,
        expired: ExpiredLease,
        resolution: Option<DnsResolution>,
        now: LeaseInstant,
    ) -> Result<Result<Readmission, Refusal>, LeaseError> {
        let ExpiredLease {
            name,
            address,
            port,
            route_class,
            decision,
        } = expired;
        let Some(resolution) = resolution else {
            return Ok(Err(self.refuse(RefusalReason::LeaseExpired, decision)));
        };
        match self.admit_resolution(&name, route_class, resolution, now)? {
            Err(refusal) => return Ok(Err(refusal)),
            Ok(admitted) if !admitted.addresses.contains(&address) => {
                return Ok(Err(self.refuse(RefusalReason::LeaseExpired, decision)));
            }
            Ok(_) => {}
        }
        Ok(
            match self.admit_tcp_or_expired(address, port, route_class, now)? {
                TcpVerdict::Allowed(admission) => Ok(Readmission::Allowed(admission)),
                TcpVerdict::Intercepted(interception) => Ok(Readmission::Intercepted(interception)),
                TcpVerdict::Refused(refusal) => Err(refusal),
                TcpVerdict::LeaseExpired(again) => {
                    Err(self.refuse(RefusalReason::LeaseExpired, again.decision))
                }
            },
        )
    }

    /// Swap the policy for a new revision in one call: every lease the new
    /// revision refuses is dropped, and of the flows the broker passes, the
    /// keys of those it refuses, or would now dial where it intercepted or
    /// intercept where it dialled, are returned so the broker resets them.
    /// Later DNS questions and dials see only the new revision; nothing can
    /// observe the table between the two.
    pub fn replace_policy<'a, K, F>(
        &mut self,
        policy: CompiledPolicy,
        flows: impl IntoIterator<Item = (K, F)>,
        now: LeaseInstant,
    ) -> PolicyReplacement<K>
    where
        F: Into<EstablishedFlow<'a>>,
    {
        self.purge_expired(now);
        let previous = self.policy.digest();
        let before = self.leases.len();
        let leases = std::mem::take(&mut self.leases)
            .into_iter()
            .filter(|lease| lease_allowed(&policy, &self.intercepts, lease))
            .collect();
        self.policy = policy;
        self.leases = leases;
        PolicyReplacement {
            previous,
            current: self.policy.digest(),
            dropped_leases: before - self.leases.len(),
            refused_flows: self.flows_to_reset(flows),
        }
    }

    /// Swap the interception bindings in one call (#3999), as
    /// [`Self::replace_policy`] swaps the policy: every lease only a removed
    /// binding admitted is dropped, and of the flows the broker passes, the
    /// keys of those whose outcome changes are returned so the broker resets
    /// them: a dialled flow a binding would now intercept, an intercepted flow
    /// no binding intercepts any more, or one now refused.
    pub fn replace_intercepts<'a, K, F>(
        &mut self,
        intercepts: InterceptSet,
        flows: impl IntoIterator<Item = (K, F)>,
        now: LeaseInstant,
    ) -> InterceptReplacement<K>
    where
        F: Into<EstablishedFlow<'a>>,
    {
        self.purge_expired(now);
        let before = self.leases.len();
        let leases = std::mem::take(&mut self.leases)
            .into_iter()
            .filter(|lease| lease_allowed(&self.policy, &intercepts, lease))
            .collect();
        self.intercepts = intercepts;
        self.leases = leases;
        InterceptReplacement {
            dropped_leases: before - self.leases.len(),
            reset_flows: self.flows_to_reset(flows),
        }
    }

    fn flows_to_reset<'a, K, F>(&self, flows: impl IntoIterator<Item = (K, F)>) -> Vec<K>
    where
        F: Into<EstablishedFlow<'a>>,
    {
        flows
            .into_iter()
            .filter_map(|(key, flow)| {
                let reset = match flow.into() {
                    EstablishedFlow::Dialled(admission) => {
                        self.meets_bound_name(admission) || !self.still_admits(admission)
                    }
                    EstablishedFlow::Intercepted(interception) => {
                        !self.still_intercepts(interception)
                    }
                };
                reset.then_some(key)
            })
            .collect()
    }

    /// Unexpired leases.
    pub fn active_leases(&mut self, now: LeaseInstant) -> usize {
        self.purge_expired(now);
        self.leases
            .iter()
            .filter(|lease| lease.is_active(now))
            .count()
    }

    /// Whether the current policy admits an established flow as it would a
    /// new dial: directly, or by a name whose lease it keeps for the address.
    /// The flow's own attributed name counts even after its lease aged out,
    /// so a long-lived flow is reset only when the new revision refuses it.
    fn still_admits(&self, admission: &TcpAdmission) -> bool {
        let TcpAdmission {
            address,
            port,
            route_class,
            ..
        } = *admission;
        if self.host_addresses.classify(address).is_some() {
            return false;
        }
        let allowed = |hostname: Option<&str>| {
            EgressRequest::tcp(address, port, hostname, route_class)
                .is_ok_and(|request| self.policy.evaluate(&request).is_allowed())
        };
        let own_name = admission.hostname.as_deref().filter(|name| {
            lease_allowed(
                &self.policy,
                &self.intercepts,
                &DnsLease {
                    name: (*name).to_owned(),
                    address,
                    route_class,
                    expires_at: LeaseInstant::ZERO,
                },
            )
        });
        allowed(None)
            || own_name
                .into_iter()
                .chain(
                    self.leases
                        .iter()
                        .filter(|lease| {
                            lease.address == address && lease.route_class == route_class
                        })
                        .map(|lease| lease.name.as_str()),
                )
                .any(|hostname| allowed(Some(hostname)))
    }

    /// Whether a dialled flow's destination now meets a name bound on its
    /// port, by its own attributed name or a lease kept for its address. A new
    /// dial there would be intercepted or refused, never dialled, so the flow
    /// is reset.
    fn meets_bound_name(&self, admission: &TcpAdmission) -> bool {
        admission
            .hostname
            .as_deref()
            .into_iter()
            .chain(
                self.leases_at(admission.address, admission.route_class)
                    .map(|lease| lease.name.as_str()),
            )
            .any(|name| self.intercepts.binds(name, admission.port))
    }

    /// Whether the current state would still intercept an established
    /// intercepted flow under its own name. Like [`Self::still_admits`], the
    /// name counts after its lease aged out while the name could still be
    /// leased for the address.
    fn still_intercepts(&self, interception: &TcpInterception) -> bool {
        let TcpInterception {
            address,
            port,
            route_class,
            ref hostname,
            ..
        } = *interception;
        if self.host_addresses.classify(address).is_some()
            || !self.intercepts.binds(hostname, port)
            || !lease_allowed(
                &self.policy,
                &self.intercepts,
                &DnsLease {
                    name: hostname.clone(),
                    address,
                    route_class,
                    expires_at: LeaseInstant::ZERO,
                },
            )
        {
            return false;
        }
        let bound = std::iter::once(hostname.as_str()).chain(
            self.leases_at(address, route_class)
                .map(|lease| lease.name.as_str())
                .filter(|name| self.intercepts.binds(name, port)),
        );
        matches!(
            self.deny_beats_interception(address, port, route_class, bound),
            Ok(None)
        )
    }

    /// The kept leases, active or expired, for one address and route class.
    fn leases_at(
        &self,
        address: IpAddr,
        route_class: RouteClass,
    ) -> impl Iterator<Item = &DnsLease> + '_ {
        self.leases
            .iter()
            .filter(move |lease| lease.address == address && lease.route_class == route_class)
    }

    fn tcp_refusal_reason(&self, direct_request: &EgressRequest) -> RefusalReason {
        let address = direct_request
            .address()
            .expect("a TCP request always carries its address");
        let route_class = direct_request.route_class();
        let mut named = false;
        for lease in &self.leases {
            if lease.address != address || lease.route_class != route_class {
                continue;
            }
            named = true;
            if EgressRequest::tcp(
                address,
                direct_request.port(),
                Some(&lease.name),
                route_class,
            )
            .is_ok_and(|request| self.policy.allows_on_another_port(&request))
            {
                return RefusalReason::PortNotAllowed;
            }
        }
        if self.policy.allows_on_another_port(direct_request) {
            RefusalReason::PortNotAllowed
        } else if named {
            RefusalReason::NameNotAllowed
        } else {
            RefusalReason::AddressNotAllowed
        }
    }

    fn refuse(&self, reason: RefusalReason, decision: PolicyDecision) -> Refusal {
        self.refusals.record(reason);
        Refusal { reason, decision }
    }

    fn purge_expired(&mut self, now: LeaseInstant) {
        self.leases.retain(|lease| lease.is_retained(now));
    }
}

fn lease_allowed(policy: &CompiledPolicy, intercepts: &InterceptSet, lease: &DnsLease) -> bool {
    let query = EgressRequest::dns_query(&lease.name, lease.route_class);
    let answer = EgressRequest::dns_answer(&lease.name, lease.address, lease.route_class);
    matches!(
        (query, answer),
        (Ok(query), Ok(answer))
            if judge_dns(policy, intercepts, &query).is_allowed()
                && judge_dns(policy, intercepts, &answer).is_allowed()
    )
}

/// The policy's decision on a DNS question or answer, except that a name
/// bound for interception that the policy refuses only by default is
/// admitted (#3999): a bound name must resolve to be intercepted. A rule
/// deny, a protected name or a protected address still refuses it.
fn judge_dns(
    policy: &CompiledPolicy,
    intercepts: &InterceptSet,
    request: &EgressRequest,
) -> PolicyDecision {
    let decision = policy.evaluate(request);
    if decision.reason == DecisionReason::DefaultDeny
        && request
            .hostname()
            .is_some_and(|name| intercepts.binds_name(name))
    {
        return PolicyDecision {
            action: DecisionAction::Allow,
            reason: DecisionReason::InterceptBinding,
            rule_id: None,
            policy_digest: decision.policy_digest,
        };
    }
    decision
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

    /// A dial's admission where an expired lease counts as a refusal, as the
    /// broker's answer is when its one re-resolve finds nothing.
    trait AdmitOrRefuse {
        fn admit_or_refuse(
            &mut self,
            address: IpAddr,
            port: u16,
            route_class: RouteClass,
            now: LeaseInstant,
        ) -> Result<Admission<TcpAdmission>, LeaseError>;
    }

    impl AdmitOrRefuse for EgressLeaseTable {
        fn admit_or_refuse(
            &mut self,
            address: IpAddr,
            port: u16,
            route_class: RouteClass,
            now: LeaseInstant,
        ) -> Result<Admission<TcpAdmission>, LeaseError> {
            Ok(
                match self.admit_tcp_or_expired(address, port, route_class, now)? {
                    TcpVerdict::Allowed(admission) => Admission::Allowed(admission),
                    TcpVerdict::Intercepted(interception) => {
                        panic!("unexpected interception: {interception:?}")
                    }
                    TcpVerdict::Refused(refusal) => Admission::Denied(refusal.decision),
                    TcpVerdict::LeaseExpired(expired) => Admission::Denied(
                        self.readmit_expired(expired, None, now)?
                            .expect_err("no answer never readmits")
                            .decision,
                    ),
                },
            )
        }
    }
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
                .admit_or_refuse(PUBLIC_V4, 443, RouteClass::General, LeaseInstant::ZERO)
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
                .admit_or_refuse(
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
                .admit_or_refuse(
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
    fn dns_query_policy_runs_before_resolution_and_returns_only_a_canonical_name() {
        let table = EgressLeaseTable::new(named_policy());
        let query = allowed(
            table
                .authorize_dns_query("Allowed.Example.COM.", RouteClass::General)
                .unwrap(),
        );
        assert_eq!(query.name(), "allowed.example.com");
        assert!(query.decision().is_allowed());

        let decision = denied(
            table
                .authorize_dns_query("denied.example.com", RouteClass::General)
                .unwrap(),
        );
        assert_eq!(decision.reason, DecisionReason::DefaultDeny);
    }

    #[test]
    fn direct_ip_allow_does_not_claim_a_hostname_lease() {
        let mut table = EgressLeaseTable::new(CompiledPolicy::developer_baseline());
        let tcp = allowed(
            table
                .admit_or_refuse(PUBLIC_V4, 443, RouteClass::General, LeaseInstant::ZERO)
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
        // The shortest TTL left after filtering is 20 s, clamped up to 60 s.
        assert_eq!(dns.ttl_seconds(), 60);
        assert_eq!(dns.expires_at(), LeaseInstant::from_millis(61_000));
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
        // The 5 s answer is clamped up to a 60 s lease from 10 s.
        assert_eq!(refreshed.expires_at(), LeaseInstant::from_millis(70_000));
        let tcp = allowed(
            table
                .admit_or_refuse(
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
                .admit_or_refuse(PUBLIC_V4, 443, RouteClass::General, LeaseInstant::ZERO)
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
                .admit_or_refuse(PUBLIC_V4, 443, RouteClass::Credential, LeaseInstant::ZERO)
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
                .admit_or_refuse(
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

    // #2537: lease clamp, expired-lease re-resolve, replace_policy and
    // refusal counters.

    use std::sync::{Arc, Barrier, Mutex};

    use crate::typed::{AllowRule, AllowTarget, TypedPolicy};

    const CDN_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35));

    fn at(seconds: u64) -> LeaseInstant {
        LeaseInstant::from_millis(seconds * 1_000)
    }

    fn resolution(addresses: &[(IpAddr, u32)]) -> DnsResolution {
        DnsResolution::new(
            vec![],
            addresses
                .iter()
                .map(|(ip, ttl)| address(*ip, *ttl))
                .collect(),
        )
        .unwrap()
    }

    fn typed(rules: &[(&str, &[u16])]) -> CompiledPolicy {
        TypedPolicy::new(rules.iter().map(|(target, ports)| {
            AllowRule::new(AllowTarget::parse(target).unwrap(), ports.iter().copied()).unwrap()
        }))
        .unwrap()
        .compile()
    }

    fn resolve(table: &mut EgressLeaseTable, name: &str, ip: IpAddr, ttl: u32, now: LeaseInstant) {
        allowed(
            table
                .admit_dns(name, RouteClass::General, resolution(&[(ip, ttl)]), now)
                .unwrap(),
        );
    }

    fn verdict(
        table: &mut EgressLeaseTable,
        ip: IpAddr,
        port: u16,
        now: LeaseInstant,
    ) -> TcpVerdict {
        table
            .admit_tcp_or_expired(ip, port, RouteClass::General, now)
            .unwrap()
    }

    fn expired_lease(verdict: TcpVerdict) -> ExpiredLease {
        match verdict {
            TcpVerdict::LeaseExpired(expired) => expired,
            other => panic!("expected an expired lease, got {other:?}"),
        }
    }

    fn refused(verdict: TcpVerdict) -> Refusal {
        match verdict {
            TcpVerdict::Refused(refusal) => refusal,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn admitted(verdict: TcpVerdict) -> TcpAdmission {
        match verdict {
            TcpVerdict::Allowed(admission) => admission,
            other => panic!("expected an admission, got {other:?}"),
        }
    }

    fn only(counts: RefusalCounts, reason: RefusalReason, count: u64) {
        for (each, value) in counts.iter() {
            let expected = if each == reason { count } else { 0 };
            assert_eq!(value, expected, "{} count", each.code());
        }
    }

    #[test]
    fn clamped_leases_live_sixty_to_three_hundred_seconds_and_the_ttl_is_the_lease() {
        for ttl in (1..=1_000)
            .step_by(7)
            .chain([59, 60, 61, 299, 300, 301, u32::MAX])
        {
            let mut table = EgressLeaseTable::new(named_policy());
            let now = at(1_000);
            let dns = allowed(
                table
                    .admit_dns(
                        "allowed.example.com",
                        RouteClass::General,
                        DnsResolution::new(
                            vec![DnsAlias::new("edge.example.net", ttl.saturating_add(5)).unwrap()],
                            vec![address(PUBLIC_V4, ttl)],
                        )
                        .unwrap(),
                        now,
                    )
                    .unwrap(),
            );
            let lease = dns.ttl_seconds();
            assert!(
                (MIN_NAME_BOUND_LEASE_SECONDS..=MAX_DNS_TTL_SECONDS).contains(&lease),
                "a TTL of {ttl} leased for {lease} s"
            );
            assert_eq!(
                lease,
                ttl.clamp(MIN_NAME_BOUND_LEASE_SECONDS, MAX_DNS_TTL_SECONDS)
            );
            assert_eq!(
                dns.expires_at().as_millis() - now.as_millis(),
                u64::from(lease) * 1_000,
                "the guest TTL must equal the lease"
            );
            let last = LeaseInstant::from_millis(dns.expires_at().as_millis() - 1);
            assert_eq!(
                admitted(verdict(&mut table, PUBLIC_V4, 443, last)).lease_expires_at(),
                Some(dns.expires_at())
            );
            expired_lease(verdict(&mut table, PUBLIC_V4, 443, dns.expires_at()));
        }
    }

    #[test]
    fn a_one_second_answer_gets_the_minimum_name_bound_lease() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(
            &mut table,
            "allowed.example.com",
            PUBLIC_V4,
            1,
            LeaseInstant::ZERO,
        );
        assert!(
            table
                .admit_or_refuse(
                    PUBLIC_V4,
                    443,
                    RouteClass::General,
                    LeaseInstant::from_millis(59_999)
                )
                .unwrap()
                .is_allowed()
        );
        assert!(matches!(
            table
                .admit_tcp_or_expired(PUBLIC_V4, 443, RouteClass::General, at(60))
                .unwrap(),
            TcpVerdict::LeaseExpired(_)
        ));
    }

    #[test]
    fn a_dial_on_an_expired_lease_names_the_lease_and_readmits_once_answered() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "Allowed.Example.COM.", PUBLIC_V4, 60, at(0));
        assert_eq!(table.active_leases(at(60)), 0);

        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
        assert_eq!(expired.name(), "allowed.example.com");
        assert_eq!(expired.address(), PUBLIC_V4);
        assert_eq!(expired.port(), 443);
        assert_eq!(table.refusal_counts().total(), 0, "nothing is refused yet");

        let Readmission::Allowed(admission) = table
            .readmit_expired(
                expired,
                Some(resolution(&[(PUBLIC_V4, 120), (CDN_V4, 120)])),
                at(61),
            )
            .unwrap()
            .unwrap()
        else {
            panic!("expected a dial");
        };
        assert_eq!(admission.hostname(), Some("allowed.example.com"));
        assert_eq!(admission.lease_expires_at(), Some(at(181)));
        assert_eq!(table.active_leases(at(61)), 2);
        assert_eq!(table.refusal_counts().total(), 0);
        admitted(verdict(&mut table, PUBLIC_V4, 443, at(180)));
    }

    #[test]
    fn a_re_resolve_that_no_longer_answers_the_address_is_refused_as_lease_expired() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));

        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(70)));
        let refusal = table
            .readmit_expired(expired, Some(resolution(&[(CDN_V4, 60)])), at(70))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.reason(), RefusalReason::LeaseExpired);
        assert_eq!(refusal.decision().reason, DecisionReason::DefaultDeny);
        only(table.refusal_counts(), RefusalReason::LeaseExpired, 1);
        // The new answer is leased; the old address's expired lease remains
        // within its grace and is still not admitted.
        admitted(verdict(&mut table, CDN_V4, 443, at(71)));
        expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(71)));

        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(72)));
        let refusal = table
            .readmit_expired(expired, None, at(72))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.reason(), RefusalReason::LeaseExpired);
        only(table.refusal_counts(), RefusalReason::LeaseExpired, 2);
    }

    #[test]
    fn the_legacy_dial_path_refuses_an_expired_lease_as_before_and_counts_it() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
        let decision = denied(
            table
                .admit_or_refuse(PUBLIC_V4, 443, RouteClass::General, at(60))
                .unwrap(),
        );
        assert_eq!(decision.reason, DecisionReason::DefaultDeny);
        only(table.refusal_counts(), RefusalReason::LeaseExpired, 1);
    }

    #[test]
    fn expired_leases_are_kept_for_their_grace_and_then_forgotten() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
        let grace_end = 60 + u64::from(EXPIRED_LEASE_GRACE_SECONDS);
        expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(grace_end - 1)));
        let refusal = refused(verdict(&mut table, PUBLIC_V4, 443, at(grace_end)));
        assert_eq!(refusal.reason(), RefusalReason::AddressNotAllowed);
        assert!(table.leases.is_empty());
    }

    #[test]
    fn capacity_pressure_ends_the_grace_of_the_longest_expired_leases_first() {
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
    destinations: ["*.example.com"]
    route_classes: [general]
"#,
        )
        .unwrap();
        let mut table = EgressLeaseTable::with_maximum_leases(policy, 2).unwrap();
        // Both answers are clamped up to the 60 s minimum lease.
        resolve(&mut table, "a.example.com", PUBLIC_V4, 10, at(0));
        resolve(&mut table, "b.example.com", CDN_V4, 20, at(10));
        // Both are expired at 80 s and kept; a third name evicts the older.
        resolve(&mut table, "c.example.com", OTHER_PUBLIC_V4, 60, at(80));
        assert_eq!(table.leases.len(), 2);
        assert!(
            table
                .leases
                .iter()
                .all(|lease| lease.name != "a.example.com")
        );
        // A refresh of a kept expired lease reuses it instead of evicting it.
        resolve(&mut table, "b.example.com", CDN_V4, 60, at(81));
        assert_eq!(table.active_leases(at(81)), 2);
        // Active leases are never evicted.
        assert!(matches!(
            table.admit_dns(
                "d.example.com",
                RouteClass::General,
                resolution(&[(PUBLIC_V6, 60)]),
                at(82),
            ),
            Err(LeaseError::CapacityExhausted { maximum: 2 })
        ));
        assert_eq!(table.active_leases(at(82)), 2);
    }

    #[test]
    fn a_re_resolve_rechecks_protected_and_host_addresses() {
        // The answer is admitted like a guest lookup: protected addresses and
        // CNAME targets refuse it.
        for answer in [
            resolution(&[(IpAddr::V4(Ipv4Addr::LOCALHOST), 60)]),
            resolution(&[("10.0.0.7".parse().unwrap(), 60)]),
            DnsResolution::new(
                vec![DnsAlias::new("metadata.google.internal", 60).unwrap()],
                vec![address(PUBLIC_V4, 60)],
            )
            .unwrap(),
        ] {
            let mut table = EgressLeaseTable::new(named_policy());
            resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
            let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
            let refusal = table
                .readmit_expired(expired, Some(answer), at(60))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.reason(), RefusalReason::ProtectedAnswersOnly);
            only(
                table.refusal_counts(),
                RefusalReason::ProtectedAnswersOnly,
                1,
            );
            assert_eq!(table.active_leases(at(60)), 0);
        }

        // The dialed address became local to the host while the broker was
        // resolving: the answer drops it, and the dial is refused.
        for (answer, reason) in [
            (
                resolution(&[(PUBLIC_V4, 60)]),
                RefusalReason::ProtectedAnswersOnly,
            ),
            (
                resolution(&[(PUBLIC_V4, 60), (CDN_V4, 60)]),
                RefusalReason::LeaseExpired,
            ),
        ] {
            let mut table = EgressLeaseTable::new(named_policy());
            resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
            let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
            table.set_host_addresses(HostAddressSet::new([], [PUBLIC_V4]).unwrap());
            let refusal = table
                .readmit_expired(expired, Some(answer), at(60))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.reason(), reason);
            assert!(
                table
                    .leases
                    .iter()
                    .all(|lease| lease.address != PUBLIC_V4 || !lease.is_active(at(60)))
            );
        }
    }

    #[test]
    fn a_re_resolve_uses_the_current_policy() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
        // The broker resolves without the table's lock; a revision that no
        // longer allows the name lands meanwhile. Its lease is dropped and
        // the re-resolve is refused for the name.
        let replacement = table.replace_policy(
            typed(&[("other.example.org", &[443])]),
            std::iter::empty::<((), &TcpAdmission)>(),
            at(60),
        );
        assert_eq!(replacement.dropped_leases(), 1);
        let refusal = table
            .readmit_expired(expired, Some(resolution(&[(PUBLIC_V4, 60)])), at(60))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.reason(), RefusalReason::NameNotAllowed);
        assert_eq!(refusal.decision().policy_digest, table.policy_digest());
    }

    #[test]
    fn dns_answers_local_to_the_host_are_left_out() {
        let mut table = EgressLeaseTable::new(named_policy());
        table.set_host_addresses(HostAddressSet::new([PUBLIC_V4], []).unwrap());
        let dns = allowed(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    resolution(&[(PUBLIC_V4, 60), (CDN_V4, 60)]),
                    at(0),
                )
                .unwrap(),
        );
        assert_eq!(dns.addresses(), [CDN_V4]);
        let decision = denied(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    resolution(&[(PUBLIC_V4, 60)]),
                    at(0),
                )
                .unwrap(),
        );
        assert_eq!(
            decision.reason,
            DecisionReason::ProtectedAddress(crate::AddressClass::HostInterface)
        );
        only(
            table.refusal_counts(),
            RefusalReason::ProtectedAnswersOnly,
            1,
        );
    }

    #[test]
    fn refusals_are_counted_by_reason_and_reset_only_by_the_owner() {
        let mut table = EgressLeaseTable::new(named_policy());
        table.set_host_addresses(HostAddressSet::new([], [OTHER_PUBLIC_V4]).unwrap());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));

        denied(
            table
                .authorize_dns_query("denied.example.com", RouteClass::General)
                .unwrap(),
        );
        denied(
            table
                .admit_dns(
                    "allowed.example.com",
                    RouteClass::General,
                    resolution(&[("192.168.1.1".parse().unwrap(), 60)]),
                    at(0),
                )
                .unwrap(),
        );
        let port = refused(verdict(&mut table, PUBLIC_V4, 80, at(1)));
        let raw = refused(verdict(&mut table, CDN_V4, 443, at(1)));
        let private = refused(verdict(&mut table, "10.1.2.3".parse().unwrap(), 443, at(1)));
        let host = refused(verdict(&mut table, OTHER_PUBLIC_V4, 443, at(1)));
        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
        let lapsed = table
            .readmit_expired(expired, None, at(60))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            [port, raw, private, host, lapsed].map(|refusal| refusal.reason()),
            [
                RefusalReason::PortNotAllowed,
                RefusalReason::AddressNotAllowed,
                RefusalReason::ProtectedAddress,
                RefusalReason::ProtectedAddress,
                RefusalReason::LeaseExpired,
            ]
        );

        let counts = table.refusal_counts();
        assert_eq!(
            counts.iter().collect::<Vec<_>>(),
            [
                (RefusalReason::NameNotAllowed, 1),
                (RefusalReason::ProtectedAnswersOnly, 1),
                (RefusalReason::PortNotAllowed, 1),
                (RefusalReason::AddressNotAllowed, 1),
                (RefusalReason::ProtectedAddress, 2),
                (RefusalReason::LeaseExpired, 1),
                (RefusalReason::InterceptUnavailable, 0),
            ]
        );
        assert_eq!(counts.total(), 7);
        // A clone carries a snapshot and then counts on its own.
        let clone = table.clone();
        denied(
            table
                .authorize_dns_query("denied.example.com", RouteClass::General)
                .unwrap(),
        );
        assert_eq!(clone.refusal_counts(), counts);
        assert_eq!(table.refusal_counts().get(RefusalReason::NameNotAllowed), 2);

        table.reset_refusal_counts();
        assert_eq!(table.refusal_counts(), RefusalCounts::default());
        assert_eq!(table.refusal_counts().total(), 0);
    }

    #[test]
    fn refusal_reason_codes_and_wording_are_stable() {
        assert_eq!(
            RefusalReason::ALL.map(RefusalReason::code),
            [
                "name_not_allowed",
                "protected_answers_only",
                "port_not_allowed",
                "address_not_allowed",
                "protected_address",
                "lease_expired",
                "intercept_unavailable",
            ]
        );
        assert_eq!(
            RefusalReason::ALL.map(RefusalReason::description),
            [
                "name not allowed",
                "answers only protected addresses",
                "port not allowed",
                "address not allowed",
                "protected address",
                "lease expired",
                "interception unavailable",
            ]
        );
        for (index, reason) in RefusalReason::ALL.into_iter().enumerate() {
            assert_eq!(reason.index(), index);
        }
    }

    #[test]
    fn open_refuses_an_uncurated_port_as_port_not_allowed() {
        let mut table = EgressLeaseTable::new(CompiledPolicy::developer_baseline());
        let refusal = refused(verdict(&mut table, PUBLIC_V4, 25, at(0)));
        assert_eq!(refusal.reason(), RefusalReason::PortNotAllowed);
    }

    #[test]
    fn a_leased_name_tcp_does_not_allow_is_name_not_allowed() {
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
    destinations: [allowed.example.com]
    route_classes: [general]
"#,
        )
        .unwrap();
        let mut table = EgressLeaseTable::new(policy);
        resolve(&mut table, "other.example.com", PUBLIC_V4, 60, at(0));
        let refusal = refused(verdict(&mut table, PUBLIC_V4, 443, at(1)));
        assert_eq!(refusal.reason(), RefusalReason::NameNotAllowed);
    }

    #[test]
    fn replace_policy_drops_refused_leases_and_reports_refused_flows() {
        let mut table = EgressLeaseTable::new(CompiledPolicy::developer_baseline());
        let previous = table.policy_digest();
        resolve(&mut table, "github.com", PUBLIC_V4, 60, at(0));
        resolve(&mut table, "registry.npmjs.org", CDN_V4, 60, at(0));
        let github = admitted(verdict(&mut table, PUBLIC_V4, 443, at(1)));
        let npm = admitted(verdict(&mut table, CDN_V4, 443, at(1)));
        let raw = admitted(verdict(&mut table, OTHER_PUBLIC_V4, 22, at(1)));
        assert_eq!(github.hostname(), None, "open admits by CIDR");

        let work = typed(&[("github.com", &[22, 443])]);
        let current = work.digest();
        let replacement = table.replace_policy(
            work,
            [("github", &github), ("npm", &npm), ("raw", &raw)],
            at(2),
        );
        assert_eq!(replacement.previous_digest(), previous);
        assert_eq!(replacement.current_digest(), current);
        assert_eq!(table.policy_digest(), current);
        assert_eq!(replacement.dropped_leases(), 1);
        assert_eq!(replacement.refused_flows(), ["npm", "raw"]);

        // From that instant only the new revision answers.
        let dial = admitted(verdict(&mut table, PUBLIC_V4, 22, at(3)));
        assert_eq!(dial.hostname(), Some("github.com"));
        assert_eq!(dial.decision().policy_digest, current);
        assert_eq!(
            refused(verdict(&mut table, CDN_V4, 443, at(3))).reason(),
            RefusalReason::AddressNotAllowed
        );
        denied(
            table
                .authorize_dns_query("registry.npmjs.org", RouteClass::General)
                .unwrap(),
        );

        // Locked refuses every flow and every lease.
        let replacement = table.replace_policy(
            CompiledPolicy::locked(),
            [("github", &github), ("dial", &dial)],
            at(4),
        );
        assert_eq!(replacement.dropped_leases(), 1);
        assert_eq!(replacement.into_refused_flows(), ["github", "dial"]);
        assert!(table.leases.is_empty());
    }

    #[test]
    fn replace_policy_judges_each_passed_flow_even_with_the_same_identity() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
        let flow = admitted(verdict(&mut table, PUBLIC_V4, 443, at(1)));
        let same = flow.clone();

        let kept = table.replace_policy(named_policy(), [(1, &flow), (2, &same)], at(2));
        assert!(kept.refused_flows().is_empty());
        assert_eq!(kept.dropped_leases(), 0);

        let refused =
            table.replace_policy(CompiledPolicy::locked(), [(1, &flow), (2, &same)], at(3));
        assert_eq!(refused.refused_flows(), [1, 2]);
    }

    #[test]
    fn a_flow_whose_lease_is_dropped_survives_when_a_cidr_rule_still_allows_it() {
        let mut table = EgressLeaseTable::new(named_policy());
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
        let flow = admitted(verdict(&mut table, PUBLIC_V4, 443, at(1)));
        assert_eq!(flow.hostname(), Some("allowed.example.com"));

        let replacement =
            table.replace_policy(typed(&[("93.0.0.0/8", &[443])]), [("flow", &flow)], at(2));
        assert_eq!(replacement.dropped_leases(), 1);
        assert!(replacement.refused_flows().is_empty());
        assert!(table.leases.is_empty());
        // A new dial is admitted by the CIDR rule, without a name.
        assert_eq!(
            admitted(verdict(&mut table, PUBLIC_V4, 443, at(3))).hostname(),
            None
        );
    }

    #[test]
    fn replace_policy_refuses_flows_to_addresses_now_local_to_the_host() {
        let mut table = EgressLeaseTable::new(CompiledPolicy::developer_baseline());
        let flow = admitted(verdict(&mut table, PUBLIC_V4, 443, at(0)));
        table.set_host_addresses(HostAddressSet::new([], [PUBLIC_V4]).unwrap());
        let replacement = table.replace_policy(
            CompiledPolicy::developer_baseline(),
            [("flow", &flow)],
            at(1),
        );
        assert_eq!(replacement.refused_flows(), ["flow"]);
    }

    /// A tiny deterministic generator, so the property runs need no new
    /// dependency.
    struct Sequence(u64);

    impl Sequence {
        fn next(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }
    }

    const NAMES: [&str; 3] = ["a.example.com", "b.example.com", "c.example.com"];
    const ADDRESSES: [IpAddr; 3] = [PUBLIC_V4, CDN_V4, OTHER_PUBLIC_V4];

    /// Revisions that differ in which names resolve, while every revision
    /// allows TCP to every name: a lease left over from an older revision
    /// would admit a dial the current one refuses.
    fn revision(allowed: &[&str]) -> CompiledPolicy {
        let destinations = allowed
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let dns = if allowed.is_empty() {
            String::new()
        } else {
            format!(
                "  - id: dns\n    action: allow\n    protocols: [dns]\n    ports: [53]\n    destinations: [{destinations}]\n    route_classes: [general]\n"
            )
        };
        PolicyDocument::parse_yaml(
            format!(
                "version: 1\ndefault: deny\nrules:\n{dns}  - id: tcp\n    action: allow\n    protocols: [tcp]\n    ports: [443]\n    destinations: [\"*.example.com\"]\n    route_classes: [general]\n"
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn revisions() -> Vec<(Vec<&'static str>, CompiledPolicy)> {
        [
            vec!["a.example.com"],
            vec!["b.example.com"],
            vec!["a.example.com", "c.example.com"],
            vec![],
        ]
        .into_iter()
        .map(|names| {
            let policy = revision(&names);
            (names, policy)
        })
        .collect()
    }

    #[test]
    fn property_every_decision_after_a_replacement_is_the_new_revisions_alone() {
        let revisions = revisions();
        for seed in 1..=64_u64 {
            let mut sequence = Sequence(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            let mut current = 0;
            let mut table = EgressLeaseTable::new(revisions[current].1.clone());
            let mut flows: Vec<TcpAdmission> = Vec::new();
            let mut now = 0;
            for _ in 0..200 {
                now += sequence.next(30) as u64;
                let (allowed_names, policy) = &revisions[current];
                match sequence.next(3) {
                    0 => {
                        let name = NAMES[sequence.next(NAMES.len())];
                        let ip = ADDRESSES[sequence.next(ADDRESSES.len())];
                        let result = table
                            .admit_dns(name, RouteClass::General, resolution(&[(ip, 60)]), at(now))
                            .unwrap();
                        assert_eq!(result.is_allowed(), allowed_names.contains(&name));
                    }
                    1 => {
                        let ip = ADDRESSES[sequence.next(ADDRESSES.len())];
                        if let TcpVerdict::Allowed(admission) =
                            verdict(&mut table, ip, 443, at(now))
                        {
                            let name = admission.hostname().unwrap().to_owned();
                            assert!(
                                allowed_names.contains(&name.as_str()),
                                "{name} from an older revision"
                            );
                            assert_eq!(admission.decision().policy_digest, policy.digest());
                            flows.push(admission);
                        }
                    }
                    _ => {
                        current = sequence.next(revisions.len());
                        let (allowed_names, policy) = &revisions[current];
                        let replacement =
                            table.replace_policy(policy.clone(), flows.iter().enumerate(), at(now));
                        assert_eq!(replacement.current_digest(), policy.digest());
                        assert!(
                            table
                                .leases
                                .iter()
                                .all(|lease| allowed_names.contains(&lease.name.as_str()))
                        );
                        let refused: BTreeSet<usize> =
                            replacement.refused_flows().iter().copied().collect();
                        for (index, flow) in flows.iter().enumerate() {
                            let name = flow.hostname().unwrap();
                            let still_leased = table.leases.iter().any(|lease| {
                                lease.address == flow.address()
                                    && allowed_names.contains(&lease.name.as_str())
                            });
                            // TCP allows every name, so a flow survives exactly
                            // while it has a name the new revision lets resolve.
                            let expected_kept = allowed_names.contains(&name) || still_leased;
                            assert_eq!(!refused.contains(&index), expected_kept);
                        }
                        let mut index = 0;
                        flows.retain(|_| {
                            let keep = !refused.contains(&index);
                            index += 1;
                            keep
                        });
                    }
                }
            }
        }
    }

    #[test]
    fn concurrent_admissions_see_the_old_or_the_new_revision_never_a_mix() {
        let revisions = Arc::new(revisions());
        let table = Arc::new(Mutex::new(EgressLeaseTable::new(revisions[0].1.clone())));
        let barrier = Arc::new(Barrier::new(4));
        let mut threads = Vec::new();
        {
            let (table, revisions, barrier) = (
                Arc::clone(&table),
                Arc::clone(&revisions),
                Arc::clone(&barrier),
            );
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for step in 0..2_000 {
                    let policy = revisions[step % revisions.len()].1.clone();
                    table.lock().unwrap().replace_policy(
                        policy,
                        std::iter::empty::<((), &TcpAdmission)>(),
                        at(0),
                    );
                }
            }));
        }
        for worker in 0..3_u64 {
            let (table, revisions, barrier) = (
                Arc::clone(&table),
                Arc::clone(&revisions),
                Arc::clone(&barrier),
            );
            threads.push(std::thread::spawn(move || {
                let mut sequence = Sequence(worker + 7);
                barrier.wait();
                for _ in 0..2_000 {
                    let mut table = table.lock().unwrap();
                    let digest = table.policy_digest();
                    let (allowed_names, _) = revisions
                        .iter()
                        .find(|(_, policy)| policy.digest() == digest)
                        .unwrap();
                    let index = sequence.next(NAMES.len());
                    let name = NAMES[index];
                    let dns = table
                        .admit_dns(
                            name,
                            RouteClass::General,
                            resolution(&[(ADDRESSES[index], 60)]),
                            at(1),
                        )
                        .unwrap();
                    match &dns {
                        Admission::Allowed(resolution) => {
                            assert!(allowed_names.contains(&name));
                            assert_eq!(resolution.decision().policy_digest, digest);
                        }
                        Admission::Denied(decision) => {
                            assert!(!allowed_names.contains(&name));
                            assert_eq!(decision.policy_digest, digest);
                        }
                    }
                    for (index, ip) in ADDRESSES.into_iter().enumerate() {
                        let decision = table
                            .admit_or_refuse(ip, 443, RouteClass::General, at(1))
                            .unwrap();
                        // A lease from another revision must never admit a
                        // dial under this one.
                        if let Admission::Allowed(admission) = decision {
                            assert!(allowed_names.contains(&NAMES[index]));
                            assert_eq!(admission.decision().policy_digest, digest);
                        }
                    }
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
    }

    // #3999: interception bindings.

    use crate::intercept::{InterceptBinding, InterceptSet};

    const BOUND: &str = "api.example.com";

    fn bind(table: &mut EgressLeaseTable, bound: &[(&str, u16)], now: LeaseInstant) {
        let set = InterceptSet::new(
            bound
                .iter()
                .map(|(name, port)| InterceptBinding::new(name, *port).unwrap()),
        )
        .unwrap();
        table.replace_intercepts(set, std::iter::empty::<((), &TcpAdmission)>(), now);
    }

    fn intercepted(verdict: TcpVerdict) -> TcpInterception {
        match verdict {
            TcpVerdict::Intercepted(interception) => interception,
            other => panic!("expected an interception, got {other:?}"),
        }
    }

    fn rules(yaml: &str) -> CompiledPolicy {
        PolicyDocument::parse_yaml(format!("version: 1\ndefault: deny\nrules:\n{yaml}").as_bytes())
            .unwrap()
    }

    #[test]
    fn a_bound_name_resolves_without_an_allow_rule_and_its_dial_is_intercepted() {
        let mut table = EgressLeaseTable::new(named_policy());
        assert!(table.intercepts().is_empty(), "nothing is bound by default");
        assert_eq!(
            denied(
                table
                    .authorize_dns_query(BOUND, RouteClass::General)
                    .unwrap()
            )
            .reason,
            DecisionReason::DefaultDeny
        );
        table.reset_refusal_counts();

        bind(&mut table, &[(BOUND, 443)], at(0));
        let query = allowed(
            table
                .authorize_dns_query("API.Example.COM.", RouteClass::General)
                .unwrap(),
        );
        assert_eq!(query.name(), BOUND);
        assert_eq!(query.decision().reason_code(), "intercept-binding");
        assert_eq!(query.decision().rule_id, None);
        let dns = allowed(
            table
                .admit_dns(
                    BOUND,
                    RouteClass::General,
                    resolution(&[(PUBLIC_V4, 60)]),
                    at(0),
                )
                .unwrap(),
        );
        assert_eq!(dns.addresses(), [PUBLIC_V4]);
        assert_eq!(dns.decision().reason, DecisionReason::InterceptBinding);

        let interception = intercepted(verdict(&mut table, PUBLIC_V4, 443, at(1)));
        assert_eq!(interception.hostname(), BOUND);
        assert_eq!(interception.address(), PUBLIC_V4);
        assert_eq!(interception.port(), 443);
        assert_eq!(interception.route_class(), RouteClass::General);
        assert_eq!(interception.lease_expires_at(), at(60));
        assert_eq!(interception.policy_digest(), table.policy_digest());
        assert_eq!(table.refusal_counts().total(), 0);

        // The same address on a port the name is not bound on, and an
        // address no lease names, are judged as without the binding.
        let other_port = refused(verdict(&mut table, PUBLIC_V4, 80, at(1)));
        assert_eq!(other_port.decision().reason, DecisionReason::DefaultDeny);
        let literal = refused(verdict(&mut table, CDN_V4, 443, at(1)));
        assert_eq!(literal.reason(), RefusalReason::AddressNotAllowed);

        // A broker that has nothing to hand the connection to refuses it.
        let refusal = table.refuse_interception(interception);
        assert_eq!(refusal.reason(), RefusalReason::InterceptUnavailable);
        assert_eq!(refusal.decision().reason_code(), "intercept-binding");
        assert!(!refusal.decision().is_allowed());
        assert_eq!(
            table
                .refusal_counts()
                .get(RefusalReason::InterceptUnavailable),
            1
        );
    }

    #[test]
    fn a_cidr_allow_does_not_carry_a_bound_name_past_interception() {
        let mut table = EgressLeaseTable::new(typed(&[("93.0.0.0/8", &[80, 443])]));
        bind(&mut table, &[(BOUND, 443)], at(0));
        resolve(&mut table, BOUND, PUBLIC_V4, 60, at(0));

        assert_eq!(
            intercepted(verdict(&mut table, PUBLIC_V4, 443, at(1))).hostname(),
            BOUND
        );
        // Another port, and a literal address no lease names, dial directly.
        assert_eq!(
            admitted(verdict(&mut table, PUBLIC_V4, 80, at(1))).hostname(),
            None
        );
        assert_eq!(
            admitted(verdict(&mut table, CDN_V4, 443, at(1))).hostname(),
            None
        );
        // An expired lease of the bound name is re-resolved, never dialled by
        // the CIDR rule.
        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
        assert_eq!(expired.name(), BOUND);
    }

    #[test]
    fn a_shared_address_is_intercepted_when_one_of_its_names_is_bound() {
        let mut table = EgressLeaseTable::new(named_policy());
        bind(&mut table, &[(BOUND, 443)], at(0));
        resolve(&mut table, "allowed.example.com", PUBLIC_V4, 60, at(0));
        resolve(&mut table, BOUND, PUBLIC_V4, 60, at(0));
        // Raw TCP carries no name, so the allowed name cannot win the dial
        // away from the bound one.
        assert_eq!(
            intercepted(verdict(&mut table, PUBLIC_V4, 443, at(1))).hostname(),
            BOUND
        );
    }

    #[test]
    fn a_deny_rule_beats_interception() {
        let open = "  - id: open\n    action: allow\n    protocols: [tcp]\n    ports: [443]\n    cidrs: [0.0.0.0/0]\n    route_classes: [general]\n";
        for (deny, rule_id, reason) in [
            (
                "  - id: deny-name\n    action: deny\n    protocols: [tcp]\n    destinations: [api.example.com]\n    route_classes: [general]\n",
                "deny-name",
                RefusalReason::NameNotAllowed,
            ),
            (
                "  - id: deny-network\n    action: deny\n    protocols: [tcp]\n    cidrs: [93.184.216.0/24]\n    route_classes: [general]\n",
                "deny-network",
                RefusalReason::AddressNotAllowed,
            ),
        ] {
            let mut table = EgressLeaseTable::new(rules(&format!("{deny}{open}")));
            bind(&mut table, &[(BOUND, 443)], at(0));
            resolve(&mut table, BOUND, PUBLIC_V4, 60, at(0));
            let refusal = refused(verdict(&mut table, PUBLIC_V4, 443, at(1)));
            assert_eq!(refusal.reason(), reason, "{rule_id}");
            assert_eq!(refusal.decision().reason, DecisionReason::RuleDeny);
            assert_eq!(refusal.decision().rule_id.as_deref(), Some(rule_id));
            // Also once the lease lapsed: refused, not re-resolved.
            refused(verdict(&mut table, PUBLIC_V4, 443, at(60)));
        }

        // A rule that denies the name's DNS keeps it from resolving at all.
        let mut table = EgressLeaseTable::new(rules(&format!(
            "  - id: deny-name\n    action: deny\n    protocols: [dns, tcp]\n    destinations: [api.example.com]\n    route_classes: [general]\n{open}"
        )));
        bind(&mut table, &[(BOUND, 443)], at(0));
        let decision = denied(
            table
                .authorize_dns_query(BOUND, RouteClass::General)
                .unwrap(),
        );
        assert_eq!(decision.reason, DecisionReason::RuleDeny);
        denied(
            table
                .admit_dns(
                    BOUND,
                    RouteClass::General,
                    resolution(&[(PUBLIC_V4, 60)]),
                    at(0),
                )
                .unwrap(),
        );
        assert_eq!(table.active_leases(at(0)), 0);
    }

    #[test]
    fn a_bound_name_never_leases_a_protected_or_host_address() {
        let mut table = EgressLeaseTable::new(named_policy());
        table.set_host_addresses(HostAddressSet::new([], [OTHER_PUBLIC_V4]).unwrap());
        bind(&mut table, &[(BOUND, 443)], at(0));
        let private: IpAddr = "10.0.0.7".parse().unwrap();
        for answer in [private, OTHER_PUBLIC_V4] {
            let decision = denied(
                table
                    .admit_dns(
                        BOUND,
                        RouteClass::General,
                        resolution(&[(answer, 60)]),
                        at(0),
                    )
                    .unwrap(),
            );
            assert!(matches!(
                decision.reason,
                DecisionReason::ProtectedAddress(_)
            ));
            let refusal = refused(verdict(&mut table, answer, 443, at(1)));
            assert_eq!(refusal.reason(), RefusalReason::ProtectedAddress);
        }
        assert_eq!(table.active_leases(at(1)), 0);
        // A mixed answer keeps only its public address, as for any name.
        let dns = allowed(
            table
                .admit_dns(
                    BOUND,
                    RouteClass::General,
                    resolution(&[(private, 60), (PUBLIC_V4, 60)]),
                    at(1),
                )
                .unwrap(),
        );
        assert_eq!(dns.addresses(), [PUBLIC_V4]);
    }

    #[test]
    fn an_expired_bound_lease_re_resolves_into_interception_or_refusal() {
        let mut table = EgressLeaseTable::new(named_policy());
        bind(&mut table, &[(BOUND, 443)], at(0));
        resolve(&mut table, BOUND, PUBLIC_V4, 60, at(0));

        let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(60)));
        assert_eq!(expired.name(), BOUND);
        assert_eq!(table.refusal_counts().total(), 0, "nothing is refused yet");
        let readmission = table
            .readmit_expired(expired, Some(resolution(&[(PUBLIC_V4, 120)])), at(61))
            .unwrap()
            .unwrap();
        let Readmission::Intercepted(interception) = readmission else {
            panic!("expected an interception, got {readmission:?}");
        };
        assert_eq!(interception.hostname(), BOUND);
        assert_eq!(interception.lease_expires_at(), at(181));

        // The name moved elsewhere, or did not answer: lease_expired.
        for answer in [Some(resolution(&[(CDN_V4, 60)])), None] {
            let expired = expired_lease(verdict(&mut table, PUBLIC_V4, 443, at(181)));
            let refusal = table
                .readmit_expired(expired, answer, at(181))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.reason(), RefusalReason::LeaseExpired);
            assert_eq!(refusal.decision().reason, DecisionReason::InterceptBinding);
            assert!(!refusal.decision().is_allowed());
        }
        only(table.refusal_counts(), RefusalReason::LeaseExpired, 2);
    }

    #[test]
    fn replacing_the_bindings_resets_only_the_flows_whose_outcome_changes() {
        let mut table = EgressLeaseTable::new(rules(
            "  - id: dns\n    action: allow\n    protocols: [dns]\n    destinations: [api.example.com, other.example.com]\n    route_classes: [general]\n  - id: open\n    action: allow\n    protocols: [tcp]\n    ports: [443]\n    cidrs: [0.0.0.0/0]\n    route_classes: [general]\n",
        ));
        bind(&mut table, &[("old.example.com", 443)], at(0));
        resolve(&mut table, BOUND, PUBLIC_V4, 60, at(0));
        resolve(&mut table, "other.example.com", OTHER_PUBLIC_V4, 60, at(0));
        // No rule lets this name resolve; only its binding does.
        resolve(&mut table, "old.example.com", CDN_V4, 60, at(0));
        let soon_bound = admitted(verdict(&mut table, PUBLIC_V4, 443, at(1)));
        let unaffected = admitted(verdict(&mut table, OTHER_PUBLIC_V4, 443, at(1)));
        let unbound = intercepted(verdict(&mut table, CDN_V4, 443, at(1)));

        let set = InterceptSet::new([InterceptBinding::new(BOUND, 443).unwrap()]).unwrap();
        let replacement = table.replace_intercepts(
            set.clone(),
            [
                ("soon-bound", EstablishedFlow::from(&soon_bound)),
                ("unaffected", EstablishedFlow::from(&unaffected)),
                ("unbound", EstablishedFlow::from(&unbound)),
            ],
            at(2),
        );
        assert_eq!(replacement.reset_flows(), ["soon-bound", "unbound"]);
        assert_eq!(replacement.dropped_leases(), 1);
        assert!(
            table
                .leases
                .iter()
                .all(|lease| lease.name != "old.example.com")
        );
        assert_eq!(table.intercepts(), &set);

        // New dials see the new bindings only.
        let now_bound = intercepted(verdict(&mut table, PUBLIC_V4, 443, at(3)));
        assert_eq!(now_bound.hostname(), BOUND);
        assert_eq!(
            admitted(verdict(&mut table, CDN_V4, 443, at(3))).hostname(),
            None
        );
        denied(
            table
                .authorize_dns_query("old.example.com", RouteClass::General)
                .unwrap(),
        );

        // The same bindings again change nothing.
        let again = table.replace_intercepts(
            set,
            [
                ("unaffected", EstablishedFlow::from(&unaffected)),
                ("now-bound", EstablishedFlow::from(&now_bound)),
            ],
            at(4),
        );
        assert!(again.reset_flows().is_empty());
        assert_eq!(again.dropped_leases(), 0);

        // Removing every binding resets the intercepted flow. Its lease stays,
        // because a rule lets the name resolve.
        let cleared = table.replace_intercepts(
            InterceptSet::default(),
            [
                ("unaffected", EstablishedFlow::from(&unaffected)),
                ("now-bound", EstablishedFlow::from(&now_bound)),
            ],
            at(5),
        );
        assert_eq!(cleared.dropped_leases(), 0);
        assert_eq!(cleared.into_reset_flows(), ["now-bound"]);
        assert_eq!(table.active_leases(at(5)), 2);
    }

    #[test]
    fn a_policy_replacement_rejudges_intercepted_flows() {
        let mut table = EgressLeaseTable::new(named_policy());
        bind(&mut table, &[(BOUND, 443)], at(0));
        resolve(&mut table, BOUND, PUBLIC_V4, 60, at(0));
        let flow = intercepted(verdict(&mut table, PUBLIC_V4, 443, at(1)));

        let kept = table.replace_policy(named_policy(), [(1, &flow)], at(2));
        assert!(kept.refused_flows().is_empty());
        assert_eq!(kept.dropped_leases(), 0);

        // A deny rule for the bound name ends the intercepted flow, and its
        // DNS still resolves, so the lease is kept for the refusal's sake.
        let deny = rules(
            "  - id: deny-name\n    action: deny\n    protocols: [tcp]\n    destinations: [api.example.com]\n    route_classes: [general]\n",
        );
        let replacement = table.replace_policy(deny, [(1, &flow)], at(3));
        assert_eq!(replacement.refused_flows(), [1]);
        assert_eq!(replacement.dropped_leases(), 0);
        assert_eq!(
            refused(verdict(&mut table, PUBLIC_V4, 443, at(4)))
                .decision()
                .reason,
            DecisionReason::RuleDeny
        );

        // A rule that denies the name's DNS drops its lease as well.
        let deny_dns = rules(
            "  - id: deny-name\n    action: deny\n    protocols: [dns]\n    destinations: [api.example.com]\n    route_classes: [general]\n",
        );
        let replacement = table.replace_policy(deny_dns, [(1, &flow)], at(5));
        assert_eq!(replacement.refused_flows(), [1]);
        assert_eq!(replacement.dropped_leases(), 1);
    }
}
