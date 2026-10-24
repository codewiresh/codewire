//! Placement-neutral admission core for one Codewire egress broker.
//!
//! This crate owns no process, credential, or audit sink. It composes the pure
//! policy/lease state with injected resolver, connector, and monotonic-clock
//! ports, supplies bounded host DNS/TCP adapters for general egress, and, on
//! Unix, defines the authenticated capability IPC used to reach that core
//! across a confinement boundary.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use codewire_egress_policy::host_addresses::HostAddressSet;
use codewire_egress_policy::lease::{
    Admission, AdmittedDnsQuery, AdmittedDnsResolution, DnsResolution, EgressLeaseTable,
    LeaseError, LeaseInstant, RefusalCounts, TcpAdmission, TcpVerdict,
};
use codewire_egress_policy::{CompiledPolicy, PolicyDecision, PolicyDigest, RouteClass};
use thiserror::Error;
use tokio::sync::Mutex;

pub mod adapters;
#[cfg(unix)]
pub mod ipc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRecordFamily {
    Ipv4,
    Ipv6,
}

impl DnsRecordFamily {
    fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    fn accepts(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResolverRequest {
    name: String,
    family: DnsRecordFamily,
}

impl DnsResolverRequest {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn family(&self) -> DnsRecordFamily {
        self.family
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResolverOutcome {
    Positive(DnsResolution),
    NoData,
    NameError,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BrokerAdapterFailure {
    #[error("adapter unavailable")]
    Unavailable,
    #[error("adapter timed out")]
    Timeout,
    #[error("adapter returned malformed data")]
    Malformed,
}

#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    /// Resolve one canonical policy-admitted name.
    async fn resolve(
        &self,
        request: DnsResolverRequest,
    ) -> Result<DnsResolverOutcome, BrokerAdapterFailure>;
}

#[async_trait]
pub trait TcpConnector: Send + Sync + 'static {
    type Stream: Send + 'static;

    /// Connect the exact already-admitted destination without resolving it.
    async fn connect(&self, destination: SocketAddr) -> Result<Self::Stream, BrokerAdapterFailure>;
}

pub trait BrokerClock: Send + Sync + 'static {
    fn now(&self) -> LeaseInstant;
}

#[derive(Clone, Debug)]
pub struct SystemBrokerClock {
    epoch: Instant,
}

impl SystemBrokerClock {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemBrokerClock {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerClock for SystemBrokerClock {
    fn now(&self) -> LeaseInstant {
        let milliseconds = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        LeaseInstant::from_millis(milliseconds)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerDnsResponse {
    Positive(AdmittedDnsResolution),
    NoData(AdmittedDnsQuery),
    NameError(AdmittedDnsQuery),
}

#[derive(Debug)]
pub struct BrokerTcpConnection<S> {
    stream: S,
    admission: TcpAdmission,
}

impl<S> BrokerTcpConnection<S> {
    pub fn stream(&self) -> &S {
        &self.stream
    }

    pub fn admission(&self) -> &TcpAdmission {
        &self.admission
    }

    pub fn into_parts(self) -> (S, TcpAdmission) {
        (self.stream, self.admission)
    }
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("egress policy denied request")]
    Denied(PolicyDecision),
    #[error("egress policy state rejected request")]
    Policy(#[from] LeaseError),
    #[error("egress resolver failed: {0}")]
    Resolver(BrokerAdapterFailure),
    #[error("egress connector failed: {0}")]
    Connector(BrokerAdapterFailure),
    #[error("egress resolver returned an address outside the requested family")]
    MalformedDnsAnswer,
}

pub struct PolicyEgressBroker<R, C, K> {
    route_class: RouteClass,
    state: Mutex<EgressLeaseTable>,
    resolver: Arc<R>,
    connector: Arc<C>,
    clock: Arc<K>,
}

impl<R, C, K> PolicyEgressBroker<R, C, K>
where
    R: DnsResolver,
    C: TcpConnector,
    K: BrokerClock,
{
    pub fn new(
        policy: CompiledPolicy,
        route_class: RouteClass,
        resolver: Arc<R>,
        connector: Arc<C>,
        clock: Arc<K>,
    ) -> Self {
        Self {
            route_class,
            state: Mutex::new(EgressLeaseTable::new(policy)),
            resolver,
            connector,
            clock,
        }
    }

    pub fn route_class(&self) -> RouteClass {
        self.route_class
    }

    pub async fn policy_digest(&self) -> PolicyDigest {
        self.state.lock().await.policy_digest()
    }

    /// Refusals by reason since start, never a name or an address. They are
    /// the only place a refusal's reason is visible (#2537): every refused
    /// lookup looks the same to the guest.
    pub async fn refusal_counts(&self) -> RefusalCounts {
        self.state.lock().await.refusal_counts()
    }

    /// Replace the addresses local to the host this broker dials from (#2614);
    /// later admissions, including a dial already authorized, refuse them.
    pub async fn set_host_addresses(&self, addresses: HostAddressSet) {
        self.state.lock().await.set_host_addresses(addresses);
    }

    /// Resolve only after the policy admits the canonical query, then bind the
    /// complete bounded answer set into expiring TCP evidence.
    pub async fn resolve_dns(
        &self,
        name: &str,
        family: DnsRecordFamily,
    ) -> Result<BrokerDnsResponse, BrokerError> {
        let query = {
            let state = self.state.lock().await;
            match state.authorize_dns_query(name, self.route_class)? {
                Admission::Allowed(query) => query,
                Admission::Denied(decision) => return Err(BrokerError::Denied(decision)),
            }
        };
        let request = DnsResolverRequest {
            name: query.name().to_string(),
            family,
        };
        match self
            .resolver
            .resolve(request)
            .await
            .map_err(BrokerError::Resolver)?
        {
            DnsResolverOutcome::NoData => Ok(BrokerDnsResponse::NoData(query)),
            DnsResolverOutcome::NameError => Ok(BrokerDnsResponse::NameError(query)),
            DnsResolverOutcome::Positive(resolution) => {
                if resolution
                    .addresses()
                    .iter()
                    .any(|record| !family.accepts(record.address()))
                {
                    return Err(BrokerError::MalformedDnsAnswer);
                }
                let now = self.clock.now();
                let mut state = self.state.lock().await;
                match state.admit_dns(query.name(), self.route_class, resolution, now)? {
                    Admission::Allowed(resolution) => Ok(BrokerDnsResponse::Positive(resolution)),
                    Admission::Denied(decision) => Err(BrokerError::Denied(decision)),
                }
            }
        }
    }

    /// Perform the cheap pre-listener admission used by a packet worker.
    pub async fn authorize_tcp(
        &self,
        destination: SocketAddr,
    ) -> Result<TcpAdmission, BrokerError> {
        self.admit_tcp(destination).await
    }

    /// Re-evaluate policy and lease expiry immediately before every dial.
    pub async fn connect_tcp(
        &self,
        destination: SocketAddr,
    ) -> Result<BrokerTcpConnection<C::Stream>, BrokerError> {
        let admission = self.admit_tcp(destination).await?;
        let stream = self
            .connector
            .connect(destination)
            .await
            .map_err(BrokerError::Connector)?;
        Ok(BrokerTcpConnection { stream, admission })
    }

    /// Admit a dial against the policy and the lease table. When only an
    /// expired lease would admit it, re-resolve that lease's own name once,
    /// never a guest-supplied one, and admit the dial only if the fresh
    /// answer, checked like any guest lookup, still contains its address.
    async fn admit_tcp(&self, destination: SocketAddr) -> Result<TcpAdmission, BrokerError> {
        let expired = {
            let mut state = self.state.lock().await;
            match state.admit_tcp_or_expired(
                destination.ip(),
                destination.port(),
                self.route_class,
                self.clock.now(),
            )? {
                TcpVerdict::Allowed(admission) => return Ok(admission),
                TcpVerdict::Refused(refusal) => {
                    return Err(BrokerError::Denied(refusal.decision().clone()));
                }
                TcpVerdict::LeaseExpired(expired) => expired,
            }
        };
        let family = DnsRecordFamily::of(destination.ip());
        let request = DnsResolverRequest {
            name: expired.name().to_string(),
            family,
        };
        // A failed, empty or wrong-family lookup is no answer: the dial is
        // refused as `lease_expired`.
        let resolution = match self.resolver.resolve(request).await {
            Ok(DnsResolverOutcome::Positive(resolution))
                if resolution
                    .addresses()
                    .iter()
                    .all(|record| family.accepts(record.address())) =>
            {
                Some(resolution)
            }
            _ => None,
        };
        let mut state = self.state.lock().await;
        state
            .readmit_expired(expired, resolution, self.clock.now())?
            .map_err(|refusal| BrokerError::Denied(refusal.decision().clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use codewire_egress_policy::lease::{DnsAddress, DnsAlias, RefusalReason};
    use codewire_egress_policy::{DecisionReason, PolicyDocument};

    use super::*;

    const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const OTHER_PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    const PUBLIC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    const HTTPS: u16 = 443;

    #[derive(Default)]
    struct FakeClock {
        milliseconds: AtomicU64,
    }

    impl FakeClock {
        fn set(&self, milliseconds: u64) {
            self.milliseconds.store(milliseconds, Ordering::Relaxed);
        }
    }

    impl BrokerClock for FakeClock {
        fn now(&self) -> LeaseInstant {
            LeaseInstant::from_millis(self.milliseconds.load(Ordering::Relaxed))
        }
    }

    struct FakeResolver {
        outcomes: StdMutex<VecDeque<Result<DnsResolverOutcome, BrokerAdapterFailure>>>,
        requests: StdMutex<Vec<DnsResolverRequest>>,
    }

    impl FakeResolver {
        fn new(outcomes: impl IntoIterator<Item = DnsResolverOutcome>) -> Self {
            Self::with_results(outcomes.into_iter().map(Ok))
        }

        fn with_results(
            outcomes: impl IntoIterator<Item = Result<DnsResolverOutcome, BrokerAdapterFailure>>,
        ) -> Self {
            Self {
                outcomes: StdMutex::new(outcomes.into_iter().collect()),
                requests: StdMutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<DnsResolverRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DnsResolver for FakeResolver {
        async fn resolve(
            &self,
            request: DnsResolverRequest,
        ) -> Result<DnsResolverOutcome, BrokerAdapterFailure> {
            self.requests.lock().unwrap().push(request);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(BrokerAdapterFailure::Unavailable))
        }
    }

    struct FakeConnector {
        outcomes: StdMutex<VecDeque<Result<u64, BrokerAdapterFailure>>>,
        destinations: StdMutex<Vec<SocketAddr>>,
    }

    impl FakeConnector {
        fn new(outcomes: impl IntoIterator<Item = Result<u64, BrokerAdapterFailure>>) -> Self {
            Self {
                outcomes: StdMutex::new(outcomes.into_iter().collect()),
                destinations: StdMutex::new(Vec::new()),
            }
        }

        fn destinations(&self) -> Vec<SocketAddr> {
            self.destinations.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TcpConnector for FakeConnector {
        type Stream = u64;

        async fn connect(
            &self,
            destination: SocketAddr,
        ) -> Result<Self::Stream, BrokerAdapterFailure> {
            self.destinations.lock().unwrap().push(destination);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(BrokerAdapterFailure::Unavailable))
        }
    }

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

    fn positive(ip: IpAddr, ttl_seconds: u32) -> DnsResolverOutcome {
        DnsResolverOutcome::Positive(
            DnsResolution::new(vec![], vec![address(ip, ttl_seconds)]).unwrap(),
        )
    }

    fn broker(
        policy: CompiledPolicy,
        route_class: RouteClass,
        resolver: Arc<FakeResolver>,
        connector: Arc<FakeConnector>,
        clock: Arc<FakeClock>,
    ) -> PolicyEgressBroker<FakeResolver, FakeConnector, FakeClock> {
        PolicyEgressBroker::new(policy, route_class, resolver, connector, clock)
    }

    #[tokio::test]
    async fn denied_or_malformed_dns_never_reaches_the_resolver() {
        let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
        let connector = Arc::new(FakeConnector::new([]));
        let broker = broker(
            named_policy(),
            RouteClass::General,
            Arc::clone(&resolver),
            connector,
            Arc::new(FakeClock::default()),
        );

        assert!(matches!(
            broker
                .resolve_dns("denied.example.com", DnsRecordFamily::Ipv4)
                .await,
            Err(BrokerError::Denied(_))
        ));
        assert!(matches!(
            broker
                .resolve_dns("bad_name.example.com", DnsRecordFamily::Ipv4)
                .await,
            Err(BrokerError::Policy(_))
        ));
        assert!(resolver.requests().is_empty());
    }

    #[tokio::test]
    async fn positive_dns_is_canonical_bounded_and_supplies_named_tcp_evidence() {
        let resolution = DnsResolution::new(
            vec![DnsAlias::new("edge.example.net", 45).unwrap()],
            vec![address(PUBLIC_V4, 90)],
        )
        .unwrap();
        let resolver = Arc::new(FakeResolver::new([DnsResolverOutcome::Positive(
            resolution,
        )]));
        let connector = Arc::new(FakeConnector::new([Ok(7)]));
        let clock = Arc::new(FakeClock::default());
        let broker = broker(
            named_policy(),
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            clock,
        );

        let response = broker
            .resolve_dns("Allowed.Example.COM.", DnsRecordFamily::Ipv4)
            .await
            .unwrap();
        let BrokerDnsResponse::Positive(response) = response else {
            panic!("expected positive DNS response");
        };
        assert_eq!(response.name(), "allowed.example.com");
        assert_eq!(response.aliases(), ["edge.example.net"]);
        assert_eq!(response.addresses(), [PUBLIC_V4]);
        // The shortest TTL in the chain is 45 s; the lease, and so the TTL
        // the guest gets, is clamped up to 60 s.
        assert_eq!(response.ttl_seconds(), 60);
        assert_eq!(
            resolver.requests(),
            [DnsResolverRequest {
                name: "allowed.example.com".to_string(),
                family: DnsRecordFamily::Ipv4,
            }]
        );

        let destination = SocketAddr::new(PUBLIC_V4, HTTPS);
        let connection = broker.connect_tcp(destination).await.unwrap();
        assert_eq!(connection.stream(), &7);
        assert_eq!(
            connection.admission().hostname(),
            Some("allowed.example.com")
        );
        assert_eq!(connector.destinations(), [destination]);
    }

    #[tokio::test]
    async fn wrong_family_and_protected_answers_fail_without_a_tcp_capability() {
        let resolver = Arc::new(FakeResolver::new([
            positive(PUBLIC_V6, 60),
            positive(IpAddr::V4(Ipv4Addr::LOCALHOST), 60),
        ]));
        let connector = Arc::new(FakeConnector::new([Ok(1)]));
        let broker = broker(
            named_policy(),
            RouteClass::General,
            resolver,
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );

        assert!(matches!(
            broker
                .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
                .await,
            Err(BrokerError::MalformedDnsAnswer)
        ));
        let error = broker
            .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BrokerError::Denied(PolicyDecision {
                reason: DecisionReason::ProtectedAddress(_),
                ..
            })
        ));
        assert!(matches!(
            broker.connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS)).await,
            Err(BrokerError::Denied(_))
        ));
        assert!(connector.destinations().is_empty());
    }

    #[tokio::test]
    async fn tcp_is_rechecked_at_dial_time_after_dns_expiry() {
        // The answer's 1 s TTL is clamped to a 60 s lease. At expiry the dial
        // re-resolves the lease's own name once; here that lookup fails, so
        // the dial is refused as lease_expired and never reaches the network.
        let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 1)]));
        let connector = Arc::new(FakeConnector::new([Ok(9)]));
        let clock = Arc::new(FakeClock::default());
        let broker = broker(
            named_policy(),
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            Arc::clone(&clock),
        );
        broker
            .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
            .await
            .unwrap();
        clock.set(59_999);
        assert!(
            broker
                .authorize_tcp(SocketAddr::new(PUBLIC_V4, HTTPS))
                .await
                .is_ok()
        );
        assert_eq!(resolver.requests().len(), 1);
        clock.set(60_000);
        assert!(matches!(
            broker.connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS)).await,
            Err(BrokerError::Denied(_))
        ));
        assert_eq!(resolver.requests().len(), 2);
        assert_eq!(
            broker
                .refusal_counts()
                .await
                .get(RefusalReason::LeaseExpired),
            1
        );
        assert!(connector.destinations().is_empty());
    }

    #[tokio::test]
    async fn a_dial_on_an_expired_lease_re_resolves_its_own_name_once() {
        let resolver = Arc::new(FakeResolver::new([
            positive(PUBLIC_V4, 60),
            // The re-resolve at expiry still answers the dialed address.
            positive(PUBLIC_V4, 120),
            // The next one has moved the name elsewhere.
            positive(OTHER_PUBLIC_V4, 120),
        ]));
        let connector = Arc::new(FakeConnector::new([Ok(5)]));
        let clock = Arc::new(FakeClock::default());
        let broker = broker(
            named_policy(),
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            Arc::clone(&clock),
        );
        broker
            .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
            .await
            .unwrap();

        clock.set(61_000);
        let destination = SocketAddr::new(PUBLIC_V4, HTTPS);
        let connection = broker.connect_tcp(destination).await.unwrap();
        assert_eq!(connection.stream(), &5);
        assert_eq!(
            connection.admission().hostname(),
            Some("allowed.example.com")
        );
        let lookup = DnsResolverRequest {
            name: "allowed.example.com".to_string(),
            family: DnsRecordFamily::Ipv4,
        };
        assert_eq!(resolver.requests(), [lookup.clone(), lookup.clone()]);
        // The refreshed lease admits later dials without another lookup.
        assert!(broker.authorize_tcp(destination).await.is_ok());
        assert_eq!(resolver.requests().len(), 2);

        // After the refreshed 120 s lease lapses, the name no longer answers
        // the dialed address: one lookup, then lease_expired.
        clock.set(182_000);
        assert!(matches!(
            broker.connect_tcp(destination).await,
            Err(BrokerError::Denied(_))
        ));
        assert_eq!(
            resolver.requests(),
            [lookup.clone(), lookup.clone(), lookup]
        );
        assert_eq!(
            broker
                .refusal_counts()
                .await
                .get(RefusalReason::LeaseExpired),
            1
        );
        assert_eq!(connector.destinations(), [destination]);
    }

    #[tokio::test]
    async fn a_dial_with_no_lease_history_never_triggers_a_lookup() {
        let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
        let connector = Arc::new(FakeConnector::new([Ok(1)]));
        let broker = broker(
            named_policy(),
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );
        assert!(matches!(
            broker.connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS)).await,
            Err(BrokerError::Denied(_))
        ));
        assert!(resolver.requests().is_empty());
        assert!(connector.destinations().is_empty());
    }

    #[tokio::test]
    async fn direct_ip_policy_dials_without_dns_or_hostname_attribution() {
        let resolver = Arc::new(FakeResolver::new([]));
        let connector = Arc::new(FakeConnector::new([Ok(11)]));
        let broker = broker(
            CompiledPolicy::developer_baseline(),
            RouteClass::General,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );
        let destination = SocketAddr::new(PUBLIC_V4, HTTPS);
        let connection = broker.connect_tcp(destination).await.unwrap();
        assert_eq!(connection.stream(), &11);
        assert_eq!(connection.admission().hostname(), None);
        assert!(resolver.requests().is_empty());
        assert_eq!(connector.destinations(), [destination]);
    }

    #[tokio::test]
    async fn addresses_local_to_the_host_are_refused_before_any_dial() {
        // #2614: the host's interface address and the public address its
        // network is seen from, which the fixed protected ranges cannot know.
        const INTERFACE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 114, 7));
        const LEARNED: IpAddr = IpAddr::V4(Ipv4Addr::new(87, 0, 0, 180));
        let connector = Arc::new(FakeConnector::new([Ok(21), Ok(22)]));
        let broker = broker(
            CompiledPolicy::developer_baseline(),
            RouteClass::General,
            Arc::new(FakeResolver::new([])),
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );
        // Before the host's addresses are known, both are ordinary egress.
        let before = SocketAddr::new(LEARNED, HTTPS);
        assert!(broker.authorize_tcp(before).await.is_ok());

        broker
            .set_host_addresses(HostAddressSet::new([INTERFACE], [LEARNED]).unwrap())
            .await;
        for (destination, reason) in [
            (
                SocketAddr::new(INTERFACE, 22),
                "protected-address-host-interface",
            ),
            (
                SocketAddr::new(LEARNED, HTTPS),
                "protected-address-network-public",
            ),
            (
                SocketAddr::new(
                    IpAddr::V6(Ipv4Addr::new(87, 0, 0, 180).to_ipv6_mapped()),
                    80,
                ),
                "protected-address-network-public",
            ),
        ] {
            for result in [
                broker.authorize_tcp(destination).await.err(),
                broker.connect_tcp(destination).await.err(),
            ] {
                match result {
                    Some(BrokerError::Denied(decision)) => {
                        assert_eq!(decision.reason_code(), reason)
                    }
                    other => panic!("{destination} was not refused: {other:?}"),
                }
            }
        }
        // An address authorized before the update is checked again at the dial.
        assert!(matches!(
            broker.connect_tcp(before).await.err(),
            Some(BrokerError::Denied(_))
        ));
        assert!(connector.destinations().is_empty());

        // Any other public address still dials, and an unchanged update keeps
        // refusing.
        let other = SocketAddr::new(PUBLIC_V4, HTTPS);
        assert_eq!(broker.connect_tcp(other).await.unwrap().stream(), &21);
        broker
            .set_host_addresses(HostAddressSet::new([INTERFACE], [LEARNED]).unwrap())
            .await;
        assert!(broker.connect_tcp(before).await.is_err());
        assert_eq!(connector.destinations(), [other]);
    }

    #[tokio::test]
    async fn negative_dns_outcomes_create_no_tcp_lease() {
        let resolver = Arc::new(FakeResolver::new([
            DnsResolverOutcome::NoData,
            DnsResolverOutcome::NameError,
        ]));
        let connector = Arc::new(FakeConnector::new([]));
        let broker = broker(
            named_policy(),
            RouteClass::General,
            resolver,
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );
        assert!(matches!(
            broker
                .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
                .await
                .unwrap(),
            BrokerDnsResponse::NoData(_)
        ));
        assert!(matches!(
            broker
                .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
                .await
                .unwrap(),
            BrokerDnsResponse::NameError(_)
        ));
        assert!(matches!(
            broker.connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS)).await,
            Err(BrokerError::Denied(_))
        ));
        assert!(connector.destinations().is_empty());
    }

    #[tokio::test]
    async fn route_class_is_fixed_before_any_adapter_call() {
        let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
        let connector = Arc::new(FakeConnector::new([Ok(1)]));
        let broker = broker(
            named_policy(),
            RouteClass::Credential,
            Arc::clone(&resolver),
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );
        assert_eq!(broker.route_class(), RouteClass::Credential);
        assert!(matches!(
            broker
                .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
                .await,
            Err(BrokerError::Denied(_))
        ));
        assert!(matches!(
            broker.connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS)).await,
            Err(BrokerError::Denied(_))
        ));
        assert!(resolver.requests().is_empty());
        assert!(connector.destinations().is_empty());
    }

    #[tokio::test]
    async fn adapter_failures_are_bounded_and_do_not_change_policy() {
        let resolver = Arc::new(FakeResolver::with_results([Err(
            BrokerAdapterFailure::Timeout,
        )]));
        let connector = Arc::new(FakeConnector::new([Err(BrokerAdapterFailure::Unavailable)]));
        let broker = broker(
            CompiledPolicy::developer_baseline(),
            RouteClass::General,
            resolver,
            Arc::clone(&connector),
            Arc::new(FakeClock::default()),
        );
        assert!(matches!(
            broker
                .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
                .await,
            Err(BrokerError::Resolver(BrokerAdapterFailure::Timeout))
        ));
        let destination = SocketAddr::new(PUBLIC_V4, HTTPS);
        assert!(matches!(
            broker.connect_tcp(destination).await,
            Err(BrokerError::Connector(BrokerAdapterFailure::Unavailable))
        ));
        assert_eq!(connector.destinations(), [destination]);
        assert_eq!(
            broker.policy_digest().await,
            CompiledPolicy::developer_baseline().digest()
        );
    }
}
