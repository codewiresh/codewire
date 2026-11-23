use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};
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

    async fn connect(&self, destination: SocketAddr) -> Result<Self::Stream, BrokerAdapterFailure> {
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
async fn a_dial_the_table_would_intercept_is_refused_and_never_dialled() {
    // #3999: the open baseline allows every public address on 443 by
    // CIDR, yet a bound name's lease makes the dial an interception.
    // Nothing receives intercepted connections yet, so it is refused.
    let resolver = Arc::new(FakeResolver::new([
        positive(PUBLIC_V4, 60),
        positive(PUBLIC_V4, 60),
    ]));
    let connector = Arc::new(FakeConnector::new([Ok(3)]));
    let clock = Arc::new(FakeClock::default());
    let broker = broker(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::clone(&resolver),
        Arc::clone(&connector),
        Arc::clone(&clock),
    );
    broker
        .replace_intercepts(
            InterceptSet::new([InterceptBinding::new("api.example.com", HTTPS).unwrap()]).unwrap(),
        )
        .await;
    broker
        .resolve_dns("api.example.com", DnsRecordFamily::Ipv4)
        .await
        .unwrap();

    let destination = SocketAddr::new(PUBLIC_V4, HTTPS);
    for result in [
        broker.authorize_tcp(destination).await.err(),
        broker.connect_tcp(destination).await.err(),
    ] {
        match result {
            Some(BrokerError::Denied(decision)) => {
                assert_eq!(decision.reason_code(), "intercept-binding");
                assert!(!decision.is_allowed());
            }
            other => panic!("an intercepted dial was not refused: {other:?}"),
        }
    }
    // Once the lease lapses, the re-resolve readmits the dial as an
    // interception, which is refused the same way.
    clock.set(61_000);
    assert!(matches!(
        broker.connect_tcp(destination).await,
        Err(BrokerError::Denied(_))
    ));
    assert_eq!(resolver.requests().len(), 2);
    let counts = broker.refusal_counts().await;
    assert_eq!(counts.get(RefusalReason::InterceptUnavailable), 3);
    assert_eq!(counts.total(), 3);
    assert!(connector.destinations().is_empty());

    // The name is bound on 443 only; another port dials as before.
    let other_port = SocketAddr::new(PUBLIC_V4, 80);
    assert_eq!(broker.connect_tcp(other_port).await.unwrap().stream(), &3);
    assert_eq!(connector.destinations(), [other_port]);
}

struct FakeHandoff {
    handed: StdMutex<Vec<(String, u16, IpAddr)>>,
    front_door: StdMutex<Vec<OwnedFd>>,
}

impl InterceptHandoff for FakeHandoff {
    fn hand_off(&self, interception: &TcpInterception) -> Result<OwnedFd, BrokerAdapterFailure> {
        self.handed.lock().unwrap().push((
            interception.hostname().to_string(),
            interception.port(),
            interception.address(),
        ));
        let (worker, front_door) = std::os::unix::net::UnixStream::pair().unwrap();
        self.front_door.lock().unwrap().push(front_door.into());
        Ok(worker.into())
    }
}

struct FailingHandoff;

impl InterceptHandoff for FailingHandoff {
    fn hand_off(&self, _interception: &TcpInterception) -> Result<OwnedFd, BrokerAdapterFailure> {
        Err(BrokerAdapterFailure::Unavailable)
    }
}

#[tokio::test]
async fn a_failed_hand_off_is_a_counted_refusal_and_is_never_dialled() {
    let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
    let connector = Arc::new(FakeConnector::new([Ok(3)]));
    let broker = PolicyEgressBroker::new(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::clone(&resolver),
        Arc::clone(&connector),
        Arc::new(FakeClock::default()),
    )
    .with_intercept_handoff(Arc::new(FailingHandoff) as Arc<dyn InterceptHandoff>);
    broker
        .replace_intercepts(
            InterceptSet::new([InterceptBinding::new("api.example.com", HTTPS).unwrap()]).unwrap(),
        )
        .await;
    broker
        .resolve_dns("api.example.com", DnsRecordFamily::Ipv4)
        .await
        .unwrap();
    let destination = SocketAddr::new(PUBLIC_V4, HTTPS);

    assert!(matches!(
        broker.connect_or_intercept(destination).await,
        Err(BrokerError::Denied(_))
    ));
    let counts = broker.refusal_counts().await;
    assert_eq!(counts.get(RefusalReason::InterceptUnavailable), 1);
    assert_eq!(counts.total(), 1);
    assert!(connector.destinations().is_empty());
}

struct EndedFlow(Arc<std::sync::atomic::AtomicBool>);

impl PassedFlow for EndedFlow {
    fn finished(&self) -> bool {
        false
    }

    fn end(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn with_a_handoff_an_intercepted_dial_goes_to_the_front_door_and_is_never_dialled() {
    let resolver = Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)]));
    let connector = Arc::new(FakeConnector::new([Ok(3)]));
    let clock = Arc::new(FakeClock::default());
    let handoff = Arc::new(FakeHandoff {
        handed: StdMutex::new(Vec::new()),
        front_door: StdMutex::new(Vec::new()),
    });
    let broker = PolicyEgressBroker::new(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::clone(&resolver),
        Arc::clone(&connector),
        Arc::clone(&clock),
    )
    .with_intercept_handoff(Arc::clone(&handoff) as Arc<dyn InterceptHandoff>);
    broker
        .replace_intercepts(
            InterceptSet::new([InterceptBinding::new("api.example.com", HTTPS).unwrap()]).unwrap(),
        )
        .await;
    broker
        .resolve_dns("api.example.com", DnsRecordFamily::Ipv4)
        .await
        .unwrap();
    let destination = SocketAddr::new(PUBLIC_V4, HTTPS);

    assert!(matches!(
        broker.authorize_tcp(destination).await.unwrap(),
        TcpAuthorization::Intercept(_)
    ));
    let BrokerConnection::Intercepted {
        stream: _,
        interception,
        revision,
    } = broker.connect_or_intercept(destination).await.unwrap()
    else {
        panic!("an intercepted dial was dialled");
    };
    assert_eq!(
        handoff.handed.lock().unwrap().as_slice(),
        [("api.example.com".to_string(), HTTPS, PUBLIC_V4)]
    );
    assert!(connector.destinations().is_empty());
    assert_eq!(broker.refusal_counts().await.total(), 0);

    // `connect_tcp` never hands over: it refuses, as before.
    assert!(matches!(
        broker.connect_tcp(destination).await,
        Err(BrokerError::Denied(_))
    ));
    assert_eq!(handoff.handed.lock().unwrap().len(), 1);

    // The intercepted flow is recorded, and unbinding the name ends it.
    let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
    broker
        .record_intercepted_flow(
            interception,
            revision,
            Box::new(EndedFlow(Arc::clone(&ended))),
        )
        .await
        .unwrap();
    assert_eq!(broker.passed_flows().await, 1);
    let replacement = broker.replace_intercepts(InterceptSet::default()).await;
    assert_eq!(replacement.reset_flows(), [0]);
    assert!(ended.load(Ordering::SeqCst));
    assert_eq!(broker.passed_flows().await, 0);
}

#[derive(Default)]
struct FakeFlow {
    finished: std::sync::atomic::AtomicBool,
    ended: std::sync::atomic::AtomicBool,
}

struct SharedFlow(Arc<FakeFlow>);

impl PassedFlow for SharedFlow {
    fn finished(&self) -> bool {
        self.0.finished.load(Ordering::Relaxed)
    }

    fn end(&self) {
        self.0.ended.store(true, Ordering::Relaxed);
    }
}

fn v4_https_only() -> CompiledPolicy {
    PolicyDocument::parse_yaml(
        br#"
version: 1
default: deny
rules:
  - id: one-network
    action: allow
    protocols: [tcp]
    ports: [443]
    cidrs: [93.184.216.0/24]
    route_classes: [general]
"#,
    )
    .unwrap()
}

#[tokio::test]
async fn a_replacement_ends_the_passed_flows_it_refuses_and_keeps_the_rest() {
    let connector = Arc::new(FakeConnector::new([Ok(1), Ok(2), Ok(3)]));
    let broker = broker(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::new(FakeResolver::new([])),
        connector,
        Arc::new(FakeClock::default()),
    );
    let mut flows = Vec::new();
    for destination in [PUBLIC_V4, PUBLIC_V6, PUBLIC_V6] {
        let (_, admission) = broker
            .connect_tcp(SocketAddr::new(destination, HTTPS))
            .await
            .unwrap()
            .into_parts();
        let flow = Arc::new(FakeFlow::default());
        broker
            .record_passed_flow(
                admission,
                broker.current_intercept_revision(),
                Box::new(SharedFlow(Arc::clone(&flow))),
            )
            .await
            .unwrap();
        flows.push(flow);
    }
    // The guest already closed the last one; it is forgotten, not ended.
    flows[2].finished.store(true, Ordering::Relaxed);
    assert_eq!(broker.passed_flows().await, 2);

    let replacement = broker.replace_policy(v4_https_only()).await;
    assert_eq!(replacement.current_digest(), v4_https_only().digest());
    assert_eq!(broker.policy_digest().await, v4_https_only().digest());
    assert_eq!(replacement.refused_flows().len(), 1);
    assert!(
        !flows[0].ended.load(Ordering::Relaxed),
        "an allowed flow is kept"
    );
    assert!(
        flows[1].ended.load(Ordering::Relaxed),
        "a refused flow is ended"
    );
    assert!(!flows[2].ended.load(Ordering::Relaxed));
    assert_eq!(broker.passed_flows().await, 1);
    assert!(matches!(
        broker.connect_tcp(SocketAddr::new(PUBLIC_V6, HTTPS)).await,
        Err(BrokerError::Denied(_))
    ));
}

#[tokio::test]
async fn a_flow_admitted_before_a_replacement_is_not_recorded_after_it() {
    let broker = broker(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::new(FakeResolver::new([])),
        Arc::new(FakeConnector::new([Ok(1)])),
        Arc::new(FakeClock::default()),
    );
    let (_, admission) = broker
        .connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS))
        .await
        .unwrap()
        .into_parts();
    broker.replace_policy(v4_https_only()).await;
    assert!(matches!(
        broker
            .record_passed_flow(
                admission,
                broker.current_intercept_revision(),
                Box::new(SharedFlow(Arc::default()))
            )
            .await,
        Err(BrokerError::PolicyReplaced)
    ));
}

#[tokio::test]
async fn the_record_holds_a_bounded_number_of_live_flows() {
    let connector = Arc::new(FakeConnector::new((0..=MAX_PASSED_FLOWS as u64).map(Ok)));
    let broker = broker(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::new(FakeResolver::new([])),
        connector,
        Arc::new(FakeClock::default()),
    );
    let mut first = None;
    for _ in 0..MAX_PASSED_FLOWS {
        let (_, admission) = broker
            .connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS))
            .await
            .unwrap()
            .into_parts();
        let flow = Arc::new(FakeFlow::default());
        first.get_or_insert_with(|| Arc::clone(&flow));
        broker
            .record_passed_flow(
                admission,
                broker.current_intercept_revision(),
                Box::new(SharedFlow(flow)),
            )
            .await
            .unwrap();
    }
    let (_, admission) = broker
        .connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS))
        .await
        .unwrap()
        .into_parts();
    assert!(matches!(
        broker
            .record_passed_flow(
                admission.clone(),
                broker.current_intercept_revision(),
                Box::new(SharedFlow(Arc::default()))
            )
            .await,
        Err(BrokerError::TooManyPassedFlows)
    ));
    // Once one finishes, its place is free again.
    first.unwrap().finished.store(true, Ordering::Relaxed);
    broker
        .record_passed_flow(
            admission,
            broker.current_intercept_revision(),
            Box::new(SharedFlow(Arc::default())),
        )
        .await
        .unwrap();
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
        RouteClass::Mesh,
        Arc::clone(&resolver),
        Arc::clone(&connector),
        Arc::new(FakeClock::default()),
    );
    assert_eq!(broker.route_class(), RouteClass::Mesh);
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

/// A flow admitted under one interception set and recorded after the set was
/// replaced is refused, so the replacement can never miss it.
#[tokio::test]
async fn a_flow_admitted_before_an_intercept_replacement_is_not_recorded() {
    let broker = broker(
        CompiledPolicy::developer_baseline(),
        RouteClass::General,
        Arc::new(FakeResolver::new([])),
        Arc::new(FakeConnector::new([Ok(1)])),
        Arc::new(FakeClock::default()),
    );
    let connection = broker
        .connect_tcp(SocketAddr::new(PUBLIC_V4, HTTPS))
        .await
        .unwrap();
    let revision = connection.intercept_revision();
    let (_, admission) = connection.into_parts();
    broker.replace_intercepts(InterceptSet::default()).await;
    assert!(matches!(
        broker
            .record_passed_flow(admission, revision, Box::new(SharedFlow(Arc::default())))
            .await,
        Err(BrokerError::InterceptsReplaced)
    ));
    assert_eq!(broker.passed_flows().await, 0);
}

/// A datagram the worker dropped is counted and folded as `udp_not_carried`
/// with its port: under the name a lease gives its address, else the
/// address, one row however often it is refused (#3997).
#[tokio::test]
async fn a_dropped_datagram_is_a_folded_udp_refusal_with_its_port() {
    let fold = Arc::new(refusals::RefusalFold::new());
    let broker = broker(
        named_policy(),
        RouteClass::General,
        Arc::new(FakeResolver::new([positive(PUBLIC_V4, 60)])),
        Arc::new(FakeConnector::new([])),
        Arc::new(FakeClock::default()),
    )
    .with_refusal_fold(Arc::clone(&fold));
    let digest = broker.policy_digest().await;

    for _ in 0..3 {
        broker
            .refuse_udp(SocketAddr::new(OTHER_PUBLIC_V4, 3478))
            .await;
    }
    broker
        .resolve_dns("allowed.example.com", DnsRecordFamily::Ipv4)
        .await
        .unwrap();
    broker.refuse_udp(SocketAddr::new(PUBLIC_V4, HTTPS)).await;

    let mut rows = fold.take().rows;
    rows.sort_by_key(|row| row.count);
    assert_eq!(
        rows,
        [
            refusals::RefusedRow {
                destination: Destination::checked_name("allowed.example.com"),
                address: Some(PUBLIC_V4),
                transport: Transport::Udp { port: HTTPS },
                reason: RefusalReason::UdpNotCarried,
                policy_digest: digest,
                count: 1,
            },
            refusals::RefusedRow {
                destination: Destination::Address(OTHER_PUBLIC_V4),
                address: Some(OTHER_PUBLIC_V4),
                transport: Transport::Udp { port: 3478 },
                reason: RefusalReason::UdpNotCarried,
                policy_digest: digest,
                count: 3,
            },
        ]
    );
    assert_eq!(
        broker
            .refusal_counts()
            .await
            .get(RefusalReason::UdpNotCarried),
        4
    );
}
