//! Concrete, bounded DNS and TCP adapters for the general egress broker.
//!
//! DNS uses the host's configured recursive name servers, but never its hosts
//! file or search expansion. The policy core has already admitted each exact
//! canonical name before this adapter sees it. TCP accepts only a concrete
//! [`SocketAddr`], so this layer cannot perform an implicit second resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use codewire_egress_policy::lease::{
    DnsAddress, DnsAlias, DnsResolution, MAX_CNAME_CHAIN, MAX_DNS_ADDRESSES, MAX_DNS_TTL_SECONDS,
};
use hickory_resolver::config::ResolveHosts;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{DnsError, NetError, runtime::TokioRuntimeProvider};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_resolver::{Resolver, ResolverBuilder, TokioResolver};
use tokio::net::TcpStream;

use crate::{
    BrokerAdapterFailure, DnsRecordFamily, DnsResolver, DnsResolverOutcome, DnsResolverRequest,
    TcpConnector,
};

/// Maximum wall-clock time spent on one general-egress DNS lookup.
pub const SYSTEM_DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum wall-clock time spent opening one general-egress TCP connection.
pub const SYSTEM_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ADAPTER_TIMEOUT: Duration = Duration::from_secs(30);
const DNS_CACHE_ENTRIES: u64 = 256;
const DNS_MAX_ACTIVE_REQUESTS: usize = 32;
const DNS_NEGATIVE_TTL_SECONDS: u64 = 30;

/// Resolver backed by the host's configured recursive DNS servers.
///
/// Input names are converted to absolute DNS names. `/etc/hosts`, platform
/// hosts files, and resolver search paths therefore cannot add an unreviewed
/// destination. Hickory's response cache and all upstream attempts are
/// explicitly bounded.
#[derive(Clone)]
pub struct SystemDnsResolver {
    resolver: TokioResolver,
    query_timeout: Duration,
}

impl SystemDnsResolver {
    /// Read the platform resolver configuration and apply Codewire's fixed
    /// safety limits.
    pub fn from_system_config() -> Result<Self, BrokerAdapterFailure> {
        let builder = Resolver::builder_tokio().map_err(|_| BrokerAdapterFailure::Unavailable)?;
        Self::from_builder(builder, SYSTEM_DNS_QUERY_TIMEOUT)
    }

    /// Resolve one exact canonical host into a bounded, de-duplicated address
    /// set without consulting the hosts file or applying a search suffix.
    ///
    /// This is the non-policy adapter seam used by trusted host transports
    /// which must finish name resolution before entering a filesystem-denied
    /// process domain. Workload DNS still goes through [`DnsResolver`] and the
    /// policy/lease state machine.
    pub async fn resolve_host_addresses(
        &self,
        name: &str,
    ) -> Result<Vec<IpAddr>, BrokerAdapterFailure> {
        let canonical = canonical_record_name(name)?;
        if canonical != name {
            return Err(BrokerAdapterFailure::Malformed);
        }
        let mut addresses = BTreeSet::new();
        for family in [DnsRecordFamily::Ipv4, DnsRecordFamily::Ipv6] {
            match self
                .resolve(DnsResolverRequest {
                    name: canonical.clone(),
                    family,
                })
                .await?
            {
                DnsResolverOutcome::Positive(resolution) => {
                    addresses.extend(
                        resolution
                            .addresses()
                            .iter()
                            .copied()
                            .map(|address| address.address()),
                    );
                }
                DnsResolverOutcome::NoData => {}
                DnsResolverOutcome::NameError => {
                    return Err(BrokerAdapterFailure::Unavailable);
                }
            }
        }
        if addresses.is_empty() {
            return Err(BrokerAdapterFailure::Unavailable);
        }
        Ok(addresses.into_iter().collect())
    }

    fn from_builder(
        mut builder: ResolverBuilder<TokioRuntimeProvider>,
        query_timeout: Duration,
    ) -> Result<Self, BrokerAdapterFailure> {
        validate_timeout(query_timeout)?;
        let options = builder.options_mut();
        options.ndots = 1;
        options.timeout = query_timeout;
        options.attempts = 1;
        options.edns0 = true;
        options.cache_size = DNS_CACHE_ENTRIES;
        options.use_hosts_file = ResolveHosts::Never;
        options.positive_min_ttl = None;
        options.negative_min_ttl = None;
        options.positive_max_ttl = Some(Duration::from_secs(u64::from(MAX_DNS_TTL_SECONDS)));
        options.negative_max_ttl = Some(Duration::from_secs(DNS_NEGATIVE_TTL_SECONDS));
        options.num_concurrent_reqs = 1;
        options.max_active_requests = DNS_MAX_ACTIVE_REQUESTS;
        options.preserve_intermediates = true;
        options.try_tcp_on_error = true;
        options.recursion_desired = true;
        options.os_port_selection = false;
        options.case_randomization = true;
        options.trust_anchor = None;
        options.allow_answers.clear();
        options.deny_answers.clear();
        let resolver = builder
            .build()
            .map_err(|_| BrokerAdapterFailure::Unavailable)?;
        Ok(Self {
            resolver,
            query_timeout,
        })
    }

    #[cfg(test)]
    fn from_config(
        config: hickory_resolver::config::ResolverConfig,
        query_timeout: Duration,
    ) -> Result<Self, BrokerAdapterFailure> {
        Self::from_builder(
            Resolver::builder_with_config(config, TokioRuntimeProvider::default()),
            query_timeout,
        )
    }
}

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(
        &self,
        request: DnsResolverRequest,
    ) -> Result<DnsResolverOutcome, BrokerAdapterFailure> {
        let canonical = canonical_record_name(request.name())?;
        if canonical != request.name() {
            return Err(BrokerAdapterFailure::Malformed);
        }
        let absolute = Name::from_ascii(format!("{canonical}."))
            .map_err(|_| BrokerAdapterFailure::Malformed)?;
        let record_type = match request.family() {
            DnsRecordFamily::Ipv4 => RecordType::A,
            DnsRecordFamily::Ipv6 => RecordType::AAAA,
        };
        let lookup = match tokio::time::timeout(
            self.query_timeout,
            self.resolver.lookup(absolute, record_type),
        )
        .await
        {
            Err(_) => return Err(BrokerAdapterFailure::Timeout),
            Ok(Err(error)) => return map_resolver_error(error),
            Ok(Ok(lookup)) => lookup,
        };
        decode_lookup(&canonical, request.family(), &lookup).map(DnsResolverOutcome::Positive)
    }
}

/// Exact-address Tokio connector for general TCP egress.
#[derive(Clone, Copy, Debug)]
pub struct SystemTcpConnector {
    connect_timeout: Duration,
}

impl SystemTcpConnector {
    pub fn new() -> Self {
        Self {
            connect_timeout: SYSTEM_TCP_CONNECT_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(connect_timeout: Duration) -> Result<Self, BrokerAdapterFailure> {
        validate_timeout(connect_timeout)?;
        Ok(Self { connect_timeout })
    }
}

impl Default for SystemTcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TcpConnector for SystemTcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, destination: SocketAddr) -> Result<Self::Stream, BrokerAdapterFailure> {
        if destination.port() == 0 {
            return Err(BrokerAdapterFailure::Malformed);
        }
        let stream =
            await_tcp_connection(self.connect_timeout, TcpStream::connect(destination)).await?;
        if stream.peer_addr().map_err(map_connect_error)? != destination {
            return Err(BrokerAdapterFailure::Malformed);
        }
        Ok(stream)
    }
}

fn validate_timeout(timeout: Duration) -> Result<(), BrokerAdapterFailure> {
    if timeout.is_zero() || timeout > MAX_ADAPTER_TIMEOUT {
        Err(BrokerAdapterFailure::Malformed)
    } else {
        Ok(())
    }
}

async fn await_tcp_connection<F>(
    timeout: Duration,
    connection: F,
) -> Result<TcpStream, BrokerAdapterFailure>
where
    F: Future<Output = io::Result<TcpStream>>,
{
    match tokio::time::timeout(timeout, connection).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(map_connect_error(error)),
        Err(_) => Err(BrokerAdapterFailure::Timeout),
    }
}

fn map_connect_error(error: io::Error) -> BrokerAdapterFailure {
    match error.kind() {
        io::ErrorKind::TimedOut => BrokerAdapterFailure::Timeout,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => BrokerAdapterFailure::Malformed,
        _ => BrokerAdapterFailure::Unavailable,
    }
}

fn map_resolver_error(error: NetError) -> Result<DnsResolverOutcome, BrokerAdapterFailure> {
    if error.is_nx_domain()
        || matches!(
            error,
            NetError::Dns(DnsError::ResponseCode(ResponseCode::NXDomain))
        )
    {
        return Ok(DnsResolverOutcome::NameError);
    }
    if error.is_no_records_found() {
        return Ok(DnsResolverOutcome::NoData);
    }
    match error {
        NetError::Timeout => Err(BrokerAdapterFailure::Timeout),
        NetError::Proto(_) | NetError::Message(_) | NetError::Msg(_) => {
            Err(BrokerAdapterFailure::Malformed)
        }
        _ => Err(BrokerAdapterFailure::Unavailable),
    }
}

fn decode_lookup(
    query_name: &str,
    family: DnsRecordFamily,
    lookup: &Lookup,
) -> Result<DnsResolution, BrokerAdapterFailure> {
    let maximum_records = MAX_CNAME_CHAIN
        .checked_add(MAX_DNS_ADDRESSES)
        .ok_or(BrokerAdapterFailure::Malformed)?;
    if lookup.answers().is_empty() || lookup.answers().len() > maximum_records {
        return Err(BrokerAdapterFailure::Malformed);
    }
    let remaining_ttl = remaining_lookup_ttl(lookup)?;
    let mut aliases = BTreeMap::<String, (String, u32)>::new();
    let mut addresses = Vec::<(String, IpAddr, u32)>::new();
    for record in lookup.answers() {
        if record.dns_class != DNSClass::IN {
            return Err(BrokerAdapterFailure::Malformed);
        }
        let owner = canonical_record_name(&record.name.to_ascii())?;
        // A TTL of 0 means "this lookup only": it lasts one second (#2621).
        let ttl = record.ttl.clamp(1, remaining_ttl);
        match &record.data {
            RData::CNAME(target) => {
                if aliases.len() == MAX_CNAME_CHAIN {
                    return Err(BrokerAdapterFailure::Malformed);
                }
                let target = canonical_record_name(&target.to_ascii())?;
                if aliases.insert(owner, (target, ttl)).is_some() {
                    return Err(BrokerAdapterFailure::Malformed);
                }
            }
            RData::A(address) if family == DnsRecordFamily::Ipv4 => {
                if addresses.len() == MAX_DNS_ADDRESSES {
                    return Err(BrokerAdapterFailure::Malformed);
                }
                addresses.push((owner, IpAddr::V4(address.0), ttl));
            }
            RData::AAAA(address) if family == DnsRecordFamily::Ipv6 => {
                if addresses.len() == MAX_DNS_ADDRESSES {
                    return Err(BrokerAdapterFailure::Malformed);
                }
                addresses.push((owner, IpAddr::V6(address.0), ttl));
            }
            _ => return Err(BrokerAdapterFailure::Malformed),
        }
    }

    let mut current = query_name.to_string();
    let mut visited = BTreeSet::from([current.clone()]);
    let mut chain = Vec::new();
    while let Some((target, ttl)) = aliases.remove(&current) {
        if chain.len() == MAX_CNAME_CHAIN || !visited.insert(target.clone()) {
            return Err(BrokerAdapterFailure::Malformed);
        }
        chain.push(DnsAlias::new(&target, ttl).map_err(|_| BrokerAdapterFailure::Malformed)?);
        current = target;
    }
    if !aliases.is_empty()
        || addresses.is_empty()
        || addresses.iter().any(|(owner, _, _)| owner != &current)
    {
        return Err(BrokerAdapterFailure::Malformed);
    }
    let addresses = addresses
        .into_iter()
        .map(|(_, address, ttl)| {
            DnsAddress::new(address, ttl).map_err(|_| BrokerAdapterFailure::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    DnsResolution::new(chain, addresses).map_err(|_| BrokerAdapterFailure::Malformed)
}

/// Whole seconds the lookup may still be used, never less than one. A caching
/// resolver counts every record down through a TTL of 1, which leaves under a
/// second here; an answer that arrived valid is usable for one second (#2621).
fn remaining_lookup_ttl(lookup: &Lookup) -> Result<u32, BrokerAdapterFailure> {
    let remaining = lookup
        .valid_until()
        .saturating_duration_since(Instant::now());
    u32::try_from(remaining.as_secs())
        .map(|seconds| seconds.clamp(1, MAX_DNS_TTL_SECONDS))
        .map_err(|_| BrokerAdapterFailure::Malformed)
}

fn canonical_record_name(value: &str) -> Result<String, BrokerAdapterFailure> {
    DnsAlias::new(value, 1)
        .map(|alias| alias.name().to_string())
        .map_err(|_| BrokerAdapterFailure::Malformed)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr as _;
    use std::sync::Arc;

    use codewire_egress_policy::{DecisionReason, PolicyDecision, PolicyDocument, RouteClass};
    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{Message, Query};
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;

    use super::*;
    use crate::{BrokerDnsResponse, BrokerError, PolicyEgressBroker, SystemBrokerClock};

    const TEST_NAME: &str = "allowed.example.com";
    const TEST_ALIAS: &str = "edge.example.net";
    const TEST_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const TEST_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 0x34);

    fn name(value: &str) -> Name {
        Name::from_str(value).unwrap()
    }

    fn lookup(records: Vec<Record>, lifetime: Duration) -> Lookup {
        Lookup::new_with_deadline(
            Query::query(name(&format!("{TEST_NAME}.")), RecordType::A),
            records,
            Instant::now() + lifetime,
        )
    }

    fn cname(owner: &str, target: &str, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::CNAME(CNAME(name(target))))
    }

    fn a(owner: &str, address: Ipv4Addr, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(address)))
    }

    fn aaaa(owner: &str, address: Ipv6Addr, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::AAAA(AAAA(address)))
    }

    fn loopback_resolver_config(address: SocketAddr) -> ResolverConfig {
        let mut server = NameServerConfig::udp(address.ip());
        let mut connection = ConnectionConfig::udp();
        connection.port = address.port();
        server.connections = vec![connection];
        ResolverConfig::from_parts(None, vec![name("search-path.invalid.")], vec![server])
    }

    /// A resolver whose loopback server answers its one query with `answers`.
    async fn resolver_answering(
        answers: Vec<Record>,
    ) -> (SystemDnsResolver, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 1_232];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer[..length])
                .unwrap()
                .into_response();
            response.metadata.recursion_available = true;
            response.add_answers(answers);
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let resolver = SystemDnsResolver::from_config(
            loopback_resolver_config(address),
            Duration::from_secs(1),
        )
        .unwrap();
        (resolver, server)
    }

    #[test]
    fn complete_cname_chain_is_canonical_bounded_and_family_specific() {
        let records = vec![
            cname("Allowed.Example.COM.", "Edge.Example.NET.", 90),
            cname("edge.example.net.", "origin.example.org.", 75),
            a("origin.example.org.", TEST_V4, 60),
        ];
        let resolution = decode_lookup(
            TEST_NAME,
            DnsRecordFamily::Ipv4,
            &lookup(records, Duration::from_secs(60)),
        )
        .unwrap();
        assert_eq!(resolution.aliases().len(), 2);
        assert_eq!(resolution.aliases()[0].name(), TEST_ALIAS);
        assert_eq!(resolution.aliases()[1].name(), "origin.example.org");
        assert!((1..=60).contains(&resolution.aliases()[0].ttl_seconds()));
        assert_eq!(resolution.addresses().len(), 1);
        assert_eq!(resolution.addresses()[0].address(), IpAddr::V4(TEST_V4));
        assert!((1..=60).contains(&resolution.addresses()[0].ttl_seconds()));

        assert_eq!(
            decode_lookup(
                TEST_NAME,
                DnsRecordFamily::Ipv6,
                &lookup(
                    vec![a(&format!("{TEST_NAME}."), TEST_V4, 60)],
                    Duration::from_secs(60),
                ),
            ),
            Err(BrokerAdapterFailure::Malformed)
        );
    }

    #[test]
    fn disconnected_cycles_duplicates_and_foreign_classes_fail_closed() {
        let valid_address = a(&format!("{TEST_NAME}."), TEST_V4, 60);
        let mut chaos_class = valid_address.clone();
        chaos_class.dns_class = DNSClass::CH;
        let invalid_sets = [
            vec![
                cname(&format!("{TEST_NAME}."), "edge.example.net.", 60),
                cname("unrelated.example.org.", "other.example.org.", 60),
                a("edge.example.net.", TEST_V4, 60),
            ],
            vec![
                cname(&format!("{TEST_NAME}."), "edge.example.net.", 60),
                cname("edge.example.net.", &format!("{TEST_NAME}."), 60),
            ],
            vec![valid_address.clone(), valid_address],
            vec![chaos_class],
        ];
        for records in invalid_sets {
            assert_eq!(
                decode_lookup(
                    TEST_NAME,
                    DnsRecordFamily::Ipv4,
                    &lookup(records, Duration::from_secs(60)),
                ),
                Err(BrokerAdapterFailure::Malformed)
            );
        }
    }

    #[test]
    fn ttls_are_at_least_one_second_and_still_capped() {
        let chain = |ttl| {
            vec![
                cname(&format!("{TEST_NAME}."), "edge.example.net.", 60),
                a("edge.example.net.", TEST_V4, ttl),
            ]
        };
        let decode = |ttl, lifetime| {
            decode_lookup(
                TEST_NAME,
                DnsRecordFamily::Ipv4,
                &lookup(chain(ttl), lifetime),
            )
            .unwrap()
        };

        // A record with no TTL, in a lookup with time left.
        let no_ttl = decode(0, Duration::from_secs(60));
        assert_eq!(no_ttl.addresses()[0].ttl_seconds(), 1);
        assert!((1..=60).contains(&no_ttl.aliases()[0].ttl_seconds()));
        // A lookup in its last second, and one with none left.
        for lifetime in [Duration::from_millis(900), Duration::ZERO] {
            let last_second = decode(60, lifetime);
            assert_eq!(last_second.addresses()[0].ttl_seconds(), 1);
            assert_eq!(last_second.aliases()[0].ttl_seconds(), 1);
        }
        let long = decode(86_400, Duration::from_secs(86_400));
        assert_eq!(long.addresses()[0].ttl_seconds(), MAX_DNS_TTL_SECONDS);
    }

    #[test]
    fn resolver_errors_distinguish_name_no_data_timeout_and_malformed() {
        let query = Query::query(name(&format!("{TEST_NAME}.")), RecordType::A);
        assert_eq!(
            map_resolver_error(NoRecords::new(query.clone(), ResponseCode::NXDomain).into()),
            Ok(DnsResolverOutcome::NameError)
        );
        assert_eq!(
            map_resolver_error(NoRecords::new(query, ResponseCode::NoError).into()),
            Ok(DnsResolverOutcome::NoData)
        );
        assert_eq!(
            map_resolver_error(NetError::Timeout),
            Err(BrokerAdapterFailure::Timeout)
        );
        assert_eq!(
            map_resolver_error(NetError::Message("malformed")),
            Err(BrokerAdapterFailure::Malformed)
        );
    }

    #[tokio::test]
    async fn loopback_dns_uses_one_absolute_query_and_preserves_cname_evidence() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let (observed_sender, observed_receiver) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut buffer = [0_u8; 1_232];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..length]).unwrap();
            let query = request.queries[0].clone();
            let mut response = request.into_response();
            response.metadata.recursion_available = true;
            response.add_answers([
                cname("allowed.example.com.", "edge.example.net.", 60),
                a("edge.example.net.", TEST_V4, 45),
            ]);
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            observed_sender
                .send((query.name().to_ascii(), query.query_type()))
                .unwrap();
        });
        let resolver = SystemDnsResolver::from_config(
            loopback_resolver_config(address),
            Duration::from_secs(1),
        )
        .unwrap();
        let options = resolver.resolver.options();
        assert_eq!(options.use_hosts_file, ResolveHosts::Never);
        assert_eq!(options.cache_size, DNS_CACHE_ENTRIES);
        assert_eq!(options.attempts, 1);
        assert_eq!(options.num_concurrent_reqs, 1);
        assert_eq!(options.max_active_requests, DNS_MAX_ACTIVE_REQUESTS);
        assert!(options.preserve_intermediates);
        assert!(options.try_tcp_on_error);
        assert!(options.case_randomization);

        let outcome = resolver
            .resolve(DnsResolverRequest {
                name: TEST_NAME.to_string(),
                family: DnsRecordFamily::Ipv4,
            })
            .await
            .unwrap();
        let DnsResolverOutcome::Positive(resolution) = outcome else {
            panic!("expected a positive response");
        };
        assert_eq!(resolution.aliases()[0].name(), TEST_ALIAS);
        assert_eq!(resolution.addresses()[0].address(), IpAddr::V4(TEST_V4));
        let (observed_name, observed_type) = observed_receiver.await.unwrap();
        assert_eq!(observed_name.to_ascii_lowercase(), "allowed.example.com.");
        assert_eq!(observed_type, RecordType::A);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn loopback_dns_answers_in_their_last_second_resolve_for_one_second() {
        for ttl in [1, 0] {
            let (resolver, server) = resolver_answering(vec![
                cname("allowed.example.com.", "edge.example.net.", 60),
                a("edge.example.net.", TEST_V4, ttl),
            ])
            .await;
            let outcome = resolver
                .resolve(DnsResolverRequest {
                    name: TEST_NAME.to_string(),
                    family: DnsRecordFamily::Ipv4,
                })
                .await;
            let Ok(DnsResolverOutcome::Positive(resolution)) = outcome else {
                panic!("an answer with a TTL of {ttl} resolved to {outcome:?}");
            };
            assert_eq!(resolution.aliases()[0].ttl_seconds(), 1);
            assert_eq!(resolution.addresses()[0].address(), IpAddr::V4(TEST_V4));
            assert_eq!(resolution.addresses()[0].ttl_seconds(), 1);
            server.await.unwrap();
        }
    }

    /// The one-second floor does not let an answer past the address classes: a
    /// rebinding answer is refused for its address, whatever its TTL.
    #[tokio::test]
    async fn an_answer_without_a_ttl_is_still_refused_for_a_protected_address() {
        let broker_answering = |address| async move {
            let policy = PolicyDocument::parse_yaml(
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
            .unwrap();
            let (resolver, server) =
                resolver_answering(vec![a(&format!("{TEST_NAME}."), address, 0)]).await;
            let broker = PolicyEgressBroker::new(
                policy,
                RouteClass::General,
                Arc::new(resolver),
                Arc::new(SystemTcpConnector::new()),
                Arc::new(SystemBrokerClock::new()),
            );
            let resolved = broker.resolve_dns(TEST_NAME, DnsRecordFamily::Ipv4).await;
            server.await.unwrap();
            (broker, resolved)
        };

        let (broker, resolved) = broker_answering(TEST_V4).await;
        let Ok(BrokerDnsResponse::Positive(admitted)) = resolved else {
            panic!("a public answer without a TTL resolved to {resolved:?}");
        };
        assert_eq!(admitted.ttl_seconds(), 1);
        assert!(
            broker
                .authorize_tcp(SocketAddr::new(IpAddr::V4(TEST_V4), 443))
                .await
                .is_ok()
        );

        for protected in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 7),
            Ipv4Addr::new(169, 254, 169, 254),
        ] {
            let (broker, resolved) = broker_answering(protected).await;
            assert!(
                matches!(
                    resolved,
                    Err(BrokerError::Denied(PolicyDecision {
                        reason: DecisionReason::ProtectedAddress(_),
                        ..
                    }))
                ),
                "{protected} resolved to {resolved:?}"
            );
            assert!(matches!(
                broker
                    .authorize_tcp(SocketAddr::new(IpAddr::V4(protected), 443))
                    .await,
                Err(BrokerError::Denied(_))
            ));
        }
    }

    #[tokio::test]
    async fn trusted_host_resolution_combines_exact_a_and_aaaa_answers() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut buffer = [0_u8; 1_232];
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[..length]).unwrap();
                let query = request.queries[0].clone();
                let mut response = request.into_response();
                response.metadata.recursion_available = true;
                match query.query_type() {
                    RecordType::A => response.add_answer(a(&format!("{TEST_NAME}."), TEST_V4, 60)),
                    RecordType::AAAA => {
                        response.add_answer(aaaa(&format!("{TEST_NAME}."), TEST_V6, 60))
                    }
                    other => panic!("unexpected query type {other:?}"),
                };
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let resolver = SystemDnsResolver::from_config(
            loopback_resolver_config(address),
            Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(
            resolver.resolve_host_addresses(TEST_NAME).await.unwrap(),
            vec![IpAddr::V4(TEST_V4), IpAddr::V6(TEST_V6)]
        );
        assert_eq!(
            resolver.resolve_host_addresses("Allowed.Example.Com").await,
            Err(BrokerAdapterFailure::Malformed)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn silent_loopback_dns_is_stopped_by_the_outer_deadline() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let resolver = SystemDnsResolver::from_config(
            loopback_resolver_config(socket.local_addr().unwrap()),
            Duration::from_millis(20),
        )
        .unwrap();
        assert_eq!(
            resolver
                .resolve(DnsResolverRequest {
                    name: TEST_NAME.to_string(),
                    family: DnsRecordFamily::Ipv4,
                })
                .await,
            Err(BrokerAdapterFailure::Timeout)
        );
        drop(socket);
    }

    #[tokio::test]
    async fn exact_loopback_tcp_is_connected_without_name_resolution() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            (peer, byte)
        });
        let mut connected = SystemTcpConnector::with_timeout(Duration::from_secs(1))
            .unwrap()
            .connect(destination)
            .await
            .unwrap();
        assert_eq!(connected.peer_addr().unwrap(), destination);
        connected.write_all(b"x").await.unwrap();
        assert_eq!(accepted.await.unwrap().1, [b'x']);
    }

    #[tokio::test]
    async fn pending_tcp_connection_is_stopped_by_the_deadline() {
        assert!(matches!(
            await_tcp_connection(
                Duration::from_millis(5),
                std::future::pending::<io::Result<TcpStream>>(),
            )
            .await,
            Err(BrokerAdapterFailure::Timeout)
        ));
        assert_eq!(
            map_connect_error(io::Error::new(io::ErrorKind::InvalidInput, "invalid")),
            BrokerAdapterFailure::Malformed
        );
        assert!(matches!(
            SystemTcpConnector::with_timeout(Duration::ZERO),
            Err(BrokerAdapterFailure::Malformed)
        ));
    }

    #[test]
    fn ipv6_records_are_preserved_without_ipv4_mapping() {
        let address = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let resolution = decode_lookup(
            TEST_NAME,
            DnsRecordFamily::Ipv6,
            &Lookup::new_with_deadline(
                Query::query(name(&format!("{TEST_NAME}.")), RecordType::AAAA),
                [aaaa(&format!("{TEST_NAME}."), address, 60)],
                Instant::now() + Duration::from_secs(60),
            ),
        )
        .unwrap();
        assert_eq!(resolution.addresses()[0].address(), IpAddr::V6(address));
    }
}
