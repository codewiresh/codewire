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
        if record.dns_class != DNSClass::IN || record.ttl == 0 {
            return Err(BrokerAdapterFailure::Malformed);
        }
        let owner = canonical_record_name(&record.name.to_ascii())?;
        let ttl = record.ttl.min(remaining_ttl).min(MAX_DNS_TTL_SECONDS);
        if ttl == 0 {
            return Err(BrokerAdapterFailure::Malformed);
        }
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

fn remaining_lookup_ttl(lookup: &Lookup) -> Result<u32, BrokerAdapterFailure> {
    let remaining = lookup
        .valid_until()
        .saturating_duration_since(Instant::now());
    u32::try_from(remaining.as_secs())
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(|seconds| seconds.min(MAX_DNS_TTL_SECONDS))
        .ok_or(BrokerAdapterFailure::Malformed)
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

    use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{Message, Query};
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;

    use super::*;

    const TEST_NAME: &str = "allowed.example.com";
    const TEST_ALIAS: &str = "edge.example.net";
    const TEST_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

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
    fn disconnected_cycles_duplicates_and_expired_records_fail_closed() {
        let valid_address = a(&format!("{TEST_NAME}."), TEST_V4, 60);
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
            vec![valid_address.clone(), valid_address.clone()],
            vec![a(&format!("{TEST_NAME}."), TEST_V4, 0)],
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
        assert_eq!(
            decode_lookup(
                TEST_NAME,
                DnsRecordFamily::Ipv4,
                &lookup(vec![valid_address], Duration::ZERO),
            ),
            Err(BrokerAdapterFailure::Malformed)
        );
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
