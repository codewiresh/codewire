//! Guest UDP other than admitted DNS is dropped and reported to the broker
//! as refused (#3997); everything else the worker does not carry is dropped
//! with no report.

use std::net::Ipv6Addr;

use super::super::udp::MAX_UDP_REFUSALS_IN_FLIGHT;
use super::*;

const TEST_DNS_ANSWER_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20);
const STUN: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478);
const SENTINEL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 99), 9);

/// Answers [`TEST_DNS_NAME`] for A and AAAA and records every datagram it
/// is asked to refuse. With `held`, each refusal waits for a permit.
struct UdpBroker {
    started: AtomicUsize,
    refused: Mutex<Vec<SocketAddr>>,
    held: Option<Semaphore>,
}

impl UdpBroker {
    fn new() -> Arc<Self> {
        Self::with(None)
    }

    fn holding() -> Arc<Self> {
        Self::with(Some(Semaphore::new(0)))
    }

    fn with(held: Option<Semaphore>) -> Arc<Self> {
        Arc::new(Self {
            started: AtomicUsize::new(0),
            refused: Mutex::new(Vec::new()),
            held,
        })
    }

    fn refused(&self) -> Vec<SocketAddr> {
        self.refused.lock().unwrap().clone()
    }

    /// Waits until `count` refusals were recorded.
    async fn wait_for_refused(&self, count: usize) {
        tokio::time::timeout(HANG_GUARD, async {
            while self.refused.lock().unwrap().len() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the refusals reached the broker");
    }
}

#[async_trait]
impl EgressBroker for UdpBroker {
    async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
        Err(denied())
    }

    async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
        Err(denied())
    }

    async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
        let answer = match question.record_type {
            DnsRecordType::A => DnsAnswer::Ipv4(TEST_DNS_ANSWER),
            DnsRecordType::Aaaa => DnsAnswer::Ipv6(TEST_DNS_ANSWER_V6),
        };
        Ok(BrokerDnsAnswer {
            answer,
            ttl_seconds: 30,
        })
    }

    async fn refuse_udp(&self, destination: SocketAddr) -> io::Result<()> {
        self.started.fetch_add(1, Ordering::AcqRel);
        if let Some(held) = &self.held {
            held.acquire().await.unwrap().forget();
        }
        self.refused.lock().unwrap().push(destination);
        Ok(())
    }
}

fn datagram(destination: SocketAddrV4) -> Vec<u8> {
    udp_packet(
        GUEST_IP,
        *destination.ip(),
        41_641,
        destination.port(),
        b"datagram",
    )
}

/// A question to the worker's resolver of record type `record_type`.
fn question_of_type(record_type: u16) -> Vec<u8> {
    let mut dns = dns_query(TEST_DNS_NAME, &[]);
    let at = dns.len() - 4;
    dns[at..at + 2].copy_from_slice(&record_type.to_be_bytes());
    udp_packet(GUEST_IP, WORKER_IP, 53_000, 53, &dns)
}

/// `packet` with its IPv4 flags and fragment offset set to `flags` and its
/// header checksum recomputed.
fn with_ipv4_flags(mut packet: Vec<u8>, flags: u16) -> Vec<u8> {
    packet[6..8].copy_from_slice(&flags.to_be_bytes());
    packet[10..12].copy_from_slice(&[0, 0]);
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Sends `packets`, then a datagram to [`SENTINEL`], and returns, sorted,
/// what the broker was asked to refuse once the sentinel's refusal arrives:
/// packets are handled in order, so anything they reported was reported
/// first.
async fn refused_through_sentinel(
    broker: &UdpBroker,
    guest: &mut DuplexStream,
    session: &mut NetworkSession,
    packets: &[Vec<u8>],
) -> Vec<SocketAddr> {
    for packet in packets {
        write_guest_packet(guest, session, packet).await.unwrap();
    }
    write_guest_packet(guest, session, &datagram(SENTINEL))
        .await
        .unwrap();
    tokio::time::timeout(HANG_GUARD, async {
        while !broker.refused().contains(&SocketAddr::V4(SENTINEL)) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the sentinel's refusal reached the broker");
    let mut refused = broker.refused();
    refused.sort();
    refused
}

#[tokio::test]
async fn a_datagram_to_a_public_address_is_refused_with_its_port_and_no_reply() {
    let broker = UdpBroker::new();
    let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
    write_guest_packet(&mut guest, &mut session, &datagram(STUN))
        .await
        .unwrap();
    broker.wait_for_refused(1).await;
    assert_eq!(broker.refused(), [SocketAddr::V4(STUN)]);

    // The next packet back answers the question sent after: the datagram
    // got no reply.
    let query = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
    let reply = exchange(&mut guest, &mut session, &query).await;
    assert_eq!(&reply[12..16], &WORKER_IP.octets());
    assert_eq!(&reply[20..22], &53_u16.to_be_bytes());
    assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));
}

#[tokio::test]
async fn an_admitted_question_is_answered_and_not_refused() {
    let broker = UdpBroker::new();
    let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
    let a = question_of_type(1);
    let reply = exchange(&mut guest, &mut session, &a).await;
    assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));
    let aaaa = question_of_type(28);
    let reply = exchange(&mut guest, &mut session, &aaaa).await;
    assert!(reply.ends_with(&TEST_DNS_ANSWER_V6.octets()));

    let refused = refused_through_sentinel(&broker, &mut guest, &mut session, &[]).await;
    assert_eq!(refused, [SocketAddr::V4(SENTINEL)]);
}

#[tokio::test]
async fn dns_to_another_server_or_of_another_type_is_refused() {
    let broker = UdpBroker::new();
    let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
    let google = Ipv4Addr::new(8, 8, 8, 8);
    let refused = refused_through_sentinel(
        &broker,
        &mut guest,
        &mut session,
        &[
            dns_query_packet(google, 53, TEST_DNS_NAME),
            // TXT, to the worker's own resolver.
            question_of_type(16),
        ],
    )
    .await;
    assert_eq!(
        refused,
        [
            SocketAddr::new(IpAddr::V4(google), 53),
            SocketAddr::new(IpAddr::V4(WORKER_IP), 53),
            SocketAddr::V4(SENTINEL),
        ]
    );
}

#[tokio::test]
async fn a_burst_of_datagrams_is_reported_within_its_bound() {
    let broker = UdpBroker::holding();
    let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
    let query = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);

    // While one destination's report waits, more datagrams to it add none.
    for _ in 0..200 {
        write_guest_packet(&mut guest, &mut session, &datagram(STUN))
            .await
            .unwrap();
    }
    exchange(&mut guest, &mut session, &query).await;
    assert_eq!(broker.started.load(Ordering::Acquire), 1);

    // Distinct destinations: at most the bound of reports wait at once.
    for index in 0..200 {
        let destination = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 10_000 + index);
        write_guest_packet(&mut guest, &mut session, &datagram(destination))
            .await
            .unwrap();
    }
    exchange(&mut guest, &mut session, &query).await;
    assert_eq!(
        broker.started.load(Ordering::Acquire),
        MAX_UDP_REFUSALS_IN_FLIGHT
    );

    // Once they finish, the destination is reported again.
    broker.held.as_ref().unwrap().add_permits(1_000);
    broker.wait_for_refused(MAX_UDP_REFUSALS_IN_FLIGHT).await;
    write_guest_packet(&mut guest, &mut session, &datagram(STUN))
        .await
        .unwrap();
    broker
        .wait_for_refused(MAX_UDP_REFUSALS_IN_FLIGHT + 1)
        .await;
    assert_eq!(broker.refused().last(), Some(&SocketAddr::V4(STUN)));
}

#[tokio::test]
async fn icmp_ipv6_fragments_and_malformed_packets_are_dropped_unreported() {
    let broker = UdpBroker::new();
    // An echo request that, read as UDP, would be a well-formed datagram
    // with no checksum: only its protocol number tells it apart.
    let mut echo = vec![8, 0, 0, 0, 0, 8, 0, 0];
    let checksum = internet_checksum(&echo);
    echo[2..4].copy_from_slice(&checksum.to_be_bytes());
    let icmp = ipv4_packet(GUEST_IP, *STUN.ip(), 1, &echo);
    let first_fragment = with_ipv4_flags(datagram(STUN), 0x2000);
    let later_fragment = with_ipv4_flags(datagram(STUN), 0x0001);
    let mut bad_checksum = datagram(STUN);
    *bad_checksum.last_mut().unwrap() ^= 0xff;
    let mut ipv6 = vec![0_u8; 48];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&8_u16.to_be_bytes());
    ipv6[6] = 17;
    ipv6[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    ipv6[40..42].copy_from_slice(&41_641_u16.to_be_bytes());
    ipv6[42..44].copy_from_slice(&3478_u16.to_be_bytes());
    ipv6[44..46].copy_from_slice(&8_u16.to_be_bytes());
    // A datagram that is not the guest's.
    let spoofed = udp_packet(
        Ipv4Addr::new(198, 51, 100, 9),
        *STUN.ip(),
        41_641,
        STUN.port(),
        b"datagram",
    );

    let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
    let refused = refused_through_sentinel(
        &broker,
        &mut guest,
        &mut session,
        &[
            icmp,
            first_fragment,
            later_fragment,
            bad_checksum,
            ipv6,
            spoofed,
        ],
    )
    .await;
    assert_eq!(refused, [SocketAddr::V4(SENTINEL)]);
}
