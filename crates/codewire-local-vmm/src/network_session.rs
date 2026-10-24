//! Portable authenticated host-side packet session for one local microVM.
//!
//! This module owns no host socket creation, inherited-descriptor handling, or
//! process confinement. Callers must provide an already-connected guest stream
//! and an egress broker capability. The Linux worker keeps those outer trust
//! boundaries in `network_worker`; the macOS developer fixture uses this same
//! production handshake and packet engine with a socket-free synthetic broker.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use codewire_netstack::{
    DnsAnswer, DnsQuestion, Netstack, NetstackConfig, NetstackLimits, TcpListener,
    build_ipv4_dns_response, build_ipv4_tcp_refusal, parse_canonical_ipv4_tcp_packet,
    parse_ipv4_dns_question,
};
use codewire_vmm_guest_probe::{
    NETWORK_FRAME_HEADER_LEN, NETWORK_GUEST_ACK_LEN, NETWORK_MAX_PACKET_BYTES, NetworkGuestAck,
    NetworkHostHello, NetworkHostReady, NetworkKey, NetworkRole, NetworkSession,
    encoded_network_frame_len,
};
use rand::{RngCore as _, rngs::OsRng};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use uuid::Uuid;

pub(crate) const PACKET_QUEUE: usize = 256;
pub(crate) const MAX_INBOUND_STREAM_FLOWS: usize = 64;
pub(crate) const NETWORK_MTU: usize = 1_500;
const DNS_MESSAGE_LIMIT: usize = 1_232;
/// Guest DNS questions answered at once (#2638). Each runs in its own task, so
/// a slow upstream lookup holds up no other packet; a question beyond the
/// bound is answered SERVFAIL at once.
pub(crate) const MAX_DNS_IN_FLIGHT: usize = 32;
const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// New guest connections the broker is still authorizing and dialing. A SYN
/// beyond this is dropped; the guest retries it.
pub(crate) const MAX_TCP_DIALS_IN_FLIGHT: usize = 64;
/// How long an upstream dialed for a guest SYN waits for the guest's
/// handshake to reach the listener.
const DIALED_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const WORKER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}

pub type BoxedBrokerStream = Pin<Box<dyn AsyncReadWrite + Send + Sync + Unpin + 'static>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpFlow {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerDnsAnswer {
    pub answer: DnsAnswer,
    pub ttl_seconds: u32,
}

/// Implementations bind queue admission separately from each transaction.
/// An outer deadline must not cancel a broker request after it starts.
#[async_trait]
pub trait EgressBroker: Send + Sync + 'static {
    /// Cheap policy admission before the engine binds an AnyIP listener.
    async fn authorize_tcp(&self, flow: TcpFlow) -> io::Result<()>;

    /// Return an already-connected stream for one accepted guest flow.
    async fn connect_tcp(&self, flow: TcpFlow) -> io::Result<BoxedBrokerStream>;

    /// Resolve one already-parsed canonical DNS question.
    async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer>;
}

#[derive(Debug, Default)]
pub struct DenyBroker;

#[async_trait]
impl EgressBroker for DenyBroker {
    async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
        Err(denied())
    }

    async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
        Err(denied())
    }

    async fn resolve_dns(&self, _question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
        Err(denied())
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "network broker denied request",
    )
}

pub(crate) struct InboundGuestStream {
    pub(crate) guest_port: u16,
    pub(crate) stream: BoxedBrokerStream,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum NetworkSessionError {
    #[error("network session identity is invalid")]
    InvalidIdentity,
    #[error("network session host hello write timed out")]
    HelloWriteTimeout,
    #[error("network session host hello write failed")]
    HelloWriteIo,
    #[error("network session guest acknowledgement read timed out")]
    AcknowledgementReadTimeout,
    #[error("network session guest acknowledgement read failed")]
    AcknowledgementReadIo,
    #[error("network session guest acknowledgement authentication failed")]
    AcknowledgementInvalid,
    #[error("network session host-ready proof write failed")]
    HostReadyIo,
    #[error("network session ready notification failed")]
    ReadyIo,
    #[error("network session protocol authentication failed")]
    Protocol,
    #[error("network session frame I/O failed")]
    FrameIo,
    #[error("network session packet engine failed")]
    Engine,
}

/// Run one authenticated generation-bound packet engine over an injected
/// connected stream. `ready` is called only after the bounded netstack exists,
/// the genuine guest acknowledgement authenticates, and HostReady is flushed.
pub async fn run_network_session<S, B, R>(
    stream: S,
    key: NetworkKey,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
    ready: R,
) -> Result<(), NetworkSessionError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B: EgressBroker,
    R: FnOnce() -> io::Result<()> + Send,
{
    run_network_session_with_ingress(stream, key, vm_id, generation, broker, None, ready).await
}

pub(crate) async fn run_network_session_with_ingress<S, B, R>(
    mut stream: S,
    key: NetworkKey,
    vm_id: Uuid,
    generation: u64,
    broker: Arc<B>,
    inbound: Option<mpsc::Receiver<InboundGuestStream>>,
    ready: R,
) -> Result<(), NetworkSessionError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B: EgressBroker,
    R: FnOnce() -> io::Result<()> + Send,
{
    validate_identity(vm_id, generation)?;
    // Build the fixed-size engine before beginning the guest handshake. Once
    // the guest acknowledges the hello, no setup work remains that could
    // consume the guest's bounded authentication window.
    let limits = NetstackLimits::default();
    let (to_stack, stack_packets) = mpsc::channel(PACKET_QUEUE);
    let (from_stack, outbound_packets) = mpsc::channel(PACKET_QUEUE);
    let stack = Netstack::with_config_and_limits(
        NetstackConfig {
            local_ip: IpAddr::V4(WORKER_IP),
            prefix_len: 30,
            mtu: NETWORK_MTU,
            verify_rx_checksums: true,
            accept_any_ip: true,
            default_gateway: None,
        },
        limits,
        stack_packets,
        from_stack.clone(),
    )
    .map_err(|_| NetworkSessionError::Engine)?;

    let nonce = network_nonce();
    let hello = NetworkHostHello::new(vm_id, generation, nonce)
        .map_err(|_| NetworkSessionError::Protocol)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(&hello.encode(&key)))
        .await
        .map_err(|_| NetworkSessionError::HelloWriteTimeout)?
        .map_err(|_| NetworkSessionError::HelloWriteIo)?;
    let mut ack = [0_u8; NETWORK_GUEST_ACK_LEN];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .map_err(|_| NetworkSessionError::AcknowledgementReadTimeout)?
        .map_err(|_| NetworkSessionError::AcknowledgementReadIo)?;
    NetworkGuestAck::decode(&ack, &key, &nonce)
        .map_err(|_| NetworkSessionError::AcknowledgementInvalid)?;

    let session = Arc::new(Mutex::new(
        NetworkSession::new(&key, &nonce, NetworkRole::Host)
            .map_err(|_| NetworkSessionError::Protocol)?,
    ));

    stream
        .write_all(
            &NetworkHostReady::new(nonce)
                .map_err(|_| NetworkSessionError::Protocol)?
                .encode(&key),
        )
        .await
        .map_err(|_| NetworkSessionError::HostReadyIo)?;
    stream
        .flush()
        .await
        .map_err(|_| NetworkSessionError::HostReadyIo)?;
    ready().map_err(|_| NetworkSessionError::ReadyIo)?;

    let (stream_read, stream_write) = tokio::io::split(stream);
    let (guest_packet_tx, guest_packets) = mpsc::channel(PACKET_QUEUE);
    let reader = read_authenticated_frames(stream_read, Arc::clone(&session), guest_packet_tx);
    let writer = write_authenticated_frames(stream_write, session, outbound_packets);
    let dispatcher = dispatch_packets(guest_packets, stack, to_stack, from_stack, broker, inbound);
    tokio::pin!(reader, writer, dispatcher);
    tokio::select! {
        result = &mut reader => result,
        result = &mut writer => result,
        result = &mut dispatcher => result,
    }
}

fn validate_identity(vm_id: Uuid, generation: u64) -> Result<(), NetworkSessionError> {
    if vm_id.is_nil() || generation == 0 {
        return Err(NetworkSessionError::InvalidIdentity);
    }
    Ok(())
}

fn network_nonce() -> [u8; 32] {
    loop {
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce.iter().any(|byte| *byte != 0) {
            return nonce;
        }
    }
}

async fn read_authenticated_frames<R>(
    mut stream: R,
    session: Arc<Mutex<NetworkSession>>,
    packets: mpsc::Sender<Vec<u8>>,
) -> Result<(), NetworkSessionError>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|_| NetworkSessionError::FrameIo)?;
        let frame_len =
            encoded_network_frame_len(&header).map_err(|_| NetworkSessionError::Protocol)?;
        let mut frame = vec![0_u8; frame_len];
        frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
        stream
            .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
            .await
            .map_err(|_| NetworkSessionError::FrameIo)?;
        let packet = session
            .lock()
            .await
            .decode_packet(&frame)
            .map_err(|_| NetworkSessionError::Protocol)?;
        packets
            .send(packet)
            .await
            .map_err(|_| NetworkSessionError::Engine)?;
    }
}

async fn write_authenticated_frames<W>(
    mut stream: W,
    session: Arc<Mutex<NetworkSession>>,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> Result<(), NetworkSessionError>
where
    W: AsyncWrite + Unpin,
{
    while let Some(packet) = packets.recv().await {
        if packet.is_empty() || packet.len() > NETWORK_MAX_PACKET_BYTES {
            return Err(NetworkSessionError::Engine);
        }
        let frame = session
            .lock()
            .await
            .encode_packet(&packet)
            .map_err(|_| NetworkSessionError::Protocol)?;
        stream
            .write_all(&frame)
            .await
            .map_err(|_| NetworkSessionError::FrameIo)?;
    }
    Err(NetworkSessionError::Engine)
}

/// Upstream connections dialed for guest SYNs, keyed by the guest's source
/// and destination, waiting for the catch-all listener to accept the guest
/// side. One whose guest never completes its handshake is dropped after
/// [`DIALED_UPSTREAM_TIMEOUT`].
#[derive(Default)]
struct DialedUpstreams(
    std::sync::Mutex<HashMap<(SocketAddr, SocketAddr), (BoxedBrokerStream, tokio::time::Instant)>>,
);

impl DialedUpstreams {
    fn insert(&self, flow: (SocketAddr, SocketAddr), upstream: BoxedBrokerStream) {
        let now = tokio::time::Instant::now();
        let mut dialed = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dialed.retain(|_, (_, at)| now.duration_since(*at) < DIALED_UPSTREAM_TIMEOUT);
        dialed.insert(flow, (upstream, now));
    }

    fn take(&self, flow: &(SocketAddr, SocketAddr)) -> Option<BoxedBrokerStream> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(flow)
            .map(|(upstream, _)| upstream)
    }
}

async fn dispatch_packets<B: EgressBroker>(
    mut packets: mpsc::Receiver<Vec<u8>>,
    stack: Netstack,
    to_stack: mpsc::Sender<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    broker: Arc<B>,
    mut inbound: Option<mpsc::Receiver<InboundGuestStream>>,
) -> Result<(), NetworkSessionError> {
    // One catch-all listener accepts every guest connection, whatever its
    // destination; only the netstack's connection limit bounds them (#2993).
    let listener = stack
        .bind_catch_all()
        .await
        .map_err(|_| NetworkSessionError::Engine)?;
    let dialed = Arc::new(DialedUpstreams::default());
    let mut egress = JoinSet::new();
    egress.spawn(serve_listener(listener, Arc::clone(&dialed)));
    let mut dials = JoinSet::new();
    let mut dialing = HashSet::<(SocketAddr, SocketAddr)>::new();
    let mut inbound_bridges = JoinSet::new();
    let mut dns_questions = JoinSet::new();
    loop {
        let packet = tokio::select! {
            packet = packets.recv() => {
                packet.ok_or(NetworkSessionError::FrameIo)?
            }
            incoming = next_inbound_guest_stream(&mut inbound) => {
                let Some(mut incoming) = incoming else {
                    inbound = None;
                    continue;
                };
                if inbound_bridges.len() >= MAX_INBOUND_STREAM_FLOWS {
                    continue;
                }
                let destination = SocketAddr::new(IpAddr::V4(GUEST_IP), incoming.guest_port);
                let guest = tokio::time::timeout(
                    GUEST_CONNECT_TIMEOUT,
                    stack.connect(destination),
                )
                .await;
                let Ok(Ok(mut guest)) = guest else {
                    continue;
                };
                inbound_bridges.spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut incoming.stream, &mut guest).await;
                    let _ = incoming.stream.shutdown().await;
                    let _ = guest.shutdown().await;
                });
                continue;
            }
            dial = dials.join_next(), if !dials.is_empty() => {
                let Some(Ok((flow, syn, upstream))) = dial else { continue; };
                dialing.remove(&flow);
                match upstream {
                    Some(upstream) => {
                        dialed.insert(flow, upstream);
                        to_stack
                            .send(syn)
                            .await
                            .map_err(|_| NetworkSessionError::Engine)?;
                    }
                    None => {
                        // Refused, or the destination could not be reached:
                        // answer the SYN with RST, so the guest sees a refused
                        // connection, never a handshake that is later reset
                        // (#3003).
                        if let Ok(refusal) = build_ipv4_tcp_refusal(&syn) {
                            outbound
                                .send(refusal)
                                .await
                                .map_err(|_| NetworkSessionError::Engine)?;
                        }
                    }
                }
                continue;
            }
            _ = egress.join_next() => {
                // The catch-all listener ends only with the stack.
                return Err(NetworkSessionError::Engine);
            }
            completed = inbound_bridges.join_next(), if !inbound_bridges.is_empty() => {
                let _ = completed;
                continue;
            }
            answered = dns_questions.join_next(), if !dns_questions.is_empty() => {
                match answered {
                    Some(Ok(Ok(()))) | None => {}
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(_)) => return Err(NetworkSessionError::Engine),
                }
                continue;
            }
        };
        if let Ok(question) = parse_ipv4_dns_question(&packet, WORKER_IP, DNS_MESSAGE_LIMIT) {
            if question.source.ip() != IpAddr::V4(GUEST_IP) {
                continue;
            }
            // Count only questions still in flight.
            while let Some(answered) = dns_questions.try_join_next() {
                match answered {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(NetworkSessionError::Engine),
                }
            }
            if dns_questions.len() >= MAX_DNS_IN_FLIGHT {
                let response =
                    build_ipv4_dns_response(&question, DnsAnswer::ServerFailure, 0, NETWORK_MTU)
                        .map_err(|_| NetworkSessionError::Engine)?;
                outbound
                    .send(response)
                    .await
                    .map_err(|_| NetworkSessionError::Engine)?;
                continue;
            }
            dns_questions.spawn(answer_dns_question(
                question,
                Arc::clone(&broker),
                outbound.clone(),
            ));
            continue;
        }

        let Ok(tcp) = parse_canonical_ipv4_tcp_packet(&packet) else {
            // UDP other than canonical virtual-resolver DNS, ICMP, IPv6, and
            // malformed/fragmented packets are intentionally not admitted.
            continue;
        };
        if tcp.source.ip() != IpAddr::V4(GUEST_IP) {
            continue;
        }
        if tcp.destination.ip() == IpAddr::V4(WORKER_IP) {
            if tcp.initial_syn {
                // Nothing serves TCP at the worker's address (its DNS is UDP),
                // and the catch-all listener must not accept a connection
                // there: refuse it as any refused dial is (#3060).
                if let Ok(refusal) = build_ipv4_tcp_refusal(&packet) {
                    outbound
                        .send(refusal)
                        .await
                        .map_err(|_| NetworkSessionError::Engine)?;
                }
                continue;
            }
            // Host-port publication creates an outbound userspace-netstack
            // connection from WORKER_IP to one exact guest port. Feed return
            // packets to that stack; it rejects non-matching connections.
            to_stack
                .send(packet)
                .await
                .map_err(|_| NetworkSessionError::Engine)?;
            continue;
        }
        if !tcp.initial_syn {
            // A segment of a connection the catch-all listener accepted. The
            // stack answers a segment that matches no connection with RST.
            to_stack
                .send(packet)
                .await
                .map_err(|_| NetworkSessionError::Engine)?;
            continue;
        }
        // A new connection: off this loop, the broker authorizes it and dials
        // the destination. Only then does the SYN reach the stack, so the
        // guest's handshake completes only once the upstream is connected,
        // and a refusal is answered as one (#3003). Every connection is
        // decided, so a policy change applies to the next one.
        let flow = (tcp.source, tcp.destination);
        if dialing.contains(&flow) {
            // The guest retransmitted the SYN while its dial runs.
            continue;
        }
        if dials.len() >= MAX_TCP_DIALS_IN_FLIGHT {
            continue;
        }
        dialing.insert(flow);
        let tcp_flow = TcpFlow {
            source: tcp.source,
            destination: tcp.destination,
        };
        let broker = Arc::clone(&broker);
        dials.spawn(async move {
            let upstream = match broker.authorize_tcp(tcp_flow).await {
                Ok(()) => broker.connect_tcp(tcp_flow).await.ok(),
                Err(_) => None,
            };
            (flow, packet, upstream)
        });
    }
}

/// Resolve one guest question and send the reply. A lookup that fails is
/// answered at once, with the query's ID and question only, so the guest does
/// not wait out its timeout: REFUSED when the policy refused, SERVFAIL for
/// anything else.
async fn answer_dns_question<B: EgressBroker>(
    question: DnsQuestion,
    broker: Arc<B>,
    outbound: mpsc::Sender<Vec<u8>>,
) -> Result<(), NetworkSessionError> {
    let answer = broker
        .resolve_dns(&question)
        .await
        .unwrap_or_else(|error| BrokerDnsAnswer {
            answer: if error.kind() == io::ErrorKind::PermissionDenied {
                DnsAnswer::Refused
            } else {
                DnsAnswer::ServerFailure
            },
            ttl_seconds: 0,
        });
    let response =
        build_ipv4_dns_response(&question, answer.answer, answer.ttl_seconds, NETWORK_MTU)
            .map_err(|_| NetworkSessionError::Engine)?;
    outbound
        .send(response)
        .await
        .map_err(|_| NetworkSessionError::Engine)
}

async fn next_inbound_guest_stream(
    inbound: &mut Option<mpsc::Receiver<InboundGuestStream>>,
) -> Option<InboundGuestStream> {
    match inbound {
        Some(inbound) => inbound.recv().await,
        None => std::future::pending().await,
    }
}

/// Bridge every guest connection the catch-all listener accepts to the
/// upstream already dialed for it.
async fn serve_listener(mut listener: TcpListener, dialed: Arc<DialedUpstreams>) {
    let mut bridges = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Some(mut guest) = accepted else { return; };
                // Dialed before its SYN reached the stack; one that expired
                // leaves the guest connection to be reset.
                let Some(mut upstream) = dialed.take(&(guest.peer_addr(), guest.local_addr())) else {
                    continue;
                };
                bridges.spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut guest, &mut upstream).await;
                    let _ = guest.shutdown().await;
                    let _ = upstream.shutdown().await;
                });
            }
            completed = bridges.join_next(), if !bridges.is_empty() => {
                let _ = completed;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use codewire_netstack::DnsRecordType;
    use codewire_vmm_guest_probe::{NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkError};
    use tokio::io::{DuplexStream, duplex};
    use tokio::sync::Semaphore;

    use super::*;

    const TOKEN: &str = "portable-session-test-token-0123456789";
    const TEST_DNS_NAME: &str = "fixture.codewire.test";
    const TEST_DNS_ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 20);
    /// Bounds a wait that its own event ends: a reply, an answered SYN, a
    /// reset or a lookup reaching the broker. The bound only turns a hang
    /// into a failure; fixed windows of up to 2 s failed on a loaded CI slot
    /// (#3277).
    const HANG_GUARD: Duration = Duration::from_secs(120);

    fn identity() -> (Uuid, u64) {
        (
            Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            9,
        )
    }

    struct FixtureBroker {
        resolved: AtomicUsize,
    }

    #[async_trait]
    impl EgressBroker for FixtureBroker {
        async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
            Err(denied())
        }

        async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            Err(denied())
        }

        async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
            if question.source.ip() != IpAddr::V4(GUEST_IP)
                || question.server != SocketAddr::new(IpAddr::V4(WORKER_IP), 53)
                || question.name != TEST_DNS_NAME
                || question.record_type != DnsRecordType::A
            {
                return Err(denied());
            }
            self.resolved.fetch_add(1, Ordering::Relaxed);
            Ok(BrokerDnsAnswer {
                answer: DnsAnswer::Ipv4(TEST_DNS_ANSWER),
                ttl_seconds: 30,
            })
        }
    }

    type DnsOutcome = fn() -> io::Result<BrokerDnsAnswer>;

    /// Records every DNS question it is asked and answers each the same way.
    struct RecordingBroker {
        questions: Mutex<Vec<DnsQuestion>>,
        outcome: DnsOutcome,
    }

    impl RecordingBroker {
        fn new(outcome: DnsOutcome) -> Arc<Self> {
            Arc::new(Self {
                questions: Mutex::new(Vec::new()),
                outcome,
            })
        }
    }

    #[async_trait]
    impl EgressBroker for RecordingBroker {
        async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
            Err(denied())
        }

        async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            Err(denied())
        }

        async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
            self.questions.lock().unwrap().push(question.clone());
            (self.outcome)()
        }
    }

    /// The guest's end of a ready, authenticated session served by `broker`.
    async fn ready_session<B: EgressBroker>(broker: Arc<B>) -> (DuplexStream, NetworkSession) {
        let (vm_id, generation) = identity();
        let (host_endpoint, mut guest_endpoint) = duplex(128 * 1024);
        let host_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        tokio::spawn(run_network_session(
            host_endpoint,
            host_key,
            vm_id,
            generation,
            broker,
            || Ok(()),
        ));
        let guest_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let session =
            authenticate_guest_endpoint(&mut guest_endpoint, &guest_key, vm_id, generation)
                .await
                .unwrap();
        (guest_endpoint, session)
    }

    /// Send one guest packet and read the packet that comes back.
    async fn exchange(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
        packet: &[u8],
    ) -> Vec<u8> {
        write_guest_packet(stream, session, packet).await.unwrap();
        tokio::time::timeout(HANG_GUARD, read_guest_packet(stream, session))
            .await
            .expect("the reply timed out")
            .unwrap()
    }

    /// One EDNS OPT record: the root name, type 41, then the given payload
    /// size, flags and options.
    fn opt_record(payload_size: u16, flags: u32, options: &[u8]) -> Vec<u8> {
        let mut record = vec![0, 0, 41];
        record.extend_from_slice(&payload_size.to_be_bytes());
        record.extend_from_slice(&flags.to_be_bytes());
        record.extend_from_slice(&(options.len() as u16).to_be_bytes());
        record.extend_from_slice(options);
        record
    }

    /// Nothing in a query's OPT record reaches the broker or the reply: not
    /// the payload size, the DO bit, the version, a cookie or a client subnet.
    #[tokio::test]
    async fn an_edns_record_changes_neither_the_broker_request_nor_the_reply() {
        let broker = RecordingBroker::new(|| {
            Ok(BrokerDnsAnswer {
                answer: DnsAnswer::Ipv4(TEST_DNS_ANSWER),
                ttl_seconds: 30,
            })
        });
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;

        let cookie = [0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let client_subnet = [0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100];
        let queries = [
            dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME),
            dns_query_packet_with(WORKER_IP, 53, TEST_DNS_NAME, &opt_record(1232, 0, &[])),
            dns_query_packet_with(
                WORKER_IP,
                53,
                TEST_DNS_NAME,
                &opt_record(4096, 0x0000_8000, &cookie),
            ),
            dns_query_packet_with(
                WORKER_IP,
                53,
                TEST_DNS_NAME,
                &opt_record(512, 0x0001_0000, &client_subnet),
            ),
        ];
        let mut replies = Vec::new();
        for query in &queries {
            replies.push(exchange(&mut guest, &mut session, query).await);
        }

        assert!(replies[0].ends_with(&TEST_DNS_ANSWER.octets()));
        assert!(replies.iter().all(|reply| reply == &replies[0]));
        let questions = broker.questions.lock().unwrap();
        assert_eq!(questions.len(), queries.len());
        assert!(questions.iter().all(|question| question == &questions[0]));
    }

    /// The low flags byte of a DNS reply packet (RA and the response code),
    /// after checking that it is addressed to the guest's source and repeats
    /// only the query's ID and question.
    fn reply_code(reply: &[u8], query: &[u8]) -> u8 {
        const DNS: usize = 28;
        assert_eq!(&reply[12..16], &WORKER_IP.octets());
        assert_eq!(&reply[16..20], &GUEST_IP.octets());
        assert_eq!(&reply[20..22], &53_u16.to_be_bytes());
        assert_eq!(&reply[22..24], &query[20..22]);
        assert_eq!(&reply[DNS..DNS + 2], &query[DNS..DNS + 2]);
        assert_eq!(reply[DNS + 2], 0x81);
        assert_eq!(&reply[DNS + 4..DNS + 12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&reply[DNS + 12..], &query[DNS + 12..]);
        reply[DNS + 3]
    }

    #[tokio::test]
    async fn a_refused_or_failed_lookup_is_answered_at_once() {
        let query = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        let outcomes: [(DnsOutcome, u8); 4] = [
            (|| Err(denied()), 5),
            (|| Err(io::ErrorKind::ConnectionRefused.into()), 2),
            (|| Err(io::ErrorKind::ConnectionAborted.into()), 2),
            (|| Err(io::ErrorKind::InvalidData.into()), 2),
        ];
        for (outcome, code) in outcomes {
            let broker = RecordingBroker::new(outcome);
            let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
            let reply = exchange(&mut guest, &mut session, &query).await;
            assert_eq!(reply_code(&reply, &query), 0x80 | code);
            assert_eq!(broker.questions.lock().unwrap().len(), 1);
        }

        // The deny-all broker refuses, and the session keeps serving.
        let (mut guest, mut session) = ready_session(Arc::new(DenyBroker)).await;
        for _ in 0..2 {
            let reply = exchange(&mut guest, &mut session, &query).await;
            assert_eq!(reply_code(&reply, &query), 0x80 | 5);
        }
    }

    /// A question the worker does not admit gets no reply, whatever the
    /// broker would say: it never reaches the broker.
    #[tokio::test]
    async fn an_unadmitted_question_is_still_dropped_without_a_reply() {
        let broker = RecordingBroker::new(|| Err(denied()));
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let admitted = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        let unadmitted = [
            dns_query_packet(Ipv4Addr::new(8, 8, 8, 8), 53, TEST_DNS_NAME),
            dns_query_packet(WORKER_IP, 5_353, TEST_DNS_NAME),
            dns_query_packet_with(
                WORKER_IP,
                53,
                TEST_DNS_NAME,
                &[opt_record(1232, 0, &[]), opt_record(1232, 0, &[])].concat(),
            ),
            // A well-formed question from a source that is not the guest: a
            // reply to it would make the worker a reflector.
            udp_packet(
                Ipv4Addr::new(198, 51, 100, 9),
                WORKER_IP,
                53_000,
                53,
                &dns_query(TEST_DNS_NAME, &[]),
            ),
        ];
        for packet in &unadmitted {
            write_guest_packet(&mut guest, &mut session, packet)
                .await
                .unwrap();
        }
        // The one reply that arrives is for the admitted question sent last.
        let reply = exchange(&mut guest, &mut session, &admitted).await;
        assert_eq!(reply_code(&reply, &admitted), 0x80 | 5);
        assert_eq!(broker.questions.lock().unwrap().len(), 1);
    }

    const SLOW_DNS_NAME: &str = "slow.codewire.test";

    /// Lookups of [`SLOW_DNS_NAME`] wait until released, as an upstream
    /// lookup that times out would; every other request answers at once.
    struct SlowLookupBroker {
        slow: AtomicUsize,
        release: Semaphore,
        authorized: AtomicUsize,
    }

    impl SlowLookupBroker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                slow: AtomicUsize::new(0),
                release: Semaphore::new(0),
                authorized: AtomicUsize::new(0),
            })
        }

        async fn wait_for_slow(&self, count: usize) {
            tokio::time::timeout(HANG_GUARD, async {
                while self.slow.load(Ordering::Acquire) < count {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the slow lookups reached the broker");
        }
    }

    #[async_trait]
    impl EgressBroker for SlowLookupBroker {
        async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
            self.authorized.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            let (upstream, _) = duplex(1024);
            Ok(Box::pin(upstream))
        }

        async fn resolve_dns(&self, question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
            if question.name == SLOW_DNS_NAME {
                self.slow.fetch_add(1, Ordering::AcqRel);
                self.release.acquire().await.unwrap().forget();
            }
            Ok(BrokerDnsAnswer {
                answer: DnsAnswer::Ipv4(TEST_DNS_ANSWER),
                ttl_seconds: 30,
            })
        }
    }

    /// The TCP flags of a reply packet.
    fn tcp_flags(packet: &[u8]) -> u8 {
        assert_eq!(packet[9], 6, "not TCP");
        packet[20 + 13]
    }

    fn tcp_syn_packet(destination: SocketAddrV4) -> Vec<u8> {
        let mut tcp = vec![0_u8; 20];
        tcp[..2].copy_from_slice(&40_000_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&1_u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&64_240_u16.to_be_bytes());
        let checksum = transport_checksum(GUEST_IP, *destination.ip(), 6, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        ipv4_packet(GUEST_IP, *destination.ip(), 6, &tcp)
    }

    /// #2638: while one lookup waits upstream, another lookup is answered and
    /// a TCP handshake to an admitted destination proceeds.
    #[tokio::test]
    async fn a_slow_lookup_holds_up_no_other_packet() {
        let broker = SlowLookupBroker::new();
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let slow = dns_query_packet(WORKER_IP, 53, SLOW_DNS_NAME);
        write_guest_packet(&mut guest, &mut session, &slow)
            .await
            .unwrap();
        broker.wait_for_slow(1).await;

        let fast = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        let reply = exchange(&mut guest, &mut session, &fast).await;
        assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));

        let syn = tcp_syn_packet(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 80), 443));
        let reply = exchange(&mut guest, &mut session, &syn).await;
        assert_eq!(tcp_flags(&reply), 0x12, "expected the stack's SYN-ACK");
        assert_eq!(broker.authorized.load(Ordering::Acquire), 1);

        broker.release.add_permits(1);
        let reply = tokio::time::timeout(HANG_GUARD, read_guest_packet(&mut guest, &mut session))
            .await
            .expect("the slow lookup was answered once released")
            .unwrap();
        assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));
    }

    /// Admits every TCP flow and dials each in `dial` before handing back an
    /// upstream that is already closed; lookups answer at once.
    struct BurstBroker {
        dial: Duration,
        dialled: AtomicUsize,
        authorized: AtomicUsize,
    }

    #[async_trait]
    impl EgressBroker for BurstBroker {
        async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
            self.authorized.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            tokio::time::sleep(self.dial).await;
            self.dialled.fetch_add(1, Ordering::AcqRel);
            let (upstream, _) = duplex(1024);
            Ok(Box::pin(upstream))
        }

        async fn resolve_dns(&self, _question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
            Ok(BrokerDnsAnswer {
                answer: DnsAnswer::Ipv4(TEST_DNS_ANSWER),
                ttl_seconds: 30,
            })
        }
    }

    fn tcp_packet(
        source_port: u16,
        destination: SocketAddrV4,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut tcp = vec![0_u8; 20];
        tcp[..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64_240_u16.to_be_bytes());
        let checksum = transport_checksum(GUEST_IP, *destination.ip(), 6, &tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        ipv4_packet(GUEST_IP, *destination.ip(), 6, &tcp)
    }

    /// Every packet the worker sends within `quiet` of the last one.
    async fn drain(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
        quiet: Duration,
    ) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        while let Ok(packet) = tokio::time::timeout(quiet, read_guest_packet(stream, session)).await
        {
            packets.push(packet.unwrap());
        }
        packets
    }

    /// Every packet up to and including the first TCP reset.
    async fn packets_through_reset(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
    ) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        tokio::time::timeout(HANG_GUARD, async {
            loop {
                let packet = read_guest_packet(stream, session).await.unwrap();
                let reset = packet[9] == 6 && tcp_flags(&packet) & 0x04 != 0;
                packets.push(packet);
                if reset {
                    break;
                }
            }
        })
        .await
        .expect("no TCP reset arrived");
        packets
    }

    /// Reads packets until `answered` holds a SYN-ACK for `expected` ports.
    async fn await_syn_acks(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
        answered: &mut std::collections::BTreeMap<u16, u32>,
        expected: usize,
    ) {
        tokio::time::timeout(HANG_GUARD, async {
            while answered.len() < expected {
                let packet = read_guest_packet(stream, session).await.unwrap();
                note_syn_acks(answered, vec![packet]);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{} of {expected} SYNs were answered", answered.len()));
    }

    /// Authorizes and dials as configured, counting dials. Each dial answers
    /// once `dial` has a permit, so a test can hold dials open.
    struct DialBroker {
        authorize: bool,
        connect: bool,
        dial: Semaphore,
        dials: AtomicUsize,
    }

    #[async_trait]
    impl EgressBroker for DialBroker {
        async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
            if self.authorize {
                Ok(())
            } else {
                Err(denied())
            }
        }

        async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            self.dials.fetch_add(1, Ordering::AcqRel);
            drop(self.dial.acquire().await.unwrap());
            if !self.connect {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            let (upstream, _) = duplex(1024);
            Ok(Box::pin(upstream))
        }

        async fn resolve_dns(&self, _question: &DnsQuestion) -> io::Result<BrokerDnsAnswer> {
            Err(denied())
        }
    }

    /// #3003: a connection the broker refuses, or one it cannot dial, is
    /// answered with RST to the SYN, so the guest sees a refused connection;
    /// no handshake ever completes first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_or_undialable_connection_is_refused_never_reset_after_a_handshake() {
        for (authorize, connect) in [(false, true), (true, false)] {
            let broker = Arc::new(DialBroker {
                authorize,
                connect,
                dial: Semaphore::new(Semaphore::MAX_PERMITS),
                dials: AtomicUsize::new(0),
            });
            let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
            let destination = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 80), 443);
            let syn = tcp_packet(40_000, destination, 1, 0, 0x02);
            write_guest_packet(&mut guest, &mut session, &syn)
                .await
                .unwrap();
            let packets = packets_through_reset(&mut guest, &mut session).await;
            let tcp: Vec<&Vec<u8>> = packets.iter().filter(|packet| packet[9] == 6).collect();
            assert!(
                !tcp.iter().any(|packet| tcp_flags(packet) & 0x12 == 0x12),
                "authorize {authorize}, connect {connect}: a handshake was offered"
            );
            let refusal = tcp
                .iter()
                .find(|packet| tcp_flags(packet) & 0x04 != 0)
                .unwrap_or_else(|| panic!("authorize {authorize}, connect {connect}: no RST"));
            assert_eq!(tcp_flags(refusal), 0x14, "RST and ACK");
            assert_eq!(
                u32::from_be_bytes([refusal[28], refusal[29], refusal[30], refusal[31]]),
                2,
                "the RST acknowledges the SYN"
            );
            assert_eq!(u16::from_be_bytes([refusal[22], refusal[23]]), 40_000);
            assert_eq!(broker.dials.load(Ordering::Acquire), usize::from(authorize));
        }
    }

    /// #3060: a guest connection to the worker's own address is refused at
    /// once, on every port, without asking the broker; nothing serves TCP
    /// there and the catch-all listener must not accept it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connection_to_the_worker_address_is_refused_without_the_broker() {
        let broker = Arc::new(DialBroker {
            authorize: true,
            connect: true,
            dial: Semaphore::new(Semaphore::MAX_PERMITS),
            dials: AtomicUsize::new(0),
        });
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        for (source_port, port) in [(41_022, 22), (41_053, 53), (41_080, 80), (41_443, 443)] {
            let syn = tcp_packet(source_port, SocketAddrV4::new(WORKER_IP, port), 1, 0, 0x02);
            write_guest_packet(&mut guest, &mut session, &syn)
                .await
                .unwrap();
            let packets = packets_through_reset(&mut guest, &mut session).await;
            let tcp: Vec<&Vec<u8>> = packets.iter().filter(|packet| packet[9] == 6).collect();
            assert!(
                !tcp.iter().any(|packet| tcp_flags(packet) & 0x12 == 0x12),
                "port {port}: a handshake was offered"
            );
            let refusal = tcp
                .iter()
                .find(|packet| tcp_flags(packet) & 0x04 != 0)
                .unwrap_or_else(|| panic!("port {port}: no RST"));
            assert_eq!(tcp_flags(refusal), 0x14, "port {port}: RST and ACK");
            assert_eq!(u16::from_be_bytes([refusal[22], refusal[23]]), source_port);
        }
        assert_eq!(
            broker.dials.load(Ordering::Acquire),
            0,
            "the broker is never asked"
        );
    }

    /// #3003: the guest's handshake waits for the upstream dial, and a SYN the
    /// guest retransmits while it runs does not dial again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_handshake_waits_for_the_dial_and_a_retransmitted_syn_dials_once() {
        // The dial stays open until the test releases it, so no wait can
        // outlast it on a slow runner (#3277).
        let broker = Arc::new(DialBroker {
            authorize: true,
            connect: true,
            dial: Semaphore::new(0),
            dials: AtomicUsize::new(0),
        });
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let destination = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 81), 443);
        let syn = tcp_packet(40_001, destination, 1, 0, 0x02);
        write_guest_packet(&mut guest, &mut session, &syn)
            .await
            .unwrap();
        tokio::time::timeout(HANG_GUARD, async {
            while broker.dials.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the SYN reached the broker");
        write_guest_packet(&mut guest, &mut session, &syn)
            .await
            .unwrap();
        let early = drain(&mut guest, &mut session, Duration::from_millis(150)).await;
        assert!(
            !early
                .iter()
                .any(|packet| packet[9] == 6 && tcp_flags(packet) == 0x12),
            "SYN-ACK before the dial finished"
        );
        broker.dial.add_permits(1);
        let mut answered = std::collections::BTreeMap::new();
        await_syn_acks(&mut guest, &mut session, &mut answered, 1).await;
        assert_eq!(broker.dials.load(Ordering::Acquire), 1);
    }

    fn note_syn_acks(answered: &mut std::collections::BTreeMap<u16, u32>, packets: Vec<Vec<u8>>) {
        for packet in packets {
            if packet[9] == 6 && tcp_flags(&packet) == 0x12 {
                let port = u16::from_be_bytes([packet[22], packet[23]]);
                let seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
                answered.insert(port, seq);
            }
        }
    }

    fn distinct_destination(index: usize) -> SocketAddrV4 {
        SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, 1 + u8::try_from(index / 200).unwrap()),
            1_000 + u16::try_from(index % 200).unwrap(),
        )
    }

    /// #2993: far more destinations than the netstack has listeners are live
    /// at once, every one answered by the one catch-all listener, and each
    /// new connection is authorized.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn more_live_destinations_than_listeners_all_answer() {
        const DESTINATIONS: usize = 200;
        assert!(DESTINATIONS > NetstackLimits::default().max_listeners);
        let broker = Arc::new(BurstBroker {
            dial: Duration::ZERO,
            dialled: AtomicUsize::new(0),
            authorized: AtomicUsize::new(0),
        });
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let mut answered = std::collections::BTreeMap::new();
        for index in 0..DESTINATIONS {
            let port = 40_000 + u16::try_from(index).unwrap();
            let syn = tcp_packet(port, distinct_destination(index), 1, 0, 0x02);
            write_guest_packet(&mut guest, &mut session, &syn)
                .await
                .unwrap();
            note_syn_acks(
                &mut answered,
                drain(&mut guest, &mut session, Duration::from_millis(5)).await,
            );
        }
        await_syn_acks(&mut guest, &mut session, &mut answered, DESTINATIONS).await;
        assert_eq!(broker.authorized.load(Ordering::Acquire), DESTINATIONS);
    }

    /// #2993: more distinct destinations than the netstack has connections,
    /// one after another, all answer: a connection the guest resets frees its
    /// slot.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sequential_destinations_beyond_the_connection_limit_all_answer() {
        const DESTINATIONS: usize = 300;
        assert!(DESTINATIONS > NetstackLimits::default().max_connections);
        let broker = Arc::new(BurstBroker {
            dial: Duration::ZERO,
            dialled: AtomicUsize::new(0),
            authorized: AtomicUsize::new(0),
        });
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let mut answered = std::collections::BTreeMap::new();
        for index in 0..DESTINATIONS {
            let port = 40_000 + u16::try_from(index).unwrap();
            let destination = distinct_destination(index);
            let syn = tcp_packet(port, destination, 1, 0, 0x02);
            write_guest_packet(&mut guest, &mut session, &syn)
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + HANG_GUARD;
            while !answered.contains_key(&port) && tokio::time::Instant::now() < deadline {
                note_syn_acks(
                    &mut answered,
                    drain(&mut guest, &mut session, Duration::from_millis(20)).await,
                );
            }
            assert!(
                answered.contains_key(&port),
                "destination {index} was not answered"
            );
            let reset = tcp_packet(port, destination, 2, 0, 0x04);
            write_guest_packet(&mut guest, &mut session, &reset)
                .await
                .unwrap();
        }
    }

    /// #2714: the guest completes many handshakes to one destination and
    /// closes them; a lookup made right after is answered without waiting for
    /// the dials those connections caused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_burst_to_one_destination_does_not_hold_up_dns() {
        const CONNECTIONS: u16 = 300;
        let broker = Arc::new(BurstBroker {
            dial: Duration::from_millis(160),
            dialled: AtomicUsize::new(0),
            authorized: AtomicUsize::new(0),
        });
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let destination = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 80), 443);
        let mut syn_acks = std::collections::BTreeMap::new();
        for index in 0..CONNECTIONS {
            let syn = tcp_packet(30_000 + index, destination, 1, 0, 0x02);
            write_guest_packet(&mut guest, &mut session, &syn)
                .await
                .unwrap();
            note_syn_acks(
                &mut syn_acks,
                drain(&mut guest, &mut session, Duration::from_millis(5)).await,
            );
        }
        // Every connection slot completes its handshake before the guest
        // closes them; on a loaded runner a fixed wait saw none (#3277).
        await_syn_acks(
            &mut guest,
            &mut session,
            &mut syn_acks,
            NetstackLimits::default().max_connections,
        )
        .await;
        for (port, seq) in &syn_acks {
            let ack = tcp_packet(*port, destination, 2, seq.wrapping_add(1), 0x10);
            write_guest_packet(&mut guest, &mut session, &ack)
                .await
                .unwrap();
            drain(&mut guest, &mut session, Duration::from_millis(2)).await;
        }
        for (port, seq) in &syn_acks {
            let fin = tcp_packet(*port, destination, 2, seq.wrapping_add(1), 0x11);
            write_guest_packet(&mut guest, &mut session, &fin)
                .await
                .unwrap();
            drain(&mut guest, &mut session, Duration::from_millis(2)).await;
        }
        let established = syn_acks.len();

        let started = tokio::time::Instant::now();
        let query = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        write_guest_packet(&mut guest, &mut session, &query)
            .await
            .unwrap();
        let answered = tokio::time::timeout(HANG_GUARD, async {
            loop {
                let packet = read_guest_packet(&mut guest, &mut session).await.unwrap();
                if packet[9] == 17 && u16::from_be_bytes([packet[20], packet[21]]) == 53 {
                    return packet;
                }
            }
        })
        .await;
        let elapsed = started.elapsed();
        eprintln!(
            "#2714: {established} handshakes completed, {} dialled before the lookup, \
             lookup answered after {elapsed:?}",
            broker.dialled.load(Ordering::Acquire)
        );
        let answer = answered.expect("the lookup was answered");
        assert!(answer.ends_with(&TEST_DNS_ANSWER.octets()));
        // #2714 held a lookup about 1 s for each connection closed, over four
        // minutes for this burst; an unloaded run answers in under 1 ms. 10 s
        // keeps slack for a loaded runner, where 1 s failed (#3277).
        assert!(
            elapsed < Duration::from_secs(10),
            "the lookup waited {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_question_beyond_the_in_flight_bound_is_answered_servfail_at_once() {
        let broker = SlowLookupBroker::new();
        let (mut guest, mut session) = ready_session(Arc::clone(&broker)).await;
        let slow = dns_query_packet(WORKER_IP, 53, SLOW_DNS_NAME);
        for _ in 0..MAX_DNS_IN_FLIGHT {
            write_guest_packet(&mut guest, &mut session, &slow)
                .await
                .unwrap();
        }
        broker.wait_for_slow(MAX_DNS_IN_FLIGHT).await;

        let beyond = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        let reply = exchange(&mut guest, &mut session, &beyond).await;
        assert_eq!(reply_code(&reply, &beyond), 0x80 | 2);
        assert_eq!(broker.slow.load(Ordering::Acquire), MAX_DNS_IN_FLIGHT);

        broker.release.add_permits(MAX_DNS_IN_FLIGHT);
        for _ in 0..MAX_DNS_IN_FLIGHT {
            let reply =
                tokio::time::timeout(HANG_GUARD, read_guest_packet(&mut guest, &mut session))
                    .await
                    .expect("every released lookup was answered")
                    .unwrap();
            assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));
        }
        // With the bound free again, a question goes to the broker.
        let reply = exchange(&mut guest, &mut session, &beyond).await;
        assert!(reply.ends_with(&TEST_DNS_ANSWER.octets()));
    }

    #[tokio::test]
    async fn genuine_handshake_precedes_ready_and_authenticated_dns_processing() {
        let (vm_id, generation) = identity();
        let (host_endpoint, mut guest_endpoint) = duplex(128 * 1024);
        let host_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let broker = Arc::new(FixtureBroker {
            resolved: AtomicUsize::new(0),
        });
        let host_broker = Arc::clone(&broker);
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let host = tokio::spawn(run_network_session(
            host_endpoint,
            host_key,
            vm_id,
            generation,
            host_broker,
            move || ready_tx.try_send(()).map_err(io::Error::other),
        ));

        assert!(ready_rx.try_recv().is_err());
        let guest_key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let mut session =
            authenticate_guest_endpoint(&mut guest_endpoint, &guest_key, vm_id, generation)
                .await
                .unwrap();
        ready_rx
            .recv()
            .await
            .expect("ready notification was absent");

        let query = dns_query_packet(WORKER_IP, 53, TEST_DNS_NAME);
        write_guest_packet(&mut guest_endpoint, &mut session, &query)
            .await
            .unwrap();
        let response = tokio::time::timeout(
            HANG_GUARD,
            read_guest_packet(&mut guest_endpoint, &mut session),
        )
        .await
        .expect("authenticated DNS response timed out")
        .unwrap();
        assert!(response.ends_with(&TEST_DNS_ANSWER.octets()));
        assert_eq!(broker.resolved.load(Ordering::Relaxed), 1);

        drop(guest_endpoint);
        assert!(matches!(
            tokio::time::timeout(HANG_GUARD, host)
                .await
                .unwrap()
                .unwrap(),
            Err(NetworkSessionError::FrameIo)
        ));
    }

    #[tokio::test]
    async fn identity_and_guest_acknowledgement_fail_closed_before_ready() {
        let key = NetworkKey::derive(TOKEN, identity().0, identity().1).unwrap();
        let (host_endpoint, _guest_endpoint) = duplex(1024);
        assert_eq!(
            run_network_session(
                host_endpoint,
                key,
                Uuid::nil(),
                identity().1,
                Arc::new(DenyBroker),
                || panic!("invalid identity cannot become ready"),
            )
            .await,
            Err(NetworkSessionError::InvalidIdentity)
        );

        let (vm_id, generation) = identity();
        let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
        let (host_endpoint, mut guest_endpoint) = duplex(1024);
        let host = tokio::spawn(run_network_session(
            host_endpoint,
            key,
            vm_id,
            generation,
            Arc::new(DenyBroker),
            || panic!("forged acknowledgement cannot become ready"),
        ));
        let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
        guest_endpoint.read_exact(&mut hello).await.unwrap();
        guest_endpoint
            .write_all(&[0_u8; NETWORK_GUEST_ACK_LEN])
            .await
            .unwrap();
        assert_eq!(
            host.await.unwrap(),
            Err(NetworkSessionError::AcknowledgementInvalid)
        );
    }

    async fn authenticate_guest_endpoint(
        stream: &mut DuplexStream,
        key: &NetworkKey,
        vm_id: Uuid,
        generation: u64,
    ) -> Result<NetworkSession, NetworkError> {
        let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
        stream.read_exact(&mut hello).await.unwrap();
        let hello = NetworkHostHello::decode(&hello, key, vm_id, generation)?;
        stream
            .write_all(&NetworkGuestAck::new(hello.nonce)?.encode(key))
            .await
            .unwrap();
        let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
        stream.read_exact(&mut ready).await.unwrap();
        NetworkHostReady::decode(&ready, key, &hello.nonce)?;
        NetworkSession::new(key, &hello.nonce, NetworkRole::Guest)
    }

    async fn write_guest_packet(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
        packet: &[u8],
    ) -> io::Result<()> {
        let frame = session.encode_packet(packet).map_err(io::Error::other)?;
        stream.write_all(&frame).await
    }

    async fn read_guest_packet(
        stream: &mut DuplexStream,
        session: &mut NetworkSession,
    ) -> io::Result<Vec<u8>> {
        let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let length = encoded_network_frame_len(&header).map_err(io::Error::other)?;
        let mut frame = vec![0_u8; length];
        frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
        stream
            .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
            .await?;
        session.decode_packet(&frame).map_err(io::Error::other)
    }

    fn dns_query_packet(server: Ipv4Addr, port: u16, name: &str) -> Vec<u8> {
        dns_query_packet_with(server, port, name, &[])
    }

    /// A query whose additional section is `additional`, counted as one
    /// record unless it is empty.
    fn dns_query_packet_with(
        server: Ipv4Addr,
        port: u16,
        name: &str,
        additional: &[u8],
    ) -> Vec<u8> {
        udp_packet(GUEST_IP, server, 53_000, port, &dns_query(name, additional))
    }

    fn dns_query(name: &str, additional: &[u8]) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&0x1234_u16.to_be_bytes());
        dns.extend_from_slice(&0x0100_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[0_u8; 4]);
        dns.extend_from_slice(&u16::from(!additional.is_empty()).to_be_bytes());
        for label in name.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(additional);
        dns
    }

    fn udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = 8 + payload.len();
        let mut udp = vec![0_u8; length];
        udp[..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);
        let checksum = transport_checksum(source, destination, 17, &udp);
        udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
        ipv4_packet(source, destination, 17, &udp)
    }

    fn ipv4_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0_u8; 20 + payload.len()];
        let packet_length = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(payload);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn transport_checksum(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + payload.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.push(0);
        pseudo.push(protocol);
        pseudo.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(payload);
        internet_checksum(&pseudo)
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
        !(sum as u16)
    }
}
