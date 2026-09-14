use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use codewire_netstack::{
    DnsAnswer, DnsQuestion, DnsRecordType, Netstack, NetstackConfig, build_ipv4_dns_response,
    parse_ipv4_dns_question,
};
use codewire_vmm_guest_probe::{
    NETWORK_FRAME_HEADER_LEN, NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck,
    NetworkHostHello, NetworkHostReady, NetworkKey, NetworkRole, NetworkSession,
    encoded_network_frame_len,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, mpsc};

use super::descriptor as fd;
use super::{Result, invalid};
use crate::network_worker::{BoxedBrokerStream, BrokerDnsAnswer, EgressBroker, TcpFlow};

const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const WORKER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const ANSWER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const DNS_NAME: &str = "console-pair.test";
const PORT: u16 = 4242;
const PAYLOAD_LEN: usize = 4096;

fn destination() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ANSWER), PORT)
}
fn resolver() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(WORKER_IP), 53)
}
fn payload(response: bool) -> [u8; PAYLOAD_LEN] {
    std::array::from_fn(|i| (i as u8) ^ if response { 0x5a } else { 0 })
}

/// The injected broker runs under the worker's real Linux boundary. It never
/// creates an OS socket. Responses require exactly the bounded binary request.
pub(super) struct FixtureBroker {
    connected: AtomicBool,
    check_denials: bool,
}

impl FixtureBroker {
    pub(super) fn new(check_denials: bool) -> Self {
        Self {
            connected: AtomicBool::new(false),
            check_denials,
        }
    }
}

#[async_trait]
impl EgressBroker for FixtureBroker {
    async fn authorize_tcp(&self, flow: TcpFlow) -> Result<()> {
        if flow.source.ip() != IpAddr::V4(GUEST_IP) || flow.destination != destination() {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }
    async fn connect_tcp(&self, flow: TcpFlow) -> Result<BoxedBrokerStream> {
        self.authorize_tcp(flow).await?;
        if self.connected.swap(true, Ordering::SeqCst) {
            return Err(invalid());
        }
        let (stream, mut peer) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let exchange = async {
                let mut received = [0; PAYLOAD_LEN];
                peer.read_exact(&mut received).await?;
                if received != payload(false) {
                    return Err(invalid());
                }
                let mut extra = [0];
                if peer.read(&mut extra).await? != 0 {
                    return Err(invalid());
                }
                peer.write_all(&payload(true)).await?;
                peer.shutdown().await
            };
            let _ = tokio::time::timeout(Duration::from_secs(10), exchange).await;
        });
        Ok(Box::pin(stream))
    }
    async fn resolve_dns(&self, question: &DnsQuestion) -> Result<BrokerDnsAnswer> {
        if self.check_denials {
            super::process::denial_canaries(c"/init")?;
        }
        if question.source.ip() != IpAddr::V4(GUEST_IP)
            || question.server != resolver()
            || question.name != DNS_NAME
            || question.record_type != DnsRecordType::A
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(BrokerDnsAnswer {
            answer: DnsAnswer::Ipv4(ANSWER),
            ttl_seconds: 30,
        })
    }
}

pub(super) struct CharacterStream(AsyncFd<OwnedFd>);
impl CharacterStream {
    pub(super) fn new(owned: OwnedFd) -> Result<Self> {
        Ok(Self(AsyncFd::new(owned)?))
    }
    pub(super) fn into_inner(self) -> OwnedFd {
        self.0.into_inner()
    }
}
impl AsyncRead for CharacterStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        loop {
            let mut ready = match self.0.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            match ready
                .try_io(|fd| fd::read_some(fd.get_ref().as_raw_fd(), buffer.initialize_unfilled()))
            {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}
impl AsyncWrite for CharacterStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<Result<usize>> {
        loop {
            let mut ready = match self.0.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(ready)) => ready,
            };
            match ready.try_io(|fd| fd::write_some(fd.get_ref().as_raw_fd(), bytes)) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
        // A char port has no socket half-close; never pretend otherwise.
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }
}

pub(super) async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    key: NetworkKey,
    vm_id: uuid::Uuid,
    generation: u64,
) -> Result<NetworkSession> {
    let mut bytes = [0; NETWORK_HOST_HELLO_LEN];
    stream.read_exact(&mut bytes).await?;
    let hello = NetworkHostHello::decode(&bytes, &key, vm_id, generation).map_err(|_| invalid())?;
    stream
        .write_all(
            &NetworkGuestAck::new(hello.nonce)
                .map_err(|_| invalid())?
                .encode(&key),
        )
        .await?;
    let mut ready = [0; NETWORK_HOST_READY_LEN];
    stream.read_exact(&mut ready).await?;
    NetworkHostReady::decode(&ready, &key, &hello.nonce).map_err(|_| invalid())?;
    NetworkSession::new(&key, &hello.nonce, NetworkRole::Guest).map_err(|_| invalid())
}

async fn read_packet<S: AsyncRead + Unpin>(
    stream: &mut S,
    session: &Mutex<NetworkSession>,
) -> Result<Vec<u8>> {
    let mut header = [0; NETWORK_FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let length = encoded_network_frame_len(&header).map_err(|_| invalid())?;
    let mut frame = vec![0; length];
    frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
        .await?;
    session
        .lock()
        .await
        .decode_packet(&frame)
        .map_err(|_| invalid())
}

async fn write_packet<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &Mutex<NetworkSession>,
    packet: &[u8],
) -> Result<()> {
    let frame = session
        .lock()
        .await
        .encode_packet(packet)
        .map_err(|_| invalid())?;
    stream.write_all(&frame).await
}

pub(super) async fn traffic_for<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    session: NetworkSession,
    profile: super::binding::Profile,
) -> Result<()> {
    match profile {
        super::binding::Profile::ConsolePair => traffic(stream, session).await,
        #[cfg(feature = "macos-product-network-fixture")]
        super::binding::Profile::ProductNetwork => {
            tcp_traffic(
                stream,
                &Mutex::new(session),
                super::product_network::destination(),
            )
            .await
        }
    }
}

pub(super) async fn traffic<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    session: NetworkSession,
) -> Result<()> {
    let session = Mutex::new(session);
    let query = dns_query(WORKER_IP, 53);
    let question = parse_ipv4_dns_question(&query, WORKER_IP, 1232).map_err(|_| invalid())?;
    let expected = build_ipv4_dns_response(&question, DnsAnswer::Ipv4(ANSWER), 30, 1500)
        .map_err(|_| invalid())?;
    write_packet(stream, &session, &query).await?;
    if read_packet(stream, &session).await? != expected {
        return Err(invalid());
    }
    // A wrong resolver must produce no response. No production deadline is
    // changed; this fixed fixture observation is followed by another real query.
    write_packet(
        stream,
        &session,
        &dns_query(Ipv4Addr::new(203, 0, 113, 1), 53),
    )
    .await?;
    // Reject even one unexpected byte. Cancelling a partially consumed frame
    // must never turn malformed/partial output into a successful deny proof.
    let mut unexpected = [0];
    if tokio::time::timeout(Duration::from_millis(100), stream.read(&mut unexpected))
        .await
        .is_ok()
    {
        return Err(invalid());
    }
    write_packet(stream, &session, &query).await?;
    if read_packet(stream, &session).await? != expected {
        return Err(invalid());
    }

    tcp_traffic(stream, &session, destination()).await
}

async fn tcp_traffic<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    session: &Mutex<NetworkSession>,
    peer: SocketAddr,
) -> Result<()> {
    let (to_stack, inbound) = mpsc::channel(32);
    let (outbound, mut from_stack) = mpsc::channel(32);
    let stack = Netstack::with_config(
        NetstackConfig {
            local_ip: IpAddr::V4(GUEST_IP),
            prefix_len: 30,
            mtu: 1500,
            verify_rx_checksums: true,
            accept_any_ip: false,
            default_gateway: Some(IpAddr::V4(WORKER_IP)),
        },
        inbound,
        outbound,
    )?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let receive = async {
        for _ in 0..512 {
            to_stack
                .send(read_packet(&mut reader, session).await?)
                .await
                .map_err(|_| invalid())?;
        }
        Err::<(), _>(invalid())
    };
    let send = async {
        for _ in 0..512 {
            let packet = from_stack.recv().await.ok_or_else(invalid)?;
            write_packet(&mut writer, session, &packet).await?;
        }
        Err::<(), _>(invalid())
    };
    let application = async {
        let mut stream = stack.connect(peer).await?;
        stream.write_all(&payload(false)).await?;
        stream.shutdown().await?;
        let mut response = [0; PAYLOAD_LEN];
        stream.read_exact(&mut response).await?;
        if response != payload(true) {
            return Err(invalid());
        }
        let mut extra = [0];
        if stream.read(&mut extra).await? != 0 {
            return Err(invalid());
        }
        Ok(())
    };
    tokio::select! { result = receive => result, result = send => result, result = application => result }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]) as u32)
        .sum::<u32>();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn dns_query(server: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in DNS_NAME.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut packet = vec![0; 28 + dns.len()];
    let size = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&size.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&GUEST_IP.octets());
    packet[16..20].copy_from_slice(&server.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    packet[20..22].copy_from_slice(&53000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[24..26].copy_from_slice(&(size - 20).to_be_bytes());
    packet[28..].copy_from_slice(&dns);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&GUEST_IP.octets());
    pseudo.extend_from_slice(&server.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(size - 20).to_be_bytes());
    pseudo.extend_from_slice(&packet[20..]);
    let sum = checksum(&pseudo);
    packet[26..28].copy_from_slice(&(if sum == 0 { 65535 } else { sum }).to_be_bytes());
    packet
}
