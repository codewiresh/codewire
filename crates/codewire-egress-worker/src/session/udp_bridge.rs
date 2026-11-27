//! Narrow, host-enforced tailnet UDP `:31000` bridge (#6637).
//!
//! General workload UDP stays closed in `codewire-egress-worker` (TCP + DNS-53
//! only). When a `standard` Pod configures explicit literal `CODEWIRE_POD_UDP_PEERS`,
//! the host runner binds Pod `0.0.0.0:31000` and hands this confined worker a
//! pre-connected `UnixStream` so the worker never needs `socket`/`bind`/`sendto`/
//! `recvfrom` syscalls.
//!
//! Both directions enforce the exact literal IPv4:port allowlist, canonical
//! unfragmented IPv4/UDP framing, MTU payload bounds, and bounded drop-on-full
//! (`try_send`) queueing so UDP traffic never blocks TCP platform flows or wakes
//! a suspended VM.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use codewire_netstack::parse_canonical_ipv4_udp_datagram;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{BoxedBrokerStream, NETWORK_MTU};

/// The guest tailnet daemon's UDP port routed out `eth0` by hosted routing.
pub const TAILNET_UDP_PORT: u16 = 31_000;
/// Maximum literal UDP peers accepted from `CODEWIRE_POD_UDP_PEERS`.
pub const MAX_UDP_BRIDGE_PEERS: usize = 8;
/// Canonical IPv4 (20 B) + UDP (8 B) header length.
pub const IPV4_UDP_HEADER_LEN: usize = 28;
/// Maximum UDP payload carried over the bridge (`MTU - 28`, matching `UDP_PACKET_LIMIT`).
pub const MAX_UDP_BRIDGE_PAYLOAD: usize = NETWORK_MTU - IPV4_UDP_HEADER_LEN;
/// Wire header length on the worker<->runner bridge stream: 4B IPv4 + 2B port + 2B len.
pub const UDP_BRIDGE_FRAME_HEADER_LEN: usize = 8;
/// Bounded queue depth in each direction; full queues drop datagrams immediately.
pub const UDP_BRIDGE_QUEUE_CAPACITY: usize = 64;

/// A pre-connected bridge stream and its immutable literal IPv4:port allowlist,
/// handed to a confined worker session for tailnet UDP `:31000` forwarding.
pub struct UdpBridgeAttachment {
    pub stream: BoxedBrokerStream,
    pub allowed_peers: Vec<SocketAddrV4>,
}

/// Active worker-side tailnet UDP bridge tasks. Dropping this aborts both
/// background I/O tasks when the session ends.
pub(super) struct UdpBridgeHandle {
    guest_ip: Ipv4Addr,
    guest_port: u16,
    allowed_peers: Arc<[SocketAddrV4]>,
    max_payload: usize,
    to_host: mpsc::Sender<(SocketAddrV4, Vec<u8>)>,
    tasks: [JoinHandle<()>; 2],
}

impl UdpBridgeHandle {
    /// Spawns the bounded, non-blocking outbound writer and inbound reader over
    /// `attachment.stream`. Returns `None` when `allowed_peers` is empty.
    pub(super) fn spawn(
        attachment: UdpBridgeAttachment,
        guest_ip: Ipv4Addr,
        mtu: usize,
        outbound_to_guest: mpsc::Sender<Vec<u8>>,
    ) -> Option<Self> {
        if attachment.allowed_peers.is_empty() || mtu <= IPV4_UDP_HEADER_LEN {
            return None;
        }
        let max_payload = mtu - IPV4_UDP_HEADER_LEN;
        let allowed_peers: Arc<[SocketAddrV4]> = attachment.allowed_peers.into();
        let (to_host_tx, mut to_host_rx) =
            mpsc::channel::<(SocketAddrV4, Vec<u8>)>(UDP_BRIDGE_QUEUE_CAPACITY);
        let (mut reader, mut writer) = tokio::io::split(attachment.stream);

        let write_task = tokio::spawn(async move {
            while let Some((destination, payload)) = to_host_rx.recv().await {
                if write_udp_bridge_frame(&mut writer, destination, &payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let inbound_peers = Arc::clone(&allowed_peers);
        let read_task = tokio::spawn(async move {
            let mut buffer = vec![0_u8; max_payload];
            while let Ok(Some((source, payload_len))) =
                read_udp_bridge_frame(&mut reader, &mut buffer).await
            {
                let Some(frame) = build_inbound_udp(
                    source,
                    guest_ip,
                    TAILNET_UDP_PORT,
                    &buffer[..payload_len],
                    &inbound_peers,
                    max_payload,
                ) else {
                    continue;
                };
                // Drop-on-full: never block the reader or wake a paused VM.
                let _ = outbound_to_guest.try_send(frame);
            }
        });

        Some(Self {
            guest_ip,
            guest_port: TAILNET_UDP_PORT,
            allowed_peers,
            max_payload,
            to_host: to_host_tx,
            tasks: [write_task, read_task],
        })
    }

    /// Attempts to forward one guest IPv4/UDP packet to the host UDP bridge.
    ///
    /// Returns `true` when the packet matched `(guest_ip, 31000) -> allowlisted peer`
    /// and was handed to the bounded queue (or dropped on queue full). Returns
    /// `false` for every other packet so the caller routes it to `udp_refusals`.
    pub(super) fn try_forward_from_guest(&self, packet: &[u8]) -> bool {
        let Some((destination, payload)) = parse_outbound_udp(
            packet,
            self.guest_ip,
            self.guest_port,
            &self.allowed_peers,
            self.max_payload,
        ) else {
            return false;
        };
        // Drop-on-full: a guest UDP flood must never stall TCP platform traffic.
        let _ = self.to_host.try_send((destination, payload.to_vec()));
        true
    }
}

impl Drop for UdpBridgeHandle {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Validates one guest IPv4/UDP packet for outbound tailnet forwarding:
/// canonical unfragmented IPv4/UDP (20-byte header, exact lengths, valid IPv4
/// checksum, valid UDP checksum when non-zero), exact `(guest_ip, guest_port)`
/// source, allowlisted IPv4:port destination, and payload within `max_payload`.
pub fn parse_outbound_udp<'a>(
    packet: &'a [u8],
    guest_ip: Ipv4Addr,
    guest_port: u16,
    allowed_peers: &[SocketAddrV4],
    max_payload: usize,
) -> Option<(SocketAddrV4, &'a [u8])> {
    let datagram = parse_canonical_ipv4_udp_datagram(packet).ok()?;
    let expected_source = SocketAddr::V4(SocketAddrV4::new(guest_ip, guest_port));
    if datagram.source != expected_source {
        return None;
    }
    let SocketAddr::V4(destination) = datagram.destination else {
        return None;
    };
    if !allowed_peers.contains(&destination) {
        return None;
    }
    let payload = packet.get(IPV4_UDP_HEADER_LEN..)?;
    if payload.len() > max_payload {
        return None;
    }
    Some((destination, payload))
}

/// Builds one canonical unfragmented IPv4/UDP frame addressed from an
/// allowlisted `source` to `(guest_ip, guest_port)` with valid IPv4 and UDP
/// checksums. Returns `None` if `source` is not allowlisted or `payload`
/// exceeds `max_payload`.
pub fn build_inbound_udp(
    source: SocketAddrV4,
    guest_ip: Ipv4Addr,
    guest_port: u16,
    payload: &[u8],
    allowed_peers: &[SocketAddrV4],
    max_payload: usize,
) -> Option<Vec<u8>> {
    if guest_port == 0 || !allowed_peers.contains(&source) || payload.len() > max_payload {
        return None;
    }
    let udp_len = u16::try_from(8usize.checked_add(payload.len())?).ok()?;
    let total_len = u16::try_from(IPV4_UDP_HEADER_LEN.checked_add(payload.len())?).ok()?;
    let mut packet = vec![0_u8; usize::from(total_len)];

    // Canonical 20-byte IPv4 header: version 4, IHL 5, DF set, TTL 64, UDP (17).
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.ip().octets());
    packet[16..20].copy_from_slice(&guest_ip.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // 8-byte UDP header + payload.
    packet[20..22].copy_from_slice(&source.port().to_be_bytes());
    packet[22..24].copy_from_slice(&guest_port.to_be_bytes());
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let udp_checksum = udp_ipv4_checksum(*source.ip(), guest_ip, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());

    debug_assert!(parse_canonical_ipv4_udp_datagram(&packet).is_ok());
    Some(packet)
}

/// Writes one framed UDP datagram across the worker<->runner stream.
pub async fn write_udp_bridge_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    peer: SocketAddrV4,
    payload: &[u8],
) -> io::Result<()> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UDP payload exceeds u16"))?;
    let mut header = [0_u8; UDP_BRIDGE_FRAME_HEADER_LEN];
    header[..4].copy_from_slice(&peer.ip().octets());
    header[4..6].copy_from_slice(&peer.port().to_be_bytes());
    header[6..8].copy_from_slice(&payload_len.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

/// Reads one framed UDP datagram from the worker<->runner stream into `buffer`.
/// Returns `Ok(None)` on clean EOF, and rejects frames larger than `buffer`.
pub async fn read_udp_bridge_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> io::Result<Option<(SocketAddrV4, usize)>> {
    let mut header = [0_u8; UDP_BRIDGE_FRAME_HEADER_LEN];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let ip = Ipv4Addr::new(header[0], header[1], header[2], header[3]);
    let port = u16::from_be_bytes([header[4], header[5]]);
    let payload_len = usize::from(u16::from_be_bytes([header[6], header[7]]));
    if payload_len > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UDP bridge frame exceeds MTU payload bound",
        ));
    }
    reader.read_exact(&mut buffer[..payload_len]).await?;
    Ok(Some((SocketAddrV4::new(ip, port), payload_len)))
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [last] = remainder {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    fold_checksum(sum)
}

fn udp_ipv4_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut pseudo = [0_u8; 12];
    pseudo[..4].copy_from_slice(&source.octets());
    pseudo[4..8].copy_from_slice(&destination.octets());
    pseudo[9] = 17;
    let udp_len = u16::try_from(udp_segment.len()).unwrap_or(u16::MAX);
    pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());
    let (pseudo_chunks, _) = pseudo.as_chunks::<2>();
    for chunk in pseudo_chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    let (chunks, remainder) = udp_segment.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [last] = remainder {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    let checksum = fold_checksum(sum);
    if checksum == 0 { u16::MAX } else { checksum }
}

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

/// Checks whether a guest packet is addressed to `worker` DNS or needs the bridge;
/// exposed for sibling tests.
#[cfg(test)]
pub(crate) fn is_ipv4_udp_peer(addr: SocketAddr) -> Option<SocketAddrV4> {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => Some(SocketAddrV4::new(ip, addr.port())),
        std::net::IpAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests;
