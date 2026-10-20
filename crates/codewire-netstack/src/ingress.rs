//! Strict, allocation-free parsing of an initial guest IPv4 TCP SYN.
//!
//! This surfaces the original source and destination before a consumer feeds
//! the packet into an AnyIP netstack. It deliberately performs no egress
//! policy: the local VM worker must reject loopback, metadata, multicast,
//! link-local, denied ports, and other destinations before binding the exact
//! endpoint and forwarding the packet.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpPacket, TcpSeqNumber};

/// Source and original destination carried by one initial TCP SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialTcpSyn {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// Canonical source/destination metadata for any admitted IPv4 TCP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalIpv4TcpPacket {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub initial_syn: bool,
}

/// Why a packet cannot open a new transparent TCP admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialTcpSynError {
    InvalidIpv4,
    NonCanonicalIpv4Length,
    Ipv4Options,
    InvalidIpv4Checksum,
    FragmentedIpv4,
    NotTcp,
    InvalidTcp,
    InvalidTcpChecksum,
    NotInitialSyn,
    ZeroPort,
    SynPayload,
}

impl fmt::Display for InitialTcpSynError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIpv4 => "packet is not valid IPv4",
            Self::NonCanonicalIpv4Length => "IPv4 total length is not the exact frame length",
            Self::Ipv4Options => "IPv4 options are not accepted",
            Self::InvalidIpv4Checksum => "IPv4 checksum is invalid",
            Self::FragmentedIpv4 => "fragmented IPv4 is not accepted",
            Self::NotTcp => "IPv4 packet is not TCP",
            Self::InvalidTcp => "TCP segment is malformed",
            Self::InvalidTcpChecksum => "TCP checksum is invalid",
            Self::NotInitialSyn => "TCP segment is not an initial SYN",
            Self::ZeroPort => "TCP source and destination ports must be nonzero",
            Self::SynPayload => "TCP SYN payload is not accepted",
        })
    }
}

impl std::error::Error for InitialTcpSynError {}

/// Parse one canonical, unfragmented IPv4 TCP SYN without allocating.
///
/// The caller must apply destination and source policy to the returned flow
/// before it creates an exact AnyIP listener or forwards the packet.
pub fn parse_initial_ipv4_tcp_syn(packet: &[u8]) -> Result<InitialTcpSyn, InitialTcpSynError> {
    let parsed = parse_canonical_ipv4_tcp_packet_inner(packet)?;
    if !parsed.syn || parsed.ack || parsed.fin || parsed.rst {
        return Err(InitialTcpSynError::NotInitialSyn);
    }
    if !parsed.payload_empty {
        return Err(InitialTcpSynError::SynPayload);
    }
    Ok(InitialTcpSyn {
        source: parsed.source,
        destination: parsed.destination,
    })
}

/// The segment that refuses one initial IPv4 TCP SYN, as a closed port
/// answers it: RST and ACK of the SYN, from its destination back to its
/// source. The client sees a refused connection at once, never a handshake
/// that is later reset.
pub fn build_ipv4_tcp_refusal(syn: &[u8]) -> Result<Vec<u8>, InitialTcpSynError> {
    let initial = parse_initial_ipv4_tcp_syn(syn)?;
    let (IpAddr::V4(client), IpAddr::V4(destination)) =
        (initial.source.ip(), initial.destination.ip())
    else {
        return Err(InitialTcpSynError::InvalidIpv4);
    };
    let acknowledged = {
        let ipv4 = Ipv4Packet::new_unchecked(syn);
        TcpPacket::new_unchecked(ipv4.payload()).seq_number() + 1
    };
    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 20;
    let mut packet = vec![0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];
    let source_ip = Ipv4Address::from_octets(destination.octets());
    let destination_ip = Ipv4Address::from_octets(client.octets());
    {
        let mut tcp = TcpPacket::new_unchecked(&mut packet[IPV4_HEADER_LEN..]);
        tcp.set_src_port(initial.destination.port());
        tcp.set_dst_port(initial.source.port());
        tcp.set_seq_number(TcpSeqNumber(0));
        tcp.set_ack_number(acknowledged);
        tcp.set_header_len(TCP_HEADER_LEN as u8);
        tcp.clear_flags();
        tcp.set_rst(true);
        tcp.set_ack(true);
        tcp.set_window_len(0);
        tcp.set_urgent_at(0);
        tcp.fill_checksum(
            &IpAddress::Ipv4(source_ip),
            &IpAddress::Ipv4(destination_ip),
        );
    }
    {
        let mut ipv4 = Ipv4Packet::new_unchecked(packet.as_mut_slice());
        ipv4.set_version(4);
        ipv4.set_header_len(IPV4_HEADER_LEN as u8);
        ipv4.set_total_len((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
        ipv4.set_dont_frag(true);
        ipv4.set_hop_limit(64);
        ipv4.set_next_header(IpProtocol::Tcp);
        ipv4.set_src_addr(source_ip);
        ipv4.set_dst_addr(destination_ip);
        ipv4.fill_checksum();
    }
    Ok(packet)
}

/// Parse one canonical, unfragmented IPv4 TCP packet without allocating.
///
/// Consumers use this after the strict initial-SYN admission to ensure only
/// the expected guest source and an already-admitted destination enter the
/// userspace TCP/IP engine.
pub fn parse_canonical_ipv4_tcp_packet(
    packet: &[u8],
) -> Result<CanonicalIpv4TcpPacket, InitialTcpSynError> {
    let parsed = parse_canonical_ipv4_tcp_packet_inner(packet)?;
    Ok(CanonicalIpv4TcpPacket {
        source: parsed.source,
        destination: parsed.destination,
        initial_syn: parsed.syn
            && !parsed.ack
            && !parsed.fin
            && !parsed.rst
            && parsed.payload_empty,
    })
}

struct ParsedTcpPacket {
    source: SocketAddr,
    destination: SocketAddr,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    payload_empty: bool,
}

fn parse_canonical_ipv4_tcp_packet_inner(
    packet: &[u8],
) -> Result<ParsedTcpPacket, InitialTcpSynError> {
    let ipv4 = Ipv4Packet::new_checked(packet).map_err(|_| InitialTcpSynError::InvalidIpv4)?;
    if usize::from(ipv4.total_len()) != packet.len() {
        return Err(InitialTcpSynError::NonCanonicalIpv4Length);
    }
    if ipv4.header_len() != 20 {
        return Err(InitialTcpSynError::Ipv4Options);
    }
    if !ipv4.verify_checksum() {
        return Err(InitialTcpSynError::InvalidIpv4Checksum);
    }
    if ipv4.more_frags() || ipv4.frag_offset() != 0 {
        return Err(InitialTcpSynError::FragmentedIpv4);
    }
    if ipv4.next_header() != IpProtocol::Tcp {
        return Err(InitialTcpSynError::NotTcp);
    }

    let source_ip = IpAddress::Ipv4(ipv4.src_addr());
    let destination_ip = IpAddress::Ipv4(ipv4.dst_addr());
    let tcp = TcpPacket::new_checked(ipv4.payload()).map_err(|_| InitialTcpSynError::InvalidTcp)?;
    if !tcp.verify_checksum(&source_ip, &destination_ip) {
        return Err(InitialTcpSynError::InvalidTcpChecksum);
    }
    if tcp.src_port() == 0 || tcp.dst_port() == 0 {
        return Err(InitialTcpSynError::ZeroPort);
    }

    Ok(ParsedTcpPacket {
        source: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.src_addr().octets())),
            tcp.src_port(),
        ),
        destination: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.dst_addr().octets())),
            tcp.dst_port(),
        ),
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        payload_empty: tcp.payload().is_empty(),
    })
}
