//! Strict, allocation-free parsing of an initial guest IPv4 TCP SYN.
//!
//! This surfaces the original source and destination before a consumer feeds
//! the packet into an AnyIP netstack. It deliberately performs no egress
//! policy: the local VM worker must reject loopback, metadata, multicast,
//! link-local, denied ports, and other destinations before binding the exact
//! endpoint and forwarding the packet.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket};

/// Source and original destination carried by one initial TCP SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialTcpSyn {
    pub source: SocketAddr,
    pub destination: SocketAddr,
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
    if !tcp.syn() || tcp.ack() || tcp.fin() || tcp.rst() {
        return Err(InitialTcpSynError::NotInitialSyn);
    }
    if tcp.src_port() == 0 || tcp.dst_port() == 0 {
        return Err(InitialTcpSynError::ZeroPort);
    }
    if !tcp.payload().is_empty() {
        return Err(InitialTcpSynError::SynPayload);
    }

    Ok(InitialTcpSyn {
        source: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.src_addr().octets())),
            tcp.src_port(),
        ),
        destination: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.dst_addr().octets())),
            tcp.dst_port(),
        ),
    })
}
