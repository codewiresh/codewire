//! Strict, allocation-free parsing of a guest IPv4 UDP datagram's addresses.
//!
//! This surfaces the source and destination of a datagram the worker does
//! not carry, so the refusal can be recorded. It forwards nothing and admits
//! nothing: only DNS to the virtual resolver is carried, through
//! [`crate::parse_ipv4_dns_question`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};

/// Source and destination of one canonical IPv4 UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4UdpDatagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// Why a packet is not a canonical IPv4 UDP datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4UdpDatagramError {
    InvalidIpv4,
    NonCanonicalIpv4Length,
    Ipv4Options,
    InvalidIpv4Checksum,
    FragmentedIpv4,
    NotUdp,
    InvalidUdp,
    InvalidUdpChecksum,
    ZeroPort,
}

impl fmt::Display for Ipv4UdpDatagramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIpv4 => "packet is not valid IPv4",
            Self::NonCanonicalIpv4Length => "IPv4 total length is not the exact frame length",
            Self::Ipv4Options => "IPv4 options are not accepted",
            Self::InvalidIpv4Checksum => "IPv4 checksum is invalid",
            Self::FragmentedIpv4 => "fragmented IPv4 is not accepted",
            Self::NotUdp => "IPv4 packet is not UDP",
            Self::InvalidUdp => "UDP datagram is malformed",
            Self::InvalidUdpChecksum => "UDP checksum is invalid",
            Self::ZeroPort => "UDP source and destination ports must be nonzero",
        })
    }
}

impl std::error::Error for Ipv4UdpDatagramError {}

/// Parse one canonical, unfragmented IPv4 UDP datagram without allocating:
/// no IPv4 options, exact lengths, valid checksums (a zero UDP checksum is
/// IPv4's "none") and nonzero ports.
pub fn parse_canonical_ipv4_udp_datagram(
    packet: &[u8],
) -> Result<Ipv4UdpDatagram, Ipv4UdpDatagramError> {
    let ipv4 = Ipv4Packet::new_checked(packet).map_err(|_| Ipv4UdpDatagramError::InvalidIpv4)?;
    if ipv4.version() != 4 {
        return Err(Ipv4UdpDatagramError::InvalidIpv4);
    }
    if usize::from(ipv4.total_len()) != packet.len() {
        return Err(Ipv4UdpDatagramError::NonCanonicalIpv4Length);
    }
    if ipv4.header_len() != 20 {
        return Err(Ipv4UdpDatagramError::Ipv4Options);
    }
    if !ipv4.verify_checksum() {
        return Err(Ipv4UdpDatagramError::InvalidIpv4Checksum);
    }
    if ipv4.more_frags() || ipv4.frag_offset() != 0 {
        return Err(Ipv4UdpDatagramError::FragmentedIpv4);
    }
    if ipv4.next_header() != IpProtocol::Udp {
        return Err(Ipv4UdpDatagramError::NotUdp);
    }
    let udp =
        UdpPacket::new_checked(ipv4.payload()).map_err(|_| Ipv4UdpDatagramError::InvalidUdp)?;
    if usize::from(udp.len()) != ipv4.payload().len() {
        return Err(Ipv4UdpDatagramError::InvalidUdp);
    }
    let source_ip = IpAddress::Ipv4(ipv4.src_addr());
    let destination_ip = IpAddress::Ipv4(ipv4.dst_addr());
    if !udp.verify_checksum(&source_ip, &destination_ip) {
        return Err(Ipv4UdpDatagramError::InvalidUdpChecksum);
    }
    if udp.src_port() == 0 || udp.dst_port() == 0 {
        return Err(Ipv4UdpDatagramError::ZeroPort);
    }
    Ok(Ipv4UdpDatagram {
        source: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.src_addr().octets())),
            udp.src_port(),
        ),
        destination: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.dst_addr().octets())),
            udp.dst_port(),
        ),
    })
}
