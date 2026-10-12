//! Strict DNS-only IPv4/UDP boundary for a userspace network worker.
//!
//! This module does not resolve names or open sockets. It accepts only one
//! canonical, unfragmented DNS question sent to the caller-selected virtual
//! resolver address, surfaces bounded policy metadata, and builds a bounded
//! reply from an already-authorized answer. A query may carry one EDNS OPT
//! record, which is ignored. All other UDP stays outside the admitted
//! interface.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket};

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_MESSAGE_LEN: usize = 4096;

/// DNS record families admitted by the local boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Aaaa,
}

impl DnsRecordType {
    fn wire(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// Policy metadata extracted from one bounded DNS question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub id: u16,
    pub source: SocketAddr,
    pub server: SocketAddr,
    pub name: String,
    pub record_type: DnsRecordType,
    recursion_desired: bool,
}

/// An answer supplied by an injected resolver or policy broker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsAnswer {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    NoData,
    NameError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsBoundaryError {
    InvalidLimit,
    InvalidIpv4,
    NonCanonicalIpv4Length,
    Ipv4Options,
    InvalidIpv4Checksum,
    FragmentedIpv4,
    NotUdp,
    WrongResolver,
    InvalidUdp,
    InvalidUdpChecksum,
    InvalidDnsHeader,
    UnsupportedDnsShape,
    InvalidDnsName,
    UnsupportedRecordType,
    AnswerTypeMismatch,
    ResponseTooLarge,
}

impl fmt::Display for DnsBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimit => "DNS message limit is invalid",
            Self::InvalidIpv4 => "DNS packet is not valid IPv4",
            Self::NonCanonicalIpv4Length => "DNS IPv4 length is not canonical",
            Self::Ipv4Options => "DNS IPv4 options are not accepted",
            Self::InvalidIpv4Checksum => "DNS IPv4 checksum is invalid",
            Self::FragmentedIpv4 => "fragmented DNS IPv4 is not accepted",
            Self::NotUdp => "packet is not UDP",
            Self::WrongResolver => "UDP packet is not for the selected virtual resolver",
            Self::InvalidUdp => "UDP datagram is malformed",
            Self::InvalidUdpChecksum => "UDP checksum is missing or invalid",
            Self::InvalidDnsHeader => "DNS header is malformed",
            Self::UnsupportedDnsShape => "DNS message shape is not admitted",
            Self::InvalidDnsName => "DNS question name is invalid",
            Self::UnsupportedRecordType => "DNS record type is not admitted",
            Self::AnswerTypeMismatch => "DNS answer does not match the question type",
            Self::ResponseTooLarge => "DNS response exceeds its packet bound",
        })
    }
}

impl std::error::Error for DnsBoundaryError {}

/// Parse one strict IPv4/UDP DNS question without admitting general UDP.
pub fn parse_ipv4_dns_question(
    packet: &[u8],
    expected_server: Ipv4Addr,
    max_dns_message_len: usize,
) -> Result<DnsQuestion, DnsBoundaryError> {
    if !(DNS_HEADER_LEN + 5..=MAX_DNS_MESSAGE_LEN).contains(&max_dns_message_len) {
        return Err(DnsBoundaryError::InvalidLimit);
    }
    let ipv4 = Ipv4Packet::new_checked(packet).map_err(|_| DnsBoundaryError::InvalidIpv4)?;
    if usize::from(ipv4.total_len()) != packet.len() {
        return Err(DnsBoundaryError::NonCanonicalIpv4Length);
    }
    if usize::from(ipv4.header_len()) != IPV4_HEADER_LEN {
        return Err(DnsBoundaryError::Ipv4Options);
    }
    if !ipv4.verify_checksum() {
        return Err(DnsBoundaryError::InvalidIpv4Checksum);
    }
    if ipv4.more_frags() || ipv4.frag_offset() != 0 {
        return Err(DnsBoundaryError::FragmentedIpv4);
    }
    if ipv4.next_header() != IpProtocol::Udp {
        return Err(DnsBoundaryError::NotUdp);
    }
    if ipv4.dst_addr().octets() != expected_server.octets() {
        return Err(DnsBoundaryError::WrongResolver);
    }

    let udp = UdpPacket::new_checked(ipv4.payload()).map_err(|_| DnsBoundaryError::InvalidUdp)?;
    if usize::from(udp.len()) != ipv4.payload().len() || udp.src_port() == 0 {
        return Err(DnsBoundaryError::InvalidUdp);
    }
    if udp.dst_port() != DNS_PORT {
        return Err(DnsBoundaryError::WrongResolver);
    }
    let source_ip = IpAddress::Ipv4(ipv4.src_addr());
    let server_ip = IpAddress::Ipv4(ipv4.dst_addr());
    if udp.checksum() == 0 || !udp.verify_checksum(&source_ip, &server_ip) {
        return Err(DnsBoundaryError::InvalidUdpChecksum);
    }
    let dns = udp.payload();
    if dns.len() > max_dns_message_len || dns.len() < DNS_HEADER_LEN {
        return Err(DnsBoundaryError::InvalidDnsHeader);
    }

    let id = u16::from_be_bytes([dns[0], dns[1]]);
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    let ancount = u16::from_be_bytes([dns[6], dns[7]]);
    let nscount = u16::from_be_bytes([dns[8], dns[9]]);
    let arcount = u16::from_be_bytes([dns[10], dns[11]]);
    // Admit only a standard single-question query. RD, AD and CD are the only
    // request flags admitted; compressed names are intentionally a later,
    // separately bounded extension. AD in a query only says the client
    // understands AD in a reply (RFC 6840 5.7); musl's res_mkquery sets it,
    // so BusyBox nslookup sends it. Replies never set AD.
    if flags & !(0x0100 | 0x0020 | 0x0010) != 0
        || qdcount != 1
        || ancount != 0
        || nscount != 0
        || arcount > 1
    {
        return Err(DnsBoundaryError::UnsupportedDnsShape);
    }

    let (name, cursor) = parse_qname(dns, DNS_HEADER_LEN)?;
    let additional = cursor
        .checked_add(4)
        .and_then(|end| dns.get(end..))
        .ok_or(DnsBoundaryError::UnsupportedDnsShape)?;
    // The only additional record admitted is one EDNS OPT, which Go's resolver
    // and dig send with every query. Nothing in it is read, kept or forwarded:
    // not its payload size, DO bit, version or options. Replies never carry
    // one, so the client sees a resolver without EDNS.
    let admitted = match arcount {
        0 => additional.is_empty(),
        _ => is_edns_opt(additional),
    };
    if !admitted {
        return Err(DnsBoundaryError::UnsupportedDnsShape);
    }
    let record_type = match u16::from_be_bytes([dns[cursor], dns[cursor + 1]]) {
        1 => DnsRecordType::A,
        28 => DnsRecordType::Aaaa,
        _ => return Err(DnsBoundaryError::UnsupportedRecordType),
    };
    if u16::from_be_bytes([dns[cursor + 2], dns[cursor + 3]]) != 1 {
        return Err(DnsBoundaryError::UnsupportedRecordType);
    }

    Ok(DnsQuestion {
        id,
        source: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(ipv4.src_addr().octets())),
            udp.src_port(),
        ),
        server: SocketAddr::new(IpAddr::V4(expected_server), DNS_PORT),
        name,
        record_type,
        recursion_desired: flags & 0x0100 != 0,
    })
}

/// Build one bounded IPv4/UDP DNS reply from an already-authorized answer.
pub fn build_ipv4_dns_response(
    question: &DnsQuestion,
    answer: DnsAnswer,
    ttl_seconds: u32,
    mtu: usize,
) -> Result<Vec<u8>, DnsBoundaryError> {
    let server_ip = match question.server.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(DnsBoundaryError::WrongResolver),
    };
    let source_ip = match question.source.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(DnsBoundaryError::InvalidIpv4),
    };
    let mut answer_storage = [0u8; 16];
    let answer_len = match (&question.record_type, &answer) {
        (DnsRecordType::A, DnsAnswer::Ipv4(ip)) => {
            answer_storage[..4].copy_from_slice(&ip.octets());
            Some(4)
        }
        (DnsRecordType::Aaaa, DnsAnswer::Ipv6(ip)) => {
            answer_storage.copy_from_slice(&ip.octets());
            Some(16)
        }
        (_, DnsAnswer::NoData | DnsAnswer::NameError) => None,
        _ => return Err(DnsBoundaryError::AnswerTypeMismatch),
    };

    let mut dns = Vec::with_capacity(64 + question.name.len());
    dns.extend_from_slice(&question.id.to_be_bytes());
    let mut flags: u16 = 0x8000 | 0x0080;
    if question.recursion_desired {
        flags |= 0x0100;
    }
    if matches!(answer, DnsAnswer::NameError) {
        flags |= 3;
    }
    dns.extend_from_slice(&flags.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&u16::from(answer_len.is_some()).to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes());
    encode_qname(&question.name, &mut dns)?;
    dns.extend_from_slice(&question.record_type.wire().to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    if let Some(answer_len) = answer_len {
        let rdata = &answer_storage[..answer_len];
        dns.extend_from_slice(&0xc00cu16.to_be_bytes());
        dns.extend_from_slice(&question.record_type.wire().to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&ttl_seconds.to_be_bytes());
        dns.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        dns.extend_from_slice(rdata);
    }

    let packet_len = IPV4_HEADER_LEN
        .checked_add(UDP_HEADER_LEN)
        .and_then(|length| length.checked_add(dns.len()))
        .ok_or(DnsBoundaryError::ResponseTooLarge)?;
    if packet_len > mtu || packet_len > u16::MAX as usize {
        return Err(DnsBoundaryError::ResponseTooLarge);
    }
    let udp_len = UDP_HEADER_LEN + dns.len();
    let mut packet = vec![0u8; packet_len];
    {
        let mut udp = UdpPacket::new_unchecked(&mut packet[IPV4_HEADER_LEN..]);
        udp.set_src_port(DNS_PORT);
        udp.set_dst_port(question.source.port());
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(&dns);
        udp.fill_checksum(
            &IpAddress::Ipv4(Ipv4Address::from_octets(server_ip.octets())),
            &IpAddress::Ipv4(Ipv4Address::from_octets(source_ip.octets())),
        );
    }
    {
        let mut ipv4 = Ipv4Packet::new_unchecked(packet.as_mut_slice());
        ipv4.set_version(4);
        ipv4.set_header_len(IPV4_HEADER_LEN as u8);
        ipv4.set_total_len(packet_len as u16);
        ipv4.set_ident(question.id);
        ipv4.set_dont_frag(true);
        ipv4.set_hop_limit(64);
        ipv4.set_next_header(IpProtocol::Udp);
        ipv4.set_src_addr(Ipv4Address::from_octets(server_ip.octets()));
        ipv4.set_dst_addr(Ipv4Address::from_octets(source_ip.octets()));
        ipv4.fill_checksum();
    }
    Ok(packet)
}

/// Whether `additional` is exactly one EDNS OPT pseudo-record (RFC 6891): the
/// root name as a single zero byte, type 41, and a data length that ends the
/// message. The data length is only compared, and nothing else is read.
fn is_edns_opt(additional: &[u8]) -> bool {
    const OPT_TYPE: u16 = 41;
    // Root name, type, class, TTL and data length.
    const OPT_FIXED_LEN: usize = 1 + 2 + 2 + 4 + 2;
    additional.len() >= OPT_FIXED_LEN
        && additional[0] == 0
        && u16::from_be_bytes([additional[1], additional[2]]) == OPT_TYPE
        && usize::from(u16::from_be_bytes([additional[9], additional[10]]))
            == additional.len() - OPT_FIXED_LEN
}

fn parse_qname(dns: &[u8], mut cursor: usize) -> Result<(String, usize), DnsBoundaryError> {
    let mut name = String::new();
    loop {
        let length = *dns.get(cursor).ok_or(DnsBoundaryError::InvalidDnsName)? as usize;
        cursor += 1;
        if length == 0 {
            break;
        }
        if length > 63 || cursor.checked_add(length).is_none_or(|end| end > dns.len()) {
            return Err(DnsBoundaryError::InvalidDnsName);
        }
        let label = &dns[cursor..cursor + length];
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DnsBoundaryError::InvalidDnsName);
        }
        if !name.is_empty() {
            name.push('.');
        }
        for byte in label {
            name.push(byte.to_ascii_lowercase() as char);
        }
        if name.len() > MAX_DNS_NAME_LEN {
            return Err(DnsBoundaryError::InvalidDnsName);
        }
        cursor += length;
    }
    if name.is_empty() {
        return Err(DnsBoundaryError::InvalidDnsName);
    }
    Ok((name, cursor))
}

fn encode_qname(name: &str, output: &mut Vec<u8>) -> Result<(), DnsBoundaryError> {
    if name.len() > MAX_DNS_NAME_LEN {
        return Err(DnsBoundaryError::InvalidDnsName);
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(DnsBoundaryError::InvalidDnsName);
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUEST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn dns_query(name: &str) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&0x1234u16.to_be_bytes());
        dns.extend_from_slice(&0x0100u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        dns.extend_from_slice(&0u16.to_be_bytes());
        encode_qname(name, &mut dns).expect("test DNS name");
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes());
        dns
    }

    fn query_packet(destination_port: u16, dns: &[u8]) -> Vec<u8> {
        let packet_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + dns.len();
        let mut packet = vec![0; packet_len];
        {
            let mut udp = UdpPacket::new_unchecked(&mut packet[IPV4_HEADER_LEN..]);
            udp.set_src_port(53000);
            udp.set_dst_port(destination_port);
            udp.set_len((UDP_HEADER_LEN + dns.len()) as u16);
            udp.payload_mut().copy_from_slice(dns);
            udp.fill_checksum(
                &IpAddress::Ipv4(Ipv4Address::from_octets(GUEST.octets())),
                &IpAddress::Ipv4(Ipv4Address::from_octets(RESOLVER.octets())),
            );
        }
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(packet.as_mut_slice());
            ipv4.set_version(4);
            ipv4.set_header_len(IPV4_HEADER_LEN as u8);
            ipv4.set_total_len(packet_len as u16);
            ipv4.set_ident(7);
            ipv4.set_dont_frag(true);
            ipv4.set_hop_limit(64);
            ipv4.set_next_header(IpProtocol::Udp);
            ipv4.set_src_addr(Ipv4Address::from_octets(GUEST.octets()));
            ipv4.set_dst_addr(Ipv4Address::from_octets(RESOLVER.octets()));
            ipv4.fill_checksum();
        }
        packet
    }

    #[test]
    fn strict_question_and_bounded_answer_round_trip() {
        let packet = query_packet(DNS_PORT, &dns_query("Example.COM"));
        let question =
            parse_ipv4_dns_question(&packet, RESOLVER, 1232).expect("strict DNS question");
        assert_eq!(question.id, 0x1234);
        assert_eq!(question.name, "example.com");
        assert_eq!(question.record_type, DnsRecordType::A);
        assert_eq!(question.source, SocketAddr::new(IpAddr::V4(GUEST), 53000));
        assert_eq!(question.server, SocketAddr::new(IpAddr::V4(RESOLVER), 53));

        let answer_ip = Ipv4Addr::new(203, 0, 113, 44);
        let response = build_ipv4_dns_response(&question, DnsAnswer::Ipv4(answer_ip), 30, 1500)
            .expect("bounded DNS response");
        let ipv4 = Ipv4Packet::new_checked(response.as_slice()).expect("response IPv4");
        assert!(ipv4.verify_checksum());
        assert_eq!(ipv4.src_addr().octets(), RESOLVER.octets());
        assert_eq!(ipv4.dst_addr().octets(), GUEST.octets());
        let udp = UdpPacket::new_checked(ipv4.payload()).expect("response UDP");
        assert!(udp.verify_checksum(
            &IpAddress::Ipv4(ipv4.src_addr()),
            &IpAddress::Ipv4(ipv4.dst_addr())
        ));
        assert_eq!(udp.src_port(), DNS_PORT);
        assert_eq!(udp.dst_port(), 53000);
        assert_eq!(
            &udp.payload()[udp.payload().len() - 4..],
            &answer_ip.octets()
        );
    }

    /// musl's res_mkquery, and so BusyBox nslookup, sets AD in its queries.
    #[test]
    fn authentic_data_query_bit_is_admitted_and_never_answered() {
        let mut dns = dns_query("example.com");
        dns[3] |= 0x20;
        let question = parse_ipv4_dns_question(&query_packet(DNS_PORT, &dns), RESOLVER, 1232)
            .expect("query with AD");
        assert!(question.recursion_desired);
        let response = build_ipv4_dns_response(
            &question,
            DnsAnswer::Ipv4(Ipv4Addr::new(203, 0, 113, 44)),
            30,
            1500,
        )
        .unwrap();
        let ipv4 = Ipv4Packet::new_checked(response.as_slice()).unwrap();
        let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(&udp.payload()[..4], &[0x12, 0x34, 0x81, 0x80]);

        let mut truncated = dns_query("example.com");
        truncated[2] |= 0x02;
        assert_eq!(
            parse_ipv4_dns_question(&query_packet(DNS_PORT, &truncated), RESOLVER, 1232),
            Err(DnsBoundaryError::UnsupportedDnsShape)
        );
    }

    #[test]
    fn arbitrary_udp_fragments_compression_and_oversize_fail_closed() {
        let dns = dns_query("example.com");
        assert_eq!(
            parse_ipv4_dns_question(&query_packet(54, &dns), RESOLVER, 1232),
            Err(DnsBoundaryError::WrongResolver)
        );

        let mut fragmented = query_packet(DNS_PORT, &dns);
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(fragmented.as_mut_slice());
            ipv4.set_more_frags(true);
            ipv4.fill_checksum();
        }
        assert_eq!(
            parse_ipv4_dns_question(&fragmented, RESOLVER, 1232),
            Err(DnsBoundaryError::FragmentedIpv4)
        );

        let mut compressed = dns_query("example.com");
        compressed[DNS_HEADER_LEN] = 0xc0;
        compressed[DNS_HEADER_LEN + 1] = 0x0c;
        assert_eq!(
            parse_ipv4_dns_question(&query_packet(DNS_PORT, &compressed), RESOLVER, 1232),
            Err(DnsBoundaryError::InvalidDnsName)
        );

        let question =
            parse_ipv4_dns_question(&query_packet(DNS_PORT, &dns), RESOLVER, 1232).unwrap();
        assert_eq!(
            build_ipv4_dns_response(&question, DnsAnswer::Ipv6(Ipv6Addr::LOCALHOST), 30, 1500),
            Err(DnsBoundaryError::AnswerTypeMismatch)
        );
        assert_eq!(
            build_ipv4_dns_response(&question, DnsAnswer::Ipv4(Ipv4Addr::LOCALHOST), 30, 32),
            Err(DnsBoundaryError::ResponseTooLarge)
        );
    }

    /// An OPT record: `name`, type, class (the payload size), TTL (the
    /// extended code, version and flags), then the options.
    fn opt_record(name: &[u8], record_type: u16, class: u16, ttl: u32, options: &[u8]) -> Vec<u8> {
        let mut record = name.to_vec();
        record.extend_from_slice(&record_type.to_be_bytes());
        record.extend_from_slice(&class.to_be_bytes());
        record.extend_from_slice(&ttl.to_be_bytes());
        record.extend_from_slice(&(options.len() as u16).to_be_bytes());
        record.extend_from_slice(options);
        record
    }

    /// `dns_query` with `additional_count` in its header and `additional`
    /// after the question.
    fn dns_query_with(name: &str, additional_count: u16, additional: &[u8]) -> Vec<u8> {
        let mut dns = dns_query(name);
        dns[10..12].copy_from_slice(&additional_count.to_be_bytes());
        dns.extend_from_slice(additional);
        dns
    }

    fn parse(dns: &[u8]) -> Result<DnsQuestion, DnsBoundaryError> {
        parse_ipv4_dns_question(&query_packet(DNS_PORT, dns), RESOLVER, 1232)
    }

    /// Go's resolver and dig send an OPT record with every query.
    #[test]
    fn one_edns_opt_record_is_admitted_and_nothing_in_it_is_used() {
        let plain = parse(&dns_query("example.com")).expect("query without EDNS");
        let answer = DnsAnswer::Ipv4(Ipv4Addr::new(203, 0, 113, 44));
        let plain_reply = build_ipv4_dns_response(&plain, answer, 30, 1500).unwrap();

        // Go: a 1232-byte payload size and no options.
        let go = opt_record(&[0], 41, 1232, 0, &[]);
        // dig: a 4096-byte payload size, the DO bit, and a cookie option.
        let dig = opt_record(
            &[0],
            41,
            4096,
            0x0000_8000,
            &[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
        );
        // An unknown version, a client-subnet option and an unknown option.
        let other = opt_record(
            &[0],
            41,
            512,
            0x0001_0000,
            &[
                0, 8, 0, 7, 0, 1, 24, 0, 198, 51, 100, 0xff, 0xfe, 0, 1, 0x2a,
            ],
        );
        for additional in [go, dig, other] {
            let question = parse(&dns_query_with("example.com", 1, &additional))
                .expect("query with one OPT record");
            assert_eq!(question, plain);
            assert_eq!(
                build_ipv4_dns_response(&question, answer, 30, 1500).unwrap(),
                plain_reply
            );
        }
        // The reply to an EDNS query has no additional record.
        let ipv4 = Ipv4Packet::new_checked(plain_reply.as_slice()).unwrap();
        let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(&udp.payload()[10..12], &[0, 0]);
    }

    #[test]
    fn any_other_additional_section_is_dropped() {
        let opt = opt_record(&[0], 41, 1232, 0, &[]);
        let with_options = opt_record(&[0], 41, 1232, 0, &[0, 10, 0, 2, 7, 7]);
        let mut one_short = with_options.clone();
        one_short[10] -= 1;
        let mut one_long = with_options.clone();
        one_long[10] += 1;
        let mut trailing = opt.clone();
        trailing.push(0);
        // TSIG is type 250; its name here is the root.
        let tsig = opt_record(&[0], 250, 255, 0, &[]);
        let rejected: [(&str, u16, Vec<u8>); 13] = [
            ("a type other than OPT", 1, opt_record(&[0], 1, 1, 0, &[])),
            ("TSIG alone", 1, tsig.clone()),
            (
                "a name that is not the root",
                1,
                opt_record(&[3, b'c', b'o', b'm', 0], 41, 1232, 0, &[]),
            ),
            (
                "a compression pointer for a name",
                1,
                opt_record(&[0xc0, 0x0c], 41, 1232, 0, &[]),
            ),
            ("a data length one short", 1, one_short),
            ("a data length one long", 1, one_long),
            ("bytes after the OPT record", 1, trailing),
            (
                "two OPT records counted as one",
                1,
                [opt.clone(), opt.clone()].concat(),
            ),
            ("two OPT records", 2, [opt.clone(), opt.clone()].concat()),
            ("OPT then TSIG", 2, [opt.clone(), tsig.clone()].concat()),
            ("an OPT record that is not counted", 0, opt.clone()),
            ("a counted record that is absent", 1, Vec::new()),
            ("a truncated OPT record", 1, opt[..opt.len() - 1].to_vec()),
        ];
        for (case, count, additional) in rejected {
            assert_eq!(
                parse(&dns_query_with("example.com", count, &additional)),
                Err(DnsBoundaryError::UnsupportedDnsShape),
                "{case}"
            );
        }
        // Answer and authority records stay refused beside a valid OPT.
        for count_offset in [6, 8] {
            let mut dns = dns_query_with("example.com", 1, &opt);
            dns[count_offset + 1] = 1;
            assert_eq!(parse(&dns), Err(DnsBoundaryError::UnsupportedDnsShape));
        }
    }
}
