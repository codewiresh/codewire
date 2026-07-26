//! Minimal STUN binding client.
//!
//! The Rust tailnet only needs RFC5389 Binding Request/Success with
//! MAPPED-ADDRESS or XOR-MAPPED-ADDRESS. It deliberately avoids broader ICE or
//! TURN machinery.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;
const TRANSACTION_ID_LEN: usize = 12;
const MAX_STUN_PACKET: usize = 1500;
const SOFTWARE: &[u8] = b"tailnode";
const FINGERPRINT_XOR: u32 = 0x5354_554e;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("send STUN binding request to {server}: {source}")]
    Send {
        server: SocketAddr,
        source: std::io::Error,
    },
    #[error("receive STUN binding response from {server}: {source}")]
    Receive {
        server: SocketAddr,
        source: std::io::Error,
    },
    #[error("STUN binding request to {server} timed out")]
    Timeout { server: SocketAddr },
    #[error("invalid STUN response: {0}")]
    Invalid(&'static str),
}

/// Query multiple STUN servers through `socket` and return every mapped
/// endpoint that responds before `per_server_timeout`.
pub async fn discover_mapped_addrs(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    per_server_timeout: Duration,
) -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for server in servers {
        if let Ok(addr) = discover_mapped_addr(socket, *server, per_server_timeout).await {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
    }
    addrs
}

/// A STUN Binding Request packet and its transaction ID.
#[derive(Clone, Debug)]
pub struct BindingRequest {
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    pub packet: Vec<u8>,
}

impl BindingRequest {
    pub fn new() -> Self {
        let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
        OsRng.fill_bytes(&mut transaction_id);
        Self::with_transaction_id(transaction_id)
    }

    fn with_transaction_id(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self {
            transaction_id,
            packet: binding_request(transaction_id),
        }
    }
}

impl Default for BindingRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Send one STUN Binding Request through `socket`.
pub async fn discover_mapped_addr(
    socket: &UdpSocket,
    server: SocketAddr,
    request_timeout: Duration,
) -> Result<SocketAddr, Error> {
    let request = BindingRequest::new();
    socket
        .send_to(&request.packet, server)
        .await
        .map_err(|source| Error::Send { server, source })?;

    let mut buf = [0u8; MAX_STUN_PACKET];
    loop {
        let received = timeout(request_timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| Error::Timeout { server })?
            .map_err(|source| Error::Receive { server, source })?;
        let (n, source) = received;
        if source != server {
            continue;
        }
        match parse_binding_response(&buf[..n], request.transaction_id) {
            Ok(addr) => return Ok(addr),
            Err(Error::Invalid("transaction id mismatch")) => continue,
            Err(err) => return Err(err),
        }
    }
}

fn binding_request(tx_id: [u8; TRANSACTION_ID_LEN]) -> Vec<u8> {
    let software_attr_len = 4 + SOFTWARE.len();
    let fingerprint_attr_len = 8;
    let message_len = software_attr_len + fingerprint_attr_len;
    let mut out = Vec::with_capacity(HEADER_LEN + message_len);
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&(message_len as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&tx_id);

    out.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    out.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    out.extend_from_slice(SOFTWARE);

    let fingerprint = fingerprint(&out);
    out.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    out.extend_from_slice(&(4u16).to_be_bytes());
    out.extend_from_slice(&fingerprint.to_be_bytes());
    out
}

fn fingerprint(packet_without_fingerprint: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(packet_without_fingerprint);
    hasher.finalize() ^ FINGERPRINT_XOR
}

pub(crate) fn parse_binding_response(
    packet: &[u8],
    tx_id: [u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, Error> {
    if packet.len() < HEADER_LEN {
        return Err(Error::Invalid("packet too short"));
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != BINDING_SUCCESS {
        return Err(Error::Invalid("not a binding success response"));
    }
    if u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != MAGIC_COOKIE {
        return Err(Error::Invalid("bad magic cookie"));
    }
    if packet[8..20] != tx_id {
        return Err(Error::Invalid("transaction id mismatch"));
    }

    let message_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if HEADER_LEN + message_len > packet.len() {
        return Err(Error::Invalid("declared length exceeds packet"));
    }

    let mut cursor = HEADER_LEN;
    let end = HEADER_LEN + message_len;
    while cursor + 4 <= end {
        let attr_type = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let attr_len = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + attr_len > end {
            return Err(Error::Invalid("attribute length exceeds packet"));
        }
        let attr = &packet[cursor..cursor + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => return parse_xor_mapped_address(attr, tx_id),
            ATTR_MAPPED_ADDRESS => return parse_mapped_address(attr),
            _ => {}
        }
        cursor += attr_len + ((4 - (attr_len % 4)) % 4);
    }

    Err(Error::Invalid("missing mapped address"))
}

fn parse_xor_mapped_address(
    attr: &[u8],
    tx_id: [u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, Error> {
    if attr.len() < 4 || attr[0] != 0 {
        return Err(Error::Invalid("bad xor mapped address"));
    }
    let xport = u16::from_be_bytes([attr[2], attr[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match attr[1] {
        0x01 if attr.len() >= 8 => {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                attr[4] ^ cookie[0],
                attr[5] ^ cookie[1],
                attr[6] ^ cookie[2],
                attr[7] ^ cookie[3],
            );
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if attr.len() >= 20 => {
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&tx_id);
            let mut ip = [0u8; 16];
            for i in 0..16 {
                ip[i] = attr[4 + i] ^ mask[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => Err(Error::Invalid("unsupported xor mapped address family")),
    }
}

fn parse_mapped_address(attr: &[u8]) -> Result<SocketAddr, Error> {
    if attr.len() < 4 || attr[0] != 0 {
        return Err(Error::Invalid("bad mapped address"));
    }
    let port = u16::from_be_bytes([attr[2], attr[3]]);
    match attr[1] {
        0x01 if attr.len() >= 8 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(attr[4], attr[5], attr[6], attr[7])),
            port,
        )),
        0x02 if attr.len() >= 20 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&attr[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => Err(Error::Invalid("unsupported mapped address family")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_mapped_response(tx_id: [u8; TRANSACTION_ID_LEN], mapped: SocketAddr) -> Vec<u8> {
        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        match mapped {
            SocketAddr::V4(addr) => {
                attr.extend_from_slice(&(8u16).to_be_bytes());
                attr.push(0);
                attr.push(0x01);
                attr.extend_from_slice(
                    &(addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
                );
                let cookie = MAGIC_COOKIE.to_be_bytes();
                let ip = addr.ip().octets();
                attr.extend(ip.iter().zip(cookie).map(|(a, b)| a ^ b));
            }
            SocketAddr::V6(addr) => {
                attr.extend_from_slice(&(20u16).to_be_bytes());
                attr.push(0);
                attr.push(0x02);
                attr.extend_from_slice(
                    &(addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
                );
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&tx_id);
                let ip = addr.ip().octets();
                attr.extend(ip.iter().zip(mask).map(|(a, b)| a ^ b));
            }
        }

        let mut packet = Vec::with_capacity(HEADER_LEN + attr.len());
        packet.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(&tx_id);
        packet.extend_from_slice(&attr);
        packet
    }

    #[test]
    fn binding_request_matches_tailscale_wire_shape() {
        let request = BindingRequest::with_transaction_id(*b"abcdefghijkl");

        assert_eq!(
            request.packet,
            vec![
                0x00, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, b'a', b'b', b'c', b'd', b'e', b'f',
                b'g', b'h', b'i', b'j', b'k', b'l', 0x80, 0x22, 0x00, 0x08, b't', b'a', b'i', b'l',
                b'n', b'o', b'd', b'e', 0x80, 0x28, 0x00, 0x04, 0x64, 0x06, 0x97, 0x29,
            ]
        );
    }

    #[test]
    fn parses_xor_mapped_ipv4_response() {
        let tx_id = *b"abcdefghijkl";
        let mapped = "203.0.113.10:45678".parse::<SocketAddr>().unwrap();
        let packet = xor_mapped_response(tx_id, mapped);
        assert_eq!(parse_binding_response(&packet, tx_id).unwrap(), mapped);
    }

    #[test]
    fn parses_xor_mapped_ipv6_response() {
        let tx_id = *b"abcdefghijkl";
        let mapped = "[2001:db8::42]:45678".parse::<SocketAddr>().unwrap();
        let packet = xor_mapped_response(tx_id, mapped);
        assert_eq!(parse_binding_response(&packet, tx_id).unwrap(), mapped);
    }

    #[tokio::test]
    async fn discovers_mapped_addr_through_udp_socket() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let mapped = "203.0.113.10:45678".parse::<SocketAddr>().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_STUN_PACKET];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), BINDING_REQUEST);
            assert_eq!(n, HEADER_LEN + 20);
            let mut tx_id = [0u8; TRANSACTION_ID_LEN];
            tx_id.copy_from_slice(&buf[8..20]);
            let response = xor_mapped_response(tx_id, mapped);
            server.send_to(&response, peer).await.unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let got = discover_mapped_addr(&client, server_addr, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(got, mapped);
    }

    #[tokio::test]
    #[ignore = "live dev-infra probe; set CODEWIRE_TAILNET_STUN_SERVER or use the dev default"]
    async fn live_tailscale_stun_server_discovers_mapped_addr() {
        let server = std::env::var("CODEWIRE_TAILNET_STUN_SERVER")
            .unwrap_or_else(|_| "stun.codewire-dev.sh:3478".to_string());
        let mut addrs = tokio::net::lookup_host(&server)
            .await
            .unwrap_or_else(|err| panic!("resolve {server}: {err}"));
        let server_addr = addrs
            .next()
            .unwrap_or_else(|| panic!("resolve {server}: no addresses"));
        let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        let got = discover_mapped_addr(&client, server_addr, Duration::from_secs(2))
            .await
            .unwrap_or_else(|err| panic!("discover mapped address through {server_addr}: {err}"));

        assert!(
            is_public_addr(got.ip()),
            "mapped address must be public: {got}"
        );
    }

    fn is_public_addr(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                !(ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || ip.is_unspecified())
            }
            IpAddr::V6(ip) => {
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local())
            }
        }
    }
}
