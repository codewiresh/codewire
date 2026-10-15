//! Tailscale-compatible discovery message framing.
//!
//! This module is the first direct-UDP parity primitive for #265. It mirrors
//! the subset of `tailscale.com/disco` that Codewire needs before the Rust
//! gateway can answer Go/Tailscale magicsock direct-path probes:
//!
//! ```text
//! wrapper = "TS💬" || sender_disco_pub[32] || nonce[24] || naclbox(message)
//! message = type[1] || version[1] || payload
//! ```
//!
//! The initial subset covered Ping, Pong, and CallMeMaybe. The UDP peer-relay
//! extension messages live here too, because they are part of Tailscale disco
//! rather than the gateway SSH/API layer.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SalsaBox, SecretKey,
};
use rand_core::{CryptoRng, RngCore};

use crate::node::{DiscoPublic, NodePublic, KEY_LEN};

/// Tailscale discovery magic: `TS💬`.
pub const MAGIC: &[u8] = b"TS\xf0\x9f\x92\xac";

/// Length of the NaCl box nonce in the disco wrapper.
pub const NONCE_LEN: usize = 24;

const HEADER_LEN: usize = 2;
const PONG_LEN: usize = 12 + 16 + 2;
const ENDPOINT_LEN: usize = 16 + 2;

const TYPE_PING: u8 = 0x01;
const TYPE_PONG: u8 = 0x02;
const TYPE_CALL_ME_MAYBE: u8 = 0x03;
const TYPE_BIND_UDP_RELAY_ENDPOINT: u8 = 0x04;
const TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE: u8 = 0x05;
const TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER: u8 = 0x06;
const TYPE_CALL_ME_MAYBE_VIA: u8 = 0x07;
const TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST: u8 = 0x08;
const TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE: u8 = 0x09;
const VERSION_0: u8 = 0;

const BIND_UDP_RELAY_CHALLENGE_LEN: usize = 32;
const BIND_UDP_RELAY_ENDPOINT_COMMON_LEN: usize = 4 + 4 + KEY_LEN + BIND_UDP_RELAY_CHALLENGE_LEN;
const ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN: usize = KEY_LEN * 2 + 4;
const UDP_RELAY_ENDPOINT_LEN_MINUS_ADDR_PORTS: usize = KEY_LEN + (KEY_LEN * 2) + 8 + 4 + 8 + 8;

/// Errors from disco frame parsing and crypto.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("short disco message")]
    Short,
    #[error("bad disco magic")]
    BadMagic,
    #[error("unknown disco message type 0x{0:02x}")]
    UnknownMessageType(u8),
    #[error("disco crypto: {0}")]
    Crypto(&'static str),
}

/// A disco private key.
#[derive(Clone)]
pub struct DiscoPrivate {
    secret: SecretKey,
}

impl DiscoPrivate {
    /// Generate a fresh disco private key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            secret: SecretKey::generate(rng),
        }
    }

    /// Build from the raw 32-byte scalar used by Tailscale's `key.DiscoPrivate`.
    pub fn from_raw(raw: [u8; KEY_LEN]) -> Self {
        Self {
            secret: SecretKey::from(raw),
        }
    }

    /// The public disco key.
    pub fn public(&self) -> DiscoPublic {
        DiscoPublic::from_raw(self.secret.public_key().to_bytes())
    }

    /// Seal a disco message to `peer`, returning a complete Tailscale disco
    /// wrapper with our public key in the sender field.
    pub fn seal_to<R: RngCore + CryptoRng>(
        &self,
        peer: &DiscoPublic,
        message: &Message,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let nonce = SalsaBox::generate_nonce(rng);
        self.seal_to_with_nonce(peer, message, nonce.as_slice().try_into().unwrap())
    }

    /// Deterministic variant for tests.
    pub fn seal_to_with_nonce(
        &self,
        peer: &DiscoPublic,
        message: &Message,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Vec<u8>, Error> {
        if peer.is_zero() {
            return Err(Error::Crypto("zero peer key"));
        }
        let box_ = SalsaBox::new(&PublicKey::from(*peer.as_bytes()), &self.secret);
        let ciphertext = box_
            .encrypt((&nonce).into(), message.marshal().as_slice())
            .map_err(|_| Error::Crypto("box seal failed"))?;

        let mut out = Vec::with_capacity(MAGIC.len() + KEY_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(self.public().as_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a complete disco wrapper addressed to this key.
    pub fn open(&self, packet: &[u8]) -> Result<OpenedMessage, Error> {
        let sender = source(packet).ok_or(Error::BadMagic)?;
        let sealed = packet.get(MAGIC.len() + KEY_LEN..).ok_or(Error::Short)?;
        if sealed.len() < NONCE_LEN {
            return Err(Error::Short);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let box_ = SalsaBox::new(&PublicKey::from(*sender.as_bytes()), &self.secret);
        let payload = box_
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| Error::Crypto("box open failed"))?;
        let message = Message::parse(&payload)?;
        Ok(OpenedMessage { sender, message })
    }
}

/// A decrypted disco message with its authenticated sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedMessage {
    pub sender: DiscoPublic,
    pub message: Message,
}

/// Does `packet` look like a Tailscale disco wrapper?
pub fn looks_like_wrapper(packet: &[u8]) -> bool {
    packet.len() >= MAGIC.len() + KEY_LEN + NONCE_LEN && packet.starts_with(MAGIC)
}

/// Extract the sender disco public key from a wrapper-looking packet.
pub fn source(packet: &[u8]) -> Option<DiscoPublic> {
    if !looks_like_wrapper(packet) {
        return None;
    }
    let start = MAGIC.len();
    let end = start + KEY_LEN;
    let raw: [u8; KEY_LEN] = packet[start..end].try_into().ok()?;
    Some(DiscoPublic::from_raw(raw))
}

/// Tailscale disco message subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Ping(Ping),
    Pong(Pong),
    CallMeMaybe(CallMeMaybe),
    BindUDPRelayEndpoint(BindUDPRelayEndpoint),
    BindUDPRelayEndpointChallenge(BindUDPRelayEndpointChallenge),
    BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer),
    CallMeMaybeVia(CallMeMaybeVia),
    AllocateUDPRelayEndpointRequest(AllocateUDPRelayEndpointRequest),
    AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse),
}

impl Message {
    /// Marshal the inner plaintext message.
    pub fn marshal(&self) -> Vec<u8> {
        match self {
            Self::Ping(m) => m.marshal(),
            Self::Pong(m) => m.marshal(),
            Self::CallMeMaybe(m) => m.marshal(),
            Self::BindUDPRelayEndpoint(m) => m.marshal(),
            Self::BindUDPRelayEndpointChallenge(m) => m.marshal(),
            Self::BindUDPRelayEndpointAnswer(m) => m.marshal(),
            Self::CallMeMaybeVia(m) => m.marshal(),
            Self::AllocateUDPRelayEndpointRequest(m) => m.marshal(),
            Self::AllocateUDPRelayEndpointResponse(m) => m.marshal(),
        }
    }

    /// Parse the inner plaintext message.
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() < HEADER_LEN {
            return Err(Error::Short);
        }
        let typ = payload[0];
        let version = payload[1];
        let body = &payload[HEADER_LEN..];
        match typ {
            TYPE_PING => Ok(Self::Ping(Ping::parse(body)?)),
            TYPE_PONG => Ok(Self::Pong(Pong::parse(body)?)),
            TYPE_CALL_ME_MAYBE => Ok(Self::CallMeMaybe(CallMeMaybe::parse(version, body))),
            TYPE_BIND_UDP_RELAY_ENDPOINT => Ok(Self::BindUDPRelayEndpoint(
                BindUDPRelayEndpoint::parse(body)?,
            )),
            TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE => Ok(Self::BindUDPRelayEndpointChallenge(
                BindUDPRelayEndpointChallenge::parse(body)?,
            )),
            TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER => Ok(Self::BindUDPRelayEndpointAnswer(
                BindUDPRelayEndpointAnswer::parse(body)?,
            )),
            TYPE_CALL_ME_MAYBE_VIA => {
                Ok(Self::CallMeMaybeVia(CallMeMaybeVia::parse(version, body)?))
            }
            TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST => Ok(Self::AllocateUDPRelayEndpointRequest(
                AllocateUDPRelayEndpointRequest::parse(version, body)?,
            )),
            TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE => {
                Ok(Self::AllocateUDPRelayEndpointResponse(
                    AllocateUDPRelayEndpointResponse::parse(version, body)?,
                ))
            }
            other => Err(Error::UnknownMessageType(other)),
        }
    }
}

/// Disco ping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ping {
    /// Random 12-byte transaction ID.
    pub tx_id: [u8; 12],
    /// Optional sender WireGuard node key.
    pub node_key: Option<NodePublic>,
    /// Number of zero padding bytes.
    pub padding: usize,
}

impl Ping {
    fn marshal(&self) -> Vec<u8> {
        let has_node_key = self.node_key.as_ref().is_some_and(|k| !k.is_zero());
        let len = 12 + if has_node_key { KEY_LEN } else { 0 } + self.padding;
        let mut out = message_with_header(TYPE_PING, len);
        out.extend_from_slice(&self.tx_id);
        if let Some(node_key) = self.node_key.as_ref().filter(|k| !k.is_zero()) {
            out.extend_from_slice(node_key.as_bytes());
        }
        out.resize(out.len() + self.padding, 0);
        out
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < 12 {
            return Err(Error::Short);
        }
        let mut tx_id = [0u8; 12];
        tx_id.copy_from_slice(&body[..12]);
        let rest = &body[12..];
        let (node_key, padding) = if rest.len() >= KEY_LEN {
            let raw: [u8; KEY_LEN] = rest[..KEY_LEN].try_into().unwrap();
            (Some(NodePublic::from_raw(raw)), rest.len() - KEY_LEN)
        } else {
            (None, rest.len())
        };
        Ok(Self {
            tx_id,
            node_key,
            padding,
        })
    }
}

/// Disco pong. The `src` field is the observed source address for the ping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pong {
    pub tx_id: [u8; 12],
    pub src: SocketAddr,
}

impl Pong {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(TYPE_PONG, PONG_LEN);
        out.extend_from_slice(&self.tx_id);
        out.extend_from_slice(&socket_addr_ip16(self.src));
        out.extend_from_slice(&self.src.port().to_be_bytes());
        out
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < PONG_LEN {
            return Err(Error::Short);
        }
        let mut tx_id = [0u8; 12];
        tx_id.copy_from_slice(&body[..12]);
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&body[12..28]);
        let port = u16::from_be_bytes(body[28..30].try_into().unwrap());
        Ok(Self {
            tx_id,
            src: SocketAddr::new(ip_from_16(ip), port),
        })
    }
}

/// Request sent over DERP asking a peer to try the supplied endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallMeMaybe {
    pub endpoints: Vec<SocketAddr>,
}

impl CallMeMaybe {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(TYPE_CALL_ME_MAYBE, ENDPOINT_LEN * self.endpoints.len());
        for endpoint in &self.endpoints {
            out.extend_from_slice(&socket_addr_ip16(*endpoint));
            out.extend_from_slice(&endpoint.port().to_be_bytes());
        }
        out
    }

    fn parse(version: u8, body: &[u8]) -> Self {
        if version != VERSION_0 || body.is_empty() || !body.len().is_multiple_of(ENDPOINT_LEN) {
            return Self {
                endpoints: Vec::new(),
            };
        }
        let mut endpoints = Vec::with_capacity(body.len() / ENDPOINT_LEN);
        for chunk in body.as_chunks::<ENDPOINT_LEN>().0 {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&chunk[..16]);
            let port = u16::from_be_bytes(chunk[16..18].try_into().unwrap());
            endpoints.push(SocketAddr::new(ip_from_16(ip), port));
        }
        Self { endpoints }
    }
}

/// Common payload shared by the UDP relay bind handshake messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindUDPRelayEndpointCommon {
    /// Geneve virtual network identifier. This must match the cleartext
    /// Geneve header carried by relayed packets.
    pub vni: u32,
    /// Nonzero client-generated handshake generation.
    pub generation: u32,
    /// The other client's disco key for this relay endpoint.
    pub remote_key: DiscoPublic,
    /// Server challenge for challenge/answer messages. In the first bind
    /// message this is padding, matching Tailscale's fixed-size payload.
    pub challenge: [u8; BIND_UDP_RELAY_CHALLENGE_LEN],
}

impl BindUDPRelayEndpointCommon {
    fn marshal_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.vni.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(self.remote_key.as_bytes());
        out.extend_from_slice(&self.challenge);
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < BIND_UDP_RELAY_ENDPOINT_COMMON_LEN {
            return Err(Error::Short);
        }
        let vni = u32::from_be_bytes(body[0..4].try_into().unwrap());
        let generation = u32::from_be_bytes(body[4..8].try_into().unwrap());
        let remote_key = DiscoPublic::from_raw(body[8..8 + KEY_LEN].try_into().unwrap());
        let challenge_start = 8 + KEY_LEN;
        let mut challenge = [0u8; BIND_UDP_RELAY_CHALLENGE_LEN];
        let challenge_end = challenge_start + BIND_UDP_RELAY_CHALLENGE_LEN;
        challenge.copy_from_slice(&body[challenge_start..challenge_end]);
        Ok(Self {
            vni,
            generation,
            remote_key,
            challenge,
        })
    }
}

/// First client-to-relay message for binding a UDP relay endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindUDPRelayEndpoint {
    pub common: BindUDPRelayEndpointCommon,
}

impl BindUDPRelayEndpoint {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(
            TYPE_BIND_UDP_RELAY_ENDPOINT,
            BIND_UDP_RELAY_ENDPOINT_COMMON_LEN,
        );
        self.common.marshal_into(&mut out);
        out
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            common: BindUDPRelayEndpointCommon::parse(body)?,
        })
    }
}

/// Relay-to-client challenge in the UDP relay bind handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindUDPRelayEndpointChallenge {
    pub common: BindUDPRelayEndpointCommon,
}

impl BindUDPRelayEndpointChallenge {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(
            TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE,
            BIND_UDP_RELAY_ENDPOINT_COMMON_LEN,
        );
        self.common.marshal_into(&mut out);
        out
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            common: BindUDPRelayEndpointCommon::parse(body)?,
        })
    }
}

/// Client-to-relay answer in the UDP relay bind handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindUDPRelayEndpointAnswer {
    pub common: BindUDPRelayEndpointCommon,
}

impl BindUDPRelayEndpointAnswer {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(
            TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER,
            BIND_UDP_RELAY_ENDPOINT_COMMON_LEN,
        );
        self.common.marshal_into(&mut out);
        out
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            common: BindUDPRelayEndpointCommon::parse(body)?,
        })
    }
}

/// Request sent over DERP to allocate an endpoint on a UDP peer relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocateUDPRelayEndpointRequest {
    pub client_disco: [DiscoPublic; 2],
    pub generation: u32,
}

impl AllocateUDPRelayEndpointRequest {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(
            TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST,
            ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN,
        );
        for disco in &self.client_disco {
            out.extend_from_slice(disco.as_bytes());
        }
        out.extend_from_slice(&self.generation.to_be_bytes());
        out
    }

    fn parse(version: u8, body: &[u8]) -> Result<Self, Error> {
        if version != VERSION_0 {
            return Ok(Self {
                client_disco: [DiscoPublic::default(), DiscoPublic::default()],
                generation: 0,
            });
        }
        if body.len() < ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN {
            return Err(Error::Short);
        }
        let first = DiscoPublic::from_raw(body[..KEY_LEN].try_into().unwrap());
        let second = DiscoPublic::from_raw(body[KEY_LEN..KEY_LEN * 2].try_into().unwrap());
        let generation = u32::from_be_bytes(body[KEY_LEN * 2..KEY_LEN * 2 + 4].try_into().unwrap());
        Ok(Self {
            client_disco: [first, second],
            generation,
        })
    }
}

/// Shared relay endpoint descriptor carried in CallMeMaybeVia and allocation responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UDPRelayEndpoint {
    pub server_disco: DiscoPublic,
    pub client_disco: [DiscoPublic; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub bind_lifetime: Duration,
    pub steady_state_lifetime: Duration,
    pub addr_ports: Vec<SocketAddr>,
}

impl UDPRelayEndpoint {
    fn marshal_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.server_disco.as_bytes());
        for disco in &self.client_disco {
            out.extend_from_slice(disco.as_bytes());
        }
        out.extend_from_slice(&self.lamport_id.to_be_bytes());
        out.extend_from_slice(&self.vni.to_be_bytes());
        out.extend_from_slice(&duration_nanos(self.bind_lifetime).to_be_bytes());
        out.extend_from_slice(&duration_nanos(self.steady_state_lifetime).to_be_bytes());
        for addr in &self.addr_ports {
            out.extend_from_slice(&socket_addr_ip16(*addr));
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < UDP_RELAY_ENDPOINT_LEN_MINUS_ADDR_PORTS + ENDPOINT_LEN
            || !(body.len() - UDP_RELAY_ENDPOINT_LEN_MINUS_ADDR_PORTS).is_multiple_of(ENDPOINT_LEN)
        {
            return Err(Error::Short);
        }
        let mut offset = 0;
        let server_disco =
            DiscoPublic::from_raw(body[offset..offset + KEY_LEN].try_into().unwrap());
        offset += KEY_LEN;
        let first = DiscoPublic::from_raw(body[offset..offset + KEY_LEN].try_into().unwrap());
        offset += KEY_LEN;
        let second = DiscoPublic::from_raw(body[offset..offset + KEY_LEN].try_into().unwrap());
        offset += KEY_LEN;
        let lamport_id = u64::from_be_bytes(body[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let vni = u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let bind_lifetime = duration_from_nanos(u64::from_be_bytes(
            body[offset..offset + 8].try_into().unwrap(),
        ));
        offset += 8;
        let steady_state_lifetime = duration_from_nanos(u64::from_be_bytes(
            body[offset..offset + 8].try_into().unwrap(),
        ));
        offset += 8;
        let mut addr_ports = Vec::with_capacity((body.len() - offset) / ENDPOINT_LEN);
        for chunk in body[offset..].as_chunks::<ENDPOINT_LEN>().0 {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&chunk[..16]);
            let port = u16::from_be_bytes(chunk[16..18].try_into().unwrap());
            addr_ports.push(SocketAddr::new(ip_from_16(ip), port));
        }
        Ok(Self {
            server_disco,
            client_disco: [first, second],
            lamport_id,
            vni,
            bind_lifetime,
            steady_state_lifetime,
            addr_ports,
        })
    }
}

/// DERP message telling a peer to try candidate paths via a UDP relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallMeMaybeVia {
    pub endpoint: UDPRelayEndpoint,
}

impl CallMeMaybeVia {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(
            TYPE_CALL_ME_MAYBE_VIA,
            UDP_RELAY_ENDPOINT_LEN_MINUS_ADDR_PORTS + ENDPOINT_LEN * self.endpoint.addr_ports.len(),
        );
        self.endpoint.marshal_into(&mut out);
        out
    }

    fn parse(version: u8, body: &[u8]) -> Result<Self, Error> {
        if version != VERSION_0 {
            return Ok(Self {
                endpoint: empty_udp_relay_endpoint(),
            });
        }
        Ok(Self {
            endpoint: UDPRelayEndpoint::parse(body)?,
        })
    }
}

/// DERP response containing an allocated UDP relay endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocateUDPRelayEndpointResponse {
    pub generation: u32,
    pub endpoint: UDPRelayEndpoint,
}

impl AllocateUDPRelayEndpointResponse {
    fn marshal(&self) -> Vec<u8> {
        let mut out = message_with_header(
            TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE,
            4 + UDP_RELAY_ENDPOINT_LEN_MINUS_ADDR_PORTS
                + ENDPOINT_LEN * self.endpoint.addr_ports.len(),
        );
        out.extend_from_slice(&self.generation.to_be_bytes());
        self.endpoint.marshal_into(&mut out);
        out
    }

    fn parse(version: u8, body: &[u8]) -> Result<Self, Error> {
        if version != VERSION_0 {
            return Ok(Self {
                generation: 0,
                endpoint: empty_udp_relay_endpoint(),
            });
        }
        if body.len() < 4 {
            return Err(Error::Short);
        }
        Ok(Self {
            generation: u32::from_be_bytes(body[..4].try_into().unwrap()),
            endpoint: UDPRelayEndpoint::parse(&body[4..])?,
        })
    }
}

fn message_with_header(typ: u8, body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body_len);
    out.push(typ);
    out.push(VERSION_0);
    out
}

fn socket_addr_ip16(addr: SocketAddr) -> [u8; 16] {
    match addr.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn ip_from_16(raw: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(raw);
    v6.to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or(IpAddr::V6(v6))
}

fn duration_nanos(duration: Duration) -> u64 {
    duration.as_nanos().try_into().unwrap_or(u64::MAX)
}

fn duration_from_nanos(nanos: u64) -> Duration {
    Duration::from_nanos(nanos)
}

fn empty_udp_relay_endpoint() -> UDPRelayEndpoint {
    UDPRelayEndpoint {
        server_disco: DiscoPublic::default(),
        client_disco: [DiscoPublic::default(), DiscoPublic::default()],
        lamport_id: 0,
        vni: 0,
        bind_lifetime: Duration::ZERO,
        steady_state_lifetime: Duration::ZERO,
        addr_ports: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    // These vectors are derived from tailscale.com/disco/disco_test.go
    // (BSD-3-Clause, Copyright Tailscale Inc & contributors). Keeping the
    // vectors here is deliberate: this module is the compatibility boundary
    // with Go/Tailscale magicsock and UDP peer-relay disco messages.
    use super::*;
    use rand::rngs::OsRng;

    fn hex_bytes(s: &str) -> Vec<u8> {
        let compact = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        compact
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    fn node_key(raw: [u8; KEY_LEN]) -> NodePublic {
        NodePublic::from_raw(raw)
    }

    fn relay_common() -> BindUDPRelayEndpointCommon {
        BindUDPRelayEndpointCommon {
            vni: 0x0001_0203,
            generation: 0x0405_0607,
            remote_key: DiscoPublic::from_raw([0x33; KEY_LEN]),
            challenge: [0x44; BIND_UDP_RELAY_CHALLENGE_LEN],
        }
    }

    fn relay_endpoint() -> UDPRelayEndpoint {
        UDPRelayEndpoint {
            server_disco: DiscoPublic::from_raw([0xaa; KEY_LEN]),
            client_disco: [
                DiscoPublic::from_raw([0x11; KEY_LEN]),
                DiscoPublic::from_raw([0x22; KEY_LEN]),
            ],
            lamport_id: 0x0102_0304_0506_0708,
            vni: 0x000a_0b0c,
            bind_lifetime: Duration::from_secs(5),
            steady_state_lifetime: Duration::from_secs(300),
            addr_ports: vec!["203.0.113.9:31145".parse().unwrap()],
        }
    }

    #[test]
    fn message_marshal_matches_tailscale_vectors() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut raw_key = [0u8; KEY_LEN];
        raw_key[1] = 1;
        raw_key[2] = 2;
        raw_key[30] = 30;
        raw_key[31] = 31;

        let cases = [
            (
                Message::Ping(Ping {
                    tx_id,
                    node_key: None,
                    padding: 0,
                }),
                "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c",
            ),
            (
                Message::Ping(Ping {
                    tx_id,
                    node_key: Some(node_key(raw_key)),
                    padding: 0,
                }),
                "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f",
            ),
            (
                Message::Ping(Ping {
                    tx_id,
                    node_key: None,
                    padding: 3,
                }),
                "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00",
            ),
            (
                Message::Ping(Ping {
                    tx_id,
                    node_key: Some(node_key(raw_key)),
                    padding: 3,
                }),
                "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00",
            ),
            (
                Message::Pong(Pong {
                    tx_id,
                    src: "2.3.4.5:1234".parse().unwrap(),
                }),
                "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2",
            ),
            (
                Message::Pong(Pong {
                    tx_id,
                    src: "[fed0::12]:6666".parse().unwrap(),
                }),
                "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a",
            ),
            (
                Message::CallMeMaybe(CallMeMaybe { endpoints: vec![] }),
                "03 00",
            ),
            (
                Message::CallMeMaybe(CallMeMaybe {
                    endpoints: vec![
                        "1.2.3.4:567".parse().unwrap(),
                        "[2001::3456]:789".parse().unwrap(),
                    ],
                }),
                "03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15",
            ),
        ];

        for (message, want) in cases {
            let got = message.marshal();
            assert_eq!(got, hex_bytes(want));
            assert_eq!(Message::parse(&got).unwrap(), message);
        }
    }

    #[test]
    fn udp_relay_messages_match_tailscale_go_vectors() {
        let cases = [
            (
                Message::BindUDPRelayEndpoint(BindUDPRelayEndpoint {
                    common: relay_common(),
                }),
                "0400000102030405060733333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444",
            ),
            (
                Message::BindUDPRelayEndpointChallenge(BindUDPRelayEndpointChallenge {
                    common: relay_common(),
                }),
                "0500000102030405060733333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444",
            ),
            (
                Message::BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer {
                    common: relay_common(),
                }),
                "0600000102030405060733333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444",
            ),
            (
                Message::CallMeMaybeVia(CallMeMaybeVia {
                    endpoint: relay_endpoint(),
                }),
                "0700aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220102030405060708000a0b0c000000012a05f20000000045d964b80000000000000000000000ffffcb00710979a9",
            ),
            (
                Message::AllocateUDPRelayEndpointRequest(AllocateUDPRelayEndpointRequest {
                    client_disco: [
                        DiscoPublic::from_raw([0x11; KEY_LEN]),
                        DiscoPublic::from_raw([0x22; KEY_LEN]),
                    ],
                    generation: 0x0102_0304,
                }),
                "08001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222201020304",
            ),
            (
                Message::AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse {
                    generation: 0x0d0e_0f10,
                    endpoint: relay_endpoint(),
                }),
                "09000d0e0f10aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220102030405060708000a0b0c000000012a05f20000000045d964b80000000000000000000000ffffcb00710979a9",
            ),
        ];

        for (message, want) in cases {
            let got = message.marshal();
            assert_eq!(got, hex_bytes(want));
            assert_eq!(Message::parse(&got).unwrap(), message);
        }
    }

    #[test]
    fn udp_relay_endpoint_uses_go_duration_and_addrport_wire_order() {
        let message = Message::AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse {
            generation: 0x0d0e_0f10,
            endpoint: relay_endpoint(),
        });
        let got = message.marshal();

        assert_eq!(
            &got[0..2],
            &[TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE, VERSION_0]
        );
        assert_eq!(&got[2..6], &0x0d0e_0f10u32.to_be_bytes());

        let mut offset = 6;
        assert_eq!(&got[offset..offset + KEY_LEN], &[0xaa; KEY_LEN]);
        offset += KEY_LEN;
        assert_eq!(&got[offset..offset + KEY_LEN], &[0x11; KEY_LEN]);
        offset += KEY_LEN;
        assert_eq!(&got[offset..offset + KEY_LEN], &[0x22; KEY_LEN]);
        offset += KEY_LEN;
        assert_eq!(
            &got[offset..offset + 8],
            &0x0102_0304_0506_0708u64.to_be_bytes()
        );
        offset += 8;
        assert_eq!(&got[offset..offset + 4], &0x000a_0b0cu32.to_be_bytes());
        offset += 4;
        assert_eq!(&got[offset..offset + 8], &(5_000_000_000u64).to_be_bytes());
        offset += 8;
        assert_eq!(
            &got[offset..offset + 8],
            &(300_000_000_000u64).to_be_bytes()
        );
        offset += 8;
        assert_eq!(
            &got[offset..offset + ENDPOINT_LEN],
            &hex_bytes("00 00 00 00 00 00 00 00 00 00 ff ff cb 00 71 09 79 a9")
        );
    }

    #[test]
    fn wrapper_detection_and_source_match_tailscale_shape() {
        let mut packet = Vec::new();
        packet.extend_from_slice(MAGIC);
        packet.extend_from_slice(&[0x42; KEY_LEN]);
        packet.extend_from_slice(&[0x55; NONCE_LEN]);
        assert!(looks_like_wrapper(&packet));
        assert_eq!(
            source(&packet).unwrap(),
            DiscoPublic::from_raw([0x42; KEY_LEN])
        );

        packet[0] = b'X';
        assert!(!looks_like_wrapper(&packet));
        assert!(source(&packet).is_none());
    }

    #[test]
    fn sealed_wrapper_round_trips_between_disco_keys() {
        let alice = DiscoPrivate::from_raw([0x11; KEY_LEN]);
        let bob = DiscoPrivate::from_raw([0x22; KEY_LEN]);
        let message = Message::Ping(Ping {
            tx_id: [9; 12],
            node_key: Some(NodePublic::from_raw([0x33; KEY_LEN])),
            padding: 7,
        });

        let packet = alice.seal_to(&bob.public(), &message, &mut OsRng).unwrap();
        assert!(looks_like_wrapper(&packet));
        assert_eq!(source(&packet).unwrap(), alice.public());

        let opened = bob.open(&packet).unwrap();
        assert_eq!(opened.sender, alice.public());
        assert_eq!(opened.message, message);
    }

    #[test]
    fn sealed_wrapper_rejects_wrong_recipient() {
        let alice = DiscoPrivate::from_raw([0x11; KEY_LEN]);
        let bob = DiscoPrivate::from_raw([0x22; KEY_LEN]);
        let charlie = DiscoPrivate::from_raw([0x33; KEY_LEN]);
        let message = Message::Pong(Pong {
            tx_id: [8; 12],
            src: "203.0.113.10:41641".parse().unwrap(),
        });

        let packet = alice.seal_to(&bob.public(), &message, &mut OsRng).unwrap();
        assert!(matches!(charlie.open(&packet), Err(Error::Crypto(_))));
    }
}
