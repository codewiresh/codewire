//! UDP peer relay core for #257.
//!
//! This mirrors the security shape of Tailscale's experimental `udprelay`
//! package without binding sockets yet. A future daemon can wrap
//! [`crate::udp_relay::Server::handle_packet`] with UDP reads/writes.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake2::digest::{KeyInit, Mac};
use blake2::Blake2sMac256;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::UdpSocket;

use crate::disco::{
    BindUDPRelayEndpointChallenge, BindUDPRelayEndpointCommon, DiscoPrivate, Message,
    UDPRelayEndpoint,
};
use crate::node::DiscoPublic;

const GENEVE_HEADER_LEN: usize = 8;
const GENEVE_PROTOCOL_DISCO: u16 = 0x7a11;
const GENEVE_PROTOCOL_WIREGUARD: u16 = 0x7a12;
const MIN_VNI: u32 = 1;
const MAX_VNI: u32 = (1 << 24) - 1;

const DEFAULT_BIND_LIFETIME: Duration = Duration::from_secs(30);
const DEFAULT_STEADY_STATE_LIFETIME: Duration = Duration::from_secs(300);
const DEFAULT_EXPIRE_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_UDP_PACKET_LIMIT: usize = 64 << 10;

/// Errors returned by relay allocation and packet handling.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("relay server has no advertised addr:ports")]
    NotReady,
    #[error("client disco key equals server disco key")]
    ClientEqualsServerDisco,
    #[error("VNI pool exhausted")]
    VniPoolExhausted,
    #[error("short Geneve packet")]
    ShortGeneve,
    #[error("unsupported Geneve version {0}")]
    UnsupportedGeneveVersion(u8),
    #[error("unsupported Geneve protocol 0x{0:04x}")]
    UnsupportedGeneveProtocol(u16),
    #[error("Geneve packet has unset VNI")]
    UnsetVni,
    #[error("udp relay bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("udp relay local addr: {0}")]
    LocalAddr(std::io::Error),
    #[error("udp relay receive: {0}")]
    Receive(std::io::Error),
    #[error("udp relay send to {addr}: {source}")]
    Send {
        addr: SocketAddr,
        source: std::io::Error,
    },
}

/// Non-secret relay counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub allocations: u64,
    pub sessions_opened: u64,
    pub sessions_expired: u64,
    pub packets_forwarded: u64,
    pub bytes_forwarded: u64,
    pub max_packet_bytes_forwarded: u64,
    pub drops_unknown_vni: u64,
    pub drops_unknown_source: u64,
    pub drops_handshake: u64,
    pub drops_unbound: u64,
    pub drops_malformed: u64,
}

/// Packet returned by [`Server::handle_packet`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayOutput {
    pub to: SocketAddr,
    pub packet: Vec<u8>,
    pub is_data: bool,
}

/// Decoded UDP relay packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayPacket<'a> {
    Control { vni: u32, payload: &'a [u8] },
    Disco { vni: u32, payload: &'a [u8] },
    Data { vni: u32, payload: &'a [u8] },
}

impl RelayPacket<'_> {
    pub fn vni(&self) -> u32 {
        match self {
            Self::Control { vni, .. } | Self::Disco { vni, .. } | Self::Data { vni, .. } => *vni,
        }
    }
}

/// Wrap a sealed disco relay-control message in a Geneve control packet.
pub fn encode_control_packet(vni: u32, sealed_disco: &[u8]) -> Vec<u8> {
    encode_geneve(vni, true, GENEVE_PROTOCOL_DISCO, sealed_disco)
}

/// Wrap a sealed peer-to-peer disco message in a Geneve relay packet.
pub fn encode_disco_packet(vni: u32, sealed_disco: &[u8]) -> Vec<u8> {
    encode_geneve(vni, false, GENEVE_PROTOCOL_DISCO, sealed_disco)
}

/// Wrap an encrypted WireGuard datagram in a Geneve relay data packet.
pub fn encode_data_packet(vni: u32, payload: &[u8]) -> Vec<u8> {
    encode_geneve(vni, false, GENEVE_PROTOCOL_WIREGUARD, payload)
}

/// Decode a Geneve packet used by the UDP peer relay.
pub fn decode_packet(packet: &[u8]) -> Result<RelayPacket<'_>, Error> {
    let header = GeneveHeader::decode(packet)?;
    let payload = &packet[GENEVE_HEADER_LEN..];
    if header.control {
        if header.protocol != GENEVE_PROTOCOL_DISCO {
            return Err(Error::UnsupportedGeneveProtocol(header.protocol));
        }
        Ok(RelayPacket::Control {
            vni: header.vni,
            payload,
        })
    } else if header.protocol == GENEVE_PROTOCOL_DISCO {
        Ok(RelayPacket::Disco {
            vni: header.vni,
            payload,
        })
    } else if header.protocol == GENEVE_PROTOCOL_WIREGUARD {
        Ok(RelayPacket::Data {
            vni: header.vni,
            payload,
        })
    } else {
        Err(Error::UnsupportedGeneveProtocol(header.protocol))
    }
}

/// UDP socket runner options for a relay server.
#[derive(Clone, Debug)]
pub struct SocketOptions {
    pub bind_addr: SocketAddr,
    pub advertise_addr_ports: Vec<SocketAddr>,
    pub expire_interval: Duration,
    pub max_packet_size: usize,
}

impl SocketOptions {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            advertise_addr_ports: Vec::new(),
            expire_interval: DEFAULT_EXPIRE_INTERVAL,
            max_packet_size: DEFAULT_UDP_PACKET_LIMIT,
        }
    }

    pub fn with_advertise_addr_ports(mut self, addr_ports: Vec<SocketAddr>) -> Self {
        self.advertise_addr_ports = addr_ports;
        self
    }

    pub fn with_expire_interval(mut self, interval: Duration) -> Self {
        self.expire_interval = interval;
        self
    }

    pub fn with_max_packet_size(mut self, size: usize) -> Self {
        self.max_packet_size = size;
        self
    }
}

/// Handle for allocating relay endpoints while the socket runner is active.
#[derive(Clone)]
pub struct SocketHandle {
    local_addr: SocketAddr,
    server: Arc<Mutex<Server>>,
}

impl SocketHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn disco_public(&self) -> DiscoPublic {
        self.server.lock().unwrap().disco_public()
    }

    pub fn allocate_endpoint(
        &self,
        disco_a: DiscoPublic,
        disco_b: DiscoPublic,
    ) -> Result<UDPRelayEndpoint, Error> {
        self.server
            .lock()
            .unwrap()
            .allocate_endpoint(disco_a, disco_b)
    }

    pub fn stats(&self) -> Stats {
        self.server.lock().unwrap().stats()
    }
}

/// Async UDP socket wrapper around [`Server`].
pub struct SocketServer {
    socket: UdpSocket,
    handle: SocketHandle,
    expire_interval: Duration,
    max_packet_size: usize,
}

impl SocketServer {
    pub async fn bind(disco: DiscoPrivate, options: SocketOptions) -> Result<Self, Error> {
        let socket = UdpSocket::bind(options.bind_addr)
            .await
            .map_err(|source| Error::Bind {
                addr: options.bind_addr,
                source,
            })?;
        let local_addr = socket.local_addr().map_err(Error::LocalAddr)?;
        let advertise_addr_ports = if options.advertise_addr_ports.is_empty() {
            vec![local_addr]
        } else {
            options.advertise_addr_ports
        };
        let server = Arc::new(Mutex::new(Server::new(disco, advertise_addr_ports)));
        Ok(Self {
            socket,
            handle: SocketHandle { local_addr, server },
            expire_interval: options.expire_interval,
            max_packet_size: options.max_packet_size.max(1),
        })
    }

    pub fn handle(&self) -> SocketHandle {
        self.handle.clone()
    }

    pub async fn run_until<F>(self, shutdown: F) -> Result<(), Error>
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let mut buf = vec![0u8; self.max_packet_size];
        let mut expire = tokio::time::interval(self.expire_interval);
        expire.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                _ = expire.tick() => {
                    self.handle.server.lock().unwrap().expire_at(Instant::now());
                }
                received = self.socket.recv_from(&mut buf) => {
                    let (n, source) = received.map_err(Error::Receive)?;
                    let output = {
                        let mut relay = self.handle.server.lock().unwrap();
                        match relay.handle_packet(source, &buf[..n]) {
                            Ok(output) => output,
                            Err(err) => {
                                tracing::debug!(
                                    source = %source,
                                    packet_len = n,
                                    error = %err,
                                    "rust UDP peer relay dropped packet"
                                );
                                None
                            }
                        }
                    };
                    if let Some(output) = output {
                        self.socket
                            .send_to(&output.packet, output.to)
                            .await
                            .map_err(|source| Error::Send {
                                addr: output.to,
                                source,
                            })?;
                    }
                }
            }
        }
    }
}

/// In-memory UDP peer relay server core.
pub struct Server {
    disco: DiscoPrivate,
    bind_lifetime: Duration,
    steady_state_lifetime: Duration,
    addr_ports: Vec<SocketAddr>,
    next_vni: u32,
    lamport_id: u64,
    mac_secret: [u8; 32],
    endpoints_by_pair: HashMap<DiscoPair, ServerEndpointState>,
    pairs_by_vni: HashMap<u32, DiscoPair>,
    stats: Stats,
}

impl Server {
    /// Create a relay core with explicit public/static relay candidates.
    pub fn new(disco: DiscoPrivate, addr_ports: Vec<SocketAddr>) -> Self {
        let mut mac_secret = [0u8; 32];
        OsRng.fill_bytes(&mut mac_secret);
        Self {
            disco,
            bind_lifetime: DEFAULT_BIND_LIFETIME,
            steady_state_lifetime: DEFAULT_STEADY_STATE_LIFETIME,
            addr_ports,
            next_vni: MIN_VNI,
            lamport_id: 0,
            mac_secret,
            endpoints_by_pair: HashMap::new(),
            pairs_by_vni: HashMap::new(),
            stats: Stats::default(),
        }
    }

    /// Set lifetimes used for new allocation descriptors and expiry.
    pub fn with_lifetimes(mut self, bind: Duration, steady: Duration) -> Self {
        self.bind_lifetime = bind;
        self.steady_state_lifetime = steady;
        self
    }

    /// Deterministic MAC secret for unit tests.
    #[cfg(test)]
    fn with_mac_secret_for_test(mut self, secret: [u8; 32]) -> Self {
        self.mac_secret = secret;
        self
    }

    /// Public relay disco key.
    pub fn disco_public(&self) -> DiscoPublic {
        self.disco.public()
    }

    /// Non-secret counters.
    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }

    /// Allocate or return the existing relay endpoint for a disco-key pair.
    pub fn allocate_endpoint(
        &mut self,
        disco_a: DiscoPublic,
        disco_b: DiscoPublic,
    ) -> Result<UDPRelayEndpoint, Error> {
        if self.addr_ports.is_empty() {
            return Err(Error::NotReady);
        }
        let server_disco = self.disco.public();
        if disco_a == server_disco || disco_b == server_disco {
            return Err(Error::ClientEqualsServerDisco);
        }

        let pair = DiscoPair::new(disco_a, disco_b);
        if let Some(endpoint) = self.endpoints_by_pair.get(&pair) {
            return Ok(self.endpoint_descriptor(endpoint));
        }

        let vni = self.next_vni()?;
        self.lamport_id += 1;
        let state = ServerEndpointState::new(pair, self.lamport_id, vni, Instant::now());
        self.pairs_by_vni.insert(vni, pair);
        self.stats.allocations += 1;
        let descriptor = self.endpoint_descriptor(&state);
        self.endpoints_by_pair.insert(pair, state);
        Ok(descriptor)
    }

    /// Handle one UDP datagram from `from`.
    pub fn handle_packet(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
    ) -> Result<Option<RelayOutput>, Error> {
        self.handle_packet_at(from, packet, Instant::now())
    }

    fn handle_packet_at(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<RelayOutput>, Error> {
        let header = match GeneveHeader::decode(packet) {
            Ok(header) => header,
            Err(err) => {
                self.stats.drops_malformed += 1;
                return Err(err);
            }
        };
        let Some(pair) = self.pairs_by_vni.get(&header.vni).copied() else {
            self.stats.drops_unknown_vni += 1;
            return Ok(None);
        };

        if header.control {
            if header.protocol != GENEVE_PROTOCOL_DISCO {
                self.stats.drops_handshake += 1;
                return Ok(None);
            }
            let payload = &packet[GENEVE_HEADER_LEN..];
            self.handle_control_packet(pair, from, header.vni, payload, now)
        } else {
            self.handle_data_packet(pair, from, packet, now)
        }
    }

    /// Expire unbound and idle sessions using the supplied timestamp.
    pub fn expire_at(&mut self, now: Instant) {
        let mut expired = Vec::new();
        for (pair, endpoint) in &self.endpoints_by_pair {
            if endpoint.is_expired(now, self.bind_lifetime, self.steady_state_lifetime) {
                expired.push((*pair, endpoint.vni));
            }
        }
        for (pair, vni) in expired {
            self.endpoints_by_pair.remove(&pair);
            self.pairs_by_vni.remove(&vni);
            self.stats.sessions_expired += 1;
        }
    }

    fn endpoint_descriptor(&self, endpoint: &ServerEndpointState) -> UDPRelayEndpoint {
        UDPRelayEndpoint {
            server_disco: self.disco.public(),
            client_disco: endpoint.pair.0,
            lamport_id: endpoint.lamport_id,
            vni: endpoint.vni,
            bind_lifetime: self.bind_lifetime,
            steady_state_lifetime: self.steady_state_lifetime,
            addr_ports: self.addr_ports.clone(),
        }
    }

    fn next_vni(&mut self) -> Result<u32, Error> {
        for _ in MIN_VNI..=MAX_VNI {
            let vni = self.next_vni;
            self.next_vni = if self.next_vni == MAX_VNI {
                MIN_VNI
            } else {
                self.next_vni + 1
            };
            if !self.pairs_by_vni.contains_key(&vni) {
                return Ok(vni);
            }
        }
        Err(Error::VniPoolExhausted)
    }

    fn handle_control_packet(
        &mut self,
        pair: DiscoPair,
        from: SocketAddr,
        vni: u32,
        payload: &[u8],
        now: Instant,
    ) -> Result<Option<RelayOutput>, Error> {
        let opened = match self.disco.open(payload) {
            Ok(opened) => opened,
            Err(_) => {
                self.stats.drops_handshake += 1;
                return Ok(None);
            }
        };
        let Some(sender_idx) = pair.index_of(opened.sender) else {
            self.stats.drops_unknown_source += 1;
            return Ok(None);
        };
        let other_idx = 1 - sender_idx;
        let other_disco = pair.0[other_idx];

        match opened.message {
            Message::BindUDPRelayEndpoint(bind) => {
                if !valid_bind_common(&bind.common, vni, other_disco) || bind.common.generation == 0
                {
                    self.stats.drops_handshake += 1;
                    return Ok(None);
                }
                let challenge = relay_challenge_mac(
                    &self.mac_secret,
                    from,
                    &bind.common.with_remote_key(other_disco),
                );
                let endpoint = self
                    .endpoints_by_pair
                    .get_mut(&pair)
                    .expect("endpoint exists");
                endpoint.in_progress_generation[sender_idx] = bind.common.generation;
                let response =
                    Message::BindUDPRelayEndpointChallenge(BindUDPRelayEndpointChallenge {
                        common: BindUDPRelayEndpointCommon {
                            vni,
                            generation: bind.common.generation,
                            remote_key: other_disco,
                            challenge,
                        },
                    });
                let packet = self
                    .disco
                    .seal_to(&opened.sender, &response, &mut OsRng)
                    .map(|sealed| encode_geneve(vni, true, GENEVE_PROTOCOL_DISCO, &sealed))
                    .map_err(|_| Error::UnsetVni)?;
                Ok(Some(RelayOutput {
                    to: from,
                    packet,
                    is_data: false,
                }))
            }
            Message::BindUDPRelayEndpointAnswer(answer) => {
                if !valid_bind_common(&answer.common, vni, other_disco) {
                    self.stats.drops_handshake += 1;
                    return Ok(None);
                }
                let endpoint = self
                    .endpoints_by_pair
                    .get_mut(&pair)
                    .expect("endpoint exists");
                if endpoint.in_progress_generation[sender_idx] != answer.common.generation {
                    self.stats.drops_handshake += 1;
                    return Ok(None);
                }
                let want = relay_challenge_mac(
                    &self.mac_secret,
                    from,
                    &answer.common.with_remote_key(other_disco),
                );
                if answer.common.challenge != want {
                    self.stats.drops_handshake += 1;
                    return Ok(None);
                }
                let was_bound = endpoint.is_bound();
                endpoint.bound_addr[sender_idx] = Some(from);
                endpoint.last_seen[sender_idx] = Some(now);
                endpoint.in_progress_generation[sender_idx] = 0;
                if !was_bound && endpoint.is_bound() {
                    self.stats.sessions_opened += 1;
                }
                Ok(None)
            }
            _ => {
                self.stats.drops_handshake += 1;
                Ok(None)
            }
        }
    }

    fn handle_data_packet(
        &mut self,
        pair: DiscoPair,
        from: SocketAddr,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<RelayOutput>, Error> {
        let endpoint = self
            .endpoints_by_pair
            .get_mut(&pair)
            .expect("endpoint exists");
        if !endpoint.is_bound() {
            self.stats.drops_unbound += 1;
            return Ok(None);
        }
        let Some(sender_idx) = endpoint.bound_index(from) else {
            self.stats.drops_unknown_source += 1;
            return Ok(None);
        };
        let other_idx = 1 - sender_idx;
        let Some(to) = endpoint.bound_addr[other_idx] else {
            self.stats.drops_unbound += 1;
            return Ok(None);
        };
        endpoint.last_seen[sender_idx] = Some(now);
        endpoint.packets_rx[sender_idx] += 1;
        endpoint.bytes_rx[sender_idx] += packet.len() as u64;
        self.stats.packets_forwarded += 1;
        self.stats.bytes_forwarded += packet.len() as u64;
        self.stats.max_packet_bytes_forwarded = self
            .stats
            .max_packet_bytes_forwarded
            .max(packet.len() as u64);
        Ok(Some(RelayOutput {
            to,
            packet: packet.to_vec(),
            is_data: true,
        }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct DiscoPair([DiscoPublic; 2]);

impl DiscoPair {
    fn new(a: DiscoPublic, b: DiscoPublic) -> Self {
        if a.as_bytes() <= b.as_bytes() {
            Self([a, b])
        } else {
            Self([b, a])
        }
    }

    fn index_of(&self, disco: DiscoPublic) -> Option<usize> {
        if self.0[0] == disco {
            Some(0)
        } else if self.0[1] == disco {
            Some(1)
        } else {
            None
        }
    }
}

struct ServerEndpointState {
    pair: DiscoPair,
    lamport_id: u64,
    vni: u32,
    allocated_at: Instant,
    in_progress_generation: [u32; 2],
    bound_addr: [Option<SocketAddr>; 2],
    last_seen: [Option<Instant>; 2],
    packets_rx: [u64; 2],
    bytes_rx: [u64; 2],
}

impl ServerEndpointState {
    fn new(pair: DiscoPair, lamport_id: u64, vni: u32, allocated_at: Instant) -> Self {
        Self {
            pair,
            lamport_id,
            vni,
            allocated_at,
            in_progress_generation: [0, 0],
            bound_addr: [None, None],
            last_seen: [None, None],
            packets_rx: [0, 0],
            bytes_rx: [0, 0],
        }
    }

    fn is_bound(&self) -> bool {
        self.bound_addr[0].is_some() && self.bound_addr[1].is_some()
    }

    fn bound_index(&self, from: SocketAddr) -> Option<usize> {
        if self.bound_addr[0] == Some(from) {
            Some(0)
        } else if self.bound_addr[1] == Some(from) {
            Some(1)
        } else {
            None
        }
    }

    fn is_expired(
        &self,
        now: Instant,
        bind_lifetime: Duration,
        steady_state_lifetime: Duration,
    ) -> bool {
        if !self.is_bound() {
            return now.duration_since(self.allocated_at) > bind_lifetime;
        }
        self.last_seen
            .iter()
            .flatten()
            .any(|seen| now.duration_since(*seen) > steady_state_lifetime)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GeneveHeader {
    control: bool,
    protocol: u16,
    vni: u32,
}

impl GeneveHeader {
    fn decode(packet: &[u8]) -> Result<Self, Error> {
        if packet.len() < GENEVE_HEADER_LEN {
            return Err(Error::ShortGeneve);
        }
        let version = packet[0] >> 6;
        if version != 0 {
            return Err(Error::UnsupportedGeneveVersion(version));
        }
        let control = packet[1] & 0x80 != 0;
        let protocol = u16::from_be_bytes(packet[2..4].try_into().unwrap());
        let vni = u32::from_be_bytes(packet[4..8].try_into().unwrap()) >> 8;
        if vni == 0 {
            return Err(Error::UnsetVni);
        }
        Ok(Self {
            control,
            protocol,
            vni,
        })
    }
}

fn encode_geneve(vni: u32, control: bool, protocol: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; GENEVE_HEADER_LEN + payload.len()];
    if control {
        out[1] = 0x80;
    }
    out[2..4].copy_from_slice(&protocol.to_be_bytes());
    out[4..8].copy_from_slice(&(vni << 8).to_be_bytes());
    out[GENEVE_HEADER_LEN..].copy_from_slice(payload);
    out
}

fn valid_bind_common(common: &BindUDPRelayEndpointCommon, vni: u32, remote: DiscoPublic) -> bool {
    common.vni == vni && common.remote_key == remote
}

fn relay_challenge_mac(
    mac_secret: &[u8; 32],
    from: SocketAddr,
    common: &BindUDPRelayEndpointCommon,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(4 + 4 + 32 + 18);
    input.extend_from_slice(&common.vni.to_be_bytes());
    input.extend_from_slice(&common.generation.to_be_bytes());
    input.extend_from_slice(common.remote_key.as_bytes());
    append_addr_port_binary(&mut input, from);
    let mut mac =
        <Blake2sMac256 as KeyInit>::new_from_slice(mac_secret).expect("32-byte BLAKE2s MAC key");
    mac.update(&input);
    mac.finalize().into_bytes().into()
}

fn append_addr_port_binary(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
    out.extend_from_slice(&addr.port().to_le_bytes());
}

trait BindCommonExt {
    fn with_remote_key(&self, remote_key: DiscoPublic) -> BindUDPRelayEndpointCommon;
}

impl BindCommonExt for BindUDPRelayEndpointCommon {
    fn with_remote_key(&self, remote_key: DiscoPublic) -> BindUDPRelayEndpointCommon {
        BindUDPRelayEndpointCommon {
            vni: self.vni,
            generation: self.generation,
            remote_key,
            challenge: self.challenge,
        }
    }
}

#[cfg(test)]
mod tests {
    // The UDP relay handshake and data-plane shape mirrors
    // tailscale.com/net/udprelay/server_test.go (BSD-3-Clause, Copyright
    // Tailscale Inc & contributors). These tests intentionally keep that
    // behavior pinned while Codewire owns the smaller Rust implementation.
    use super::*;
    use crate::disco::{
        BindUDPRelayEndpoint, BindUDPRelayEndpointAnswer, BindUDPRelayEndpointCommon,
    };
    use crate::node::KEY_LEN;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    fn disco(raw: u8) -> DiscoPrivate {
        DiscoPrivate::from_raw([raw; KEY_LEN])
    }

    fn bind_packet(
        client: &DiscoPrivate,
        server: DiscoPublic,
        vni: u32,
        generation: u32,
        remote_key: DiscoPublic,
    ) -> Vec<u8> {
        let message = Message::BindUDPRelayEndpoint(BindUDPRelayEndpoint {
            common: BindUDPRelayEndpointCommon {
                vni,
                generation,
                remote_key,
                challenge: [0; 32],
            },
        });
        let sealed = client.seal_to(&server, &message, &mut OsRng).unwrap();
        encode_geneve(vni, true, GENEVE_PROTOCOL_DISCO, &sealed)
    }

    fn answer_packet(
        client: &DiscoPrivate,
        server: DiscoPublic,
        vni: u32,
        generation: u32,
        remote_key: DiscoPublic,
        challenge: [u8; 32],
    ) -> Vec<u8> {
        let message = Message::BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer {
            common: BindUDPRelayEndpointCommon {
                vni,
                generation,
                remote_key,
                challenge,
            },
        });
        let sealed = client.seal_to(&server, &message, &mut OsRng).unwrap();
        encode_geneve(vni, true, GENEVE_PROTOCOL_DISCO, &sealed)
    }

    fn data_packet(vni: u32, payload: &[u8]) -> Vec<u8> {
        encode_geneve(vni, false, GENEVE_PROTOCOL_WIREGUARD, payload)
    }

    fn disco_packet(vni: u32, payload: &[u8]) -> Vec<u8> {
        encode_disco_packet(vni, payload)
    }

    fn open_challenge(client: &DiscoPrivate, packet: &[u8]) -> [u8; 32] {
        let header = GeneveHeader::decode(packet).unwrap();
        assert!(header.control);
        let opened = client.open(&packet[GENEVE_HEADER_LEN..]).unwrap();
        match opened.message {
            Message::BindUDPRelayEndpointChallenge(challenge) => challenge.common.challenge,
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn allocate_endpoint_sorts_pair_and_reuses_existing_vni() {
        let mut server = Server::new(disco(0xaa), vec!["203.0.113.34:41641".parse().unwrap()]);
        let a = disco(0x22).public();
        let b = disco(0x11).public();

        let first = server.allocate_endpoint(a, b).unwrap();
        let second = server.allocate_endpoint(b, a).unwrap();

        assert_eq!(first.vni, 1);
        assert_eq!(first.vni, second.vni);
        assert_eq!(first.client_disco, DiscoPair::new(a, b).0);
        assert_eq!(server.stats().allocations, 1);
    }

    #[test]
    fn bind_challenge_answer_opens_session_and_forwards_data() {
        let server_key = disco(0xaa);
        let mut server = Server::new(
            server_key.clone(),
            vec!["203.0.113.34:41641".parse().unwrap()],
        )
        .with_mac_secret_for_test([0x55; 32]);
        let a = disco(0x11);
        let b = disco(0x22);
        let a_addr: SocketAddr = "198.51.100.44:55231".parse().unwrap();
        let b_addr: SocketAddr = "203.0.113.34:31000".parse().unwrap();

        let endpoint = server
            .allocate_endpoint(a.public(), b.public())
            .expect("allocate");
        let a_bind = bind_packet(&a, server_key.public(), endpoint.vni, 7, b.public());
        let a_challenge = server
            .handle_packet(a_addr, &a_bind)
            .unwrap()
            .expect("challenge");
        assert_eq!(a_challenge.to, a_addr);
        assert!(!a_challenge.is_data);
        let a_mac = open_challenge(&a, &a_challenge.packet);
        let a_answer = answer_packet(&a, server_key.public(), endpoint.vni, 7, b.public(), a_mac);
        assert!(server.handle_packet(a_addr, &a_answer).unwrap().is_none());

        let b_bind = bind_packet(&b, server_key.public(), endpoint.vni, 9, a.public());
        let b_challenge = server
            .handle_packet(b_addr, &b_bind)
            .unwrap()
            .expect("challenge");
        let b_mac = open_challenge(&b, &b_challenge.packet);
        let b_answer = answer_packet(&b, server_key.public(), endpoint.vni, 9, a.public(), b_mac);
        assert!(server.handle_packet(b_addr, &b_answer).unwrap().is_none());

        let payload = b"encrypted-wireguard";
        let packet = data_packet(endpoint.vni, payload);
        let forwarded = server
            .handle_packet(a_addr, &packet)
            .unwrap()
            .expect("forwarded");

        assert_eq!(forwarded.to, b_addr);
        assert_eq!(forwarded.packet, packet);
        assert!(forwarded.is_data);

        let packet = disco_packet(endpoint.vni, b"sealed-peer-disco-ping");
        let forwarded = server
            .handle_packet(a_addr, &packet)
            .unwrap()
            .expect("forwarded disco");

        assert_eq!(forwarded.to, b_addr);
        assert_eq!(forwarded.packet, packet);
        assert!(forwarded.is_data);
        assert_eq!(server.stats().sessions_opened, 1);
        assert_eq!(server.stats().packets_forwarded, 2);
    }

    #[tokio::test]
    async fn socket_runner_binds_and_relays_udp_packets() {
        let server_key = disco(0xaa);
        let relay = SocketServer::bind(
            server_key.clone(),
            SocketOptions::new("127.0.0.1:0".parse().unwrap())
                .with_expire_interval(Duration::from_millis(50)),
        )
        .await
        .unwrap();
        let handle = relay.handle();
        let relay_addr = handle.local_addr();
        let a = disco(0x11);
        let b = disco(0x22);
        let endpoint = handle.allocate_endpoint(a.public(), b.public()).unwrap();
        assert_eq!(endpoint.addr_ports, vec![relay_addr]);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let relay_task = tokio::spawn(relay.run_until(async {
            let _ = shutdown_rx.await;
        }));
        let a_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0u8; 2048];

        let a_bind = bind_packet(&a, server_key.public(), endpoint.vni, 7, b.public());
        a_socket.send_to(&a_bind, relay_addr).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(1), a_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay_addr);
        let a_mac = open_challenge(&a, &buf[..n]);
        let a_answer = answer_packet(&a, server_key.public(), endpoint.vni, 7, b.public(), a_mac);
        a_socket.send_to(&a_answer, relay_addr).await.unwrap();

        let b_bind = bind_packet(&b, server_key.public(), endpoint.vni, 9, a.public());
        b_socket.send_to(&b_bind, relay_addr).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(1), b_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay_addr);
        let b_mac = open_challenge(&b, &buf[..n]);
        let b_answer = answer_packet(&b, server_key.public(), endpoint.vni, 9, a.public(), b_mac);
        b_socket.send_to(&b_answer, relay_addr).await.unwrap();

        let packet = data_packet(endpoint.vni, b"encrypted-wireguard");
        a_socket.send_to(&packet, relay_addr).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(1), b_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay_addr);
        assert_eq!(&buf[..n], packet.as_slice());

        let packet = disco_packet(endpoint.vni, b"sealed-peer-disco-ping");
        a_socket.send_to(&packet, relay_addr).await.unwrap();
        let (n, source) = timeout(Duration::from_secs(1), b_socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, relay_addr);
        assert_eq!(&buf[..n], packet.as_slice());

        assert_eq!(handle.stats().sessions_opened, 1);
        assert_eq!(handle.stats().packets_forwarded, 2);
        let _ = shutdown_tx.send(());
        relay_task.await.unwrap().unwrap();
    }

    #[test]
    fn drops_unknown_vni_unbound_and_unknown_source() {
        let server_key = disco(0xaa);
        let mut server = Server::new(
            server_key.clone(),
            vec!["203.0.113.34:41641".parse().unwrap()],
        );
        let a = disco(0x11);
        let b = disco(0x22);
        let endpoint = server.allocate_endpoint(a.public(), b.public()).unwrap();
        let a_addr: SocketAddr = "198.51.100.44:55231".parse().unwrap();

        assert!(matches!(
            server.handle_packet(a_addr, b"short").unwrap_err(),
            Error::ShortGeneve
        ));
        let unknown = data_packet(endpoint.vni + 1, b"wg");
        assert!(server.handle_packet(a_addr, &unknown).unwrap().is_none());

        let unbound = data_packet(endpoint.vni, b"wg");
        assert!(server.handle_packet(a_addr, &unbound).unwrap().is_none());

        let bind = bind_packet(&a, server_key.public(), endpoint.vni, 7, b.public());
        let challenge = server.handle_packet(a_addr, &bind).unwrap().unwrap();
        let mac = open_challenge(&a, &challenge.packet);
        let answer = answer_packet(&a, server_key.public(), endpoint.vni, 7, b.public(), mac);
        assert!(server.handle_packet(a_addr, &answer).unwrap().is_none());
        assert!(server.handle_packet(a_addr, &unbound).unwrap().is_none());

        let stats = server.stats();
        assert_eq!(stats.drops_unknown_vni, 1);
        assert_eq!(stats.drops_unbound, 2);
        assert_eq!(stats.drops_malformed, 1);
    }

    #[test]
    fn expires_unbound_session() {
        let mut server = Server::new(disco(0xaa), vec!["203.0.113.34:41641".parse().unwrap()])
            .with_lifetimes(Duration::from_secs(1), Duration::from_secs(10));
        let endpoint = server
            .allocate_endpoint(disco(0x11).public(), disco(0x22).public())
            .unwrap();

        server.expire_at(Instant::now() + Duration::from_secs(2));

        let packet = data_packet(endpoint.vni, b"wg");
        assert!(server
            .handle_packet("198.51.100.44:55231".parse().unwrap(), &packet)
            .unwrap()
            .is_none());
        assert_eq!(server.stats().sessions_expired, 1);
        assert_eq!(server.stats().drops_unknown_vni, 1);
    }
}
