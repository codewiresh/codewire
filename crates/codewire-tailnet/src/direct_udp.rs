//! Direct UDP path selection for the Rust tailnet.
//!
//! This wraps an existing DERP transport and opportunistically upgrades
//! encrypted WireGuard datagrams to a verified direct UDP endpoint or a shared
//! UDP relay. The packet path priority is direct UDP, then UDP relay, then
//! DERP fallback; DERP also carries disco control messages such as CallMeMaybe.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::conn::{PeerPath, Transport, WgDatagram};
use crate::derp::NodePublic as DerpPublic;
use crate::disco::{
    self, AllocateUDPRelayEndpointResponse, BindUDPRelayEndpoint, BindUDPRelayEndpointAnswer,
    BindUDPRelayEndpointCommon, CallMeMaybe, CallMeMaybeVia, DiscoPrivate, Message, Ping, Pong,
    UDPRelayEndpoint,
};
use crate::endpoint_tracker::EndpointTracker;
use crate::node::{AddrPort, DiscoPublic, Node, NodePublic};
use crate::stun;
use crate::udp_relay::{self, RelayPacket};

const UDP_PACKET_LIMIT: usize = 64 << 10;
const VERIFIED_ENDPOINT_TTL: Duration = Duration::from_secs(30);
const PEER_RELAY_BIND_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const DIRECT_PROBE_RETRY_WINDOW: Duration = Duration::from_secs(5);
const STUN_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(750);
const STUN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);
const DEFAULT_DERP_REGION_ID: u16 = 1;

fn derp_magic_addr(region_id: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(DERP_MAGIC_IP), region_id)
}

/// Direct UDP transport options.
pub struct Options {
    /// Local UDP bind address. Gateways usually bind an ephemeral UDP port.
    pub bind_addr: SocketAddr,
    /// Public/static endpoints to publish in our `Node` after the socket binds.
    pub advertise_endpoints: Vec<SocketAddr>,
    /// STUN servers to query from the same UDP socket before publishing our node.
    pub stun_servers: Vec<SocketAddr>,
    /// Per-server timeout for STUN binding requests.
    pub stun_timeout: Duration,
    /// How often to refresh mapped endpoints from STUN after startup.
    pub stun_refresh_interval: Duration,
    /// Whether direct peer UDP candidates may be discovered and selected.
    /// UDP peer-relay negotiation remains enabled when this is false.
    pub peer_direct_udp_enabled: bool,
    /// Our WireGuard node key.
    pub local_node_key: NodePublic,
    /// Our disco private key. Its public half must match our published node.
    pub local_disco: DiscoPrivate,
}

impl Options {
    /// Build options for a fixed UDP port and explicit advertised endpoints.
    pub fn new(
        bind_addr: SocketAddr,
        advertise_endpoints: Vec<SocketAddr>,
        local_node_key: NodePublic,
        local_disco: DiscoPrivate,
    ) -> Self {
        Self {
            bind_addr,
            advertise_endpoints,
            stun_servers: Vec::new(),
            stun_timeout: STUN_DISCOVERY_TIMEOUT,
            stun_refresh_interval: STUN_REFRESH_INTERVAL,
            peer_direct_udp_enabled: true,
            local_node_key,
            local_disco,
        }
    }

    /// Add STUN servers used to discover the socket's public mapped endpoint.
    pub fn with_stun_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// Override the per-server STUN timeout.
    pub fn with_stun_timeout(mut self, timeout: Duration) -> Self {
        self.stun_timeout = timeout;
        self
    }

    /// Override the STUN refresh interval.
    pub fn with_stun_refresh_interval(mut self, interval: Duration) -> Self {
        self.stun_refresh_interval = interval;
        self
    }

    /// Enable or disable direct peer UDP while retaining UDP peer relay.
    pub fn with_peer_direct_udp_enabled(mut self, enabled: bool) -> Self {
        self.peer_direct_udp_enabled = enabled;
        self
    }
}

/// Errors from direct UDP transport setup.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("udp bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("udp local addr: {0}")]
    LocalAddr(std::io::Error),
}

/// Non-secret counters for tests and future path reporting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub disco_udp_sent: u64,
    pub disco_udp_received: u64,
    pub disco_derp_sent: u64,
    pub disco_derp_received: u64,
    pub direct_wg_sent: u64,
    pub direct_wg_received: u64,
    pub peer_relay_wg_sent: u64,
    pub peer_relay_wg_received: u64,
    pub peer_relay_disco_sent: u64,
    pub peer_relay_disco_received: u64,
    pub peer_relay_drops: u64,
    pub peer_relay_unmatched: u64,
    pub fallback_wg_sent: u64,
}

#[derive(Default)]
struct StatsAtoms {
    disco_udp_sent: AtomicU64,
    disco_udp_received: AtomicU64,
    disco_derp_sent: AtomicU64,
    disco_derp_received: AtomicU64,
    direct_wg_sent: AtomicU64,
    direct_wg_received: AtomicU64,
    peer_relay_wg_sent: AtomicU64,
    peer_relay_wg_received: AtomicU64,
    peer_relay_disco_sent: AtomicU64,
    peer_relay_disco_received: AtomicU64,
    peer_relay_drops: AtomicU64,
    peer_relay_unmatched: AtomicU64,
    fallback_wg_sent: AtomicU64,
}

impl StatsAtoms {
    fn snapshot(&self) -> Stats {
        Stats {
            disco_udp_sent: self.disco_udp_sent.load(Ordering::Relaxed),
            disco_udp_received: self.disco_udp_received.load(Ordering::Relaxed),
            disco_derp_sent: self.disco_derp_sent.load(Ordering::Relaxed),
            disco_derp_received: self.disco_derp_received.load(Ordering::Relaxed),
            direct_wg_sent: self.direct_wg_sent.load(Ordering::Relaxed),
            direct_wg_received: self.direct_wg_received.load(Ordering::Relaxed),
            peer_relay_wg_sent: self.peer_relay_wg_sent.load(Ordering::Relaxed),
            peer_relay_wg_received: self.peer_relay_wg_received.load(Ordering::Relaxed),
            peer_relay_disco_sent: self.peer_relay_disco_sent.load(Ordering::Relaxed),
            peer_relay_disco_received: self.peer_relay_disco_received.load(Ordering::Relaxed),
            peer_relay_drops: self.peer_relay_drops.load(Ordering::Relaxed),
            peer_relay_unmatched: self.peer_relay_unmatched.load(Ordering::Relaxed),
            fallback_wg_sent: self.fallback_wg_sent.load(Ordering::Relaxed),
        }
    }
}

/// Handle returned alongside the wrapped transport.
#[derive(Clone)]
pub struct Handle {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
    peer_relay_requests: mpsc::UnboundedSender<PeerRelayRequest>,
    peer_relay_allocation_events:
        Arc<Mutex<Option<mpsc::UnboundedReceiver<PeerRelayAllocationEvent>>>>,
}

impl Handle {
    /// The UDP socket address actually bound on this host.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Endpoints safe for publishing in our coordinator `Node`.
    pub fn advertised_endpoints(&self) -> Vec<AddrPort> {
        self.shared.advertised_endpoints()
    }

    /// Whether a peer currently has an authenticated direct endpoint.
    pub fn has_verified_endpoint(&self, peer: &NodePublic) -> bool {
        self.shared
            .state
            .lock()
            .unwrap()
            .peers_by_node
            .get(peer.as_bytes())
            .and_then(PeerState::active_verified_endpoint)
            .is_some()
    }

    /// Non-secret transport counters.
    pub fn stats(&self) -> Stats {
        self.shared.stats.snapshot()
    }

    /// Non-secret path snapshot for a peer.
    pub fn path_for_peer(&self, peer: &NodePublic) -> PeerPath {
        path_for_peer(&self.shared, *peer)
    }

    /// Ask the direct-UDP adapter to start a shared UDP peer-relay path for a
    /// known peer. The endpoint descriptor must come from a trusted allocator
    /// and include this node's disco key plus the peer's disco key.
    pub fn request_peer_relay(
        &self,
        peer: NodePublic,
        endpoint: UDPRelayEndpoint,
    ) -> Result<(), PeerRelayRequestError> {
        self.request_peer_relay_with_bind_endpoint(peer, endpoint.clone(), endpoint)
    }

    /// Ask the direct-UDP adapter to bind to `bind_endpoint` while advertising
    /// `advertise_endpoint` to the peer. Kubernetes gateways use this to bind
    /// through the in-cluster relay service while remote clients receive the
    /// public relay tuple.
    pub fn request_peer_relay_with_bind_endpoint(
        &self,
        peer: NodePublic,
        bind_endpoint: UDPRelayEndpoint,
        advertise_endpoint: UDPRelayEndpoint,
    ) -> Result<(), PeerRelayRequestError> {
        self.peer_relay_requests
            .send(PeerRelayRequest {
                peer,
                bind_endpoint,
                advertise_endpoint,
                response_generation: None,
            })
            .map_err(|_| PeerRelayRequestError::Closed)
    }

    /// Ask the direct-UDP adapter to bind a trusted relay endpoint and answer a
    /// peer's DERP `AllocateUDPRelayEndpointRequest`.
    pub fn answer_peer_relay_allocation_with_bind_endpoint(
        &self,
        peer: NodePublic,
        generation: u32,
        bind_endpoint: UDPRelayEndpoint,
        advertise_endpoint: UDPRelayEndpoint,
    ) -> Result<(), PeerRelayRequestError> {
        self.peer_relay_requests
            .send(PeerRelayRequest {
                peer,
                bind_endpoint,
                advertise_endpoint,
                response_generation: Some(generation),
            })
            .map_err(|_| PeerRelayRequestError::Closed)
    }

    /// Take the one-shot receiver for peer-relay allocation requests observed
    /// over DERP. The gateway owns the allocator implementation; the tailnet
    /// crate only authenticates and surfaces the request.
    pub fn take_peer_relay_allocation_events(
        &self,
    ) -> Option<mpsc::UnboundedReceiver<PeerRelayAllocationEvent>> {
        self.peer_relay_allocation_events.lock().unwrap().take()
    }

    #[cfg(test)]
    fn expire_verified_endpoint_for_test(&self, peer: &NodePublic) {
        let mut state = self.shared.state.lock().unwrap();
        if let Some(peer) = state.peers_by_node.get_mut(peer.as_bytes()) {
            if let Some(mut verified) = peer.verified_endpoint {
                verified.verified_at =
                    Instant::now() - VERIFIED_ENDPOINT_TTL - Duration::from_secs(1);
                peer.verified_endpoint = Some(verified);
            }
        }
    }
}

/// Errors returned by [`Handle::request_peer_relay`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerRelayRequestError {
    #[error("direct UDP transport stopped")]
    Closed,
}

struct PeerRelayRequest {
    peer: NodePublic,
    bind_endpoint: UDPRelayEndpoint,
    advertise_endpoint: UDPRelayEndpoint,
    response_generation: Option<u32>,
}

/// Authenticated DERP allocation request from a known peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRelayAllocationEvent {
    pub peer: NodePublic,
    pub peer_disco: DiscoPublic,
    pub client_disco: [DiscoPublic; 2],
    pub generation: u32,
}

struct PendingPeerRelayRequest {
    bind_endpoint: UDPRelayEndpoint,
    advertise_endpoint: UDPRelayEndpoint,
    response_generation: Option<u32>,
}

struct Shared {
    local_node_key: NodePublic,
    local_disco: DiscoPrivate,
    peer_direct_udp_enabled: bool,
    peer_relay_allocation_events: mpsc::UnboundedSender<PeerRelayAllocationEvent>,
    advertise_endpoints: Mutex<Vec<SocketAddr>>,
    state: Mutex<State>,
    stats: StatsAtoms,
}

impl Shared {
    fn new(
        options: &Options,
        peer_relay_allocation_events: mpsc::UnboundedSender<PeerRelayAllocationEvent>,
    ) -> Self {
        Self {
            local_node_key: options.local_node_key,
            local_disco: options.local_disco.clone(),
            peer_direct_udp_enabled: options.peer_direct_udp_enabled,
            peer_relay_allocation_events,
            advertise_endpoints: Mutex::new(if options.peer_direct_udp_enabled {
                options.advertise_endpoints.clone()
            } else {
                Vec::new()
            }),
            state: Mutex::new(State::default()),
            stats: StatsAtoms::default(),
        }
    }

    fn advertised_socket_addrs(&self) -> Vec<SocketAddr> {
        self.advertise_endpoints.lock().unwrap().clone()
    }

    fn advertised_endpoints(&self) -> Vec<AddrPort> {
        self.advertised_socket_addrs()
            .into_iter()
            .map(AddrPort)
            .collect()
    }

    fn set_advertised_endpoints(&self, endpoints: Vec<SocketAddr>) {
        if self.peer_direct_udp_enabled {
            *self.advertise_endpoints.lock().unwrap() = endpoints;
        }
    }
}

#[derive(Default)]
struct State {
    peers_by_node: HashMap<[u8; 32], PeerState>,
    peers_by_disco: HashMap<[u8; 32], DiscoPeerIndex>,
    peers_by_endpoint: HashMap<SocketAddr, [u8; 32]>,
    peers_by_relay: HashMap<RelayKey, [u8; 32]>,
    pending_peer_relays: HashMap<[u8; 32], PendingPeerRelayRequest>,
    pending_tx: HashMap<[u8; 12], [u8; 32]>,
}

impl State {
    fn resolve_relay_peer(
        &mut self,
        source: SocketAddr,
        vni: u32,
        now: Instant,
    ) -> Option<[u8; 32]> {
        let key = RelayKey { addr: source, vni };
        if let Some(peer_key) = self.peers_by_relay.get(&key).copied() {
            return Some(peer_key);
        }

        let mut candidate = None;
        for (peer_key, peer) in &self.peers_by_node {
            let Some(relay) = peer.relay_endpoint.as_ref() else {
                continue;
            };
            if relay.vni != vni || !relay.is_bound() || !relay.is_fresh(now) {
                continue;
            }
            if candidate.is_some() {
                tracing::debug!(
                    relay_addr = %source,
                    relay_vni = vni,
                    "rust tailnet ignored ambiguous UDP peer relay source alias"
                );
                return None;
            }
            candidate = Some(*peer_key);
        }

        if let Some(peer_key) = candidate {
            self.peers_by_relay.insert(key, peer_key);
            tracing::debug!(
                relay_addr = %source,
                relay_vni = vni,
                "rust tailnet learned UDP peer relay source alias"
            );
        }

        candidate
    }

    fn remove_relay_keys_for_peer(&mut self, peer_key: &[u8; 32]) {
        self.peers_by_relay.retain(|_, mapped| mapped != peer_key);
    }
}

#[derive(Clone, Copy)]
enum DiscoPeerIndex {
    Unique([u8; 32]),
    Ambiguous,
}

#[derive(Clone, Copy)]
struct VerifiedEndpoint {
    addr: SocketAddr,
    verified_at: Instant,
}

impl VerifiedEndpoint {
    fn is_fresh(&self) -> bool {
        self.verified_at.elapsed() <= VERIFIED_ENDPOINT_TTL
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RelayKey {
    addr: SocketAddr,
    vni: u32,
}

#[derive(Clone)]
struct RelayPeerEndpoint {
    server_disco: DiscoPublic,
    remote_disco: DiscoPublic,
    addr: SocketAddr,
    lamport_id: u64,
    vni: u32,
    generation: u32,
    bind_expires_at: Instant,
    steady_state_lifetime: Duration,
    steady_expires_at: Option<Instant>,
    verified_at: Option<Instant>,
    retry_call_me_maybe_via: Option<UDPRelayEndpoint>,
}

impl RelayPeerEndpoint {
    fn key(&self) -> RelayKey {
        RelayKey {
            addr: self.addr,
            vni: self.vni,
        }
    }

    fn is_bound(&self) -> bool {
        self.steady_expires_at.is_some()
    }

    fn is_fresh(&self, now: Instant) -> bool {
        match self.steady_expires_at {
            Some(deadline) => now <= deadline,
            None => now <= self.bind_expires_at,
        }
    }

    fn active_addr(&self, now: Instant) -> Option<SocketAddr> {
        if self.is_bound() && self.verified_at.is_some() && self.is_fresh(now) {
            Some(self.addr)
        } else {
            None
        }
    }

    fn stale_key(&self, now: Instant) -> Option<RelayKey> {
        (!self.is_fresh(now)).then(|| self.key())
    }

    fn mark_bound(&mut self, now: Instant) {
        self.steady_expires_at = Some(now + self.steady_state_lifetime);
    }

    fn mark_verified(&mut self, now: Instant) {
        self.verified_at = Some(now);
        self.refresh(now);
    }

    fn refresh(&mut self, now: Instant) {
        if self.is_bound() {
            self.steady_expires_at = Some(now + self.steady_state_lifetime);
        }
    }
}

#[derive(Clone)]
struct PeerState {
    node_key: NodePublic,
    derp_key: DerpPublic,
    disco_key: DiscoPublic,
    endpoints: Vec<SocketAddr>,
    verified_endpoint: Option<VerifiedEndpoint>,
    direct_probe: DirectProbeState,
    relay_endpoint: Option<RelayPeerEndpoint>,
    preferred_derp: i32,
}

impl PeerState {
    fn active_verified_endpoint(&self) -> Option<SocketAddr> {
        self.verified_endpoint
            .filter(VerifiedEndpoint::is_fresh)
            .map(|verified| verified.addr)
    }

    fn active_relay_endpoint(&self, now: Instant) -> Option<SocketAddr> {
        self.relay_endpoint
            .as_ref()
            .and_then(|relay| relay.active_addr(now))
    }
}

#[derive(Clone)]
enum DirectProbeState {
    Inactive,
    Active(DirectProbe),
    Exhausted,
}

#[derive(Clone)]
struct DirectProbe {
    expires_at: Instant,
    candidates: Vec<DirectProbeCandidate>,
}

#[derive(Clone, Copy)]
struct DirectProbeCandidate {
    endpoint: SocketAddr,
    tx_id: [u8; 12],
}

enum DiscoTarget {
    Udp(SocketAddr),
    Relay { addr: SocketAddr, vni: u32 },
    Derp(DerpPublic),
}

struct DiscoAction {
    target: DiscoTarget,
    peer_disco: DiscoPublic,
    message: Message,
}

struct EndpointRefresh {
    static_endpoints: Vec<SocketAddr>,
    stun_servers: Vec<SocketAddr>,
    stun_timeout: Duration,
    stun_refresh_interval: Duration,
    endpoint_tracker: EndpointTracker,
    local_endpoint_updates: mpsc::UnboundedSender<Vec<AddrPort>>,
}

struct TransportChannels {
    from_conn: mpsc::UnboundedReceiver<WgDatagram>,
    to_conn: mpsc::UnboundedSender<WgDatagram>,
    peer_updates_rx: mpsc::UnboundedReceiver<Vec<Node>>,
    peer_relay_requests_rx: mpsc::UnboundedReceiver<PeerRelayRequest>,
}

struct PendingStun {
    server: SocketAddr,
    transaction_id: [u8; 12],
    expires_at: Instant,
}

/// Wrap `fallback` with direct UDP discovery/path selection.
///
/// The returned [`Transport`] has the same Conn-facing shape as DERP-only. The
/// adapter decides where to send each encrypted WireGuard datagram.
pub async fn wrap_transport(
    fallback: Transport,
    mut options: Options,
) -> Result<(Transport, Handle), Error> {
    let socket = UdpSocket::bind(options.bind_addr)
        .await
        .map_err(|source| Error::Bind {
            addr: options.bind_addr,
            source,
        })?;
    let local_addr = socket.local_addr().map_err(Error::LocalAddr)?;
    let static_endpoints = options.advertise_endpoints.clone();
    tracing::info!(
        bind_addr = %options.bind_addr,
        local_addr = %local_addr,
        static_endpoint_count = static_endpoints.len(),
        stun_server_count = options.stun_servers.len(),
        "rust tailnet direct UDP socket bound"
    );

    let mut endpoint_tracker = EndpointTracker::default();
    let discovered_endpoints = if options.peer_direct_udp_enabled {
        stun::discover_mapped_addrs(&socket, &options.stun_servers, options.stun_timeout).await
    } else {
        options.advertise_endpoints.clear();
        Vec::new()
    };
    let discovered_endpoint_count = discovered_endpoints.len();
    for endpoint in discovered_endpoints {
        if is_usable_direct_endpoint(endpoint) && !options.advertise_endpoints.contains(&endpoint) {
            options.advertise_endpoints.push(endpoint);
        }
    }
    options.advertise_endpoints = endpoint_tracker.update(options.advertise_endpoints.clone());
    tracing::info!(
        discovered_endpoint_count,
        advertised_endpoint_count = options.advertise_endpoints.len(),
        "rust tailnet startup STUN discovery complete"
    );
    let socket = Arc::new(socket);

    let stun_servers = if options.peer_direct_udp_enabled {
        options.stun_servers.clone()
    } else {
        Vec::new()
    };
    let stun_timeout = options.stun_timeout;
    let stun_refresh_interval = options.stun_refresh_interval;
    let (to_transport, from_conn) = mpsc::unbounded_channel::<WgDatagram>();
    let (to_conn, from_transport) = mpsc::unbounded_channel::<WgDatagram>();
    let (peer_updates, peer_updates_rx) = mpsc::unbounded_channel::<Vec<Node>>();
    let (local_endpoint_updates, local_endpoint_updates_rx) =
        mpsc::unbounded_channel::<Vec<AddrPort>>();
    let (peer_relay_requests, peer_relay_requests_rx) =
        mpsc::unbounded_channel::<PeerRelayRequest>();
    let (peer_relay_allocation_events, peer_relay_allocation_events_rx) =
        mpsc::unbounded_channel::<PeerRelayAllocationEvent>();
    let shared = Arc::new(Shared::new(&options, peer_relay_allocation_events));

    tokio::spawn(run_direct_transport(
        shared.clone(),
        socket,
        fallback,
        TransportChannels {
            from_conn,
            to_conn,
            peer_updates_rx,
            peer_relay_requests_rx,
        },
        EndpointRefresh {
            static_endpoints,
            stun_servers,
            stun_timeout,
            stun_refresh_interval,
            endpoint_tracker,
            local_endpoint_updates,
        },
    ));

    Ok((
        Transport {
            to_transport,
            from_transport,
            peer_updates: Some(peer_updates),
            path_probe: Some(Arc::new({
                let shared = shared.clone();
                move |peer| path_for_peer(&shared, peer)
            })),
            local_endpoint_updates: Some(local_endpoint_updates_rx),
        },
        Handle {
            shared,
            local_addr,
            peer_relay_requests,
            peer_relay_allocation_events: Arc::new(Mutex::new(Some(
                peer_relay_allocation_events_rx,
            ))),
        },
    ))
}

async fn run_direct_transport(
    shared: Arc<Shared>,
    socket: Arc<UdpSocket>,
    fallback: Transport,
    channels: TransportChannels,
    mut endpoint_refresh: EndpointRefresh,
) {
    let TransportChannels {
        mut from_conn,
        to_conn,
        mut peer_updates_rx,
        mut peer_relay_requests_rx,
    } = channels;
    let fallback_tx = fallback.to_transport;
    let mut fallback_rx = fallback.from_transport;
    let mut udp_buf = vec![0u8; UDP_PACKET_LIMIT];
    let mut stun_refresh = tokio::time::interval(endpoint_refresh.stun_refresh_interval);
    stun_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut peer_relay_bind_retry = tokio::time::interval(PEER_RELAY_BIND_RETRY_INTERVAL);
    peer_relay_bind_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_stun = Vec::<PendingStun>::new();
    let mut peer_relay_requests_closed = false;
    tracing::debug!(
        advertised_endpoint_count = shared.advertised_socket_addrs().len(),
        stun_server_count = endpoint_refresh.stun_servers.len(),
        "rust tailnet direct UDP transport loop started"
    );
    peer_relay_bind_retry.tick().await;

    loop {
        tokio::select! {
            _ = stun_refresh.tick(), if !endpoint_refresh.stun_servers.is_empty() => {
                refresh_advertised_endpoints(&shared, &mut endpoint_refresh, Vec::new());
                pending_stun = send_stun_refresh(&socket, &endpoint_refresh).await;
                tracing::debug!(
                    request_count = pending_stun.len(),
                    "rust tailnet STUN refresh sent"
                );
            }
            _ = peer_relay_bind_retry.tick() => {
                let now = Instant::now();
                let actions = retry_unverified_direct_candidates(&shared, now);
                if !actions.is_empty() {
                    tracing::debug!(
                        action_count = actions.len(),
                        "rust tailnet retrying unverified direct UDP candidates"
                    );
                }
                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;

                let actions = retry_unverified_peer_relay_negotiation(&shared, now);
                if !actions.is_empty() {
                    tracing::debug!(
                        action_count = actions.len(),
                        "rust tailnet retrying unverified UDP peer relay negotiation"
                    );
                }
                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
            }
            maybe = peer_updates_rx.recv() => {
                let Some(nodes) = maybe else { return; };
                let actions = apply_peer_update(&shared, nodes);
                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
            }
            maybe = peer_relay_requests_rx.recv(), if !peer_relay_requests_closed => {
                match maybe {
                    Some(request) => {
                        let actions = apply_peer_relay_request(&shared, request);
                        send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
                    }
                    None => peer_relay_requests_closed = true,
                }
            }
            maybe = from_conn.recv() => {
                let Some(dg) = maybe else { return; };
                send_wg_datagram(&shared, &socket, &fallback_tx, dg).await;
            }
            maybe = fallback_rx.recv() => {
                let Some(dg) = maybe else { return; };
                if disco::looks_like_wrapper(&dg.data) {
                    shared.stats.disco_derp_received.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        packet_len = dg.data.len(),
                        "rust tailnet DERP disco packet received"
                    );
                    handle_disco_packet(&shared, &socket, &fallback_tx, None, Some(dg.peer), &dg.data).await;
                } else {
                    let _ = to_conn.send(dg);
                }
            }
            recv = socket.recv_from(&mut udp_buf) => {
                let Ok((n, src)) = recv else { return; };
                let data = udp_buf[..n].to_vec();
                if let Some(mapped) = take_stun_response(&mut pending_stun, src, &data) {
                    tracing::debug!(
                        server = %src,
                        mapped_endpoint = %mapped,
                        "rust tailnet STUN refresh response"
                    );
                    apply_discovered_endpoint(&shared, &mut endpoint_refresh, mapped);
                } else {
                    if let Ok(packet) = udp_relay::decode_packet(&data) {
                        if handle_relay_packet(&shared, &socket, &fallback_tx, &to_conn, src, packet).await {
                            continue;
                        }
                    }
                    if disco::looks_like_wrapper(&data) {
                        shared.stats.disco_udp_received.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            source = %src,
                            packet_len = n,
                            "rust tailnet UDP disco packet received"
                        );
                        handle_disco_packet(&shared, &socket, &fallback_tx, Some(src), None, &data).await;
                    } else if let Some(peer) = verified_peer_for_endpoint(&shared, src) {
                        shared.stats.direct_wg_received.fetch_add(1, Ordering::Relaxed);
                        let _ = to_conn.send(WgDatagram {
                            peer: derp_public_from_node(peer),
                            data,
                        });
                    }
                }
            }
        }
    }
}

async fn send_stun_refresh(socket: &UdpSocket, refresh: &EndpointRefresh) -> Vec<PendingStun> {
    let mut pending = Vec::with_capacity(refresh.stun_servers.len());
    for server in &refresh.stun_servers {
        let request = stun::BindingRequest::new();
        match socket.send_to(&request.packet, server).await {
            Ok(_) => {
                pending.push(PendingStun {
                    server: *server,
                    transaction_id: request.transaction_id,
                    expires_at: Instant::now() + refresh.stun_timeout,
                });
            }
            Err(err) => {
                tracing::warn!(
                    server = %server,
                    error = %err,
                    "rust tailnet STUN refresh send failed"
                );
            }
        }
    }
    pending
}

fn take_stun_response(
    pending: &mut Vec<PendingStun>,
    source: SocketAddr,
    packet: &[u8],
) -> Option<SocketAddr> {
    let now = Instant::now();
    pending.retain(|request| request.expires_at >= now);
    let mut matched = None;
    for (idx, request) in pending.iter().enumerate() {
        if request.server != source {
            continue;
        }
        if let Ok(mapped) = stun::parse_binding_response(packet, request.transaction_id) {
            matched = Some((idx, mapped));
            break;
        }
    }
    let (idx, mapped) = matched?;
    pending.remove(idx);
    Some(mapped)
}

fn apply_discovered_endpoint(shared: &Shared, refresh: &mut EndpointRefresh, mapped: SocketAddr) {
    if !is_usable_direct_endpoint(mapped) {
        tracing::debug!(
            mapped_endpoint = %mapped,
            "rust tailnet ignored unusable STUN endpoint"
        );
        return;
    }
    refresh_advertised_endpoints(shared, refresh, vec![mapped]);
}

async fn handle_relay_packet(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    to_conn: &mpsc::UnboundedSender<WgDatagram>,
    source: SocketAddr,
    packet: RelayPacket<'_>,
) -> bool {
    match packet {
        RelayPacket::Control { vni, payload } => {
            let response = handle_relay_control_packet(shared, source, vni, payload);
            match response {
                RelayControlOutcome::Unknown => false,
                RelayControlOutcome::Drop => true,
                RelayControlOutcome::Answer { packet, actions } => {
                    if socket.send_to(&packet, source).await.is_ok() {
                        shared
                            .stats
                            .peer_relay_disco_sent
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    send_disco_actions(shared, socket, fallback_tx, actions).await;
                    true
                }
            }
        }
        RelayPacket::Disco { vni, payload } => {
            let Some(actions) = handle_relay_disco_packet(shared, source, vni, payload) else {
                return false;
            };
            send_disco_actions(shared, socket, fallback_tx, actions).await;
            true
        }
        RelayPacket::Data { vni, payload } => {
            let mut state = shared.state.lock().unwrap();
            let Some(peer_key) = state.resolve_relay_peer(source, vni, Instant::now()) else {
                shared
                    .stats
                    .peer_relay_unmatched
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    relay_addr = %source,
                    relay_vni = vni,
                    "rust tailnet dropped UDP peer relay data from unmatched source"
                );
                return false;
            };
            let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
                state.peers_by_relay.remove(&RelayKey { addr: source, vni });
                return true;
            };
            let Some(relay) = peer.relay_endpoint.as_mut() else {
                state.peers_by_relay.remove(&RelayKey { addr: source, vni });
                return true;
            };
            let now = Instant::now();
            if !relay.is_bound() || !relay.is_fresh(now) {
                shared
                    .stats
                    .peer_relay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return true;
            }
            relay.mark_verified(now);
            let peer = peer.derp_key.clone();
            let data = payload.to_vec();
            drop(state);
            shared
                .stats
                .peer_relay_wg_received
                .fetch_add(1, Ordering::Relaxed);
            let _ = to_conn.send(WgDatagram { peer, data });
            true
        }
    }
}

fn handle_relay_disco_packet(
    shared: &Shared,
    source: SocketAddr,
    vni: u32,
    payload: &[u8],
) -> Option<Vec<DiscoAction>> {
    let opened = match shared.local_disco.open(payload) {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(
                relay_addr = %source,
                relay_vni = vni,
                error = %err,
                "rust tailnet ignored undecodable UDP peer relay disco packet"
            );
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            return Some(Vec::new());
        }
    };
    let message_kind = disco_message_kind(&opened.message);
    tracing::debug!(
        relay_addr = %source,
        relay_vni = vni,
        message_kind,
        "rust tailnet UDP peer relay disco packet opened"
    );

    let mut state = shared.state.lock().unwrap();
    let peer_key = state.resolve_relay_peer(source, vni, Instant::now())?;
    let peer_disco = {
        let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
            state.peers_by_relay.remove(&RelayKey { addr: source, vni });
            return Some(Vec::new());
        };
        if peer.disco_key != opened.sender {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            return Some(Vec::new());
        }
        let Some(relay) = peer.relay_endpoint.as_mut() else {
            state.peers_by_relay.remove(&RelayKey { addr: source, vni });
            return Some(Vec::new());
        };
        let now = Instant::now();
        if !relay.is_bound() || !relay.is_fresh(now) {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            return Some(Vec::new());
        }
        relay.mark_verified(now);
        peer.disco_key
    };
    shared
        .stats
        .peer_relay_disco_received
        .fetch_add(1, Ordering::Relaxed);

    match opened.message {
        Message::Ping(ping) => Some(vec![DiscoAction {
            target: DiscoTarget::Relay { addr: source, vni },
            peer_disco,
            message: Message::Pong(Pong {
                tx_id: ping.tx_id,
                src: source,
            }),
        }]),
        Message::Pong(pong) => {
            let matched = state.pending_tx.remove(&pong.tx_id) == Some(peer_key);
            if matched {
                if let Some(peer) = state.peers_by_node.get_mut(&peer_key) {
                    if let Some(relay) = peer.relay_endpoint.as_mut() {
                        relay.mark_verified(Instant::now());
                    }
                }
            }
            Some(Vec::new())
        }
        _ => {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            Some(Vec::new())
        }
    }
}

enum RelayControlOutcome {
    Unknown,
    Drop,
    Answer {
        packet: Vec<u8>,
        actions: Vec<DiscoAction>,
    },
}

fn handle_relay_control_packet(
    shared: &Shared,
    source: SocketAddr,
    vni: u32,
    payload: &[u8],
) -> RelayControlOutcome {
    let opened = match shared.local_disco.open(payload) {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(
                relay_addr = %source,
                relay_vni = vni,
                error = %err,
                "rust tailnet ignored undecodable UDP peer relay control packet"
            );
            return RelayControlOutcome::Drop;
        }
    };

    let mut state = shared.state.lock().unwrap();
    let Some(peer_key) = state.resolve_relay_peer(source, vni, Instant::now()) else {
        return RelayControlOutcome::Unknown;
    };
    let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
        state.peers_by_relay.remove(&RelayKey { addr: source, vni });
        return RelayControlOutcome::Drop;
    };
    let Some(relay) = peer.relay_endpoint.as_mut() else {
        state.peers_by_relay.remove(&RelayKey { addr: source, vni });
        return RelayControlOutcome::Drop;
    };
    if relay.server_disco != opened.sender {
        shared
            .stats
            .peer_relay_drops
            .fetch_add(1, Ordering::Relaxed);
        return RelayControlOutcome::Drop;
    }

    match opened.message {
        Message::BindUDPRelayEndpointChallenge(challenge) => {
            let (
                peer_node_key,
                peer_disco,
                relay_server_disco,
                relay_addr,
                relay_vni,
                relay_generation,
                relay_remote_disco,
            ) = {
                if challenge.common.vni != relay.vni
                    || challenge.common.generation != relay.generation
                    || challenge.common.remote_key != relay.remote_disco
                {
                    shared
                        .stats
                        .peer_relay_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return RelayControlOutcome::Drop;
                }
                relay.mark_bound(Instant::now());
                (
                    peer.node_key,
                    peer.disco_key,
                    relay.server_disco,
                    relay.addr,
                    relay.vni,
                    relay.generation,
                    relay.remote_disco,
                )
            };
            let answer = Message::BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer {
                common: BindUDPRelayEndpointCommon {
                    vni: relay_vni,
                    generation: relay_generation,
                    remote_key: relay_remote_disco,
                    challenge: challenge.common.challenge,
                },
            });
            let packet = match shared
                .local_disco
                .seal_to(&relay_server_disco, &answer, &mut OsRng)
            {
                Ok(sealed) => udp_relay::encode_control_packet(relay_vni, &sealed),
                Err(_) => return RelayControlOutcome::Drop,
            };
            let ping = make_relay_ping_action(
                &mut state,
                &shared.local_node_key,
                peer_node_key,
                peer_disco,
                relay_addr,
                relay_vni,
            );
            shared
                .stats
                .peer_relay_disco_received
                .fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                relay_addr = %relay_addr,
                relay_vni,
                "rust tailnet UDP peer relay bind answered"
            );
            RelayControlOutcome::Answer {
                packet,
                actions: vec![ping],
            }
        }
        _ => {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            RelayControlOutcome::Drop
        }
    }
}

fn refresh_advertised_endpoints(
    shared: &Shared,
    refresh: &mut EndpointRefresh,
    discovered: Vec<SocketAddr>,
) {
    if !shared.peer_direct_udp_enabled {
        return;
    }
    let mut current = refresh.static_endpoints.clone();
    for endpoint in discovered {
        if !current.contains(&endpoint) {
            current.push(endpoint);
        }
    }

    let advertised = refresh.endpoint_tracker.update(current);
    if advertised == shared.advertised_socket_addrs() {
        return;
    }
    tracing::info!(
        advertised_endpoint_count = advertised.len(),
        "rust tailnet advertised direct UDP endpoints changed"
    );
    shared.set_advertised_endpoints(advertised.clone());
    let _ = refresh
        .local_endpoint_updates
        .send(advertised.into_iter().map(AddrPort).collect());
}

fn apply_peer_update(shared: &Shared, nodes: Vec<Node>) -> Vec<DiscoAction> {
    let mut state = shared.state.lock().unwrap();
    let previous = std::mem::take(&mut state.peers_by_node);
    state.peers_by_disco.clear();
    state.peers_by_endpoint.clear();
    state.peers_by_relay.clear();
    let previous_pending_tx = std::mem::take(&mut state.pending_tx);
    let now = Instant::now();
    let mut start_direct_probes = Vec::new();

    for node in nodes {
        if node.key.is_zero() || node.disco_key.is_zero() {
            continue;
        }
        let raw = *node.key.as_bytes();
        let mut endpoints = if shared.peer_direct_udp_enabled {
            node.endpoints.iter().map(|ep| ep.0).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        endpoints.retain(|endpoint| is_usable_direct_endpoint(*endpoint));
        endpoints.sort_unstable();
        endpoints.dedup();
        let previous_peer = previous.get(&raw);
        let candidates_unchanged = previous_peer
            .map(|peer| peer.disco_key == node.disco_key && peer.endpoints == endpoints)
            .unwrap_or(false);
        let verified_endpoint = if shared.peer_direct_udp_enabled && candidates_unchanged {
            previous_peer
                .and_then(PeerState::active_verified_endpoint)
                .map(|addr| VerifiedEndpoint {
                    addr,
                    verified_at: now,
                })
        } else {
            None
        };
        let relay_endpoint = previous_peer
            .and_then(|peer| peer.relay_endpoint.clone())
            .filter(|relay| relay.is_fresh(now));
        let direct_probe = if verified_endpoint.is_some() || endpoints.is_empty() {
            DirectProbeState::Inactive
        } else if candidates_unchanged {
            match previous_peer.map(|peer| peer.direct_probe.clone()) {
                Some(DirectProbeState::Active(probe)) if now < probe.expires_at => {
                    DirectProbeState::Active(probe)
                }
                Some(DirectProbeState::Active(_)) | Some(DirectProbeState::Exhausted) => {
                    DirectProbeState::Exhausted
                }
                Some(DirectProbeState::Inactive) | None => {
                    start_direct_probes.push(raw);
                    DirectProbeState::Inactive
                }
            }
        } else {
            start_direct_probes.push(raw);
            DirectProbeState::Inactive
        };
        let peer = PeerState {
            node_key: node.key,
            derp_key: derp_public_from_node(node.key),
            disco_key: node.disco_key,
            endpoints,
            verified_endpoint,
            direct_probe,
            relay_endpoint,
            preferred_derp: node.preferred_derp,
        };
        if let Some(endpoint) = verified_endpoint.map(|verified| verified.addr) {
            state.peers_by_endpoint.insert(endpoint, raw);
        }
        if let Some(relay) = &peer.relay_endpoint {
            state.peers_by_relay.insert(relay.key(), raw);
        }
        match state.peers_by_disco.get_mut(node.disco_key.as_bytes()) {
            Some(DiscoPeerIndex::Unique(existing)) if *existing == raw => {}
            Some(entry) => *entry = DiscoPeerIndex::Ambiguous,
            None => {
                state
                    .peers_by_disco
                    .insert(*node.disco_key.as_bytes(), DiscoPeerIndex::Unique(raw));
            }
        }
        state.peers_by_node.insert(raw, peer);
    }

    state.pending_tx = previous_pending_tx
        .into_iter()
        .filter(|(_, peer_key)| state.peers_by_node.contains_key(peer_key))
        .collect();

    let current_direct_transactions = state
        .peers_by_node
        .iter()
        .flat_map(|(peer_key, peer)| match &peer.direct_probe {
            DirectProbeState::Active(probe) => probe
                .candidates
                .iter()
                .map(|candidate| (candidate.tx_id, *peer_key))
                .collect::<Vec<_>>(),
            DirectProbeState::Inactive | DirectProbeState::Exhausted => Vec::new(),
        })
        .collect::<Vec<_>>();
    for peer in previous.values() {
        let DirectProbeState::Active(probe) = &peer.direct_probe else {
            continue;
        };
        for candidate in &probe.candidates {
            if !current_direct_transactions
                .iter()
                .any(|(tx_id, _)| *tx_id == candidate.tx_id)
            {
                state.pending_tx.remove(&candidate.tx_id);
            }
        }
    }
    for (tx_id, peer_key) in current_direct_transactions {
        state.pending_tx.insert(tx_id, peer_key);
    }

    let peer_count = state.peers_by_node.len();
    let peer_endpoint_count = state
        .peers_by_node
        .values()
        .map(|peer| peer.endpoints.len())
        .sum::<usize>();
    start_direct_probes.sort_unstable();
    start_direct_probes.dedup();
    let mut actions = Vec::new();
    for peer_key in start_direct_probes {
        actions.extend(start_direct_probe(
            &mut state,
            &shared.local_node_key,
            peer_key,
            now,
        ));
    }
    let pending_relay_peers = state
        .pending_peer_relays
        .keys()
        .copied()
        .filter(|peer_key| state.peers_by_node.contains_key(peer_key))
        .collect::<Vec<_>>();
    for peer_key in pending_relay_peers {
        let Some(pending) = state.pending_peer_relays.remove(&peer_key) else {
            continue;
        };
        actions.extend(apply_known_peer_relay_request(
            &mut state,
            shared,
            peer_key,
            pending.bind_endpoint,
            pending.advertise_endpoint,
            pending.response_generation,
        ));
    }
    let peers = state.peers_by_node.values().cloned().collect::<Vec<_>>();
    for peer in peers {
        if shared.peer_direct_udp_enabled {
            let advertised_endpoints = shared.advertised_socket_addrs();
            if !advertised_endpoints.is_empty() {
                actions.push(DiscoAction {
                    target: DiscoTarget::Derp(peer.derp_key.clone()),
                    peer_disco: peer.disco_key,
                    message: Message::CallMeMaybe(CallMeMaybe {
                        endpoints: advertised_endpoints,
                    }),
                });
            }
        }
    }
    tracing::debug!(
        peer_count,
        peer_endpoint_count,
        disco_action_count = actions.len(),
        advertised_endpoint_count = shared.advertised_socket_addrs().len(),
        "rust tailnet peer update applied"
    );
    actions
}

fn start_direct_probe(
    state: &mut State,
    local_node_key: &NodePublic,
    peer_key: [u8; 32],
    now: Instant,
) -> Vec<DiscoAction> {
    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
        return Vec::new();
    };
    let mut candidates = Vec::with_capacity(peer.endpoints.len());
    let mut actions = Vec::with_capacity(peer.endpoints.len());
    for endpoint in &peer.endpoints {
        let tx_id = register_pending_transaction(state, peer_key);
        candidates.push(DirectProbeCandidate {
            endpoint: *endpoint,
            tx_id,
        });
        actions.push(ping_action_with_transaction(
            local_node_key,
            peer.disco_key,
            *endpoint,
            tx_id,
        ));
    }
    if let Some(peer) = state.peers_by_node.get_mut(&peer_key) {
        peer.direct_probe = if candidates.is_empty() {
            DirectProbeState::Inactive
        } else {
            DirectProbeState::Active(DirectProbe {
                expires_at: now + DIRECT_PROBE_RETRY_WINDOW,
                candidates,
            })
        };
    }
    actions
}

fn register_pending_transaction(state: &mut State, peer_key: [u8; 32]) -> [u8; 12] {
    loop {
        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        if let std::collections::hash_map::Entry::Vacant(entry) = state.pending_tx.entry(tx_id) {
            entry.insert(peer_key);
            return tx_id;
        }
    }
}

fn ping_action_with_transaction(
    local_node_key: &NodePublic,
    peer_disco: DiscoPublic,
    endpoint: SocketAddr,
    tx_id: [u8; 12],
) -> DiscoAction {
    DiscoAction {
        target: DiscoTarget::Udp(endpoint),
        peer_disco,
        message: Message::Ping(Ping {
            tx_id,
            node_key: Some(*local_node_key),
            padding: 0,
        }),
    }
}

fn make_ping_action(
    state: &mut State,
    local_node_key: &NodePublic,
    peer: &PeerState,
    endpoint: SocketAddr,
) -> DiscoAction {
    let tx_id = register_pending_transaction(state, *peer.node_key.as_bytes());
    ping_action_with_transaction(local_node_key, peer.disco_key, endpoint, tx_id)
}

fn make_relay_ping_action(
    state: &mut State,
    local_node_key: &NodePublic,
    peer_node_key: NodePublic,
    peer_disco: DiscoPublic,
    relay_addr: SocketAddr,
    relay_vni: u32,
) -> DiscoAction {
    let tx_id = register_pending_transaction(state, *peer_node_key.as_bytes());
    DiscoAction {
        target: DiscoTarget::Relay {
            addr: relay_addr,
            vni: relay_vni,
        },
        peer_disco,
        message: Message::Ping(Ping {
            tx_id,
            node_key: Some(*local_node_key),
            padding: 0,
        }),
    }
}

async fn send_wg_datagram(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    dg: WgDatagram,
) {
    let sent = match active_path_for_peer(shared, dg.peer.as_bytes()) {
        Some(ActivePeerPath::Direct(endpoint)) => match socket.send_to(&dg.data, endpoint).await {
            Ok(_) => {
                shared.stats.direct_wg_sent.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    endpoint = %endpoint,
                    "rust tailnet sent WireGuard datagram over direct UDP"
                );
                true
            }
            Err(_) => false,
        },
        Some(ActivePeerPath::Relay { addr, vni }) => {
            let packet = udp_relay::encode_data_packet(vni, &dg.data);
            match socket.send_to(&packet, addr).await {
                Ok(_) => {
                    shared
                        .stats
                        .peer_relay_wg_sent
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::trace!(
                        relay_addr = %addr,
                        relay_vni = vni,
                        "rust tailnet sent WireGuard datagram over UDP peer relay"
                    );
                    true
                }
                Err(_) => false,
            }
        }
        None => false,
    };
    if sent {
        return;
    }

    shared
        .stats
        .fallback_wg_sent
        .fetch_add(1, Ordering::Relaxed);
    tracing::trace!("rust tailnet sent WireGuard datagram over fallback DERP");
    let _ = fallback_tx.send(dg);
}

async fn handle_disco_packet(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    source_addr: Option<SocketAddr>,
    derp_source: Option<DerpPublic>,
    packet: &[u8],
) {
    let opened = match shared.local_disco.open(packet) {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(
                source = source_addr.map(|addr| addr.to_string()).as_deref().unwrap_or("derp"),
                error = %err,
                "rust tailnet ignored undecodable disco packet"
            );
            return;
        }
    };
    let message_kind = disco_message_kind(&opened.message);
    tracing::debug!(
        source = source_addr
            .map(|addr| addr.to_string())
            .as_deref()
            .unwrap_or("derp"),
        message_kind,
        "rust tailnet disco packet opened"
    );

    let actions = {
        let mut state = shared.state.lock().unwrap();
        let peer_key = match &opened.message {
            Message::Pong(pong) => peer_key_for_pong(&state, opened.sender, &pong.tx_id),
            other => peer_key_for_message(&state, opened.sender, other, derp_source.as_ref()),
        };
        let peer_key = match peer_key {
            Some(peer_key) => peer_key,
            None => {
                tracing::debug!(
                    source = source_addr
                        .map(|addr| addr.to_string())
                        .as_deref()
                        .unwrap_or("derp"),
                    message_kind,
                    "rust tailnet ignored disco packet from unknown peer"
                );
                return;
            }
        };

        match opened.message {
            Message::Ping(ping) => {
                if let Some(addr) = source_addr {
                    if !shared.peer_direct_udp_enabled {
                        return;
                    }
                    state.verify_endpoint(peer_key, addr);
                    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                        return;
                    };
                    vec![DiscoAction {
                        target: DiscoTarget::Udp(addr),
                        peer_disco: peer.disco_key,
                        message: Message::Pong(Pong {
                            tx_id: ping.tx_id,
                            src: addr,
                        }),
                    }]
                } else if let Some(derp_source) = derp_source {
                    let source_key = *derp_source.as_bytes();
                    if source_key != peer_key {
                        return;
                    }
                    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                        return;
                    };
                    vec![DiscoAction {
                        target: DiscoTarget::Derp(peer.derp_key.clone()),
                        peer_disco: peer.disco_key,
                        message: Message::Pong(Pong {
                            tx_id: ping.tx_id,
                            src: derp_magic_addr(DEFAULT_DERP_REGION_ID),
                        }),
                    }]
                } else {
                    Vec::new()
                }
            }
            Message::Pong(pong) => {
                if shared.peer_direct_udp_enabled
                    && state.pending_tx.remove(&pong.tx_id) == Some(peer_key)
                {
                    if let Some(addr) = source_addr {
                        state.verify_endpoint(peer_key, addr);
                    }
                }
                Vec::new()
            }
            Message::CallMeMaybe(call) => {
                if source_addr.is_some() {
                    return;
                }
                let Some(derp_source) = derp_source else {
                    return;
                };
                let source_key = *derp_source.as_bytes();
                if source_key != peer_key {
                    return;
                }
                if !shared.peer_direct_udp_enabled {
                    tracing::debug!(
                        "rust tailnet ignored CallMeMaybe while direct peer UDP is disabled"
                    );
                    return;
                }
                let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                    return;
                };
                call.endpoints
                    .into_iter()
                    .filter(|addr| is_usable_direct_endpoint(*addr))
                    .map(|endpoint| {
                        make_ping_action(&mut state, &shared.local_node_key, &peer, endpoint)
                    })
                    .collect()
            }
            Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
                if source_addr.is_some() {
                    return;
                }
                let Some(derp_source) = derp_source else {
                    return;
                };
                let source_key = *derp_source.as_bytes();
                if source_key != peer_key {
                    return;
                }
                apply_call_me_maybe_via(&mut state, shared, peer_key, endpoint)
            }
            Message::AllocateUDPRelayEndpointRequest(request) => {
                if source_addr.is_some() {
                    return;
                }
                let Some(derp_source) = derp_source else {
                    return;
                };
                let source_key = *derp_source.as_bytes();
                if source_key != peer_key {
                    return;
                }
                let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                    return;
                };
                let local_disco = shared.local_disco.public();
                if !request.client_disco.contains(&opened.sender)
                    || !request.client_disco.contains(&local_disco)
                    || !request.client_disco.contains(&peer.disco_key)
                {
                    tracing::debug!(
                        "rust tailnet ignored UDP peer relay allocation request with mismatched disco keys"
                    );
                    return;
                }
                tracing::info!(
                    generation = request.generation,
                    "rust tailnet UDP peer relay allocation request received"
                );
                let _ = shared
                    .peer_relay_allocation_events
                    .send(PeerRelayAllocationEvent {
                        peer: peer.node_key,
                        peer_disco: peer.disco_key,
                        client_disco: request.client_disco,
                        generation: request.generation,
                    });
                Vec::new()
            }
            Message::BindUDPRelayEndpoint(_)
            | Message::BindUDPRelayEndpointChallenge(_)
            | Message::BindUDPRelayEndpointAnswer(_)
            | Message::AllocateUDPRelayEndpointResponse(_) => Vec::new(),
        }
    };

    send_disco_actions(shared, socket, fallback_tx, actions).await;
}

fn apply_call_me_maybe_via(
    state: &mut State,
    shared: &Shared,
    peer_key: [u8; 32],
    endpoint: UDPRelayEndpoint,
) -> Vec<DiscoAction> {
    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
        return Vec::new();
    };
    let Some(relay) =
        relay_endpoint_from_descriptor(endpoint, shared.local_disco.public(), peer.disco_key)
    else {
        tracing::debug!("rust tailnet ignored unusable UDP peer relay endpoint descriptor");
        return Vec::new();
    };
    if let Some(existing) = peer.relay_endpoint.as_ref() {
        if existing.server_disco == relay.server_disco {
            if relay.lamport_id < existing.lamport_id {
                tracing::debug!(
                    relay_addr = %relay.addr,
                    relay_vni = relay.vni,
                    relay_lamport_id = relay.lamport_id,
                    current_lamport_id = existing.lamport_id,
                    "rust tailnet ignored stale UDP peer relay notification"
                );
                return Vec::new();
            }
            if relay.lamport_id == existing.lamport_id {
                tracing::debug!(
                    relay_addr = %existing.addr,
                    relay_vni = existing.vni,
                    relay_lamport_id = existing.lamport_id,
                    "rust tailnet reused duplicate UDP peer relay notification"
                );
                return (existing.verified_at.is_none() && existing.is_fresh(Instant::now()))
                    .then(|| relay_bind_action(&peer, existing))
                    .into_iter()
                    .collect();
            }
        }
    }

    let action = relay_bind_action(&peer, &relay);
    register_relay_endpoint(state, peer_key, relay);
    vec![action]
}

fn relay_endpoint_from_descriptor(
    endpoint: UDPRelayEndpoint,
    local_disco: DiscoPublic,
    peer_disco: DiscoPublic,
) -> Option<RelayPeerEndpoint> {
    if endpoint.vni == 0
        || endpoint.server_disco.is_zero()
        || endpoint.bind_lifetime.is_zero()
        || endpoint.steady_state_lifetime.is_zero()
        || !endpoint.client_disco.contains(&local_disco)
        || !endpoint.client_disco.contains(&peer_disco)
    {
        return None;
    }
    let addr = endpoint
        .addr_ports
        .into_iter()
        .find(|addr| is_usable_direct_endpoint(*addr))?;
    let generation = nonzero_generation();
    Some(RelayPeerEndpoint {
        server_disco: endpoint.server_disco,
        remote_disco: peer_disco,
        addr,
        lamport_id: endpoint.lamport_id,
        vni: endpoint.vni,
        generation,
        bind_expires_at: Instant::now() + endpoint.bind_lifetime,
        steady_state_lifetime: endpoint.steady_state_lifetime,
        steady_expires_at: None,
        verified_at: None,
        retry_call_me_maybe_via: None,
    })
}

fn apply_peer_relay_request(shared: &Shared, request: PeerRelayRequest) -> Vec<DiscoAction> {
    let peer_key = *request.peer.as_bytes();
    let mut state = shared.state.lock().unwrap();
    if !state.peers_by_node.contains_key(&peer_key) {
        state.pending_peer_relays.insert(
            peer_key,
            PendingPeerRelayRequest {
                bind_endpoint: request.bind_endpoint,
                advertise_endpoint: request.advertise_endpoint,
                response_generation: request.response_generation,
            },
        );
        tracing::debug!("rust tailnet deferred UDP peer relay request for unknown peer");
        return Vec::new();
    };
    apply_known_peer_relay_request(
        &mut state,
        shared,
        peer_key,
        request.bind_endpoint,
        request.advertise_endpoint,
        request.response_generation,
    )
}

fn apply_known_peer_relay_request(
    state: &mut State,
    shared: &Shared,
    peer_key: [u8; 32],
    bind_endpoint: UDPRelayEndpoint,
    advertise_endpoint: UDPRelayEndpoint,
    response_generation: Option<u32>,
) -> Vec<DiscoAction> {
    let local_disco = shared.local_disco.public();
    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
        tracing::debug!("rust tailnet ignored UDP peer relay request for unknown peer");
        return Vec::new();
    };
    let now = Instant::now();
    if let Some(relay) = peer
        .relay_endpoint
        .as_ref()
        .filter(|relay| relay.is_fresh(now))
    {
        tracing::debug!(
            relay_addr = %relay.addr,
            relay_vni = relay.vni,
            "rust tailnet kept existing fresh UDP peer relay endpoint"
        );
        if let Some(generation) = response_generation {
            return vec![DiscoAction {
                target: DiscoTarget::Derp(peer.derp_key),
                peer_disco: peer.disco_key,
                message: Message::AllocateUDPRelayEndpointResponse(
                    AllocateUDPRelayEndpointResponse {
                        generation,
                        endpoint: advertise_endpoint,
                    },
                ),
            }];
        }
        return Vec::new();
    }
    let Some(mut relay) =
        relay_endpoint_from_descriptor(bind_endpoint, local_disco, peer.disco_key)
    else {
        tracing::debug!(
            "rust tailnet ignored unusable UDP peer relay endpoint descriptor from control path"
        );
        return Vec::new();
    };

    if response_generation.is_none() {
        relay.retry_call_me_maybe_via = Some(advertise_endpoint.clone());
    }
    let notify = if let Some(generation) = response_generation {
        Message::AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse {
            generation,
            endpoint: advertise_endpoint,
        })
    } else {
        Message::CallMeMaybeVia(CallMeMaybeVia {
            endpoint: advertise_endpoint,
        })
    };
    let bind = relay_bind_action(&peer, &relay);
    register_relay_endpoint(state, peer_key, relay);
    vec![
        bind,
        DiscoAction {
            target: DiscoTarget::Derp(peer.derp_key),
            peer_disco: peer.disco_key,
            message: notify,
        },
    ]
}

fn nonzero_generation() -> u32 {
    loop {
        let generation = OsRng.next_u32();
        if generation != 0 {
            return generation;
        }
    }
}

fn relay_bind_action(peer: &PeerState, relay: &RelayPeerEndpoint) -> DiscoAction {
    DiscoAction {
        target: DiscoTarget::Relay {
            addr: relay.addr,
            vni: relay.vni,
        },
        peer_disco: relay.server_disco,
        message: Message::BindUDPRelayEndpoint(BindUDPRelayEndpoint {
            common: BindUDPRelayEndpointCommon {
                vni: relay.vni,
                generation: relay.generation,
                remote_key: peer.disco_key,
                challenge: [0; 32],
            },
        }),
    }
}

fn retry_unverified_peer_relay_negotiation(shared: &Shared, now: Instant) -> Vec<DiscoAction> {
    let state = shared.state.lock().unwrap();
    let mut actions = Vec::new();
    for peer in state.peers_by_node.values() {
        let Some(relay) = peer.relay_endpoint.as_ref() else {
            continue;
        };
        if relay.verified_at.is_some() || now > relay.bind_expires_at {
            continue;
        }
        actions.push(relay_bind_action(peer, relay));
        if let Some(endpoint) = relay.retry_call_me_maybe_via.clone() {
            actions.push(DiscoAction {
                target: DiscoTarget::Derp(peer.derp_key.clone()),
                peer_disco: peer.disco_key,
                message: Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }),
            });
        }
    }
    actions
}

fn retry_unverified_direct_candidates(shared: &Shared, now: Instant) -> Vec<DiscoAction> {
    let mut state = shared.state.lock().unwrap();
    let peer_keys = state.peers_by_node.keys().copied().collect::<Vec<_>>();
    let mut actions = Vec::new();
    let mut retired_transactions = Vec::new();

    for peer_key in peer_keys {
        let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
            continue;
        };
        let probe_state = std::mem::replace(&mut peer.direct_probe, DirectProbeState::Inactive);
        match probe_state {
            DirectProbeState::Active(probe) if peer.active_verified_endpoint().is_some() => {
                retired_transactions.extend(
                    probe
                        .candidates
                        .into_iter()
                        .map(|candidate| candidate.tx_id),
                );
            }
            DirectProbeState::Active(probe) if now >= probe.expires_at => {
                retired_transactions.extend(
                    probe
                        .candidates
                        .into_iter()
                        .map(|candidate| candidate.tx_id),
                );
                peer.direct_probe = DirectProbeState::Exhausted;
            }
            DirectProbeState::Active(probe) => {
                actions.extend(probe.candidates.iter().map(|candidate| {
                    ping_action_with_transaction(
                        &shared.local_node_key,
                        peer.disco_key,
                        candidate.endpoint,
                        candidate.tx_id,
                    )
                }));
                peer.direct_probe = DirectProbeState::Active(probe);
            }
            DirectProbeState::Inactive => {}
            DirectProbeState::Exhausted => {
                peer.direct_probe = DirectProbeState::Exhausted;
            }
        }
    }

    for tx_id in retired_transactions {
        state.pending_tx.remove(&tx_id);
    }
    actions
}

fn register_relay_endpoint(state: &mut State, peer_key: [u8; 32], relay: RelayPeerEndpoint) {
    state.remove_relay_keys_for_peer(&peer_key);
    let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
        return;
    };
    peer.relay_endpoint = Some(relay.clone());
    state.peers_by_relay.insert(relay.key(), peer_key);
    tracing::info!(
        relay_addr = %relay.addr,
        relay_vni = relay.vni,
        "rust tailnet UDP peer relay bind started"
    );
}

fn peer_key_for_message(
    state: &State,
    sender: DiscoPublic,
    message: &Message,
    derp_source: Option<&DerpPublic>,
) -> Option<[u8; 32]> {
    if let Some(derp_source) = derp_source {
        let peer_key = *derp_source.as_bytes();
        let peer = state.peers_by_node.get(&peer_key)?;
        if peer.disco_key == sender {
            return Some(peer_key);
        }
    }
    if let Message::Ping(Ping {
        node_key: Some(node_key),
        ..
    }) = message
    {
        // A Ping plaintext can claim a node key, but the only authenticated
        // sender identity in a disco wrapper is the disco public key. Never
        // let an unknown disco key claim a known peer's direct endpoint.
        let peer = state.peers_by_node.get(node_key.as_bytes())?;
        if !node_key.is_zero() && peer.disco_key == sender {
            return Some(*node_key.as_bytes());
        }
    }
    if let Some(DiscoPeerIndex::Unique(peer_key)) = state.peers_by_disco.get(sender.as_bytes()) {
        return Some(*peer_key);
    }
    None
}

fn peer_key_for_pong(state: &State, sender: DiscoPublic, tx_id: &[u8; 12]) -> Option<[u8; 32]> {
    let peer_key = *state.pending_tx.get(tx_id)?;
    let peer = state.peers_by_node.get(&peer_key)?;
    if peer.disco_key == sender {
        Some(peer_key)
    } else {
        None
    }
}

async fn send_disco_actions(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    actions: Vec<DiscoAction>,
) {
    let udp_actions = actions
        .iter()
        .filter(|action| {
            matches!(
                &action.target,
                DiscoTarget::Udp(_) | DiscoTarget::Relay { .. }
            )
        })
        .count();
    let derp_actions = actions.len().saturating_sub(udp_actions);
    if !actions.is_empty() {
        tracing::debug!(
            udp_actions,
            derp_actions,
            "rust tailnet sending disco actions"
        );
    }
    for action in actions {
        let Ok(packet) =
            shared
                .local_disco
                .seal_to(&action.peer_disco, &action.message, &mut OsRng)
        else {
            continue;
        };
        match action.target {
            DiscoTarget::Udp(addr) => match socket.send_to(&packet, addr).await {
                Ok(bytes_sent) => {
                    shared.stats.disco_udp_sent.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        target = %addr,
                        bytes_sent,
                        message_kind = disco_message_kind(&action.message),
                        "rust tailnet UDP disco action sent"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        target = %addr,
                        error = %err,
                        message_kind = disco_message_kind(&action.message),
                        "rust tailnet UDP disco action send failed"
                    );
                }
            },
            DiscoTarget::Relay { addr, vni } => {
                let packet = if is_relay_control_message(&action.message) {
                    udp_relay::encode_control_packet(vni, &packet)
                } else {
                    udp_relay::encode_disco_packet(vni, &packet)
                };
                match socket.send_to(&packet, addr).await {
                    Ok(bytes_sent) => {
                        shared
                            .stats
                            .peer_relay_disco_sent
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            relay_addr = %addr,
                            relay_vni = vni,
                            bytes_sent,
                            message_kind = disco_message_kind(&action.message),
                            "rust tailnet UDP peer relay disco action sent"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            relay_addr = %addr,
                            relay_vni = vni,
                            error = %err,
                            message_kind = disco_message_kind(&action.message),
                            "rust tailnet UDP peer relay disco action send failed"
                        );
                    }
                }
            }
            DiscoTarget::Derp(peer) => {
                shared.stats.disco_derp_sent.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    message_kind = disco_message_kind(&action.message),
                    "rust tailnet DERP disco action sent"
                );
                let _ = fallback_tx.send(WgDatagram { peer, data: packet });
            }
        }
    }
}

fn is_relay_control_message(message: &Message) -> bool {
    matches!(
        message,
        Message::BindUDPRelayEndpoint(_) | Message::BindUDPRelayEndpointAnswer(_)
    )
}

fn disco_message_kind(message: &Message) -> &'static str {
    match message {
        Message::Ping(_) => "ping",
        Message::Pong(_) => "pong",
        Message::CallMeMaybe(_) => "call_me_maybe",
        Message::BindUDPRelayEndpoint(_) => "bind_udp_relay_endpoint",
        Message::BindUDPRelayEndpointChallenge(_) => "bind_udp_relay_endpoint_challenge",
        Message::BindUDPRelayEndpointAnswer(_) => "bind_udp_relay_endpoint_answer",
        Message::CallMeMaybeVia(_) => "call_me_maybe_via",
        Message::AllocateUDPRelayEndpointRequest(_) => "allocate_udp_relay_endpoint_request",
        Message::AllocateUDPRelayEndpointResponse(_) => "allocate_udp_relay_endpoint_response",
    }
}

fn verified_peer_for_endpoint(shared: &Shared, endpoint: SocketAddr) -> Option<NodePublic> {
    let state = shared.state.lock().unwrap();
    let peer_key = state.peers_by_endpoint.get(&endpoint)?;
    let peer = state.peers_by_node.get(peer_key)?;
    if peer.active_verified_endpoint() != Some(endpoint) {
        return None;
    }
    Some(NodePublic::from_raw(*peer_key))
}

impl State {
    fn verify_endpoint(&mut self, peer_key: [u8; 32], endpoint: SocketAddr) {
        if !is_usable_direct_endpoint(endpoint) {
            return;
        }
        let mut retired_transactions = Vec::new();
        if let Some(peer) = self.peers_by_node.get_mut(&peer_key) {
            let already_verified = peer.active_verified_endpoint() == Some(endpoint);
            if let DirectProbeState::Active(probe) =
                std::mem::replace(&mut peer.direct_probe, DirectProbeState::Inactive)
            {
                retired_transactions.extend(
                    probe
                        .candidates
                        .into_iter()
                        .map(|candidate| candidate.tx_id),
                );
            }
            if let Some(old) = peer.verified_endpoint.replace(VerifiedEndpoint {
                addr: endpoint,
                verified_at: Instant::now(),
            }) {
                self.peers_by_endpoint.remove(&old.addr);
            }
            self.peers_by_endpoint.insert(endpoint, peer_key);
            if !already_verified {
                tracing::info!(
                    endpoint = %endpoint,
                    "rust tailnet direct UDP endpoint verified"
                );
            }
        }
        for tx_id in retired_transactions {
            self.pending_tx.remove(&tx_id);
        }
    }
}

enum ActivePeerPath {
    Direct(SocketAddr),
    Relay { addr: SocketAddr, vni: u32 },
}

fn active_path_for_peer(shared: &Shared, peer_key: &[u8; 32]) -> Option<ActivePeerPath> {
    let mut state = shared.state.lock().unwrap();
    let mut expired_direct = None;
    let mut expired_relay = None;
    let path = {
        let peer = state.peers_by_node.get_mut(peer_key)?;
        if let Some(endpoint) = peer.active_verified_endpoint() {
            Some(ActivePeerPath::Direct(endpoint))
        } else {
            expired_direct = peer.verified_endpoint.take().map(|old| old.addr);
            let now = Instant::now();
            if let Some(relay) = peer.relay_endpoint.as_ref() {
                if let Some(addr) = relay.active_addr(now) {
                    return Some(ActivePeerPath::Relay {
                        addr,
                        vni: relay.vni,
                    });
                }
                expired_relay = relay.stale_key(now);
            }
            if expired_relay.is_some() {
                peer.relay_endpoint = None;
            }
            None
        }
    };
    if let Some(old) = expired_direct {
        state.peers_by_endpoint.remove(&old);
        tracing::debug!(
            endpoint = %old,
            "rust tailnet direct UDP endpoint expired"
        );
    }
    if let Some(old) = expired_relay {
        state.remove_relay_keys_for_peer(peer_key);
        tracing::debug!(
            relay_addr = %old.addr,
            relay_vni = old.vni,
            "rust tailnet UDP peer relay endpoint expired"
        );
    }
    path
}

fn path_for_peer(shared: &Shared, peer: NodePublic) -> PeerPath {
    let mut state = shared.state.lock().unwrap();
    let (preferred_derp, expired_direct, expired_relay) = {
        let Some(peer_state) = state.peers_by_node.get_mut(peer.as_bytes()) else {
            return PeerPath::unknown();
        };
        let preferred_derp = peer_state.preferred_derp;
        if let Some(endpoint) = peer_state.active_verified_endpoint() {
            return PeerPath::direct_udp(endpoint);
        }
        let now = Instant::now();
        if let Some(endpoint) = peer_state.active_relay_endpoint(now) {
            return PeerPath::peer_relay(endpoint);
        }
        let expired_relay = peer_state
            .relay_endpoint
            .as_ref()
            .and_then(|relay| relay.stale_key(now));
        if expired_relay.is_some() {
            peer_state.relay_endpoint = None;
        }
        let expired_direct = peer_state
            .verified_endpoint
            .take()
            .map(|verified| verified.addr);
        (preferred_derp, expired_direct, expired_relay)
    };
    if let Some(old) = expired_direct {
        state.peers_by_endpoint.remove(&old);
    }
    if expired_relay.is_some() {
        state.remove_relay_keys_for_peer(peer.as_bytes());
    }
    PeerPath::derp_relay(preferred_derp)
}

fn is_usable_direct_endpoint(endpoint: SocketAddr) -> bool {
    match endpoint.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified(),
        // Match magicsock's CallMeMaybe behavior: link-local IPv6 endpoints
        // need an interface scope to ping correctly, so ignore them here.
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_unicast_link_local(),
    }
}

fn derp_public_from_node(node: NodePublic) -> DerpPublic {
    DerpPublic::from_raw(*node.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use boringtun::x25519::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{sleep, Duration};
    use uuid::Uuid;

    use crate::conn::{Conn, Options as ConnOptions, PeerTransport};
    use crate::disco::AllocateUDPRelayEndpointRequest;
    use crate::node::Prefix;

    const A_IP: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000a);
    const B_IP: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000b);

    fn reserve_local_endpoint() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    fn fallback_pair(a_node: NodePublic, b_node: NodePublic) -> (Transport, Transport) {
        fallback_pair_filtering_a_to_b(a_node, b_node, |_| true)
    }

    fn fallback_pair_filtering_a_to_b(
        a_node: NodePublic,
        b_node: NodePublic,
        mut should_forward: impl FnMut(&WgDatagram) -> bool + Send + 'static,
    ) -> (Transport, Transport) {
        let (a_out_tx, mut a_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (b_out_tx, mut b_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<WgDatagram>();

        tokio::spawn(async move {
            while let Some(dg) = a_out_rx.recv().await {
                if !should_forward(&dg) {
                    continue;
                }
                let _ = b_in_tx.send(WgDatagram {
                    peer: derp_public_from_node(a_node),
                    data: dg.data,
                });
            }
        });
        tokio::spawn(async move {
            while let Some(dg) = b_out_rx.recv().await {
                let _ = a_in_tx.send(WgDatagram {
                    peer: derp_public_from_node(b_node),
                    data: dg.data,
                });
            }
        });

        (
            Transport {
                to_transport: a_out_tx,
                from_transport: a_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
            Transport {
                to_transport: b_out_tx,
                from_transport: b_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
        )
    }

    fn fallback_pair_drop_first_call_me_maybe_via(
        a_node: NodePublic,
        b_node: NodePublic,
        b_disco: DiscoPrivate,
    ) -> (Transport, Transport, Arc<AtomicU64>) {
        let dropped = Arc::new(AtomicU64::new(0));
        let task_dropped = dropped.clone();
        let pair = fallback_pair_filtering_a_to_b(a_node, b_node, move |dg| {
            let is_call_me_maybe_via = b_disco
                .open(&dg.data)
                .map(|opened| matches!(opened.message, Message::CallMeMaybeVia(_)))
                .unwrap_or(false);
            !is_call_me_maybe_via
                || task_dropped
                    .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_err()
        });
        (pair.0, pair.1, dropped)
    }

    fn shared_for_test(options: &Options) -> Shared {
        let (allocation_tx, _allocation_rx) = mpsc::unbounded_channel();
        Shared::new(options, allocation_tx)
    }

    fn shared_arc_for_test(options: &Options) -> Arc<Shared> {
        Arc::new(shared_for_test(options))
    }

    fn recording_fallback() -> (
        Transport,
        mpsc::UnboundedReceiver<WgDatagram>,
        mpsc::UnboundedSender<WgDatagram>,
    ) {
        let (out_tx, out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        (
            Transport {
                to_transport: out_tx,
                from_transport: in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
            out_rx,
            in_tx,
        )
    }

    async fn fake_stun_server(mapped: SocketAddr) -> SocketAddr {
        fake_stun_server_sequence(vec![mapped]).await
    }

    async fn fake_stun_server_sequence(mapped: Vec<SocketAddr>) -> SocketAddr {
        const BINDING_SUCCESS: u16 = 0x0101;
        const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
        const MAGIC_COOKIE: u32 = 0x2112_A442;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut mapped = mapped.into_iter();
            let mut last = None;
            let mut buf = [0u8; 1500];
            loop {
                let Ok((_, peer)) = server.recv_from(&mut buf).await else {
                    return;
                };
                let endpoint = match mapped.next() {
                    Some(endpoint) => {
                        last = Some(endpoint);
                        endpoint
                    }
                    None => match last {
                        Some(endpoint) => endpoint,
                        None => return,
                    },
                };
                let mut tx_id = [0u8; 12];
                tx_id.copy_from_slice(&buf[8..20]);

                let mut attr = Vec::new();
                attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
                match endpoint {
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
                    SocketAddr::V6(_) => unreachable!("test uses IPv4 mapped address"),
                }

                let mut packet = Vec::new();
                packet.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
                packet.extend_from_slice(&(attr.len() as u16).to_be_bytes());
                packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
                packet.extend_from_slice(&tx_id);
                packet.extend_from_slice(&attr);
                server.send_to(&packet, peer).await.unwrap();
            }
        });
        server_addr
    }

    async fn bind_answer_loss_relay(
        disco_a: DiscoPublic,
        disco_b: DiscoPublic,
    ) -> (
        UDPRelayEndpoint,
        Arc<Mutex<HashSet<SocketAddr>>>,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = socket.local_addr().unwrap();
        let relay_disco = DiscoPrivate::generate(&mut OsRng);
        let relay = Arc::new(Mutex::new(udp_relay::Server::new(
            relay_disco.clone(),
            vec![relay_addr],
        )));
        let endpoint = relay
            .lock()
            .unwrap()
            .allocate_endpoint(disco_a, disco_b)
            .unwrap();
        let dropped_sources = Arc::new(Mutex::new(HashSet::new()));
        let task_dropped_sources = dropped_sources.clone();
        let task_relay = relay.clone();
        let mut control_counts = HashMap::<SocketAddr, usize>::new();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_PACKET_LIMIT];
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => return,
                    received = socket.recv_from(&mut buf) => {
                        let Ok((n, source)) = received else { return; };
                        if let Ok(RelayPacket::Control { payload, .. }) =
                            udp_relay::decode_packet(&buf[..n])
                        {
                            let count = control_counts.entry(source).or_default();
                            *count += 1;
                            if *count == 2 {
                                let opened = relay_disco.open(payload).unwrap();
                                assert!(matches!(
                                    opened.message,
                                    Message::BindUDPRelayEndpointAnswer(_)
                                ));
                                task_dropped_sources.lock().unwrap().insert(source);
                                continue;
                            }
                        }
                        let output = task_relay
                            .lock()
                            .unwrap()
                            .handle_packet(source, &buf[..n])
                            .unwrap();
                        if let Some(output) = output {
                            socket.send_to(&output.packet, output.to).await.unwrap();
                        }
                    }
                }
            }
        });
        (endpoint, dropped_sources, shutdown_tx, task)
    }

    fn node(
        node_key: NodePublic,
        disco_key: DiscoPublic,
        endpoint: SocketAddr,
        ip: std::net::Ipv6Addr,
    ) -> Node {
        node_with_endpoints(node_key, disco_key, vec![endpoint], ip)
    }

    fn node_with_endpoints(
        node_key: NodePublic,
        disco_key: DiscoPublic,
        endpoints: Vec<SocketAddr>,
        ip: std::net::Ipv6Addr,
    ) -> Node {
        Node {
            id: Uuid::new_v4(),
            as_of: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            key: node_key,
            disco_key,
            preferred_derp: 1,
            derp_latency: None,
            endpoints: endpoints.into_iter().map(AddrPort).collect(),
            addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
        }
    }

    fn peer_state(node_key: NodePublic, disco_key: DiscoPublic, endpoint: SocketAddr) -> PeerState {
        PeerState {
            node_key,
            derp_key: derp_public_from_node(node_key),
            disco_key,
            endpoints: vec![endpoint],
            verified_endpoint: None,
            direct_probe: DirectProbeState::Inactive,
            relay_endpoint: None,
            preferred_derp: 1,
        }
    }

    fn udp_relay_endpoint(
        server_disco: DiscoPublic,
        local_disco: DiscoPublic,
        peer_disco: DiscoPublic,
        vni: u32,
        addr: SocketAddr,
    ) -> UDPRelayEndpoint {
        UDPRelayEndpoint {
            server_disco,
            client_disco: [local_disco, peer_disco],
            lamport_id: vni as u64,
            vni,
            bind_lifetime: Duration::from_secs(5),
            steady_state_lifetime: Duration::from_secs(30),
            addr_ports: vec![addr],
        }
    }

    fn peer_relay_retry_fixture() -> (Shared, NodePublic) {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        shared.state.lock().unwrap().peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
        let endpoint = udp_relay_endpoint(
            DiscoPrivate::generate(&mut OsRng).public(),
            local_disco.public(),
            peer_disco,
            9001,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641),
        );
        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint.clone(),
                advertise_endpoint: endpoint,
                response_generation: None,
            },
        );
        assert_eq!(actions.len(), 2);
        (shared, peer_node)
    }

    fn retry_call_me_maybe_via_endpoint(
        shared: &Shared,
        peer_node: &NodePublic,
    ) -> UDPRelayEndpoint {
        shared
            .state
            .lock()
            .unwrap()
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_ref()
            .unwrap()
            .retry_call_me_maybe_via
            .clone()
            .unwrap()
    }

    fn conn_options(
        secret: &StaticSecret,
        disco: DiscoPrivate,
        ip: std::net::Ipv6Addr,
        endpoints: Vec<AddrPort>,
    ) -> ConnOptions {
        ConnOptions {
            id: Uuid::new_v4(),
            addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
            endpoints,
            private_key: Some(secret.clone()),
            disco_private: Some(disco),
        }
    }

    async fn wait_verified(handle: &Handle, peer: &NodePublic) {
        for _ in 0..500 {
            if handle.has_verified_endpoint(peer) {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("direct UDP endpoint was not verified for peer");
    }

    async fn wait_peer_known(handle: &Handle, peer: &NodePublic) {
        for _ in 0..500 {
            if handle.path_for_peer(peer).transport != PeerTransport::Unknown {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("peer metadata was not applied before relay request");
    }

    async fn wait_peer_relay(handle: &Handle, peer: &NodePublic) {
        for _ in 0..500 {
            if handle.path_for_peer(peer).transport == PeerTransport::PeerRelay {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("UDP peer relay endpoint was not bound for peer");
    }

    async fn wait_stats(handle: &Handle, predicate: impl Fn(&Stats) -> bool, message: &str) {
        for _ in 0..500 {
            let stats = handle.stats();
            if predicate(&stats) {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("{message}; final stats: {:?}", handle.stats());
    }

    #[test]
    fn peer_relay_request_binds_internal_endpoint_and_advertises_public_endpoint() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco, reserve_local_endpoint()),
            );
        }

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
        let endpoint = UDPRelayEndpoint {
            server_disco: DiscoPrivate::generate(&mut OsRng).public(),
            client_disco: [local_disco.public(), peer_disco],
            lamport_id: 7,
            vni: 9001,
            bind_lifetime: Duration::from_secs(5),
            steady_state_lifetime: Duration::from_secs(30),
            addr_ports: vec![bind_addr],
        };
        let mut advertised_endpoint = endpoint.clone();
        advertised_endpoint.addr_ports = vec![advertised_addr];

        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint,
                advertise_endpoint: advertised_endpoint.clone(),
                response_generation: None,
            },
        );

        assert_eq!(actions.len(), 2);
        match &actions[0].target {
            DiscoTarget::Relay { addr, vni } => {
                assert_eq!(*addr, bind_addr);
                assert_eq!(*vni, 9001);
            }
            _ => panic!("expected relay bind action"),
        }
        match &actions[1].message {
            Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
                assert_eq!(endpoint.addr_ports, vec![advertised_addr]);
                assert_eq!(endpoint.vni, 9001);
            }
            other => panic!("expected CallMeMaybeVia action, got {other:?}"),
        }
        {
            let state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
            assert_eq!(peer.relay_endpoint.as_ref().unwrap().addr, bind_addr);
        }

        let retries = retry_unverified_peer_relay_negotiation(&shared, Instant::now());
        assert_eq!(retries.len(), 2);
        match &retries[0].target {
            DiscoTarget::Relay { addr, vni } => {
                assert_eq!(*addr, bind_addr);
                assert_eq!(*vni, 9001);
            }
            _ => panic!("expected retry to target internal relay bind address"),
        }
        match &retries[1].message {
            Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
                assert_eq!(endpoint.addr_ports, vec![advertised_addr]);
                assert_eq!(endpoint.vni, 9001);
            }
            other => panic!("expected retried CallMeMaybeVia action, got {other:?}"),
        }
    }

    #[test]
    fn peer_relay_allocation_answer_uses_allocate_response_message() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco, reserve_local_endpoint()),
            );
        }

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
        let endpoint = udp_relay_endpoint(
            DiscoPrivate::generate(&mut OsRng).public(),
            local_disco.public(),
            peer_disco,
            9001,
            bind_addr,
        );
        let mut advertised_endpoint = endpoint.clone();
        advertised_endpoint.addr_ports = vec![advertised_addr];

        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint,
                advertise_endpoint: advertised_endpoint.clone(),
                response_generation: Some(77),
            },
        );

        assert_eq!(actions.len(), 2);
        let Message::AllocateUDPRelayEndpointResponse(response) = &actions[1].message else {
            panic!("expected AllocateUDPRelayEndpointResponse");
        };
        assert_eq!(response.generation, 77);
        assert_eq!(response.endpoint, advertised_endpoint);
    }

    #[test]
    fn peer_relay_request_keeps_fresh_existing_relay_endpoint() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco, reserve_local_endpoint()),
            );
        }

        let server_disco = DiscoPrivate::generate(&mut OsRng).public();
        let first_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let second_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41642);
        let first_advertised_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
        let second_advertised_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41642);
        let first_endpoint = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9001,
            first_bind_addr,
        );
        let first_advertised = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9001,
            first_advertised_addr,
        );
        let second_endpoint = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9002,
            second_bind_addr,
        );
        let second_advertised = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9002,
            second_advertised_addr,
        );

        let first_actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: first_endpoint,
                advertise_endpoint: first_advertised,
                response_generation: None,
            },
        );
        assert_eq!(first_actions.len(), 2);

        let second_actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: second_endpoint,
                advertise_endpoint: second_advertised,
                response_generation: None,
            },
        );
        assert!(
            second_actions.is_empty(),
            "a repeated allocation must not churn a fresh relay path"
        );

        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        let relay = peer.relay_endpoint.as_ref().unwrap();
        assert_eq!(relay.addr, first_bind_addr);
        assert_eq!(relay.vni, 9001);
        assert!(state.peers_by_relay.contains_key(&RelayKey {
            addr: first_bind_addr,
            vni: 9001
        }));
        assert!(!state.peers_by_relay.contains_key(&RelayKey {
            addr: second_bind_addr,
            vni: 9002
        }));
    }

    #[test]
    fn bound_peer_relay_requires_verification_before_selection() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco, reserve_local_endpoint()),
            );
        }

        let server_disco = DiscoPrivate::generate(&mut OsRng).public();
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let endpoint = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9001,
            bind_addr,
        );
        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint.clone(),
                advertise_endpoint: endpoint,
                response_generation: None,
            },
        );
        assert_eq!(actions.len(), 2);

        {
            let mut state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
            peer.relay_endpoint
                .as_mut()
                .unwrap()
                .mark_bound(Instant::now());
        }

        let unverified = path_for_peer(&shared, peer_node);
        assert_eq!(unverified.transport, PeerTransport::DerpRelay);
        {
            let state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
            let relay = peer.relay_endpoint.as_ref().unwrap();
            assert_eq!(relay.addr, bind_addr);
            assert_eq!(relay.vni, 9001);
            assert!(state.peers_by_relay.contains_key(&RelayKey {
                addr: bind_addr,
                vni: 9001
            }));
        }

        {
            let mut state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
            peer.relay_endpoint
                .as_mut()
                .unwrap()
                .mark_verified(Instant::now());
        }

        let verified = path_for_peer(&shared, peer_node);
        assert_eq!(verified.transport, PeerTransport::PeerRelay);
        assert_eq!(verified.endpoint, Some(bind_addr));
    }

    #[test]
    fn unverified_peer_relay_retries_bind_and_notification() {
        let (shared, _peer_node) = peer_relay_retry_fixture();

        let retries = retry_unverified_peer_relay_negotiation(&shared, Instant::now());

        assert_eq!(retries.len(), 2);
        assert!(matches!(
            retries[0].message,
            Message::BindUDPRelayEndpoint(_)
        ));
        assert!(matches!(retries[1].message, Message::CallMeMaybeVia(_)));
    }

    #[test]
    fn duplicate_call_me_maybe_via_reuses_relay_generation() {
        let (shared, peer_node) = peer_relay_retry_fixture();
        let endpoint = retry_call_me_maybe_via_endpoint(&shared, &peer_node);
        let (generation, bind_expires_at) = {
            let state = shared.state.lock().unwrap();
            let relay = state
                .peers_by_node
                .get(peer_node.as_bytes())
                .unwrap()
                .relay_endpoint
                .as_ref()
                .unwrap();
            (relay.generation, relay.bind_expires_at)
        };

        let duplicate_actions = {
            let mut state = shared.state.lock().unwrap();
            apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), endpoint.clone())
        };
        assert_eq!(duplicate_actions.len(), 1);
        assert!(matches!(
            duplicate_actions[0].message,
            Message::BindUDPRelayEndpoint(_)
        ));
        {
            let state = shared.state.lock().unwrap();
            let relay = state
                .peers_by_node
                .get(peer_node.as_bytes())
                .unwrap()
                .relay_endpoint
                .as_ref()
                .unwrap();
            assert_eq!(relay.generation, generation);
            assert_eq!(relay.bind_expires_at, bind_expires_at);
        }

        {
            let mut state = shared.state.lock().unwrap();
            state
                .peers_by_node
                .get_mut(peer_node.as_bytes())
                .unwrap()
                .relay_endpoint
                .as_mut()
                .unwrap()
                .mark_verified(Instant::now());
            assert!(
                apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), endpoint,)
                    .is_empty()
            );
        }
    }

    #[test]
    fn newer_call_me_maybe_via_replaces_older_allocation() {
        let (shared, peer_node) = peer_relay_retry_fixture();
        let mut newer = retry_call_me_maybe_via_endpoint(&shared, &peer_node);
        let old_key = RelayKey {
            addr: newer.addr_ports[0],
            vni: newer.vni,
        };
        newer.lamport_id += 1;
        newer.vni += 1;
        newer.addr_ports = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41642)];

        let actions = {
            let mut state = shared.state.lock().unwrap();
            apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), newer.clone())
        };
        assert_eq!(actions.len(), 1);

        let state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_ref()
            .unwrap();
        assert_eq!(relay.server_disco, newer.server_disco);
        assert_eq!(relay.lamport_id, newer.lamport_id);
        assert_eq!(relay.vni, newer.vni);
        assert_eq!(relay.addr, newer.addr_ports[0]);
        assert!(!state.peers_by_relay.contains_key(&old_key));
        assert!(state.peers_by_relay.contains_key(&RelayKey {
            addr: newer.addr_ports[0],
            vni: newer.vni,
        }));
    }

    #[test]
    fn stale_call_me_maybe_via_does_not_replace_newer_allocation() {
        let (shared, peer_node) = peer_relay_retry_fixture();
        let older = retry_call_me_maybe_via_endpoint(&shared, &peer_node);
        let mut newer = older.clone();
        newer.lamport_id += 1;
        newer.vni += 1;
        newer.addr_ports = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41642)];
        {
            let mut state = shared.state.lock().unwrap();
            assert_eq!(
                apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), newer.clone(),)
                    .len(),
                1
            );
        }
        let (generation, bind_expires_at) = {
            let state = shared.state.lock().unwrap();
            let relay = state
                .peers_by_node
                .get(peer_node.as_bytes())
                .unwrap()
                .relay_endpoint
                .as_ref()
                .unwrap();
            (relay.generation, relay.bind_expires_at)
        };

        let stale_actions = {
            let mut state = shared.state.lock().unwrap();
            apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), older)
        };
        assert!(stale_actions.is_empty());

        let state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_ref()
            .unwrap();
        assert_eq!(relay.lamport_id, newer.lamport_id);
        assert_eq!(relay.vni, newer.vni);
        assert_eq!(relay.addr, newer.addr_ports[0]);
        assert_eq!(relay.generation, generation);
        assert_eq!(relay.bind_expires_at, bind_expires_at);
    }

    #[test]
    fn verified_peer_relay_stops_bind_retries() {
        let (shared, peer_node) = peer_relay_retry_fixture();
        {
            let mut state = shared.state.lock().unwrap();
            let relay = state
                .peers_by_node
                .get_mut(peer_node.as_bytes())
                .unwrap()
                .relay_endpoint
                .as_mut()
                .unwrap();
            relay.mark_bound(Instant::now());
            relay.mark_verified(Instant::now());
        }

        assert!(retry_unverified_peer_relay_negotiation(&shared, Instant::now()).is_empty());
    }

    #[test]
    fn expired_peer_relay_stops_bind_retries() {
        let (shared, peer_node) = peer_relay_retry_fixture();
        {
            let mut state = shared.state.lock().unwrap();
            state
                .peers_by_node
                .get_mut(peer_node.as_bytes())
                .unwrap()
                .relay_endpoint
                .as_mut()
                .unwrap()
                .bind_expires_at = Instant::now() - Duration::from_millis(1);
        }

        assert!(retry_unverified_peer_relay_negotiation(&shared, Instant::now()).is_empty());
    }

    #[tokio::test]
    async fn peer_relay_data_accepts_observed_source_alias_after_bind() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco, reserve_local_endpoint()),
            );
        }

        let server_disco = DiscoPrivate::generate(&mut OsRng).public();
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let source_alias = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 41641);
        let endpoint = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9001,
            bind_addr,
        );
        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint.clone(),
                advertise_endpoint: endpoint,
                response_generation: None,
            },
        );
        assert_eq!(actions.len(), 2);
        {
            let mut state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
            peer.relay_endpoint
                .as_mut()
                .unwrap()
                .mark_bound(Instant::now());
        }

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (fallback_tx, _fallback_rx) = mpsc::unbounded_channel();
        let (to_conn_tx, mut to_conn_rx) = mpsc::unbounded_channel();
        let payload = b"encrypted wireguard packet from relay source alias";
        let handled = handle_relay_packet(
            &shared,
            &socket,
            &fallback_tx,
            &to_conn_tx,
            source_alias,
            RelayPacket::Data { vni: 9001, payload },
        )
        .await;

        assert!(handled);
        let got = tokio::time::timeout(Duration::from_secs(1), to_conn_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.peer.as_bytes(), peer_node.as_bytes());
        assert_eq!(got.data, payload);
        assert_eq!(shared.stats.snapshot().peer_relay_wg_received, 1);

        let state = shared.state.lock().unwrap();
        assert_eq!(
            state
                .peers_by_relay
                .get(&RelayKey {
                    addr: source_alias,
                    vni: 9001,
                })
                .copied(),
            Some(*peer_node.as_bytes())
        );
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        let relay = peer.relay_endpoint.as_ref().unwrap();
        assert_eq!(
            relay.addr, bind_addr,
            "outbound relay address stays canonical"
        );
        assert_eq!(relay.active_addr(Instant::now()), Some(bind_addr));
    }

    #[test]
    fn peer_relay_source_alias_is_not_learned_when_vni_is_ambiguous() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let first_secret = StaticSecret::random_from_rng(OsRng);
        let second_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let first_node = NodePublic::from_raw(PublicKey::from(&first_secret).to_bytes());
        let second_node = NodePublic::from_raw(PublicKey::from(&second_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let first_disco = DiscoPrivate::generate(&mut OsRng).public();
        let second_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *first_node.as_bytes(),
                peer_state(first_node, first_disco, reserve_local_endpoint()),
            );
            state.peers_by_node.insert(
                *second_node.as_bytes(),
                peer_state(second_node, second_disco, reserve_local_endpoint()),
            );
        }

        let server_disco = DiscoPrivate::generate(&mut OsRng).public();
        for (peer, disco, addr) in [
            (
                first_node,
                first_disco,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 41641),
            ),
            (
                second_node,
                second_disco,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)), 41641),
            ),
        ] {
            let endpoint =
                udp_relay_endpoint(server_disco, local_disco.public(), disco, 9001, addr);
            let actions = apply_peer_relay_request(
                &shared,
                PeerRelayRequest {
                    peer,
                    bind_endpoint: endpoint.clone(),
                    advertise_endpoint: endpoint,
                    response_generation: None,
                },
            );
            assert_eq!(actions.len(), 2);
            let mut state = shared.state.lock().unwrap();
            let peer_state = state.peers_by_node.get_mut(peer.as_bytes()).unwrap();
            peer_state
                .relay_endpoint
                .as_mut()
                .unwrap()
                .mark_bound(Instant::now());
        }

        let source_alias = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 12)), 41641);
        let mut state = shared.state.lock().unwrap();
        assert_eq!(
            state.resolve_relay_peer(source_alias, 9001, Instant::now()),
            None
        );
        assert!(!state.peers_by_relay.contains_key(&RelayKey {
            addr: source_alias,
            vni: 9001,
        }));
    }

    #[test]
    fn peer_relay_allocation_request_answers_when_existing_relay_is_fresh() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco, reserve_local_endpoint()),
            );
        }

        let server_disco = DiscoPrivate::generate(&mut OsRng).public();
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
        let endpoint = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9001,
            bind_addr,
        );
        let advertised = udp_relay_endpoint(
            server_disco,
            local_disco.public(),
            peer_disco,
            9001,
            advertised_addr,
        );

        let first_actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint.clone(),
                advertise_endpoint: advertised.clone(),
                response_generation: None,
            },
        );
        assert_eq!(first_actions.len(), 2);

        let response_actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint,
                advertise_endpoint: advertised.clone(),
                response_generation: Some(44),
            },
        );
        assert_eq!(
            response_actions.len(),
            1,
            "fresh proactive relay should still answer the peer allocation request"
        );
        let Message::AllocateUDPRelayEndpointResponse(response) = &response_actions[0].message
        else {
            panic!("expected AllocateUDPRelayEndpointResponse");
        };
        assert_eq!(response.generation, 44);
        assert_eq!(response.endpoint, advertised);
    }

    #[test]
    fn peer_update_preserves_pending_pongs_for_existing_peer_only() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco,
        );
        let shared = shared_for_test(&options);
        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        {
            let mut state = shared.state.lock().unwrap();
            state.pending_tx.insert(tx_id, *peer_node.as_bytes());
        }

        let _ = apply_peer_update(
            &shared,
            vec![node_with_endpoints(peer_node, peer_disco, Vec::new(), B_IP)],
        );
        assert_eq!(
            shared.state.lock().unwrap().pending_tx.get(&tx_id),
            Some(peer_node.as_bytes()),
            "repeated peer updates must not invalidate in-flight disco pongs"
        );

        let _ = apply_peer_update(&shared, Vec::new());
        assert!(
            !shared.state.lock().unwrap().pending_tx.contains_key(&tx_id),
            "peer removal should drop stale pending pongs"
        );
    }

    #[test]
    fn peer_relay_request_waits_for_late_peer_update() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_for_test(&options);

        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
        let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
        let endpoint = UDPRelayEndpoint {
            server_disco: DiscoPrivate::generate(&mut OsRng).public(),
            client_disco: [local_disco.public(), peer_disco],
            lamport_id: 7,
            vni: 9001,
            bind_lifetime: Duration::from_secs(5),
            steady_state_lifetime: Duration::from_secs(30),
            addr_ports: vec![bind_addr],
        };
        let mut advertised_endpoint = endpoint.clone();
        advertised_endpoint.addr_ports = vec![advertised_addr];

        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint,
                advertise_endpoint: advertised_endpoint.clone(),
                response_generation: None,
            },
        );
        assert!(
            actions.is_empty(),
            "unknown-peer relay requests should wait for the peer update"
        );

        let actions = apply_peer_update(
            &shared,
            vec![node_with_endpoints(peer_node, peer_disco, Vec::new(), B_IP)],
        );

        assert_eq!(actions.len(), 2);
        match &actions[0].target {
            DiscoTarget::Relay { addr, vni } => {
                assert_eq!(*addr, bind_addr);
                assert_eq!(*vni, 9001);
            }
            _ => panic!("expected relay bind action"),
        }
        match &actions[1].message {
            Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
                assert_eq!(endpoint.addr_ports, vec![advertised_addr]);
                assert_eq!(endpoint.vni, 9001);
            }
            other => panic!("expected CallMeMaybeVia action, got {other:?}"),
        }
        let state = shared.state.lock().unwrap();
        assert!(state.pending_peer_relays.is_empty());
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        assert_eq!(peer.relay_endpoint.as_ref().unwrap().addr, bind_addr);
    }

    #[tokio::test]
    async fn allocate_udp_relay_endpoint_request_emits_event() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng);
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let (allocation_tx, mut allocation_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::new(&options, allocation_tx));
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco.public(), reserve_local_endpoint()),
            );
        }

        let message = Message::AllocateUDPRelayEndpointRequest(AllocateUDPRelayEndpointRequest {
            client_disco: [peer_disco.public(), local_disco.public()],
            generation: 88,
        });
        let packet = peer_disco
            .seal_to(&local_disco.public(), &message, &mut OsRng)
            .expect("seal allocation request");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (fallback_tx, _fallback_rx) = mpsc::unbounded_channel();

        handle_disco_packet(
            &shared,
            &socket,
            &fallback_tx,
            None,
            Some(derp_public_from_node(peer_node)),
            &packet,
        )
        .await;

        let event = allocation_rx.try_recv().expect("allocation event");
        assert_eq!(event.peer, peer_node);
        assert_eq!(event.peer_disco, peer_disco.public());
        assert_eq!(
            event.client_disco,
            [peer_disco.public(), local_disco.public()]
        );
        assert_eq!(event.generation, 88);
    }

    #[tokio::test]
    async fn derp_disco_ping_pong_uses_tailscale_magic_source() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng);
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco.clone(),
        );
        let shared = shared_arc_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *peer_node.as_bytes(),
                peer_state(peer_node, peer_disco.public(), reserve_local_endpoint()),
            );
        }

        let tx_id = [7u8; 12];
        let message = Message::Ping(Ping {
            tx_id,
            node_key: Some(peer_node),
            padding: 0,
        });
        let packet = peer_disco
            .seal_to(&local_disco.public(), &message, &mut OsRng)
            .expect("seal DERP ping");
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();

        handle_disco_packet(
            &shared,
            &socket,
            &fallback.to_transport,
            None,
            Some(derp_public_from_node(peer_node)),
            &packet,
        )
        .await;

        let got = tokio::time::timeout(Duration::from_secs(2), fallback_rx.recv())
            .await
            .unwrap()
            .expect("DERP Pong datagram");
        assert_eq!(got.peer.as_bytes(), peer_node.as_bytes());
        let opened = peer_disco.open(&got.data).expect("open DERP Pong");
        match opened.message {
            Message::Pong(pong) => {
                assert_eq!(pong.tx_id, tx_id);
                assert_eq!(pong.src, derp_magic_addr(1));
            }
            other => panic!("expected DERP Pong, got {other:?}"),
        }
    }

    #[test]
    fn disco_peer_resolution_matches_magicsock_trust_rules() {
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let c_secret = StaticSecret::random_from_rng(OsRng);
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let c_node = NodePublic::from_raw(PublicKey::from(&c_secret).to_bytes());
        let shared_disco = DiscoPrivate::generate(&mut OsRng).public();
        let other_disco = DiscoPrivate::generate(&mut OsRng).public();
        let b_endpoint = reserve_local_endpoint();
        let c_endpoint = reserve_local_endpoint();
        let mut state = State::default();
        state.peers_by_node.insert(
            *b_node.as_bytes(),
            peer_state(b_node, shared_disco, b_endpoint),
        );
        state.peers_by_node.insert(
            *c_node.as_bytes(),
            peer_state(c_node, shared_disco, c_endpoint),
        );
        state
            .peers_by_disco
            .insert(*shared_disco.as_bytes(), DiscoPeerIndex::Ambiguous);

        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        let with_node_key = Message::Ping(Ping {
            tx_id,
            node_key: Some(b_node),
            padding: 0,
        });
        assert_eq!(
            peer_key_for_message(&state, shared_disco, &with_node_key, None),
            Some(*b_node.as_bytes()),
            "Ping NodeKey disambiguates only when the authenticated disco key matches"
        );
        assert_eq!(
            peer_key_for_message(&state, other_disco, &with_node_key, None),
            None,
            "Ping NodeKey alone is not trusted"
        );

        let without_node_key = Message::Ping(Ping {
            tx_id,
            node_key: None,
            padding: 0,
        });
        assert_eq!(
            peer_key_for_message(&state, shared_disco, &without_node_key, None),
            None,
            "ambiguous disco keys need DERP source, Ping NodeKey, or Pong TxID"
        );
        assert_eq!(
            peer_key_for_message(
                &state,
                shared_disco,
                &without_node_key,
                Some(&derp_public_from_node(c_node)),
            ),
            Some(*c_node.as_bytes()),
            "DERP source disambiguates when it matches the authenticated disco key"
        );

        state.pending_tx.insert(tx_id, *b_node.as_bytes());
        assert_eq!(
            peer_key_for_pong(&state, shared_disco, &tx_id),
            Some(*b_node.as_bytes()),
            "Pong TxID disambiguates shared disco keys"
        );
        assert_eq!(
            peer_key_for_pong(&state, other_disco, &tx_id),
            None,
            "Pong TxID does not let a different disco key claim a peer"
        );
    }

    #[test]
    fn direct_candidate_probe_expires_and_identical_updates_do_not_restart_it() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng);
        let first_endpoint = reserve_local_endpoint();
        let changed_endpoint = reserve_local_endpoint();
        let options = Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            local_node,
            local_disco,
        );
        let shared = shared_for_test(&options);

        let initial = apply_peer_update(
            &shared,
            vec![node(peer_node, peer_disco.public(), first_endpoint, B_IP)],
        );
        assert_eq!(initial.len(), 1);
        let Message::Ping(initial_ping) = &initial[0].message else {
            panic!("new direct candidate should be pinged immediately");
        };
        let initial_tx_id = initial_ping.tx_id;
        let expires_at = {
            let state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
            let DirectProbeState::Active(probe) = &peer.direct_probe else {
                panic!("new direct candidate should have an active probe window");
            };
            assert_eq!(state.pending_tx.len(), 1);
            probe.expires_at
        };

        let identical_while_active = apply_peer_update(
            &shared,
            vec![node(peer_node, peer_disco.public(), first_endpoint, B_IP)],
        );
        assert!(identical_while_active.is_empty());
        {
            let state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
            let DirectProbeState::Active(probe) = &peer.direct_probe else {
                panic!("identical update should preserve the active probe window");
            };
            assert_eq!(probe.expires_at, expires_at);
            assert_eq!(state.pending_tx.len(), 1);
        }

        let retry =
            retry_unverified_direct_candidates(&shared, expires_at - Duration::from_millis(1));
        assert_eq!(retry.len(), 1);
        let Message::Ping(retry_ping) = &retry[0].message else {
            panic!("unverified direct candidate should be pinged again");
        };
        assert_eq!(retry_ping.tx_id, initial_tx_id);

        assert!(retry_unverified_direct_candidates(&shared, expires_at).is_empty());
        {
            let state = shared.state.lock().unwrap();
            let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
            assert!(matches!(peer.direct_probe, DirectProbeState::Exhausted));
            assert!(state.pending_tx.is_empty());
        }

        let identical = apply_peer_update(
            &shared,
            vec![node(peer_node, peer_disco.public(), first_endpoint, B_IP)],
        );
        assert!(identical.is_empty());
        assert!(matches!(
            shared
                .state
                .lock()
                .unwrap()
                .peers_by_node
                .get(peer_node.as_bytes())
                .unwrap()
                .direct_probe,
            DirectProbeState::Exhausted
        ));

        let changed = apply_peer_update(
            &shared,
            vec![node(peer_node, peer_disco.public(), changed_endpoint, B_IP)],
        );
        assert_eq!(changed.len(), 1);
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        assert!(matches!(peer.direct_probe, DirectProbeState::Active(_)));
        assert_eq!(state.pending_tx.len(), 1);
    }

    #[tokio::test]
    async fn direct_udp_recovers_when_first_ping_precedes_receiver_peer_state() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

        let (a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                a_node,
                a_disco.clone(),
            ),
        )
        .await
        .unwrap();
        let (b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                b_node,
                b_disco.clone(),
            ),
        )
        .await
        .unwrap();

        a_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node(
                b_node,
                b_disco.public(),
                b_handle.local_addr(),
                B_IP,
            )])
            .unwrap();

        wait_stats(
            &b_handle,
            |stats| stats.disco_udp_received > 0,
            "b should receive the first ping before it knows a",
        )
        .await;
        assert!(!b_handle.has_verified_endpoint(&a_node));
        let received_before_peer_state = b_handle.stats().disco_udp_received;

        b_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                a_node,
                a_disco.public(),
                Vec::new(),
                A_IP,
            )])
            .unwrap();

        wait_verified(&a_handle, &b_node).await;
        wait_verified(&b_handle, &a_node).await;
        assert!(
            b_handle.stats().disco_udp_received > received_before_peer_state,
            "a scheduled retry should reach b after b applies peer state"
        );
        assert!(a_handle.stats().disco_udp_sent >= 2);
    }

    #[tokio::test]
    async fn direct_udp_verifies_endpoint_before_sending_wg() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

        let (a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
        )
        .await
        .unwrap();
        let (mut b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(b_endpoint, vec![b_endpoint], b_node, b_disco.clone()),
        )
        .await
        .unwrap();

        a_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node(b_node, b_disco.public(), b_endpoint, B_IP)])
            .unwrap();
        b_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node(a_node, a_disco.public(), a_endpoint, A_IP)])
            .unwrap();

        for _ in 0..100 {
            if a_handle.has_verified_endpoint(&b_node) && b_handle.has_verified_endpoint(&a_node) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(a_handle.has_verified_endpoint(&b_node));
        assert!(b_handle.has_verified_endpoint(&a_node));

        let payload = b"encrypted wireguard packet".to_vec();
        a_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: payload.clone(),
            })
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(got.peer.as_bytes(), a_node.as_bytes());
        assert_eq!(got.data, payload);
        assert!(a_handle.stats().direct_wg_sent > 0);
        assert!(b_handle.stats().direct_wg_received > 0);
        assert_eq!(a_handle.stats().fallback_wg_sent, 0);

        a_handle.expire_verified_endpoint_for_test(&b_node);
        let fallback_payload = b"fallback after endpoint expiry".to_vec();
        a_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: fallback_payload.clone(),
            })
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.peer.as_bytes(), a_node.as_bytes());
        assert_eq!(got.data, fallback_payload);
        assert_eq!(a_handle.stats().fallback_wg_sent, 1);
    }

    #[tokio::test]
    async fn direct_udp_advertises_stun_discovered_endpoint() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
        let disco = DiscoPrivate::generate(&mut OsRng);
        let mapped = "203.0.113.10:45678".parse::<SocketAddr>().unwrap();
        let stun_server = fake_stun_server(mapped).await;
        let (fallback, _out_rx, _in_tx) = recording_fallback();

        let (_transport, handle) = wrap_transport(
            fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                node_key,
                disco,
            )
            .with_stun_servers(vec![stun_server])
            .with_stun_timeout(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        assert_eq!(handle.advertised_endpoints(), vec![AddrPort(mapped)]);
    }

    #[tokio::test]
    async fn direct_udp_refreshes_stun_discovered_endpoints() {
        let secret = StaticSecret::random_from_rng(OsRng);
        let node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
        let disco = DiscoPrivate::generate(&mut OsRng);
        let mapped_a = "203.0.113.10:45678".parse::<SocketAddr>().unwrap();
        let mapped_b = "203.0.113.10:45679".parse::<SocketAddr>().unwrap();
        let stun_server = fake_stun_server_sequence(vec![mapped_a, mapped_b]).await;
        let (fallback, _out_rx, _in_tx) = recording_fallback();

        let (mut transport, handle) = wrap_transport(
            fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                node_key,
                disco,
            )
            .with_stun_servers(vec![stun_server])
            .with_stun_timeout(Duration::from_secs(1))
            .with_stun_refresh_interval(Duration::from_millis(20)),
        )
        .await
        .unwrap();

        assert_eq!(handle.advertised_endpoints(), vec![AddrPort(mapped_a)]);
        let mut updates = transport.local_endpoint_updates.take().unwrap();
        let update = tokio::time::timeout(Duration::from_secs(2), updates.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(update.contains(&AddrPort(mapped_a)));
        assert!(update.contains(&AddrPort(mapped_b)));
    }

    #[tokio::test]
    async fn direct_udp_rejects_ping_from_unowned_disco_key() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let attacker_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();

        let (a_transport, a_handle) = wrap_transport(
            fallback,
            Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
        )
        .await
        .unwrap();
        a_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node(b_node, b_disco.public(), b_endpoint, B_IP)])
            .unwrap();

        for _ in 0..100 {
            if a_handle.stats().disco_udp_sent > 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            a_handle.stats().disco_udp_sent > 0,
            "peer update should attempt disco before the spoof packet"
        );
        loop {
            match tokio::time::timeout(Duration::from_millis(10), fallback_rx.recv()).await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("fallback transport closed during setup"),
                Err(_) => break,
            }
        }

        let attacker_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        let spoofed = attacker_disco
            .seal_to(
                &a_disco.public(),
                &Message::Ping(Ping {
                    tx_id,
                    node_key: Some(b_node),
                    padding: 0,
                }),
                &mut OsRng,
            )
            .unwrap();
        attacker_socket
            .send_to(&spoofed, a_handle.local_addr())
            .await
            .unwrap();
        sleep(Duration::from_millis(50)).await;

        assert!(
            !a_handle.has_verified_endpoint(&b_node),
            "unknown disco keys must not claim a peer's direct endpoint"
        );

        let payload = b"must stay on DERP fallback after spoofed ping".to_vec();
        a_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: payload.clone(),
            })
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), fallback_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(got.peer.as_bytes(), b_node.as_bytes());
        assert_eq!(got.data, payload);
        assert_eq!(a_handle.stats().direct_wg_sent, 0);
        assert_eq!(a_handle.stats().fallback_wg_sent, 1);
    }

    #[tokio::test]
    async fn call_me_maybe_matches_magicsock_derp_boundary() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let c_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let c_node = NodePublic::from_raw(PublicKey::from(&c_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let call_endpoint = reserve_local_endpoint();
        let options = Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone());
        let shared = shared_arc_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *b_node.as_bytes(),
                peer_state(b_node, b_disco.public(), b_endpoint),
            );
            state.peers_by_disco.insert(
                *b_disco.public().as_bytes(),
                DiscoPeerIndex::Unique(*b_node.as_bytes()),
            );
        }
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = UdpSocket::bind(call_endpoint).await.unwrap();
        let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();
        let message = Message::CallMeMaybe(CallMeMaybe {
            endpoints: vec![call_endpoint],
        });
        let packet = b_disco
            .seal_to(&a_disco.public(), &message, &mut OsRng)
            .unwrap();

        handle_disco_packet(
            &shared,
            &socket,
            &fallback.to_transport,
            Some(b_endpoint),
            None,
            &packet,
        )
        .await;
        assert_eq!(
            shared.stats.snapshot().disco_udp_sent,
            0,
            "CallMeMaybe must be ignored when received over UDP"
        );

        handle_disco_packet(
            &shared,
            &socket,
            &fallback.to_transport,
            None,
            Some(derp_public_from_node(c_node)),
            &packet,
        )
        .await;
        assert_eq!(
            shared.stats.snapshot().disco_udp_sent,
            0,
            "CallMeMaybe must authenticate the DERP source node key"
        );

        handle_disco_packet(
            &shared,
            &socket,
            &fallback.to_transport,
            None,
            Some(derp_public_from_node(b_node)),
            &packet,
        )
        .await;
        let mut got = [0u8; UDP_PACKET_LIMIT];
        let (n, _src) = tokio::time::timeout(Duration::from_secs(2), listen.recv_from(&mut got))
            .await
            .unwrap()
            .unwrap();
        let opened = b_disco.open(&got[..n]).unwrap();
        assert!(matches!(opened.message, Message::Ping(_)));
        assert_eq!(shared.stats.snapshot().disco_udp_sent, 1);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), fallback_rx.recv())
                .await
                .is_err(),
            "CallMeMaybe handling should not emit DERP fallback datagrams"
        );
    }

    #[tokio::test]
    async fn disabled_peer_direct_udp_ignores_authenticated_call_me_maybe() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let call_endpoint = reserve_local_endpoint();
        let options = Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone())
            .with_peer_direct_udp_enabled(false);
        let shared = shared_arc_for_test(&options);
        {
            let mut state = shared.state.lock().unwrap();
            state.peers_by_node.insert(
                *b_node.as_bytes(),
                peer_state(b_node, b_disco.public(), b_endpoint),
            );
            state.peers_by_disco.insert(
                *b_disco.public().as_bytes(),
                DiscoPeerIndex::Unique(*b_node.as_bytes()),
            );
        }
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = UdpSocket::bind(call_endpoint).await.unwrap();
        let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();
        let packet = b_disco
            .seal_to(
                &a_disco.public(),
                &Message::CallMeMaybe(CallMeMaybe {
                    endpoints: vec![call_endpoint],
                }),
                &mut OsRng,
            )
            .unwrap();

        handle_disco_packet(
            &shared,
            &socket,
            &fallback.to_transport,
            None,
            Some(derp_public_from_node(b_node)),
            &packet,
        )
        .await;

        let mut got = [0u8; UDP_PACKET_LIMIT];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listen.recv_from(&mut got))
                .await
                .is_err(),
            "disabled direct peer UDP must not ping CallMeMaybe candidates"
        );
        assert!(
            shared.state.lock().unwrap().pending_tx.is_empty(),
            "disabled direct peer UDP must not retain direct probe transactions"
        );
        assert_eq!(shared.stats.snapshot().disco_udp_sent, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), fallback_rx.recv())
                .await
                .is_err(),
            "ignored CallMeMaybe must not emit fallback traffic"
        );
    }

    #[test]
    fn disabled_peer_direct_udp_drops_node_and_local_direct_candidates() {
        let local_secret = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
        let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
        let local_disco = DiscoPrivate::generate(&mut OsRng);
        let peer_disco = DiscoPrivate::generate(&mut OsRng);
        let local_endpoint = reserve_local_endpoint();
        let peer_endpoint = reserve_local_endpoint();
        let options = Options::new(
            local_endpoint,
            vec![local_endpoint],
            local_node,
            local_disco,
        )
        .with_peer_direct_udp_enabled(false);
        let shared = shared_for_test(&options);

        let actions = apply_peer_update(
            &shared,
            vec![node(peer_node, peer_disco.public(), peer_endpoint, B_IP)],
        );

        assert!(actions.is_empty());
        assert!(shared.advertised_socket_addrs().is_empty());
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        assert!(peer.endpoints.is_empty());
        assert!(peer.verified_endpoint.is_none());
    }

    #[test]
    fn call_me_maybe_endpoint_filter_matches_magicsock() {
        assert!(is_usable_direct_endpoint(
            "127.0.0.1:41641".parse().unwrap()
        ));
        assert!(is_usable_direct_endpoint(
            "[2001:db8::1]:41641".parse().unwrap()
        ));
        assert!(!is_usable_direct_endpoint("0.0.0.0:41641".parse().unwrap()));
        assert!(!is_usable_direct_endpoint("[::]:41641".parse().unwrap()));
        assert!(!is_usable_direct_endpoint(
            "[fe80::1]:41641".parse().unwrap()
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_me_maybe_via_binds_peer_relay_when_direct_udp_is_disabled() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

        let relay_key = DiscoPrivate::generate(&mut OsRng);
        let relay = udp_relay::SocketServer::bind(
            relay_key.clone(),
            udp_relay::SocketOptions::new("127.0.0.1:0".parse().unwrap())
                .with_expire_interval(Duration::from_millis(50)),
        )
        .await
        .unwrap();
        let relay_handle = relay.handle();
        let relay_endpoint = relay_handle
            .allocate_endpoint(a_disco.public(), b_disco.public())
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_task = tokio::spawn(relay.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let (a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                a_node,
                a_disco.clone(),
            )
            .with_peer_direct_udp_enabled(false),
        )
        .await
        .unwrap();
        let (mut b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                b_node,
                b_disco.clone(),
            )
            .with_peer_direct_udp_enabled(false),
        )
        .await
        .unwrap();

        a_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                b_node,
                b_disco.public(),
                Vec::new(),
                B_IP,
            )])
            .unwrap();
        b_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                a_node,
                a_disco.public(),
                Vec::new(),
                A_IP,
            )])
            .unwrap();

        wait_peer_known(&a_handle, &b_node).await;
        wait_peer_known(&b_handle, &a_node).await;
        a_handle
            .request_peer_relay(b_node, relay_endpoint)
            .expect("request peer relay");

        wait_peer_relay(&a_handle, &b_node).await;
        wait_peer_relay(&b_handle, &a_node).await;
        assert_eq!(
            a_handle.path_for_peer(&b_node).transport,
            PeerTransport::PeerRelay
        );

        let payload = b"encrypted wireguard packet via shared UDP peer relay".to_vec();
        a_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: payload.clone(),
            })
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(got.peer.as_bytes(), a_node.as_bytes());
        assert_eq!(got.data, payload);
        assert_eq!(a_handle.stats().direct_wg_sent, 0);
        wait_stats(
            &a_handle,
            |stats| stats.peer_relay_wg_sent > 0,
            "a should send WireGuard over peer relay",
        )
        .await;
        wait_stats(
            &b_handle,
            |stats| stats.peer_relay_wg_received > 0,
            "b should receive WireGuard over peer relay",
        )
        .await;
        wait_stats(
            &a_handle,
            |stats| stats.disco_derp_sent > 0,
            "a should send fallback disco traffic",
        )
        .await;
        wait_stats(
            &b_handle,
            |stats| stats.disco_derp_received > 0,
            "b should receive fallback disco traffic",
        )
        .await;
        assert_eq!(a_handle.stats().fallback_wg_sent, 0);
        assert_eq!(b_handle.stats().fallback_wg_sent, 0);

        let _ = shutdown_tx.send(());
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn conn_tunnel_uses_verified_direct_udp_path() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

        let (a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
        )
        .await
        .unwrap();
        let (b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(b_endpoint, vec![b_endpoint], b_node, b_disco.clone()),
        )
        .await
        .unwrap();

        let a = Conn::new(
            conn_options(
                &a_secret,
                a_disco.clone(),
                A_IP,
                a_handle.advertised_endpoints(),
            ),
            a_transport,
        )
        .unwrap();
        let b = Conn::new(
            conn_options(
                &b_secret,
                b_disco.clone(),
                B_IP,
                b_handle.advertised_endpoints(),
            ),
            b_transport,
        )
        .unwrap();

        let b_peer = node(b_node, b_disco.public(), b_endpoint, B_IP);
        let a_peer = node(a_node, a_disco.public(), a_endpoint, A_IP);
        a.update_peers(std::slice::from_ref(&b_peer)).unwrap();
        b.update_peers(std::slice::from_ref(&a_peer)).unwrap();
        wait_verified(&a_handle, &b_node).await;
        wait_verified(&b_handle, &a_node).await;
        assert_eq!(
            a.probe_peer_path(&b_peer).unwrap().transport,
            PeerTransport::DirectUdp
        );

        let mut listener = a.listen("tcp", ":9022").await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let dst = SocketAddr::new(IpAddr::V6(A_IP), 9022);
        let mut b_stream = tokio::time::timeout(Duration::from_secs(10), b.dial_context_tcp(dst))
            .await
            .unwrap()
            .unwrap();

        let req = b"go-style TestTunnelTCP over Rust direct UDP";
        b_stream.write_all(req).await.unwrap();
        b_stream.flush().await.unwrap();

        let mut a_stream = tokio::time::timeout(Duration::from_secs(10), accept)
            .await
            .unwrap()
            .unwrap();
        let mut got = vec![0; req.len()];
        tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, req);

        assert!(a_handle.stats().direct_wg_received > 0 || a_handle.stats().direct_wg_sent > 0);
        assert!(b_handle.stats().direct_wg_received > 0 || b_handle.stats().direct_wg_sent > 0);

        a_handle.expire_verified_endpoint_for_test(&b_node);
        assert_eq!(
            a.probe_peer_path(&b_peer).unwrap().transport,
            PeerTransport::DerpRelay
        );
    }

    #[tokio::test]
    async fn conn_tunnel_uses_stun_discovered_direct_udp_path_without_static_endpoints() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let a_stun = fake_stun_server(a_endpoint).await;
        let b_stun = fake_stun_server(b_endpoint).await;
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

        let (a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(a_endpoint, Vec::new(), a_node, a_disco.clone())
                .with_stun_servers(vec![a_stun])
                .with_stun_timeout(Duration::from_secs(1)),
        )
        .await
        .unwrap();
        let (b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(b_endpoint, Vec::new(), b_node, b_disco.clone())
                .with_stun_servers(vec![b_stun])
                .with_stun_timeout(Duration::from_secs(1)),
        )
        .await
        .unwrap();

        let a_endpoints = a_handle.advertised_endpoints();
        let b_endpoints = b_handle.advertised_endpoints();
        assert_eq!(a_endpoints, vec![AddrPort(a_endpoint)]);
        assert_eq!(b_endpoints, vec![AddrPort(b_endpoint)]);

        let a = Conn::new(
            conn_options(&a_secret, a_disco.clone(), A_IP, a_endpoints),
            a_transport,
        )
        .unwrap();
        let b = Conn::new(
            conn_options(&b_secret, b_disco.clone(), B_IP, b_endpoints),
            b_transport,
        )
        .unwrap();

        let b_peer = node_with_endpoints(b_node, b_disco.public(), vec![b_endpoint], B_IP);
        let a_peer = node_with_endpoints(a_node, a_disco.public(), vec![a_endpoint], A_IP);
        a.update_peers(std::slice::from_ref(&b_peer)).unwrap();
        b.update_peers(std::slice::from_ref(&a_peer)).unwrap();
        wait_verified(&a_handle, &b_node).await;
        wait_verified(&b_handle, &a_node).await;
        assert_eq!(
            a.probe_peer_path(&b_peer).unwrap().transport,
            PeerTransport::DirectUdp
        );
        assert_eq!(
            b.probe_peer_path(&a_peer).unwrap().transport,
            PeerTransport::DirectUdp
        );

        let mut listener = a.listen("tcp", ":9022").await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let dst = SocketAddr::new(IpAddr::V6(A_IP), 9022);
        let mut b_stream = tokio::time::timeout(Duration::from_secs(10), b.dial_context_tcp(dst))
            .await
            .unwrap()
            .unwrap();

        let req = b"go-style TestTunnelTCP over Rust STUN-discovered direct UDP";
        b_stream.write_all(req).await.unwrap();
        b_stream.flush().await.unwrap();

        let mut a_stream = tokio::time::timeout(Duration::from_secs(10), accept)
            .await
            .unwrap()
            .unwrap();
        let mut got = vec![0; req.len()];
        tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, req);

        assert!(a_handle.stats().direct_wg_received > 0 || a_handle.stats().direct_wg_sent > 0);
        assert!(b_handle.stats().direct_wg_received > 0 || b_handle.stats().direct_wg_sent > 0);
        assert_eq!(a_handle.stats().fallback_wg_sent, 0);
        assert_eq!(b_handle.stats().fallback_wg_sent, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_relay_notification_retry_recovers_call_me_maybe_via_loss() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let (a_fallback, b_fallback, dropped) =
            fallback_pair_drop_first_call_me_maybe_via(a_node, b_node, b_disco.clone());

        let relay_key = DiscoPrivate::generate(&mut OsRng);
        let relay = udp_relay::SocketServer::bind(
            relay_key,
            udp_relay::SocketOptions::new("127.0.0.1:0".parse().unwrap())
                .with_expire_interval(Duration::from_millis(50)),
        )
        .await
        .unwrap();
        let relay_handle = relay.handle();
        let relay_endpoint = relay_handle
            .allocate_endpoint(a_disco.public(), b_disco.public())
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_task = tokio::spawn(relay.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let (mut a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                a_node,
                a_disco,
            )
            .with_peer_direct_udp_enabled(false),
        )
        .await
        .unwrap();
        let (mut b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                b_node,
                b_disco,
            )
            .with_peer_direct_udp_enabled(false),
        )
        .await
        .unwrap();

        a_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                b_node,
                b_handle.shared.local_disco.public(),
                Vec::new(),
                B_IP,
            )])
            .unwrap();
        b_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                a_node,
                a_handle.shared.local_disco.public(),
                Vec::new(),
                A_IP,
            )])
            .unwrap();
        wait_peer_known(&a_handle, &b_node).await;
        wait_peer_known(&b_handle, &a_node).await;

        a_handle
            .request_peer_relay(b_node, relay_endpoint)
            .expect("request peer relay");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if a_handle.path_for_peer(&b_node).transport == PeerTransport::PeerRelay
                    && b_handle.path_for_peer(&a_node).transport == PeerTransport::PeerRelay
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "UDP peer relay did not recover the lost notification; a_stats={:?} b_stats={:?}",
                a_handle.stats(),
                b_handle.stats()
            )
        });

        assert_eq!(
            dropped.load(Ordering::Relaxed),
            1,
            "fallback must drop exactly the first CallMeMaybeVia"
        );

        let request = b"peer relay request after lossy notification".to_vec();
        a_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: request.clone(),
            })
            .unwrap();
        let got_request =
            tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(got_request.data, request);

        let response = b"peer relay response after lossy notification".to_vec();
        b_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(a_node),
                data: response.clone(),
            })
            .unwrap();
        let got_response =
            tokio::time::timeout(Duration::from_secs(2), a_transport.from_transport.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(got_response.data, response);
        assert_eq!(a_handle.stats().fallback_wg_sent, 0);
        assert_eq!(b_handle.stats().fallback_wg_sent, 0);

        let _ = shutdown_tx.send(());
        relay_task.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_relay_bind_retry_recovers_bind_answer_loss() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);
        let (relay_endpoint, dropped_sources, shutdown_tx, relay_task) =
            bind_answer_loss_relay(a_disco.public(), b_disco.public()).await;

        let (mut a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                a_node,
                a_disco,
            )
            .with_peer_direct_udp_enabled(false),
        )
        .await
        .unwrap();
        let (mut b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                b_node,
                b_disco,
            )
            .with_peer_direct_udp_enabled(false),
        )
        .await
        .unwrap();

        a_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                b_node,
                b_handle.shared.local_disco.public(),
                Vec::new(),
                B_IP,
            )])
            .unwrap();
        b_transport
            .peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node_with_endpoints(
                a_node,
                a_handle.shared.local_disco.public(),
                Vec::new(),
                A_IP,
            )])
            .unwrap();
        wait_peer_known(&a_handle, &b_node).await;
        wait_peer_known(&b_handle, &a_node).await;

        a_handle
            .request_peer_relay(b_node, relay_endpoint)
            .expect("request peer relay");
        wait_peer_relay(&a_handle, &b_node).await;
        wait_peer_relay(&b_handle, &a_node).await;

        assert_eq!(
            a_handle.path_for_peer(&b_node).transport,
            PeerTransport::PeerRelay
        );
        assert_eq!(
            b_handle.path_for_peer(&a_node).transport,
            PeerTransport::PeerRelay
        );
        assert_eq!(
            dropped_sources.lock().unwrap().len(),
            2,
            "relay must drop the first bind answer from each client source"
        );

        let request = b"peer relay request after lossy bind".to_vec();
        a_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: request.clone(),
            })
            .unwrap();
        let got_request =
            tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(got_request.data, request);

        let response = b"peer relay response after lossy bind".to_vec();
        b_transport
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(a_node),
                data: response.clone(),
            })
            .unwrap();
        let got_response =
            tokio::time::timeout(Duration::from_secs(2), a_transport.from_transport.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(got_response.data, response);
        wait_stats(
            &a_handle,
            |stats| stats.peer_relay_wg_sent > 0,
            "a should publish the peer-relay send counter",
        )
        .await;
        wait_stats(
            &b_handle,
            |stats| stats.peer_relay_wg_sent > 0,
            "b should publish the peer-relay send counter",
        )
        .await;
        assert_eq!(a_handle.stats().fallback_wg_sent, 0);
        assert_eq!(b_handle.stats().fallback_wg_sent, 0);

        let _ = shutdown_tx.send(());
        relay_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conn_tunnel_uses_verified_peer_relay_path() {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

        let relay_key = DiscoPrivate::generate(&mut OsRng);
        let relay = udp_relay::SocketServer::bind(
            relay_key,
            udp_relay::SocketOptions::new("127.0.0.1:0".parse().unwrap())
                .with_expire_interval(Duration::from_millis(50)),
        )
        .await
        .unwrap();
        let relay_handle = relay.handle();
        let relay_endpoint = relay_handle
            .allocate_endpoint(a_disco.public(), b_disco.public())
            .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let relay_task = tokio::spawn(relay.run_until(async {
            let _ = shutdown_rx.await;
        }));

        let (a_transport, a_handle) = wrap_transport(
            a_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                a_node,
                a_disco.clone(),
            ),
        )
        .await
        .unwrap();
        let (b_transport, b_handle) = wrap_transport(
            b_fallback,
            Options::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                Vec::new(),
                b_node,
                b_disco.clone(),
            ),
        )
        .await
        .unwrap();

        let a = Conn::new(
            conn_options(&a_secret, a_disco.clone(), A_IP, Vec::new()),
            a_transport,
        )
        .unwrap();
        let b = Conn::new(
            conn_options(&b_secret, b_disco.clone(), B_IP, Vec::new()),
            b_transport,
        )
        .unwrap();

        let b_peer = node_with_endpoints(b_node, b_disco.public(), Vec::new(), B_IP);
        let a_peer = node_with_endpoints(a_node, a_disco.public(), Vec::new(), A_IP);
        a.update_peers(std::slice::from_ref(&b_peer)).unwrap();
        b.update_peers(std::slice::from_ref(&a_peer)).unwrap();

        wait_peer_known(&a_handle, &b_node).await;
        wait_peer_known(&b_handle, &a_node).await;
        a_handle
            .request_peer_relay(b_node, relay_endpoint)
            .expect("request peer relay");
        wait_peer_relay(&a_handle, &b_node).await;
        wait_peer_relay(&b_handle, &a_node).await;
        assert_eq!(
            a.probe_peer_path(&b_peer).unwrap().transport,
            PeerTransport::PeerRelay
        );
        assert_eq!(
            b.probe_peer_path(&a_peer).unwrap().transport,
            PeerTransport::PeerRelay
        );

        let mut listener = a.listen("tcp", ":9022").await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let dst = SocketAddr::new(IpAddr::V6(A_IP), 9022);
        let mut b_stream = tokio::time::timeout(Duration::from_secs(10), b.dial_context_tcp(dst))
            .await
            .unwrap()
            .unwrap();

        let req: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        b_stream.write_all(&req).await.unwrap();
        b_stream.flush().await.unwrap();

        let mut a_stream = tokio::time::timeout(Duration::from_secs(10), accept)
            .await
            .unwrap()
            .unwrap();
        let mut got = vec![0; req.len()];
        tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, req);

        let resp: Vec<u8> = (0..4096).map(|i| (255 - (i % 251)) as u8).collect();
        a_stream.write_all(&resp).await.unwrap();
        a_stream.flush().await.unwrap();

        let mut got_back = vec![0; resp.len()];
        tokio::time::timeout(Duration::from_secs(10), b_stream.read_exact(&mut got_back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got_back, resp);

        wait_stats(
            &a_handle,
            |stats| stats.peer_relay_wg_received > 0,
            "a should receive WireGuard over peer relay",
        )
        .await;
        wait_stats(
            &b_handle,
            |stats| stats.peer_relay_wg_sent > 0,
            "b should send WireGuard over peer relay",
        )
        .await;
        assert_eq!(a_handle.stats().fallback_wg_sent, 0);
        assert_eq!(b_handle.stats().fallback_wg_sent, 0);
        let relay_stats = relay_handle.stats();
        assert!(
            relay_stats.packets_forwarded > 4,
            "large TCP stream should forward multiple peer-relay data packets"
        );
        let max_forwarded = relay_stats.max_packet_bytes_forwarded as usize;
        assert!(
            max_forwarded >= crate::netstack::TUNNEL_MTU,
            "large TCP stream did not exercise MTU-sized peer-relay packets, max={max_forwarded}"
        );
        assert!(
            max_forwarded <= crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET,
            "peer relay forwarded {max_forwarded}-byte UDP payload, exceeding cross-node budget {}",
            crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET
        );

        let _ = shutdown_tx.send(());
        relay_task.await.unwrap().unwrap();
    }
}
