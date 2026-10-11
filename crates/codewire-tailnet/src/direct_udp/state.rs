//! Sole ownership of mutable peer, endpoint, relay, transaction, and counter state.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::mpsc;

use crate::conn::{PeerPath, WgDatagram};
use crate::derp::NodePublic as DerpPublic;
use crate::disco::{DiscoPrivate, Message, Ping, UDPRelayEndpoint};
use crate::endpoint_tracker::EndpointTracker;
use crate::node::{AddrPort, DiscoPublic, Node, NodePublic};

use super::{
    Options, PeerRelayAllocationEvent, PeerRelayEndpointState, Stats,
    DIRECT_SESSION_ACTIVE_TIMEOUT, VERIFIED_ENDPOINT_TTL,
};

#[derive(Default)]
pub(super) struct StatsAtoms {
    pub(super) disco_udp_sent: AtomicU64,
    pub(super) disco_udp_received: AtomicU64,
    pub(super) disco_derp_sent: AtomicU64,
    pub(super) disco_derp_received: AtomicU64,
    pub(super) direct_wg_sent: AtomicU64,
    pub(super) direct_wg_received: AtomicU64,
    pub(super) peer_relay_wg_sent: AtomicU64,
    pub(super) peer_relay_wg_received: AtomicU64,
    pub(super) peer_relay_disco_sent: AtomicU64,
    pub(super) peer_relay_disco_received: AtomicU64,
    pub(super) peer_relay_notifications_opened: AtomicU64,
    pub(super) peer_relay_notifications_unknown_peer: AtomicU64,
    pub(super) peer_relay_notifications_received: AtomicU64,
    pub(super) peer_relay_notification_actions: AtomicU64,
    pub(super) peer_relay_notification_no_actions: AtomicU64,
    pub(super) peer_relay_disco_send_failures: AtomicU64,
    pub(super) peer_relay_drops: AtomicU64,
    pub(super) peer_relay_unmatched: AtomicU64,
    pub(super) fallback_wg_sent: AtomicU64,
}

impl StatsAtoms {
    pub(super) fn snapshot(&self) -> Stats {
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
            peer_relay_notifications_opened: self
                .peer_relay_notifications_opened
                .load(Ordering::Relaxed),
            peer_relay_notifications_unknown_peer: self
                .peer_relay_notifications_unknown_peer
                .load(Ordering::Relaxed),
            peer_relay_notifications_received: self
                .peer_relay_notifications_received
                .load(Ordering::Relaxed),
            peer_relay_notification_actions: self
                .peer_relay_notification_actions
                .load(Ordering::Relaxed),
            peer_relay_notification_no_actions: self
                .peer_relay_notification_no_actions
                .load(Ordering::Relaxed),
            peer_relay_disco_send_failures: self
                .peer_relay_disco_send_failures
                .load(Ordering::Relaxed),
            peer_relay_drops: self.peer_relay_drops.load(Ordering::Relaxed),
            peer_relay_unmatched: self.peer_relay_unmatched.load(Ordering::Relaxed),
            fallback_wg_sent: self.fallback_wg_sent.load(Ordering::Relaxed),
        }
    }
}

pub(super) struct PeerRelayRequest {
    pub(super) peer: NodePublic,
    pub(super) bind_endpoint: UDPRelayEndpoint,
    pub(super) advertise_endpoint: UDPRelayEndpoint,
    pub(super) response_generation: Option<u32>,
}

pub(super) struct PendingPeerRelayRequest {
    pub(super) bind_endpoint: UDPRelayEndpoint,
    pub(super) advertise_endpoint: UDPRelayEndpoint,
    pub(super) response_generation: Option<u32>,
}

pub(super) struct Shared {
    pub(super) local_node_key: NodePublic,
    pub(super) local_disco: DiscoPrivate,
    pub(super) peer_direct_udp_enabled: bool,
    pub(super) peer_relay_allocation_events: mpsc::UnboundedSender<PeerRelayAllocationEvent>,
    pub(super) advertise_endpoints: Mutex<Vec<SocketAddr>>,
    pub(super) state: Mutex<State>,
    pub(super) stats: StatsAtoms,
}

impl Shared {
    pub(super) fn new(
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
            state: Mutex::new(State {
                public_peer_endpoints_only: options.public_peer_endpoints_only,
                ..State::default()
            }),
            stats: StatsAtoms::default(),
        }
    }

    pub(super) fn advertised_socket_addrs(&self) -> Vec<SocketAddr> {
        self.advertise_endpoints.lock().unwrap().clone()
    }

    pub(super) fn advertised_endpoints(&self) -> Vec<AddrPort> {
        self.advertised_socket_addrs()
            .into_iter()
            .map(AddrPort)
            .collect()
    }

    pub(super) fn set_advertised_endpoints(&self, endpoints: Vec<SocketAddr>) {
        if self.peer_direct_udp_enabled {
            *self.advertise_endpoints.lock().unwrap() = endpoints;
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    pub(super) peers_by_node: HashMap<[u8; 32], PeerState>,
    pub(super) peers_by_disco: HashMap<[u8; 32], DiscoPeerIndex>,
    pub(super) peers_by_endpoint: HashMap<SocketAddr, [u8; 32]>,
    pub(super) peers_by_relay: HashMap<RelayKey, [u8; 32]>,
    pub(super) pending_peer_relays: HashMap<[u8; 32], PendingPeerRelayRequest>,
    pub(super) pending_tx: HashMap<[u8; 12], [u8; 32]>,
    /// See [`super::Options::public_peer_endpoints_only`].
    pub(super) public_peer_endpoints_only: bool,
}

impl State {
    pub(super) fn resolve_relay_peer(
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

    pub(super) fn remove_relay_keys_for_peer(&mut self, peer_key: &[u8; 32]) {
        self.peers_by_relay.retain(|_, mapped| mapped != peer_key);
    }
}

#[derive(Clone, Copy)]
pub(super) enum DiscoPeerIndex {
    Unique([u8; 32]),
    Ambiguous,
}

#[derive(Clone, Copy)]
pub(super) struct VerifiedEndpoint {
    pub(super) addr: SocketAddr,
    pub(super) verified_at: Instant,
}

impl VerifiedEndpoint {
    pub(super) fn is_fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.verified_at) <= VERIFIED_ENDPOINT_TTL
    }
}

/// The latest heartbeat ping sent to a peer's verified endpoint.
#[derive(Clone, Copy)]
pub(super) struct DirectHeartbeat {
    pub(super) sent_at: Instant,
    pub(super) tx_id: [u8; 12],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct RelayKey {
    pub(super) addr: SocketAddr,
    pub(super) vni: u32,
}

#[derive(Clone)]
pub(super) struct RelayPeerEndpoint {
    pub(super) server_disco: DiscoPublic,
    pub(super) remote_disco: DiscoPublic,
    pub(super) addr: SocketAddr,
    pub(super) lamport_id: u64,
    pub(super) vni: u32,
    pub(super) generation: u32,
    pub(super) bind_expires_at: Instant,
    pub(super) steady_state_lifetime: Duration,
    pub(super) steady_expires_at: Option<Instant>,
    pub(super) verified_at: Option<Instant>,
    pub(super) retry_call_me_maybe_via: Option<UDPRelayEndpoint>,
}

impl RelayPeerEndpoint {
    pub(super) fn key(&self) -> RelayKey {
        RelayKey {
            addr: self.addr,
            vni: self.vni,
        }
    }

    pub(super) fn is_bound(&self) -> bool {
        self.steady_expires_at.is_some()
    }

    pub(super) fn is_fresh(&self, now: Instant) -> bool {
        match self.steady_expires_at {
            Some(deadline) => now <= deadline,
            None => now <= self.bind_expires_at,
        }
    }

    pub(super) fn active_addr(&self, now: Instant) -> Option<SocketAddr> {
        if self.is_bound() && self.verified_at.is_some() && self.is_fresh(now) {
            Some(self.addr)
        } else {
            None
        }
    }

    pub(super) fn stale_key(&self, now: Instant) -> Option<RelayKey> {
        (!self.is_fresh(now)).then(|| self.key())
    }

    pub(super) fn mark_bound(&mut self, now: Instant) {
        self.steady_expires_at = Some(now + self.steady_state_lifetime);
    }

    pub(super) fn mark_verified(&mut self, now: Instant) {
        self.verified_at = Some(now);
        self.refresh(now);
    }

    pub(super) fn refresh(&mut self, now: Instant) {
        if self.is_bound() {
            self.steady_expires_at = Some(now + self.steady_state_lifetime);
        }
    }
}

#[derive(Clone)]
pub(super) struct PeerState {
    pub(super) node_key: NodePublic,
    pub(super) derp_key: DerpPublic,
    pub(super) disco_key: DiscoPublic,
    pub(super) endpoints: Vec<SocketAddr>,
    pub(super) verified_endpoint: Option<VerifiedEndpoint>,
    pub(super) direct_probe: DirectProbeState,
    pub(super) direct_heartbeat: Option<DirectHeartbeat>,
    /// When this side last sent the peer WireGuard, on any path.
    pub(super) last_wg_send: Option<Instant>,
    pub(super) relay_endpoint: Option<RelayPeerEndpoint>,
    pub(super) preferred_derp: i32,
}

impl PeerState {
    pub(super) fn active_verified_endpoint(&self, now: Instant) -> Option<SocketAddr> {
        self.verified_endpoint
            .filter(|verified| verified.is_fresh(now))
            .map(|verified| verified.addr)
    }

    pub(super) fn in_use(&self, now: Instant) -> bool {
        self.last_wg_send.is_some_and(|sent| {
            now.saturating_duration_since(sent) <= DIRECT_SESSION_ACTIVE_TIMEOUT
        })
    }

    pub(super) fn active_relay_endpoint(&self, now: Instant) -> Option<SocketAddr> {
        self.relay_endpoint
            .as_ref()
            .and_then(|relay| relay.active_addr(now))
    }
}

#[derive(Clone)]
pub(super) enum DirectProbeState {
    Inactive,
    Active(DirectProbe),
    Exhausted,
}

#[derive(Clone)]
pub(super) struct DirectProbe {
    pub(super) expires_at: Instant,
    pub(super) candidates: Vec<DirectProbeCandidate>,
}

#[derive(Clone, Copy)]
pub(super) struct DirectProbeCandidate {
    pub(super) endpoint: SocketAddr,
    pub(super) tx_id: [u8; 12],
}

pub(super) enum DiscoTarget {
    Udp(SocketAddr),
    Relay { addr: SocketAddr, vni: u32 },
    Derp(DerpPublic),
}

pub(super) struct DiscoAction {
    pub(super) target: DiscoTarget,
    pub(super) peer_disco: DiscoPublic,
    pub(super) message: Message,
}

pub(super) struct EndpointRefresh {
    pub(super) static_endpoints: Vec<SocketAddr>,
    pub(super) stun_servers: Vec<SocketAddr>,
    pub(super) stun_timeout: Duration,
    pub(super) stun_refresh_interval: Duration,
    pub(super) endpoint_tracker: EndpointTracker,
    pub(super) local_endpoint_updates: mpsc::UnboundedSender<Vec<AddrPort>>,
}

pub(super) struct TransportChannels {
    pub(super) from_conn: mpsc::UnboundedReceiver<WgDatagram>,
    pub(super) to_conn: mpsc::UnboundedSender<WgDatagram>,
    pub(super) peer_updates_rx: mpsc::UnboundedReceiver<Vec<Node>>,
    pub(super) peer_relay_requests_rx: mpsc::UnboundedReceiver<PeerRelayRequest>,
}

pub(super) struct PendingStun {
    pub(super) server: SocketAddr,
    pub(super) transaction_id: [u8; 12],
    pub(super) expires_at: Instant,
}

pub(super) fn register_pending_transaction(state: &mut State, peer_key: [u8; 32]) -> [u8; 12] {
    loop {
        let mut tx_id = [0u8; 12];
        OsRng.fill_bytes(&mut tx_id);
        if let std::collections::hash_map::Entry::Vacant(entry) = state.pending_tx.entry(tx_id) {
            entry.insert(peer_key);
            return tx_id;
        }
    }
}

pub(super) fn ping_action_with_transaction(
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

pub(super) fn make_ping_action(
    state: &mut State,
    local_node_key: &NodePublic,
    peer: &PeerState,
    endpoint: SocketAddr,
) -> DiscoAction {
    let tx_id = register_pending_transaction(state, *peer.node_key.as_bytes());
    ping_action_with_transaction(local_node_key, peer.disco_key, endpoint, tx_id)
}

pub(super) fn make_relay_ping_action(
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

pub(super) fn is_usable_direct_endpoint(endpoint: SocketAddr) -> bool {
    match endpoint.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified(),
        // Match magicsock's CallMeMaybe behavior: link-local IPv6 endpoints
        // need an interface scope to ping correctly, so ignore them here.
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_unicast_link_local(),
    }
}

/// A peer-supplied address this side may send to: usable, and globally
/// routable when `public_only` is set.
pub(super) fn is_acceptable_peer_endpoint(endpoint: SocketAddr, public_only: bool) -> bool {
    is_usable_direct_endpoint(endpoint) && (!public_only || is_globally_routable(endpoint.ip()))
}

/// Not loopback, private, shared (CGNAT), link-local, unique-local,
/// multicast, broadcast or unspecified, including IPv4 inside IPv6.
pub(super) fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [first, second, ..] = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || first == 0
                || (first == 100 && (second & 0xc0) == 64))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_globally_routable(IpAddr::V4(v4));
            }
            let first = ip.segments()[0];
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (first & 0xffc0) == 0xfec0)
        }
    }
}

pub(super) fn derp_public_from_node(node: NodePublic) -> DerpPublic {
    DerpPublic::from_raw(*node.as_bytes())
}

pub(super) fn disco_message_kind(message: &Message) -> &'static str {
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

pub(super) fn verified_peer_for_endpoint(
    shared: &Shared,
    endpoint: SocketAddr,
) -> Option<NodePublic> {
    let state = shared.state.lock().unwrap();
    let peer_key = state.peers_by_endpoint.get(&endpoint)?;
    let peer = state.peers_by_node.get(peer_key)?;
    if peer.active_verified_endpoint(Instant::now()) != Some(endpoint) {
        return None;
    }
    Some(NodePublic::from_raw(*peer_key))
}

impl State {
    /// Verify a pong's UDP source when the pong answers a ping this side
    /// sent the peer. A DERP pong only retires its transaction.
    pub(super) fn accept_pong(
        &mut self,
        peer_key: [u8; 32],
        tx_id: &[u8; 12],
        source: Option<SocketAddr>,
        now: Instant,
    ) {
        if self.pending_tx.remove(tx_id) == Some(peer_key) {
            if let Some(addr) = source {
                self.verify_endpoint(peer_key, addr, now);
            }
        }
    }

    pub(super) fn verify_endpoint(
        &mut self,
        peer_key: [u8; 32],
        endpoint: SocketAddr,
        now: Instant,
    ) {
        if !is_acceptable_peer_endpoint(endpoint, self.public_peer_endpoints_only) {
            return;
        }
        let mut retired_transactions = Vec::new();
        if let Some(peer) = self.peers_by_node.get_mut(&peer_key) {
            let already_verified = peer.active_verified_endpoint(now) == Some(endpoint);
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
                verified_at: now,
            }) {
                self.peers_by_endpoint.remove(&old.addr);
            }
            self.peers_by_endpoint.insert(endpoint, peer_key);
            if !already_verified {
                // A peer's endpoint is a person's address: debug only.
                tracing::debug!(
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

pub(super) enum ActivePeerPath {
    Direct(SocketAddr),
    Relay { addr: SocketAddr, vni: u32 },
}

/// Choose the path for one WireGuard datagram sent to the peer at `now`, and
/// mark the peer in use. A lapsed direct endpoint is left for
/// `maintain_direct_paths` to probe again.
pub(super) fn active_path_for_peer(
    shared: &Shared,
    peer_key: &[u8; 32],
    now: Instant,
) -> Option<ActivePeerPath> {
    let mut state = shared.state.lock().unwrap();
    let mut expired_relay = None;
    let path = {
        let peer = state.peers_by_node.get_mut(peer_key)?;
        peer.last_wg_send = Some(now);
        if let Some(endpoint) = peer.active_verified_endpoint(now) {
            Some(ActivePeerPath::Direct(endpoint))
        } else {
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

pub(super) fn path_for_peer(shared: &Shared, peer: NodePublic) -> PeerPath {
    let now = Instant::now();
    let mut state = shared.state.lock().unwrap();
    let (preferred_derp, expired_relay) = {
        let Some(peer_state) = state.peers_by_node.get_mut(peer.as_bytes()) else {
            return PeerPath::unknown();
        };
        let preferred_derp = peer_state.preferred_derp;
        if let Some(endpoint) = peer_state.active_verified_endpoint(now) {
            return PeerPath::direct_udp(endpoint);
        }
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
        (preferred_derp, expired_relay)
    };
    if expired_relay.is_some() {
        state.remove_relay_keys_for_peer(peer.as_bytes());
    }
    PeerPath::derp_relay(preferred_derp)
}

pub(super) fn peer_relay_endpoint_state(
    shared: &Shared,
    peer: NodePublic,
    peer_disco: DiscoPublic,
    now: Instant,
) -> PeerRelayEndpointState {
    let state = shared.state.lock().unwrap();
    let Some(peer) = state.peers_by_node.get(peer.as_bytes()) else {
        return PeerRelayEndpointState::Missing;
    };
    if peer.disco_key != peer_disco {
        return PeerRelayEndpointState::Missing;
    }
    let Some(relay) = peer.relay_endpoint.as_ref() else {
        return PeerRelayEndpointState::Missing;
    };
    if relay.remote_disco != peer_disco {
        return PeerRelayEndpointState::Missing;
    }
    if relay.active_addr(now).is_some() {
        PeerRelayEndpointState::Active
    } else if relay.is_fresh(now) {
        PeerRelayEndpointState::Negotiating
    } else {
        PeerRelayEndpointState::Missing
    }
}
