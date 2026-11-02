//! Direct UDP path selection for the Rust tailnet.
//!
//! This wraps an existing DERP transport and opportunistically upgrades
//! encrypted WireGuard datagrams to a verified direct UDP endpoint or a shared
//! UDP relay. The packet path priority is direct UDP, then UDP relay, then
//! DERP fallback; DERP also carries disco control messages such as CallMeMaybe.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::conn::PeerPath;
use crate::disco::{DiscoPrivate, UDPRelayEndpoint};
use crate::node::{AddrPort, DiscoPublic, NodePublic};

mod disco_transport;
mod discovery;
mod peer_relay;
mod runtime;
mod state;

use state::{path_for_peer, peer_relay_endpoint_state, PeerRelayRequest, Shared};

pub use runtime::wrap_transport;

const UDP_PACKET_LIMIT: usize = 64 << 10;
const VERIFIED_ENDPOINT_TTL: Duration = Duration::from_secs(30);
/// While WireGuard flows to a peer, ping its verified endpoint once it is
/// this old, so the pong renews it well inside [`VERIFIED_ENDPOINT_TTL`].
/// magicsock heartbeats its best address for the same reason.
const DIRECT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// A peer is in use while this side sent it WireGuard this recently. Only
/// peers in use get heartbeats or a new probe when their direct endpoint
/// lapses, as with magicsock's `sessionActiveTimeout`.
const DIRECT_SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);
const PEER_RELAY_BIND_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const DIRECT_PROBE_RETRY_WINDOW: Duration = Duration::from_secs(5);
/// How long a peer in use waits, after a probe found no direct path, before
/// probing its candidates again (#3861). Without it a cut longer than one
/// probe left direct UDP off for the life of the connection. magicsock pings
/// a peer with no trusted address at the same interval
/// (`discoPingInterval`).
const DIRECT_REPROBE_INTERVAL: Duration = Duration::from_secs(5);
const STUN_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(750);
const STUN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DERP_MAGIC_IP: Ipv4Addr = Ipv4Addr::new(127, 3, 3, 40);
const DEFAULT_DERP_REGION_ID: u16 = 1;

pub(crate) fn derp_magic_addr(region_id: u16) -> SocketAddr {
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
    /// Query STUN before [`wrap_transport`] returns, so the first published
    /// node already carries the mapped endpoint. When false, the transport
    /// starts at once and publishes the endpoint through
    /// [`crate::conn::Transport::local_endpoint_updates`] when STUN answers;
    /// WireGuard rides DERP meanwhile.
    pub stun_before_start: bool,
    /// Whether direct peer UDP candidates may be discovered and selected.
    /// UDP peer-relay negotiation remains enabled when this is false.
    pub peer_direct_udp_enabled: bool,
    /// Accept only globally routable addresses from peers: their direct
    /// endpoints, CallMeMaybe candidates, relay addresses and verified
    /// sources. A client sets this so an environment peer cannot steer its
    /// UDP at loopback or private networks.
    pub public_peer_endpoints_only: bool,
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
            stun_before_start: true,
            peer_direct_udp_enabled: true,
            public_peer_endpoints_only: false,
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

    /// Choose whether startup waits for STUN; see
    /// [`stun_before_start`](Self::stun_before_start).
    pub fn with_stun_before_start(mut self, wait: bool) -> Self {
        self.stun_before_start = wait;
        self
    }

    /// Enable or disable direct peer UDP while retaining UDP peer relay.
    pub fn with_peer_direct_udp_enabled(mut self, enabled: bool) -> Self {
        self.peer_direct_udp_enabled = enabled;
        self
    }

    /// Accept only globally routable addresses from peers.
    pub fn with_public_peer_endpoints_only(mut self, public_only: bool) -> Self {
        self.public_peer_endpoints_only = public_only;
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
    pub peer_relay_notifications_opened: u64,
    pub peer_relay_notifications_unknown_peer: u64,
    pub peer_relay_notifications_received: u64,
    pub peer_relay_notification_actions: u64,
    pub peer_relay_notification_no_actions: u64,
    pub peer_relay_disco_send_failures: u64,
    pub peer_relay_drops: u64,
    pub peer_relay_unmatched: u64,
    pub fallback_wg_sent: u64,
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
            .and_then(|peer| peer.active_verified_endpoint(Instant::now()))
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

    /// Report the lifecycle of the relay endpoint owned by this adapter.
    ///
    /// This is independent of the currently selected peer path: a direct UDP
    /// path may be active while a relay endpoint remains available as the
    /// next fallback.
    pub fn peer_relay_endpoint_state(
        &self,
        peer: &NodePublic,
        peer_disco: &DiscoPublic,
    ) -> PeerRelayEndpointState {
        peer_relay_endpoint_state(&self.shared, *peer, *peer_disco, Instant::now())
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
        self.age_verified_endpoint_for_test(peer, VERIFIED_ENDPOINT_TTL + Duration::from_secs(1));
    }

    #[cfg(test)]
    fn age_verified_endpoint_for_test(&self, peer: &NodePublic, age: Duration) {
        let mut state = self.shared.state.lock().unwrap();
        if let Some(peer) = state.peers_by_node.get_mut(peer.as_bytes()) {
            if let Some(mut verified) = peer.verified_endpoint {
                verified.verified_at = Instant::now() - age;
                peer.verified_endpoint = Some(verified);
            }
        }
    }

    #[cfg(test)]
    fn verified_endpoint_age_for_test(&self, peer: &NodePublic) -> Option<Duration> {
        let state = self.shared.state.lock().unwrap();
        state
            .peers_by_node
            .get(peer.as_bytes())?
            .verified_endpoint
            .map(|verified| verified.verified_at.elapsed())
    }
}

/// Errors returned by [`Handle::request_peer_relay`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerRelayRequestError {
    #[error("direct UDP transport stopped")]
    Closed,
}

/// Lifecycle state of a peer relay endpoint known to the direct-UDP adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRelayEndpointState {
    /// No fresh relay endpoint is known for the peer.
    Missing,
    /// A fresh endpoint is binding or waiting for path verification.
    Negotiating,
    /// The endpoint is bound, verified, and within its steady-state lifetime.
    Active,
}

/// Authenticated DERP allocation request from a known peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRelayAllocationEvent {
    pub peer: NodePublic,
    pub peer_disco: DiscoPublic,
    pub client_disco: [DiscoPublic; 2],
    pub generation: u32,
}

#[cfg(test)]
mod tests;
