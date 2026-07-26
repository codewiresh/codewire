//! The top-level [`Conn`] — the capstone that ties the four proven
//! sub-components into a working WireGuard-over-DERP tunnel (#59).
//!
//! This is the Rust equivalent of [`libs/tailnet/conn.go`]. The Go side wraps
//! Tailscale's `wgengine` + `magicsock` + gvisor `netstack`; here we assemble
//! the same data path from our own pieces:
//!
//! ```text
//!   app bytes
//!     │  (listen / dial_context_tcp)
//!     ▼
//!   netstack (#59, smoltcp)        ── bare IP packets ──┐
//!     ▲                                                 │ outbound
//!     │ inbound (decrypted IP)                          ▼
//!   ┌──────────────────────── Conn pump task ─────────────────────┐
//!   │   wg::Peer (#45, boringtun Tunn)                             │
//!   │     decapsulate ◄── encrypted WG ◄── transport recv chan    │
//!   │     encapsulate ──► encrypted WG ──► transport send chan     │
//!   └───────────────────────────────────────────────────────────── ┘
//!                                    │
//!                       transport: DERP relay client (#46)
//!                       or an in-process channel shim
//! ```
//!
//! # Scope (matches the proven sub-components)
//!
//! This is a **single-peer / small-N** Conn with pluggable encrypted-datagram
//! transport. The baseline transport is DERP relay; the #265
//! [`crate::direct_udp`] adapter wraps that relay with Tailscale-compatible
//! disco Ping/Pong/CallMeMaybe handling so verified UDP endpoints can carry
//! WireGuard data. #257 adds UDP relay as a distinct path between direct UDP
//! and DERP fallback; relayed UDP must report as `peer_relay`, not
//! `direct_udp`.
//!
//! # Transport seam
//!
//! The Conn does not embed the DERP client directly; it talks to the transport
//! over a pair of channels carrying [`WgDatagram`]s (an encrypted WG packet +
//! the peer's DERP routing key). That is the same channel-seam philosophy the
//! netstack uses for IP packets — it keeps the data path identical whether the
//! channels are pumped by the real [`crate::derp::Client`] (a thin adapter task
//! reads the send channel and calls `client.send`, and feeds `client.recv`
//! into the recv channel) or by an in-process shim that simply forwards one
//! Conn's send channel to the other's recv channel. The end-to-end test uses
//! the shim; [`DerpTransport`] wires the real client.
//!
//! # Public API (maps to the Go `Conn`)
//!
//! | Go (`conn.go`)               | Rust (`Conn`)                  |
//! |------------------------------|--------------------------------|
//! | `NewConn(opts)`              | [`Conn::new`]                  |
//! | `Listen("tcp", addr)`        | [`Conn::listen`]               |
//! | `DialContextTCP(ctx, dst)`   | [`Conn::dial_context_tcp`]     |
//! | `UpdatePeers([]*Node)`       | [`Conn::update_peers`]         |
//! | `SetNodeCallback(cb)`        | [`Conn::set_node_callback`]    |
//! | `SetDERPMap(dm)`             | [`Conn::set_preferred_derp`] † |
//! | `Node()`                     | [`Conn::node`]                 |
//! | `Close()`                    | [`Conn::close`] / `Drop`       |
//!
//! † region-tracking stand-in; DERPMap parsing/application remains in the
//! coordinator/gateway layer until the STUN slice lands.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::derp::NodePublic as DerpPublic;
use crate::derp::{Client as DerpClient, ReceivedMessage};
use crate::netstack::{Netstack, TcpListener, TcpStream};
use crate::node::{AddrPort, DiscoPublic, Node, NodePublic, Prefix};

/// Tunnel scratch-buffer size for the WG crypto.
///
/// Our smoltcp netstack emits `TUNNEL_MTU`-sized IP packets, but production peers are
/// not always Rust smoltcp peers. The Go/Tailscale client can deliver larger
/// encrypted packets, for example during OpenSSH's default KEXINIT exchange.
/// Boringtun requires the caller-provided buffer to hold the whole encrypted
/// or decrypted packet, so keep this at the same conservative ceiling its
/// device path uses internally instead of deriving it from our local MTU.
const WG_BUF: usize = 64 << 10;

/// How often the pump drives boringtun's timers (handshake retransmit,
/// keepalive, rekey). Mirrors the Go engine's internal tick; boringtun expects
/// `update_timers` on a ~100–250 ms cadence.
const TIMER_TICK: std::time::Duration = std::time::Duration::from_millis(120);

/// Errors from the top-level [`Conn`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("conn closed")]
    Closed,
    #[error("address parse: {0}")]
    Addr(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// An encrypted WireGuard datagram to/from a peer, keyed by the peer's DERP
/// routing key. This is the unit the transport channels move: the Conn never
/// asks the transport to understand WG or IP — only to deliver opaque bytes to
/// a peer key and surface bytes that arrived from one.
#[derive(Clone, Debug)]
pub struct WgDatagram {
    /// The peer's DERP public key (its relay routing address).
    pub peer: DerpPublic,
    /// The opaque encrypted WireGuard packet.
    pub data: Vec<u8>,
}

/// Non-secret snapshot of how the transport would currently reach a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerPath {
    pub transport: PeerTransport,
    /// Direct peer endpoint or UDP peer-relay endpoint, depending on
    /// [`transport`](Self::transport).
    pub endpoint: Option<SocketAddr>,
    pub derp_region_id: Option<i32>,
}

impl PeerPath {
    pub fn direct_udp(endpoint: SocketAddr) -> Self {
        Self {
            transport: PeerTransport::DirectUdp,
            endpoint: Some(endpoint),
            derp_region_id: None,
        }
    }

    pub fn peer_relay(endpoint: SocketAddr) -> Self {
        Self {
            transport: PeerTransport::PeerRelay,
            endpoint: Some(endpoint),
            derp_region_id: None,
        }
    }

    pub fn derp_relay(region_id: i32) -> Self {
        Self {
            transport: PeerTransport::DerpRelay,
            endpoint: None,
            derp_region_id: Some(if region_id == 0 { 1 } else { region_id }),
        }
    }

    pub fn unknown() -> Self {
        Self {
            transport: PeerTransport::Unknown,
            endpoint: None,
            derp_region_id: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerTransport {
    DirectUdp,
    PeerRelay,
    DerpRelay,
    Unknown,
}

/// The transport halves a [`Conn`] is built on: encrypted datagrams out
/// (`to_transport`) and in (`from_transport`).
///
/// * `to_transport` — the Conn sends encrypted [`WgDatagram`]s here; the
///   transport (DERP client adapter or shim) relays them to the named peer.
/// * `from_transport` — the transport delivers encrypted datagrams that
///   arrived from peers; the Conn decrypts them into the netstack.
pub struct Transport {
    /// Conn → transport: datagrams to relay.
    pub to_transport: mpsc::UnboundedSender<WgDatagram>,
    /// transport → Conn: datagrams received from peers.
    pub from_transport: mpsc::UnboundedReceiver<WgDatagram>,
    /// Optional transport control path. Direct-UDP transports need the current
    /// peer `Node`s so they can validate disco keys and endpoint ownership.
    pub peer_updates: Option<mpsc::UnboundedSender<Vec<Node>>>,
    /// Optional path probe supplied by transports that can select paths.
    pub path_probe: Option<Arc<dyn Fn(NodePublic) -> PeerPath + Send + Sync>>,
    /// Optional local endpoint update stream supplied by transports that
    /// discover new advertised endpoints after [`Conn::new`].
    pub local_endpoint_updates: Option<mpsc::UnboundedReceiver<Vec<AddrPort>>>,
}

/// Wire a DERP client into the Conn transport channel seam.
///
/// The Conn sends encrypted WireGuard datagrams keyed by the destination peer;
/// DERP delivers received packets keyed by the source peer. This adapter keeps
/// that relabeling at the tailnet layer so consumers do not need to understand
/// DERP frame semantics.
pub fn transport_from_derp_client<S>(mut client: DerpClient<S>) -> Transport
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (to_transport, mut to_transport_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (from_transport_tx, from_transport) = mpsc::unbounded_channel::<WgDatagram>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                maybe = to_transport_rx.recv() => {
                    let Some(dg) = maybe else { return; };
                    if client.send(&dg.peer, &dg.data).await.is_err() {
                        return;
                    }
                }
                msg = client.recv() => {
                    match msg {
                        Ok(ReceivedMessage::Packet { source, data }) => {
                            if from_transport_tx.send(WgDatagram { peer: source, data }).is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
            }
        }
    });

    Transport {
        to_transport,
        from_transport,
        peer_updates: None,
        path_probe: None,
        local_endpoint_updates: None,
    }
}

/// Per-peer state the Conn tracks: the WireGuard session and routing info.
struct Peer {
    /// boringtun session keyed by our secret + the peer's WG public key.
    tunn: Tunn,
    /// The peer's DERP routing key (transport address). For the relay-only
    /// Conn this is the peer's WG public key — both are the same Curve25519
    /// identity in Codewire's model (`Node.key`).
    derp_key: DerpPublic,
    /// The ULA addresses this peer owns (its `AllowedIPs`); used to route an
    /// outbound IP packet by destination to the right peer.
    addresses: Vec<Prefix>,
}

/// The node-change callback (Go `func(*Node)`): invoked whenever local node
/// info changes (preferred DERP, etc.) so the coordinator client can re-publish.
type NodeCallback = Arc<dyn Fn(&Node) + Send + Sync + 'static>;

/// Mutex-guarded node metadata that [`Conn::node`] reports and that the
/// node-change callback observes. Mirrors the fields the Go `Conn` guards under
/// `mu` (preferred DERP, addrs, the callback).
struct NodeState {
    id: Uuid,
    node_key: NodePublic,
    disco_key: DiscoPublic,
    addrs: Vec<Prefix>,
    endpoints: Vec<AddrPort>,
    preferred_derp: i32,
    node_cb: Option<NodeCallback>,
}

impl NodeState {
    /// Build a [`Node`] snapshot, mirroring Go `Conn.Node()` (DERP defaults to
    /// 1 when unset).
    fn snapshot(&self) -> Node {
        let derp = if self.preferred_derp == 0 {
            1
        } else {
            self.preferred_derp
        };
        Node {
            id: self.id,
            as_of: now_utc(),
            key: self.node_key,
            disco_key: self.disco_key,
            preferred_derp: derp,
            derp_latency: None,
            endpoints: self.endpoints.clone(),
            addresses: self.addrs.clone(),
        }
    }
}

/// Options for [`Conn::new`], mirroring Go `tailnet.Options`.
pub struct Options {
    /// Stable identity (environment UUID for a sidecar; per-connection UUID for
    /// a client). Drives the deterministic ULA prefix when `addresses` is empty.
    pub id: Uuid,
    /// The ULA addresses this node owns. If empty, a single `/128` is derived
    /// from `id` via [`crate::node::prefix_from_uuid`], matching the Go default.
    pub addresses: Vec<Prefix>,
    /// Direct UDP endpoints to publish. Only set this when the caller has
    /// already bound the matching UDP transport; the relay-only default stays
    /// empty so Rust never advertises an endpoint it cannot answer.
    pub endpoints: Vec<AddrPort>,
    /// Our WireGuard static secret. If `None`, a fresh key is generated (the Go
    /// `key.NewNode()` path). Tests pass explicit keys so both ends agree.
    pub private_key: Option<StaticSecret>,
    /// Our disco private key. Direct-UDP transports receive the same key so
    /// the published `Node.disco_key` and the UDP disco wrapper identity match.
    pub disco_private: Option<crate::disco::DiscoPrivate>,
}

impl Options {
    /// Minimal options: just an identity, fresh key, derived ULA address.
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            addresses: Vec::new(),
            endpoints: Vec::new(),
            private_key: None,
            disco_private: None,
        }
    }
}

/// A WireGuard-over-DERP tunnel exposing `listen` / `dial_context_tcp`.
///
/// Construct with [`Conn::new`], register peers with [`Conn::update_peers`],
/// then `listen` / `dial_context_tcp`. The encrypt/decrypt/relay data path runs
/// on an owned background pump task spawned in [`Conn::new`]; dropping the
/// `Conn` (or calling [`Conn::close`]) tears it down.
pub struct Conn {
    netstack: Netstack,
    /// Our WireGuard static secret (kept so `update_peers` can build new
    /// `Tunn`s for freshly-learned peers).
    our_secret: StaticSecret,
    /// Shared peer table, also held by the pump task. Keyed by the peer's WG
    /// public key.
    peers: Arc<Mutex<HashMap<[u8; 32], Peer>>>,
    /// Node metadata + the node-change callback.
    node_state: Arc<Mutex<NodeState>>,
    /// The pump task handle; aborted on close/drop.
    pump: tokio::task::JoinHandle<()>,
    /// Optional transport control path for peer metadata.
    transport_peer_updates: Option<mpsc::UnboundedSender<Vec<Node>>>,
    /// Optional transport path observation hook.
    transport_path_probe: Option<Arc<dyn Fn(NodePublic) -> PeerPath + Send + Sync>>,
    /// Optional task that applies local endpoint updates from the transport.
    endpoint_updates_task: Option<tokio::task::JoinHandle<()>>,
    /// Monotonic index for new `Tunn`s (boringtun wants a unique local index
    /// per peer session).
    next_index: Arc<Mutex<u32>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Conn {
    /// Create a Conn over the given transport, mirroring Go `NewConn`.
    ///
    /// Spawns the pump task that runs the full data path: it owns the WG
    /// sessions, pulls outbound IP packets from the netstack and encrypts +
    /// relays them to the transport, and pulls encrypted datagrams off the
    /// transport and decrypts them back into the netstack.
    pub fn new(opts: Options, transport: Transport) -> Result<Self, Error> {
        let our_secret = opts
            .private_key
            .unwrap_or_else(|| StaticSecret::random_from_rng(rand::rngs::OsRng));
        let our_public = PublicKey::from(&our_secret);
        let disco_private = opts
            .disco_private
            .unwrap_or_else(|| crate::disco::DiscoPrivate::generate(&mut rand::rngs::OsRng));
        let disco_public = disco_private.public();

        // Default the address to the deterministic ULA /128 if none given,
        // matching the Go client when the coordinator has not assigned one.
        let addrs = if opts.addresses.is_empty() {
            vec![crate::node::prefix_from_uuid(&opts.id)]
        } else {
            opts.addresses
        };

        // The netstack answers for our first address (the relay-only Conn is
        // single-address; multi-address routing is deferred — see notes).
        let (local_ip, prefix_len) = addrs
            .first()
            .map(|p| (p.addr(), p.bits()))
            .ok_or_else(|| Error::Addr("no local address".into()))?;

        // Channels bridging the netstack and the pump:
        //   netstack.outbound -> pump (encrypt + relay)
        //   pump (decrypt)    -> netstack.inbound
        let (ns_out_tx, ns_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (ns_in_tx, ns_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let netstack = Netstack::new(local_ip, prefix_len, ns_in_rx, ns_out_tx);

        let peers = Arc::new(Mutex::new(HashMap::<[u8; 32], Peer>::new()));
        let node_state = Arc::new(Mutex::new(NodeState {
            id: opts.id,
            node_key: NodePublic::from_raw(our_public.to_bytes()),
            disco_key: disco_public,
            addrs,
            endpoints: opts.endpoints,
            preferred_derp: 0,
            node_cb: None,
        }));
        let next_index = Arc::new(Mutex::new(1u32));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let Transport {
            to_transport,
            from_transport,
            peer_updates,
            path_probe,
            local_endpoint_updates,
        } = transport;

        let pump = tokio::spawn(pump_loop(PumpCtx {
            peers: peers.clone(),
            ns_out_rx,
            ns_in_tx,
            to_transport,
            from_transport,
        }));
        let transport_peer_updates = peer_updates;
        let transport_path_probe = path_probe;
        let endpoint_updates_task = local_endpoint_updates.map(|updates| {
            tokio::spawn(apply_local_endpoint_updates(
                node_state.clone(),
                updates,
                closed.clone(),
            ))
        });

        Ok(Self {
            netstack,
            our_secret,
            peers,
            node_state,
            pump,
            transport_peer_updates,
            transport_path_probe,
            endpoint_updates_task,
            next_index,
            closed,
        })
    }

    /// Register / replace the set of peers, mirroring Go `UpdatePeers`.
    ///
    /// For each peer we create (or keep) a boringtun [`Tunn`] keyed by our
    /// secret + the peer's WG public key, and record its DERP routing key and
    /// owned addresses for outbound routing. Peers absent from `nodes` are
    /// dropped. The relay-only Conn treats `Node.key` as both the WG identity
    /// and the DERP routing key (the same Curve25519 identity in Codewire).
    pub fn update_peers(&self, nodes: &[Node]) -> Result<(), Error> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let mut peers = self.peers.lock().unwrap();
        let mut keep: HashMap<[u8; 32], Peer> = HashMap::new();

        for node in nodes {
            let wg_pub = *node.key.as_bytes();
            if let Some(existing) = peers.remove(&wg_pub) {
                // Keep the live session; refresh routing info.
                keep.insert(
                    wg_pub,
                    Peer {
                        tunn: existing.tunn,
                        derp_key: DerpPublic::from_raw(wg_pub),
                        addresses: node.addresses.clone(),
                    },
                );
                continue;
            }
            let index = {
                let mut idx = self.next_index.lock().unwrap();
                let v = *idx;
                *idx = idx.wrapping_add(1);
                v
            };
            let tunn = Tunn::new(
                self.our_secret.clone(),
                PublicKey::from(wg_pub),
                None,
                None,
                index,
                None,
            );
            keep.insert(
                wg_pub,
                Peer {
                    tunn,
                    derp_key: DerpPublic::from_raw(wg_pub),
                    addresses: node.addresses.clone(),
                },
            );
        }
        *peers = keep;
        if let Some(tx) = self.transport_peer_updates.as_ref() {
            let _ = tx.send(nodes.to_vec());
        }
        Ok(())
    }

    /// Bind a TCP listener, mirroring Go `Listen("tcp", addr)`.
    ///
    /// Accepts a Go-style `host:port` string (`":22"`, `"[fd7a::a]:22"`); only
    /// the port is used for binding (the netstack answers for our single local
    /// address on any host), matching the Go listener which keys on port.
    pub async fn listen(&self, network: &str, addr: &str) -> Result<TcpListener, Error> {
        if network != "tcp" {
            return Err(Error::Addr(format!("unsupported network {network}")));
        }
        let port = parse_port(addr)?;
        Ok(self.netstack.bind(port).await?)
    }

    /// Dial a TCP connection over the tunnel, mirroring Go
    /// `DialContextTCP(ctx, dst)`. The deadline is the caller's responsibility
    /// (wrap in `tokio::time::timeout`), matching how the Go callers pass a
    /// context.
    pub async fn dial_context_tcp(&self, dst: SocketAddr) -> Result<TcpStream, Error> {
        Ok(self.netstack.connect(dst).await?)
    }

    /// Set the node-change callback, mirroring Go `SetNodeCallback`. Invoked
    /// immediately with the current node (as Go does).
    pub fn set_node_callback<F>(&self, cb: F)
    where
        F: Fn(&Node) + Send + Sync + 'static,
    {
        let node = {
            let mut st = self.node_state.lock().unwrap();
            st.node_cb = Some(Arc::new(cb));
            st.snapshot()
        };
        emit_node_callback(&self.node_state, &node);
    }

    /// Set the preferred DERP region — the region-tracking stand-in for Go's
    /// `SetDERPMap` + magicsock netcheck.
    ///
    /// Rust direct UDP is driven by the transport adapter, not by a Tailscale
    /// DERPMap object inside `Conn`. The full STUN-derived endpoint discovery
    /// slice will add DERPMap application at the gateway/coordinator boundary;
    /// until then the home region is recorded so [`Conn::node`] reports it to
    /// the coordinator and the node callback fires.
    pub fn set_preferred_derp(&self, region: i32) {
        let node = {
            let mut st = self.node_state.lock().unwrap();
            st.preferred_derp = region;
            st.snapshot()
        };
        emit_node_callback(&self.node_state, &node);
    }

    /// Replace the local advertised direct endpoints and notify the node
    /// callback if they changed.
    pub fn set_endpoints(&self, endpoints: Vec<AddrPort>) {
        let node = {
            let mut st = self.node_state.lock().unwrap();
            if st.endpoints == endpoints {
                return;
            }
            st.endpoints = endpoints;
            st.snapshot()
        };
        emit_node_callback(&self.node_state, &node);
    }

    /// Clear the node-change callback.
    pub fn clear_node_callback(&self) {
        let mut st = self.node_state.lock().unwrap();
        st.node_cb = None;
    }

    /// Current node info for coordination, mirroring Go `Node()`.
    pub fn node(&self) -> Node {
        self.node_state.lock().unwrap().snapshot()
    }

    /// Return the current non-secret transport path for `peer`, comparable to
    /// Go `ProbePeerPath` but without sending an active ping.
    pub fn probe_peer_path(&self, peer: &Node) -> Result<PeerPath, Error> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let known = self.peers.lock().unwrap().contains_key(peer.key.as_bytes());
        if !known {
            return Err(Error::Addr("unknown peer".into()));
        }
        if let Some(probe) = self.transport_path_probe.as_ref() {
            return Ok(probe(peer.key));
        }
        Ok(PeerPath::derp_relay(peer.preferred_derp))
    }

    /// Shut down the tunnel: abort the pump task. Idempotent. The netstack is
    /// torn down when this `Conn` drops (its driver task ends when the inbound
    /// sender and command channel are dropped).
    pub fn close(&self) {
        if self.closed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        self.pump.abort();
        if let Some(task) = self.endpoint_updates_task.as_ref() {
            task.abort();
        }
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.close();
    }
}

fn emit_node_callback(node_state: &Arc<Mutex<NodeState>>, node: &Node) {
    let cb = node_state.lock().unwrap().node_cb.as_ref().cloned();
    if let Some(cb) = cb {
        cb(node);
    }
}

async fn apply_local_endpoint_updates(
    node_state: Arc<Mutex<NodeState>>,
    mut updates: mpsc::UnboundedReceiver<Vec<AddrPort>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
) {
    while let Some(endpoints) = updates.recv().await {
        if closed.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let node = {
            let mut st = node_state.lock().unwrap();
            if st.endpoints == endpoints {
                continue;
            }
            st.endpoints = endpoints;
            st.snapshot()
        };
        emit_node_callback(&node_state, &node);
    }
}

/// Current wall-clock time as a UTC [`DateTime`], for the `Node.as_of` stamp
/// (Go's `time.Now()`). `chrono` is built without its `clock` feature here, so
/// we read the clock via `std::time::SystemTime` and convert.
fn now_utc() -> DateTime<Utc> {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos()).unwrap_or_default()
}

/// Parse the port out of a Go-style `host:port` listen/dial string.
///
/// Mirrors `net.SplitHostPort` for the cases the Conn needs: `":22"`,
/// `"host:22"`, `"[fd7a::a]:22"`. Only the port is consumed for `listen`.
fn parse_port(addr: &str) -> Result<u16, Error> {
    let port_str = addr
        .rsplit_once(':')
        .map(|(_, p)| p)
        .ok_or_else(|| Error::Addr(format!("missing ':' in {addr}")))?;
    port_str
        .parse::<u16>()
        .map_err(|_| Error::Addr(format!("invalid port in {addr}")))
}

/// Everything the pump task owns. One struct keeps the spawn a single move.
struct PumpCtx {
    peers: Arc<Mutex<HashMap<[u8; 32], Peer>>>,
    ns_out_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ns_in_tx: mpsc::UnboundedSender<Vec<u8>>,
    to_transport: mpsc::UnboundedSender<WgDatagram>,
    from_transport: mpsc::UnboundedReceiver<WgDatagram>,
}

/// The data-plane pump: a single task that owns the WG sessions and bridges the
/// netstack and the transport in both directions, plus drives boringtun timers.
///
/// Everything funnels through one task (rather than locking the `Tunn` across
/// await points) so each `Tunn`'s single-threaded state machine is only ever
/// touched synchronously, mirroring how the netstack driver confines smoltcp.
/// The `peers` mutex is held only for the synchronous encrypt/decrypt critical
/// sections, never across a channel send.
async fn pump_loop(ctx: PumpCtx) {
    let PumpCtx {
        peers,
        mut ns_out_rx,
        ns_in_tx,
        to_transport,
        mut from_transport,
    } = ctx;

    let mut timer = tokio::time::interval(TIMER_TICK);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Outbound: a bare IP packet the netstack wants to send.
            maybe_pkt = ns_out_rx.recv() => {
                let Some(pkt) = maybe_pkt else { return; };
                send_outbound(&peers, &to_transport, pkt);
            }

            // Inbound: an encrypted WG datagram off the transport.
            maybe_dg = from_transport.recv() => {
                let Some(dg) = maybe_dg else { return; };
                recv_inbound(&peers, &to_transport, &ns_in_tx, dg);
            }

            // Timer tick: drive every peer's boringtun timers (handshake
            // retransmit, keepalive, rekey). Any emitted packet is shipped.
            _ = timer.tick() => {
                drive_timers(&peers, &to_transport);
            }
        }
    }
}

/// Route an outbound IP packet to the owning peer, `encapsulate` it, and relay
/// the resulting encrypted datagram(s) over the transport.
fn send_outbound(
    peers: &Arc<Mutex<HashMap<[u8; 32], Peer>>>,
    to_transport: &mpsc::UnboundedSender<WgDatagram>,
    pkt: Vec<u8>,
) {
    let mut guard = peers.lock().unwrap();
    let Some(dst_ip) = dst_ip_of(&pkt) else {
        tracing::debug!(
            packet_len = pkt.len(),
            "rust tailnet dropped outbound IP packet with unknown destination"
        );
        return;
    };
    // Route by AllowedIPs; single-peer tunnels fall back to the only peer.
    let key = match route_key(&guard, dst_ip).or_else(|| single_peer_key(&guard)) {
        Some(k) => k,
        None => {
            tracing::debug!(
                %dst_ip,
                packet_len = pkt.len(),
                peer_count = guard.len(),
                "rust tailnet dropped outbound IP packet with no peer route"
            );
            return;
        }
    };
    let peer = guard.get_mut(&key).unwrap();
    let derp_key = peer.derp_key.clone();

    let mut buf = vec![0u8; WG_BUF];
    match peer.tunn.encapsulate(&pkt, &mut buf) {
        TunnResult::WriteToNetwork(p) => {
            tracing::debug!(
                %dst_ip,
                ip_packet_len = pkt.len(),
                wg_packet_len = p.len(),
                "rust tailnet encapsulated outbound IP packet"
            );
            let _ = to_transport.send(WgDatagram {
                peer: derp_key.clone(),
                data: p.to_vec(),
            });
        }
        // No session yet → boringtun queued `pkt` and may have emitted a
        // handshake init above; nothing more to do here (the queued packet is
        // flushed once the handshake completes, via the timer/inbound paths).
        TunnResult::Done | TunnResult::Err(_) => {}
        // encapsulate never decrypts to-tunnel; ignore defensively.
        _ => {}
    }
    // Flush any handshake-queued packets that became sendable.
    loop {
        let mut b2 = vec![0u8; WG_BUF];
        match peer.tunn.decapsulate(None, &[], &mut b2) {
            TunnResult::WriteToNetwork(p) => {
                let _ = to_transport.send(WgDatagram {
                    peer: derp_key.clone(),
                    data: p.to_vec(),
                });
            }
            _ => break,
        }
    }
}

/// Decrypt an inbound encrypted datagram. boringtun may emit handshake/cookie
/// replies (`WriteToNetwork`, shipped straight back over the transport) and/or
/// a decrypted IP packet (`WriteToTunnelV4/V6`, pushed into the netstack).
fn recv_inbound(
    peers: &Arc<Mutex<HashMap<[u8; 32], Peer>>>,
    to_transport: &mpsc::UnboundedSender<WgDatagram>,
    ns_in_tx: &mpsc::UnboundedSender<Vec<u8>>,
    dg: WgDatagram,
) {
    let key = *dg.peer.as_bytes();
    let mut guard = peers.lock().unwrap();
    let Some(peer) = guard.get_mut(&key) else {
        return;
    };
    let derp_key = peer.derp_key.clone();

    // The first decapsulate consumes the datagram; subsequent calls with an
    // empty datagram drain boringtun's internal queue until Done.
    let mut input: &[u8] = &dg.data;
    loop {
        let mut buf = vec![0u8; WG_BUF];
        match peer.tunn.decapsulate(None, input, &mut buf) {
            TunnResult::WriteToNetwork(p) => {
                tracing::debug!(
                    wg_packet_len = dg.data.len(),
                    response_len = p.len(),
                    "rust tailnet answered inbound WireGuard control packet"
                );
                let _ = to_transport.send(WgDatagram {
                    peer: derp_key.clone(),
                    data: p.to_vec(),
                });
                input = &[]; // keep draining
            }
            TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                // Decrypted IP packet → straight into the netstack inbound.
                tracing::debug!(
                    wg_packet_len = dg.data.len(),
                    ip_packet_len = p.len(),
                    "rust tailnet decrypted inbound WireGuard packet"
                );
                let _ = ns_in_tx.send(p.to_vec());
                break;
            }
            TunnResult::Done => break,
            TunnResult::Err(err) => {
                tracing::debug!(
                    wg_packet_len = dg.data.len(),
                    error = ?err,
                    "rust tailnet rejected inbound WireGuard packet"
                );
                break;
            }
        }
    }
}

/// Drive every peer's boringtun timers; ship any emitted packet (handshake
/// retransmit / keepalive).
fn drive_timers(
    peers: &Arc<Mutex<HashMap<[u8; 32], Peer>>>,
    to_transport: &mpsc::UnboundedSender<WgDatagram>,
) {
    let mut guard = peers.lock().unwrap();
    for peer in guard.values_mut() {
        let mut buf = vec![0u8; WG_BUF];
        if let TunnResult::WriteToNetwork(p) = peer.tunn.update_timers(&mut buf) {
            let _ = to_transport.send(WgDatagram {
                peer: peer.derp_key.clone(),
                data: p.to_vec(),
            });
        }
    }
}

/// Extract the destination IP from a bare IP packet (v4 or v6 header).
fn dst_ip_of(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => {
            let mut o = [0u8; 4];
            o.copy_from_slice(&pkt[16..20]);
            Some(IpAddr::from(o))
        }
        Some(6) if pkt.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::from(o))
        }
        _ => None,
    }
}

/// Find the peer whose `AllowedIPs` contain `dst` (first containing match wins;
/// longest-prefix is unnecessary for the small-N relay Conn).
fn route_key(peers: &HashMap<[u8; 32], Peer>, dst: IpAddr) -> Option<[u8; 32]> {
    for (key, peer) in peers {
        for prefix in &peer.addresses {
            if prefix_contains(prefix, dst) {
                return Some(*key);
            }
        }
    }
    None
}

/// When exactly one peer is registered, route to it unconditionally — the
/// single-peer tunnel does not need a populated address table.
fn single_peer_key(peers: &HashMap<[u8; 32], Peer>) -> Option<[u8; 32]> {
    if peers.len() == 1 {
        peers.keys().next().copied()
    } else {
        None
    }
}

/// Does `prefix` contain `addr`? Bit-prefix match over the raw address octets.
fn prefix_contains(prefix: &Prefix, addr: IpAddr) -> bool {
    let (p_bytes, a_bytes): (Vec<u8>, Vec<u8>) = match (prefix.addr(), addr) {
        (IpAddr::V4(p), IpAddr::V4(a)) => (p.octets().to_vec(), a.octets().to_vec()),
        (IpAddr::V6(p), IpAddr::V6(a)) => (p.octets().to_vec(), a.octets().to_vec()),
        _ => return false,
    };
    // Defensive bound: a Prefix built via `new` (which does not validate)
    // could carry bits > the address width; cap to the octet count so the
    // slicing below can never panic. Deserialized prefixes are already
    // range-checked, so this only guards programmatically-built values.
    let bits = (prefix.bits() as usize).min(a_bytes.len() * 8);
    let full = bits / 8;
    if a_bytes[..full] != p_bytes[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a_bytes[full] & mask) == (p_bytes[full] & mask)
}

#[cfg(test)]
mod tests;
