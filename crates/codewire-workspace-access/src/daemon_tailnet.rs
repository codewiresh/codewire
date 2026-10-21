//! The bound workspace daemon's tailnet peer (#2460).
//!
//! The daemon is its environment's tailnet peer. It reaches the public
//! coordinator with a short-lived peer token from its access grant, renews
//! the grant at half its lifetime through the Pod-bound binding exchange and
//! re-proves the open coordinator session in-band with each new token. When
//! the coordinator ends a session (a lapsed proof or a new operation
//! generation), the daemon renews the grant first and then reconnects, so a
//! replacement session always carries a strictly newer proof.
//!
//! DERP and STUN come from the coordinator's DERP map. Direct UDP listens on
//! the workspace's tailnet port and advertises the environment's own
//! LoadBalancer. UDP peer-relay slots are allocated by orchestration on the
//! daemon's behalf, so the allocator credential never enters the sandbox.
//! SSH over the tailnet is served in-process, like the Pod-network listener.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use codewire_client::{
    BearerToken, COORDINATOR_SETUP_TIMEOUT, CoordinatorError, CoordinatorHandlers,
    CoordinatorPeerSession, PrimaryCoordinateIdentity, StunServer, derp_target_from_map,
    resolve_stun_servers, stun_servers_from_map,
};
use codewire_daemon::access::WorkspaceAccessGrant;
use codewire_daemon::app_ports::AppPorts;
use codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_FILE;
use codewire_tailnet::conn::{Conn, Options};
use codewire_tailnet::derp_transport::{
    DerpTarget, DerpTransport, connect_derp_transport_absolute,
};
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::{DiscoPrivate, UDPRelayEndpoint};
use codewire_tailnet::dns::{absolute_dns_name, absolute_host_port};
use codewire_tailnet::netstack::{TcpListener as TailnetListener, TcpStream as TailnetStream};
use codewire_tailnet::node::{DiscoPublic, Node, NodePublic};
use codewire_tailnet::wg::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use russh::server;
use tokio::net::lookup_host;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

use crate::daemon_access::{
    AccessControlPlane, ControlPlaneError, DaemonSshRunners, PeerRelayAllocation,
    record_host_key_until_accepted,
};
use crate::peer_relay::{PeerRelayAllocator, PeerRelayBackend};

/// Wait between coordinator connection attempts.
pub const COORDINATOR_RETRY_DELAY: Duration = Duration::from_secs(5);
const REFRESH_RETRY_INITIAL: Duration = Duration::from_secs(1);
const REFRESH_RETRY_MAX: Duration = Duration::from_secs(30);
const HOST_KEY_RECORD_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const HOST_KEY_RECORD_MAX_BACKOFF: Duration = Duration::from_secs(5);
/// Orchestration admits at most one call per second per Pod, with a small
/// burst. Relay allocations leave room for access renewal.
const PEER_RELAY_CALL_SPACING: Duration = Duration::from_secs(2);
const PEER_RELAY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const LOG_COMPONENT: &str = "workspace daemon";

/// The access grant the daemon holds. Only [`AccessGrants::refresh`]
/// replaces it, with the grant orchestration returns.
pub struct AccessGrants {
    plane: Arc<dyn AccessControlPlane>,
    current: watch::Sender<WorkspaceAccessGrant>,
}

impl AccessGrants {
    pub fn new(plane: Arc<dyn AccessControlPlane>, initial: WorkspaceAccessGrant) -> Arc<Self> {
        Arc::new(Self {
            plane,
            current: watch::Sender::new(initial),
        })
    }

    pub fn current(&self) -> WorkspaceAccessGrant {
        self.current.borrow().clone()
    }

    /// Follow every grant that replaces the current one.
    pub fn subscribe(&self) -> watch::Receiver<WorkspaceAccessGrant> {
        self.current.subscribe()
    }

    /// Ask orchestration for a fresh grant once; it replaces the current one.
    pub async fn refresh(&self) -> Result<(), ControlPlaneError> {
        let grant = self.plane.refresh_access().await?;
        self.current.send_replace(grant);
        Ok(())
    }

    /// Renew the grant at half of each grant's remaining lifetime until
    /// shutdown. A failed renewal is retried with backoff; the coordinator
    /// ends the session if the proven token lapses meanwhile.
    pub async fn keep_fresh(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut grants = self.subscribe();
        let mut backoff = REFRESH_RETRY_INITIAL;
        loop {
            let now = SystemTime::now();
            let due = {
                let grant = grants.borrow_and_update();
                grant
                    .refresh_at(now)
                    .duration_since(now)
                    .unwrap_or_default()
            };
            tokio::select! {
                _ = shutdown.changed() => return,
                // Another caller renewed it: schedule from the new grant.
                changed = grants.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue;
                }
                () = tokio::time::sleep(due) => {}
            }
            match self.refresh().await {
                Ok(()) => backoff = REFRESH_RETRY_INITIAL,
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        retry_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                        "workspace access renewal failed; retrying"
                    );
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        () = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(REFRESH_RETRY_MAX);
                }
            }
        }
    }
}

/// Opens a coordinator session for an environment peer, authenticated by
/// the grant's peer token.
#[async_trait]
pub trait CoordinatorDialer: Send + Sync + 'static {
    async fn dial(
        &self,
        grant: &WorkspaceAccessGrant,
        environment_id: Uuid,
    ) -> Result<CoordinatorPeerSession, CoordinatorError>;
}

/// The public coordinator named by the grant, through the public gRPC edge.
/// It trusts the WebPKI roots plus, only when a bundle is mounted at its
/// extra-roots path, that bundle; a present but unusable bundle refuses
/// every dial rather than falling back. Like every endpoint the daemon dials,
/// its host is looked up as an absolute DNS name (#2701).
pub struct PublicCoordinator {
    extra_roots_file: PathBuf,
}

impl PublicCoordinator {
    /// Extra roots from [`COORDINATOR_EXTRA_ROOTS_FILE`] when mounted.
    pub fn new() -> Self {
        Self::with_extra_roots_file(COORDINATOR_EXTRA_ROOTS_FILE)
    }

    pub fn with_extra_roots_file(extra_roots_file: impl Into<PathBuf>) -> Self {
        Self {
            extra_roots_file: extra_roots_file.into(),
        }
    }
}

impl Default for PublicCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoordinatorDialer for PublicCoordinator {
    async fn dial(
        &self,
        grant: &WorkspaceAccessGrant,
        environment_id: Uuid,
    ) -> Result<CoordinatorPeerSession, CoordinatorError> {
        let extra_roots = codewire_tls::read_optional_roots(&self.extra_roots_file)
            .await
            .map_err(|_| CoordinatorError::Trust)?
            .unwrap_or_default();
        CoordinatorPeerSession::connect_public_edge_grpc_absolute(
            grant.coordinator_url(),
            grant.peer_token().expose_secret(),
            PrimaryCoordinateIdentity::sidecar(environment_id),
            extra_roots,
            COORDINATOR_SETUP_TIMEOUT,
        )
        .await
    }
}

/// One coordinator session and the grants that followed the one it was
/// opened with.
pub struct DialedSession {
    session: CoordinatorPeerSession,
    grants: watch::Receiver<WorkspaceAccessGrant>,
}

impl DialedSession {
    /// Open a session with the current grant.
    pub async fn dial(
        grants: &AccessGrants,
        dialer: &dyn CoordinatorDialer,
        environment_id: Uuid,
    ) -> Result<Self, CoordinatorError> {
        let mut followed = grants.subscribe();
        let grant = followed.borrow_and_update().clone();
        let session = dialer.dial(&grant, environment_id).await?;
        Ok(Self {
            session,
            grants: followed,
        })
    }

    /// The DERP map the coordinator sent at setup, if any.
    pub fn setup_derp_map(&self) -> Option<serde_json::Value> {
        self.session.setup_derp_map()
    }
}

/// The data plane a coordinator session drives.
pub trait PeerDataPlane: Send + Sync + 'static {
    /// Start publishing this peer's node, beginning with the current one.
    fn publish_nodes(&self) -> mpsc::UnboundedReceiver<Node>;
    /// Stop publishing nodes to the ended session.
    fn stop_publishing(&self);
    /// Apply the coordinator's complete peer snapshot.
    fn apply_peers(&self, nodes: &[Node]);
}

/// Drive one session until the coordinator ends it, re-proving it with each
/// grant that replaces the one it was opened with.
pub async fn drive_session(
    dialed: DialedSession,
    data_plane: &dyn PeerDataPlane,
) -> Result<(), CoordinatorError> {
    let DialedSession {
        mut session,
        mut grants,
    } = dialed;
    let (proofs, proof_rx) = mpsc::unbounded_channel();
    let forward_proofs = async move {
        while grants.changed().await.is_ok() {
            let token = grants.borrow_and_update().peer_token().clone();
            if let Ok(token) = BearerToken::new(token.expose_secret()) {
                let _ = proofs.send(token);
            }
        }
        std::future::pending::<()>().await;
    };
    let nodes = data_plane.publish_nodes();
    let handlers = CoordinatorHandlers {
        on_peers: |peers: &[Node]| data_plane.apply_peers(peers),
        on_derp_map: |_: &serde_json::Value| {},
    };
    let result = tokio::select! {
        result = session.run_with_node_updates_and_proofs(nodes, proof_rx, handlers) => result,
        () = forward_proofs => Ok(()),
    };
    data_plane.stop_publishing();
    result
}

/// Keep the environment's coordinator session up until shutdown: drive
/// `first`, then renew the grant and reconnect whenever a session ends.
pub async fn run_coordinator_sessions(
    first: Option<DialedSession>,
    environment_id: Uuid,
    grants: Arc<AccessGrants>,
    dialer: Arc<dyn CoordinatorDialer>,
    data_plane: Arc<dyn PeerDataPlane>,
    retry_delay: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut next = first;
    loop {
        let dialed = match next.take() {
            Some(dialed) => dialed,
            None => {
                // A replacement session must carry a newer proof than the
                // one it replaces.
                if let Err(error) = grants.refresh().await {
                    tracing::warn!(error = %error, "workspace access renewal before reconnect failed");
                }
                match DialedSession::dial(&grants, dialer.as_ref(), environment_id).await {
                    Ok(dialed) => dialed,
                    Err(error) => {
                        tracing::warn!(error = %error, "workspace tailnet coordinator unavailable; retrying");
                        tokio::select! {
                            _ = shutdown.changed() => return,
                            () = tokio::time::sleep(retry_delay) => {}
                        }
                        continue;
                    }
                }
            }
        };
        tokio::select! {
            _ = shutdown.changed() => return,
            result = drive_session(dialed, data_plane.as_ref()) => match result {
                Ok(()) => tracing::info!("workspace tailnet coordinator session ended; reconnecting"),
                Err(error) => tracing::warn!(error = %error, "workspace tailnet coordinator session failed; reconnecting"),
            },
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            () = tokio::time::sleep(retry_delay) => {}
        }
    }
}

/// Record the host key again whenever the grant's operation generation
/// differs from `recorded`, the generation it was last recorded for.
/// Orchestration keeps one key per bound Pod, so the same Pod's same key is
/// accepted again unchanged; the call only confirms it.
pub async fn record_host_key_per_generation(
    plane: Arc<dyn AccessControlPlane>,
    mut grants: watch::Receiver<WorkspaceAccessGrant>,
    public_key_openssh: String,
    mut recorded: u64,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let generation = grants.borrow_and_update().operation_generation();
        if generation != recorded {
            match record_host_key_until_accepted(
                plane.as_ref(),
                &public_key_openssh,
                HOST_KEY_RECORD_INITIAL_BACKOFF,
                HOST_KEY_RECORD_MAX_BACKOFF,
            )
            .await
            {
                Ok(()) => tracing::info!(
                    generation,
                    "workspace SSH host key recorded for the new generation"
                ),
                Err(_) => tracing::error!(
                    generation,
                    "workspace SSH host key refused for the new generation"
                ),
            }
            recorded = generation;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            changed = grants.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

/// Allocates UDP relay slots through orchestration (`AllocatePeerRelay`),
/// never with the allocator's own credential.
pub struct OrchestratedPeerRelay {
    plane: Arc<dyn AccessControlPlane>,
    next_call: Mutex<tokio::time::Instant>,
}

impl OrchestratedPeerRelay {
    pub fn new(plane: Arc<dyn AccessControlPlane>) -> Self {
        Self {
            plane,
            next_call: Mutex::new(tokio::time::Instant::now()),
        }
    }
}

#[async_trait]
impl PeerRelayBackend for OrchestratedPeerRelay {
    async fn allocate(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Result<UDPRelayEndpoint> {
        {
            let mut next_call = self.next_call.lock().await;
            tokio::time::sleep_until(*next_call).await;
            *next_call = tokio::time::Instant::now() + PEER_RELAY_CALL_SPACING;
        }
        let allocation = self
            .plane
            .allocate_peer_relay(client_disco.map(|key| disco_text(&key)), generation)
            .await
            .map_err(|error| anyhow!("allocate UDP peer relay: {error}"))?;
        relay_endpoint(allocation, client_disco, generation)
    }
}

fn disco_text(key: &DiscoPublic) -> String {
    match serde_json::to_value(key) {
        Ok(serde_json::Value::String(text)) => text,
        _ => unreachable!("a disco key always encodes as a string"),
    }
}

fn parse_disco(text: &str) -> Result<DiscoPublic> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| anyhow!("invalid disco key in relay allocation"))
}

/// The tailnet endpoint for one allocation. It must answer the request it
/// was made for: the same two disco keys and the same generation, with at
/// least one numeric relay address. The relay keeps each pair in its
/// canonical (sorted) order, so the keys may come back either way round.
fn relay_endpoint(
    allocation: PeerRelayAllocation,
    requested: [DiscoPublic; 2],
    generation: u32,
) -> Result<UDPRelayEndpoint> {
    if allocation.relay_generation != generation {
        return Err(anyhow!("relay allocation answers another generation"));
    }
    let disco = allocation
        .disco_keys
        .iter()
        .map(|key| parse_disco(key))
        .collect::<Result<Vec<_>>>()?;
    let [first, second] = disco.as_slice() else {
        return Err(anyhow!("relay allocation answers other disco keys"));
    };
    let same_pair = (*first == requested[0] && *second == requested[1])
        || (*first == requested[1] && *second == requested[0]);
    if !same_pair {
        return Err(anyhow!("relay allocation answers other disco keys"));
    }
    let client_disco = [*first, *second];
    let addr_ports = allocation
        .addr_ports
        .iter()
        .map(|addr| {
            addr.parse::<SocketAddr>()
                .map_err(|_| anyhow!("invalid relay address in allocation"))
        })
        .collect::<Result<Vec<_>>>()?;
    if addr_ports.is_empty() {
        return Err(anyhow!("relay allocation has no address"));
    }
    Ok(UDPRelayEndpoint {
        server_disco: parse_disco(&allocation.server_disco_key)?,
        client_disco,
        lamport_id: allocation.lamport_id,
        vni: allocation.vni,
        bind_lifetime: Duration::from_nanos(allocation.bind_lifetime_ns),
        steady_state_lifetime: Duration::from_nanos(allocation.steady_state_lifetime_ns),
        addr_ports,
    })
}

/// The daemon's tailnet connection and its relay allocator.
pub struct DaemonTailnet {
    conn: Arc<Conn>,
    relay: Option<PeerRelayAllocator>,
    relay_reconciler: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DaemonTailnet {
    pub fn conn(&self) -> Arc<Conn> {
        self.conn.clone()
    }
}

impl PeerDataPlane for DaemonTailnet {
    fn publish_nodes(&self) -> mpsc::UnboundedReceiver<Node> {
        let (nodes, node_rx) = mpsc::unbounded_channel();
        self.conn.set_node_callback(move |node| {
            let _ = nodes.send(node.clone());
        });
        if let Some(relay) = &self.relay {
            let mut reconciler = self.relay_reconciler.lock().unwrap();
            if let Some(previous) = reconciler.replace(relay.spawn_reconciler()) {
                previous.abort();
            }
        }
        node_rx
    }

    fn stop_publishing(&self) {
        if let Some(reconciler) = self.relay_reconciler.lock().unwrap().take() {
            reconciler.abort();
        }
        self.conn.clear_node_callback();
    }

    fn apply_peers(&self, nodes: &[Node]) {
        tracing::debug!(
            peer_count = nodes.len(),
            "workspace tailnet peer update received"
        );
        if let Err(error) = self.conn.update_peers(nodes) {
            tracing::warn!(error = %error, "apply workspace tailnet peer update failed");
        }
        if let Some(relay) = &self.relay {
            relay.observe_peers(nodes);
        }
    }
}

/// Where the daemon's tailnet listens and who it is.
#[derive(Clone, Debug)]
pub struct DaemonTailnetConfig {
    pub environment_id: Uuid,
    /// The workspace's tailnet UDP port, on all addresses.
    pub udp_listen_addr: SocketAddr,
    /// Local ports never served as application ports on the tailnet: the
    /// platform's own listeners in the workload (the credential bridge, the
    /// daemon's SSH and gRPC listeners; `codewire_daemon_proto::
    /// platform_listeners`). Port 22 is always SSH.
    pub reserved_ports: BTreeSet<u16>,
}

/// Build the tailnet connection from the coordinator's DERP map (falling
/// back to DERP on the coordinator origin) and the current grant. The DERP
/// host, the direct UDP endpoints and the STUN servers are looked up as
/// absolute DNS names: the Pod's resolver tries its search domains first, and
/// a static musl `cw` abandons a lookup when one of them fails (#2701).
pub async fn connect_daemon_tailnet(
    config: &DaemonTailnetConfig,
    derp_map: Option<&serde_json::Value>,
    grant: &WorkspaceAccessGrant,
    plane: Arc<dyn AccessControlPlane>,
) -> Result<DaemonTailnet> {
    let target = match derp_target_from_map(derp_map) {
        Some(target) => target,
        None => derp_target_from_origin(grant.coordinator_url())?,
    };
    tracing::info!(
        derp_host = %target.host,
        derp_port = target.port,
        "workspace tailnet connecting DERP relay"
    );
    let secret = StaticSecret::random_from_rng(OsRng);
    let fallback = connect_derp_transport_absolute(&target, &secret)
        .await
        .context("connect DERP relay")?;
    let local_node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
    let disco_private = DiscoPrivate::generate(&mut OsRng);
    let local_disco = disco_private.public();
    let advertised = resolve_endpoints(grant.direct_udp_endpoints())
        .await
        .context("resolve the environment's direct UDP endpoints")?;
    // Peers reach a daemon directly at the endpoint the platform publishes
    // for it. Behind that endpoint a STUN answer could name only the node's
    // outbound NAT mapping, which admits replies from that STUN server and
    // nothing else, so STUN runs only for a daemon with no published endpoint.
    let stun = if advertised.is_empty() {
        let servers = stun_servers_from_map(derp_map)
            .into_iter()
            .map(|server| StunServer {
                host: absolute_dns_name(&server.host).into_owned(),
                port: server.port,
            })
            .collect();
        resolve_stun_servers(servers)
            .await
            .context("resolve DERP map STUN servers")?
    } else {
        Vec::new()
    };
    let relay_enabled = !grant.peer_relay_endpoints().is_empty();
    let (transport, endpoints, handle) =
        if stun.is_empty() && advertised.is_empty() && !relay_enabled {
            (fallback, Vec::new(), None)
        } else {
            let (transport, handle) = direct_udp::wrap_transport(
                fallback,
                direct_udp::Options::new(
                    config.udp_listen_addr,
                    advertised,
                    local_node_key,
                    disco_private.clone(),
                )
                .with_stun_servers(stun),
            )
            .await
            .context("bind tailnet direct UDP")?;
            let endpoints = handle.advertised_endpoints();
            tracing::info!(
                udp_addr = %handle.local_addr(),
                advertise_endpoint_count = endpoints.len(),
                "workspace tailnet direct UDP enabled"
            );
            (transport, endpoints, Some(handle))
        };
    let relay = match (&handle, relay_enabled) {
        (Some(handle), true) => {
            let relay = PeerRelayAllocator::new(
                Arc::new(OrchestratedPeerRelay::new(plane)),
                LOG_COMPONENT,
                Vec::new(),
                local_disco,
                handle.clone(),
            )
            .with_attempt_timeout(PEER_RELAY_ATTEMPT_TIMEOUT);
            if let Some(events) = handle.take_peer_relay_allocation_events() {
                relay.spawn_allocation_responder(events);
            }
            Some(relay)
        }
        _ => None,
    };
    let mut options = Options::new(config.environment_id);
    options.private_key = Some(secret);
    options.disco_private = Some(disco_private);
    options.endpoints = endpoints;
    let conn = Conn::new(options, transport).context("create tailnet connection")?;
    conn.set_preferred_derp(1);
    Ok(DaemonTailnet {
        conn: Arc::new(conn),
        relay,
        relay_reconciler: std::sync::Mutex::new(None),
    })
}

/// DERP served on the coordinator's own origin: `https://host[:port]`.
fn derp_target_from_origin(origin: &str) -> Result<DerpTarget> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("coordinator origin must be https"))?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| anyhow!("invalid coordinator port"))?,
        ),
        None => (authority, 443),
    };
    Ok(DerpTarget {
        host: host.to_owned(),
        port,
        transport: DerpTransport::Tls { skip_verify: false },
    })
}

async fn resolve_endpoints(endpoints: &[String]) -> Result<Vec<SocketAddr>> {
    let mut resolved = Vec::new();
    for endpoint in endpoints {
        for addr in lookup_host(absolute_host_port(endpoint).as_ref())
            .await
            .with_context(|| format!("resolve {endpoint}"))?
        {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }
    Ok(resolved)
}

/// SSH served over the tailnet by the daemon.
#[derive(Clone)]
pub struct TailnetSsh {
    pub config: Arc<server::Config>,
    pub runners: DaemonSshRunners,
}

/// Run the daemon's tailnet peer until shutdown. The first coordinator
/// session is retried until it opens, since it carries the DERP map; SSH
/// over the tailnet starts once the connection exists.
pub async fn run(
    config: DaemonTailnetConfig,
    grants: Arc<AccessGrants>,
    plane: Arc<dyn AccessControlPlane>,
    dialer: Arc<dyn CoordinatorDialer>,
    ssh: TailnetSsh,
    app_ports: watch::Receiver<AppPorts>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut stop = shutdown.clone();
    let mut first_attempt = true;
    let (first, tailnet) = loop {
        if !first_attempt {
            if let Err(error) = grants.refresh().await {
                tracing::warn!(error = %error, "workspace access renewal before reconnect failed");
            }
            tokio::select! {
                _ = stop.changed() => return Ok(()),
                () = tokio::time::sleep(COORDINATOR_RETRY_DELAY) => {}
            }
        }
        first_attempt = false;
        let dialed = match DialedSession::dial(&grants, dialer.as_ref(), config.environment_id)
            .await
        {
            Ok(dialed) => dialed,
            Err(error) => {
                tracing::warn!(error = %error, "workspace tailnet coordinator unavailable; retrying");
                continue;
            }
        };
        let derp_map = dialed.setup_derp_map();
        match connect_daemon_tailnet(&config, derp_map.as_ref(), &grants.current(), plane.clone())
            .await
        {
            Ok(tailnet) => break (dialed, Arc::new(tailnet)),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "workspace tailnet unavailable; retrying");
            }
        }
    };
    let mut listener = tailnet
        .conn()
        .listen("tcp", ":22")
        .await
        .context("listen on the workspace tailnet :22")?;
    tracing::info!(environment_id = %config.environment_id, "workspace tailnet peer up");
    let _app_ports = AbortOnDropHandle::new(tokio::spawn(forward_app_ports(
        tailnet.conn(),
        app_ports,
        config.reserved_ports.clone(),
        shutdown.clone(),
    )));
    let sessions = tokio::spawn(run_coordinator_sessions(
        Some(first),
        config.environment_id,
        grants,
        dialer,
        tailnet.clone(),
        COORDINATOR_RETRY_DELAY,
        shutdown.clone(),
    ));
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Some(stream) = accepted else {
                    break;
                };
                let ssh = ssh.clone();
                tokio::spawn(async move {
                    ssh.runners.serve_stream(ssh.config, stream, "tailnet").await;
                });
            }
        }
    }
    sessions.abort();
    Ok(())
}

/// Serve the environment's application ports on the tailnet address,
/// forwarding each connection to the same port on the workspace's own
/// loopback (IPv4, then IPv6). Listeners follow `allowed`: a port that leaves
/// the set stops listening and its open connections end. Port 22 (SSH) and
/// `reserved` ports are never served.
pub async fn forward_app_ports(
    conn: Arc<Conn>,
    mut allowed: watch::Receiver<AppPorts>,
    reserved: BTreeSet<u16>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut listeners: BTreeMap<u16, AbortOnDropHandle<()>> = BTreeMap::new();
    loop {
        let wanted: BTreeSet<u16> = allowed
            .borrow_and_update()
            .iter()
            .copied()
            .filter(|port| *port != 22 && !reserved.contains(port))
            .collect();
        listeners.retain(|port, _| wanted.contains(port));
        for port in wanted {
            if listeners.contains_key(&port) {
                continue;
            }
            match conn.listen("tcp", &format!(":{port}")).await {
                Ok(listener) => {
                    listeners.insert(
                        port,
                        AbortOnDropHandle::new(tokio::spawn(serve_app_port(listener, port))),
                    );
                }
                Err(error) => {
                    tracing::warn!(port, error = %error, "workspace tailnet application port unavailable");
                }
            }
        }
        tracing::info!(
            app_port_count = listeners.len(),
            "workspace tailnet application ports served"
        );
        tokio::select! {
            _ = shutdown.changed() => return,
            changed = allowed.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

/// Accept on one application port until aborted; aborting ends the
/// connections it forwards too.
async fn serve_app_port(mut listener: TailnetListener, port: u16) {
    let mut connections = JoinSet::new();
    while let Some(stream) = listener.accept().await {
        while connections.try_join_next().is_some() {}
        connections.spawn(forward_to_loopback(stream, port));
    }
}

async fn forward_to_loopback(mut stream: TailnetStream, port: u16) {
    let local = match tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
        Ok(local) => Ok(local),
        Err(_) => tokio::net::TcpStream::connect((Ipv6Addr::LOCALHOST, port)).await,
    };
    let Ok(mut local) = local else {
        tracing::debug!(port, "workspace application port has no local listener");
        return;
    };
    let _ = local.set_nodelay(true);
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut local).await;
}

#[cfg(test)]
#[path = "daemon_tailnet/tests.rs"]
mod tests;
