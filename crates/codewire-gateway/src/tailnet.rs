use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use codewire_client::{
    COORDINATOR_SETUP_TIMEOUT, ClientConfig as CodewireClientConfig, CodewireClient,
    CoordinatorHandlers, PrimaryCoordinateIdentity, StaticTokenProvider,
};
use codewire_tailnet::conn::{Conn, Options, Transport};
use codewire_tailnet::derp_transport::{DerpTarget, DerpTransport, connect_derp_transport};
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::{DiscoPrivate, UDPRelayEndpoint};
use codewire_tailnet::node::{AddrPort, DiscoPublic, Node, NodePublic};
use codewire_tailnet::wg::PublicKey;
use codewire_tailnet::wg::StaticSecret;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::lookup_host;
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::config::{GatewayConfig, StunConfig, TailnetConfig};

const COORDINATOR_RETRY_DELAY: Duration = Duration::from_secs(5);
const PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const PEER_RELAY_ALLOCATION_RETRY_DELAY: Duration = Duration::from_millis(250);
const PEER_RELAY_ALLOCATION_RECONCILE_INTERVAL: Duration = Duration::from_millis(100);
const PEER_RELAY_REGISTRATION_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct TailnetRuntime {
    conn: Arc<Conn>,
    peer_relay_allocator: Option<PeerRelayAllocator>,
}

impl TailnetRuntime {
    pub fn conn(&self) -> Arc<Conn> {
        self.conn.clone()
    }
}

pub async fn connect_tailnet(
    config: &GatewayConfig,
    tailnet: &TailnetConfig,
) -> Result<TailnetRuntime> {
    let target = derp_target_from_config(config, tailnet)?;
    tracing::info!(
        derp_host = %target.host,
        derp_port = target.port,
        derp_transport = ?target.transport,
        environment_id = %tailnet.environment_id,
        "rust gateway connecting DERP relay"
    );
    let secret = StaticSecret::random_from_rng(OsRng);
    let fallback_transport = connect_derp_transport(&target, &secret)
        .await
        .context("connect DERP relay")?;
    let local_node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
    let disco_private = DiscoPrivate::generate(&mut OsRng);
    let local_disco = disco_private.public();
    let stun_configs = configured_stun_servers(config);
    let force_direct_udp = force_direct_udp_transport(config);
    let (transport, endpoints, direct_udp_handle) = maybe_wrap_direct_udp(
        fallback_transport,
        &stun_configs,
        config
            .tailnet_udp_listen_addr
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        config.tailnet_direct_udp_advertise_endpoints.clone(),
        local_node_key,
        disco_private.clone(),
        force_direct_udp,
    )
    .await?;
    let peer_relay_allocator = direct_udp_handle.as_ref().and_then(|handle| {
        config.udp_relay_allocator_url.as_ref().map(|url| {
            PeerRelayAllocator::new(
                url.clone(),
                config.udp_relay_allocator_token.clone(),
                config.udp_relay_bind_addrs.clone(),
                local_disco,
                handle.clone(),
            )
        })
    });
    if let Some(allocator) = &peer_relay_allocator
        && let Some(handle) = &direct_udp_handle
        && let Some(events) = handle.take_peer_relay_allocation_events()
    {
        allocator.spawn_allocation_responder(events);
    }
    let mut options = Options::new(tailnet.environment_id);
    options.private_key = Some(secret);
    options.disco_private = Some(disco_private);
    options.endpoints = endpoints;
    let endpoint_count = options.endpoints.len();

    let conn = Conn::new(options, transport).context("create tailnet connection")?;
    conn.set_preferred_derp(1);
    tracing::info!(
        environment_id = %tailnet.environment_id,
        endpoint_count,
        "rust gateway tailnet connection created"
    );
    Ok(TailnetRuntime {
        conn: Arc::new(conn),
        peer_relay_allocator,
    })
}

async fn maybe_wrap_direct_udp(
    fallback_transport: Transport,
    stun: &[StunConfig],
    bind_addr: SocketAddr,
    static_endpoints: Vec<SocketAddr>,
    local_node_key: NodePublic,
    disco_private: DiscoPrivate,
    force_wrap: bool,
) -> Result<(Transport, Vec<AddrPort>, Option<direct_udp::Handle>)> {
    if stun.is_empty() && static_endpoints.is_empty() && !force_wrap {
        return Ok((fallback_transport, Vec::new(), None));
    }
    let stun_servers = if stun.is_empty() {
        Vec::new()
    } else {
        resolve_stun_servers(stun).await?
    };

    let stun_server_count = stun_servers.len();
    let static_endpoint_count = static_endpoints.len();
    tracing::info!(
        bind_addr = %bind_addr,
        stun_server_count,
        static_endpoint_count,
        "rust gateway resolved STUN servers for direct UDP"
    );
    let (transport, handle) = direct_udp::wrap_transport(
        fallback_transport,
        direct_udp::Options::new(bind_addr, static_endpoints, local_node_key, disco_private)
            .with_stun_servers(stun_servers),
    )
    .await
    .context("bind tailnet direct UDP transport")?;

    let endpoints = handle.advertised_endpoints();
    tracing::info!(
        udp_addr = %handle.local_addr(),
        stun_server_count,
        advertise_endpoint_count = endpoints.len(),
        "rust gateway tailnet direct UDP transport enabled"
    );
    Ok((transport, endpoints, Some(handle)))
}

fn configured_stun_servers(config: &GatewayConfig) -> Vec<StunConfig> {
    if config.stun_servers.is_empty() {
        config.stun.iter().cloned().collect::<Vec<_>>()
    } else {
        config.stun_servers.clone()
    }
}

fn force_direct_udp_transport(config: &GatewayConfig) -> bool {
    config.udp_relay_allocator_url.is_some()
}

async fn resolve_stun_servers(stun: &[StunConfig]) -> Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for server in stun {
        let resolved = lookup_host((server.host.as_str(), server.port))
            .await
            .with_context(|| format!("resolve STUN host {}:{}", server.host, server.port))?
            .collect::<Vec<_>>();
        for addr in resolved {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
    }
    Ok(addrs)
}

#[derive(Clone)]
struct PeerRelayAllocator {
    client: reqwest::Client,
    url: Arc<str>,
    token: Option<Arc<str>>,
    bind_addr_ports: Arc<[String]>,
    local_disco: DiscoPublic,
    handle: direct_udp::Handle,
    allocations: Arc<Mutex<PeerRelayAllocationTracker>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PeerRelayKey {
    peer: NodePublic,
    peer_disco: DiscoPublic,
}

#[derive(Default)]
struct PeerRelayAllocationTracker {
    peers: HashSet<PeerRelayKey>,
    queued: HashMap<PeerRelayKey, PeerRelayQueuedState>,
    in_flight: HashSet<PeerRelayKey>,
    last_started: HashMap<PeerRelayKey, Instant>,
    attempts: usize,
    failures: usize,
}

#[derive(Clone, Copy)]
struct PeerRelayQueuedState {
    queued_at: Instant,
    observed_by_tailnet: bool,
}

#[derive(Clone, Copy)]
struct PeerRelayAllocationState {
    peer_count: usize,
    queued_count: usize,
    in_flight_count: usize,
    attempts: usize,
    failures: usize,
}

impl PeerRelayAllocationTracker {
    fn replace_peers(&mut self, peers: impl IntoIterator<Item = PeerRelayKey>) {
        self.peers = peers.into_iter().collect();
        self.queued.retain(|key, _| self.peers.contains(key));
        self.last_started
            .retain(|key, _| self.peers.contains(key) || self.in_flight.contains(key));
    }

    fn begin_pending(
        &mut self,
        now: Instant,
        mut peer_relay_state: impl FnMut(PeerRelayKey) -> direct_udp::PeerRelayEndpointState,
    ) -> Vec<PeerRelayKey> {
        let keys = self.peers.iter().copied().collect::<Vec<_>>();
        let mut started = Vec::new();
        for key in keys {
            if self.in_flight.contains(&key) {
                continue;
            }

            let relay_state = peer_relay_state(key);
            if let Some(queued) = self.queued.get_mut(&key) {
                match relay_state {
                    direct_udp::PeerRelayEndpointState::Negotiating
                    | direct_udp::PeerRelayEndpointState::Active => {
                        queued.observed_by_tailnet = true;
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Missing
                        if !queued.observed_by_tailnet
                            && now.duration_since(queued.queued_at)
                                < PEER_RELAY_REGISTRATION_GRACE =>
                    {
                        continue;
                    }
                    direct_udp::PeerRelayEndpointState::Missing => {}
                }
                self.queued.remove(&key);
            } else if relay_state != direct_udp::PeerRelayEndpointState::Missing {
                self.queued.insert(
                    key,
                    PeerRelayQueuedState {
                        queued_at: now,
                        observed_by_tailnet: true,
                    },
                );
                continue;
            }

            if self
                .last_started
                .get(&key)
                .is_some_and(|last| now.duration_since(*last) < PEER_RELAY_ALLOCATION_RETRY_DELAY)
            {
                continue;
            }
            self.in_flight.insert(key);
            self.last_started.insert(key, now);
            self.attempts += 1;
            started.push(key);
        }
        started
    }

    fn finish_success(&mut self, key: PeerRelayKey, now: Instant) -> PeerRelayAllocationState {
        self.in_flight.remove(&key);
        if self.peers.contains(&key) {
            self.queued.insert(
                key,
                PeerRelayQueuedState {
                    queued_at: now,
                    observed_by_tailnet: false,
                },
            );
        } else {
            self.last_started.remove(&key);
        }
        self.state()
    }

    fn finish_failure(&mut self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.in_flight.remove(&key);
        if !self.peers.contains(&key) {
            self.last_started.remove(&key);
        }
        self.failures += 1;
        self.state()
    }

    fn state(&self) -> PeerRelayAllocationState {
        PeerRelayAllocationState {
            peer_count: self.peers.len(),
            queued_count: self.queued.len(),
            in_flight_count: self.in_flight.len(),
            attempts: self.attempts,
            failures: self.failures,
        }
    }
}

impl PeerRelayAllocator {
    fn new(
        url: String,
        token: Option<String>,
        bind_addr_ports: Vec<String>,
        local_disco: DiscoPublic,
        handle: direct_udp::Handle,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: Arc::from(url),
            token: token.map(Arc::from),
            bind_addr_ports: Arc::from(bind_addr_ports),
            local_disco,
            handle,
            allocations: Arc::new(Mutex::new(PeerRelayAllocationTracker::default())),
        }
    }

    fn observe_peers(&self, nodes: &[Node]) {
        let peers = nodes.iter().filter_map(|node| {
            if node.key.is_zero() || node.disco_key.is_zero() || node.disco_key == self.local_disco
            {
                return None;
            }
            Some(PeerRelayKey {
                peer: node.key,
                peer_disco: node.disco_key,
            })
        });
        self.allocations.lock().unwrap().replace_peers(peers);
        self.reconcile_allocations();
    }

    fn spawn_reconciler(&self) -> tokio::task::JoinHandle<()> {
        let allocator = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PEER_RELAY_ALLOCATION_RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                allocator.reconcile_allocations();
            }
        })
    }

    fn reconcile_allocations(&self) {
        let (pending, state) = {
            let mut allocations = self.allocations.lock().unwrap();
            let pending = allocations.begin_pending(Instant::now(), |key| {
                self.handle
                    .peer_relay_endpoint_state(&key.peer, &key.peer_disco)
            });
            let state = allocations.state();
            (pending, state)
        };
        for key in pending {
            self.log_allocation_diagnostic("started", state);
            let allocator = self.clone();
            tokio::spawn(async move {
                match bounded_peer_relay_allocation_attempt(
                    PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT,
                    allocator.allocate_once(key),
                )
                .await
                {
                    Ok(()) => {
                        let state = allocator.finish_allocation_success(key);
                        allocator.log_allocation_diagnostic("queued", state);
                    }
                    Err(_) => {
                        let state = allocator.finish_allocation_failure(key);
                        allocator.log_allocation_diagnostic("retry_scheduled", state);
                    }
                }
            });
        }
    }

    fn finish_allocation_success(&self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.allocations
            .lock()
            .unwrap()
            .finish_success(key, Instant::now())
    }

    fn finish_allocation_failure(&self, key: PeerRelayKey) -> PeerRelayAllocationState {
        self.allocations.lock().unwrap().finish_failure(key)
    }

    fn allocation_state(&self) -> PeerRelayAllocationState {
        self.allocations.lock().unwrap().state()
    }

    fn log_allocation_diagnostic(&self, outcome: &str, state: PeerRelayAllocationState) {
        tracing::info!(
            outcome,
            path = "peer_relay",
            peer_count = state.peer_count,
            queued_count = state.queued_count,
            in_flight_count = state.in_flight_count,
            attempt_count = state.attempts,
            failure_count = state.failures,
            "rust gateway UDP peer relay allocation diagnostic"
        );
    }

    async fn allocate_once(&self, key: PeerRelayKey) -> Result<()> {
        let (endpoint, bind_endpoint) = self
            .allocate_endpoint([self.local_disco, key.peer_disco], 0)
            .await?;
        self.handle
            .request_peer_relay_with_bind_endpoint(key.peer, bind_endpoint, endpoint)
            .context("apply UDP peer relay endpoint")?;
        tracing::info!("rust gateway UDP peer relay proactive allocation queued");
        Ok(())
    }

    async fn answer_allocation_once(
        &self,
        event: direct_udp::PeerRelayAllocationEvent,
    ) -> Result<()> {
        tracing::info!(
            outcome = "answer_requested",
            path = "peer_relay",
            "rust gateway UDP peer relay allocation responder"
        );
        let (endpoint, bind_endpoint) = self
            .allocate_endpoint(event.client_disco, event.generation)
            .await?;
        self.handle
            .answer_peer_relay_allocation_with_bind_endpoint(
                event.peer,
                event.generation,
                bind_endpoint,
                endpoint,
            )
            .context("answer UDP peer relay allocation")?;
        tracing::info!(
            outcome = "answer_queued",
            path = "peer_relay",
            "rust gateway UDP peer relay allocation responder"
        );
        Ok(())
    }

    async fn allocate_endpoint(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Result<(UDPRelayEndpoint, UDPRelayEndpoint)> {
        let request = PeerRelayAllocationRequest {
            client_disco,
            generation,
        };
        let mut request_builder = self.client.post(self.url.as_ref()).json(&request);
        if let Some(token) = &self.token {
            request_builder = request_builder.bearer_auth(token.as_ref());
        }
        let response = request_builder
            .timeout(PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT)
            .send()
            .await
            .context("request UDP peer relay allocation")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("UDP peer relay allocator returned {status}"));
        }
        let response: PeerRelayAllocationResponse = response
            .json()
            .await
            .context("decode UDP peer relay allocation")?;
        tracing::debug!(
            outcome = "endpoint_received",
            relay_addr_count = response.endpoint.addr_ports.len(),
            "rust gateway UDP peer relay allocator returned endpoint"
        );
        let endpoint = response
            .endpoint
            .try_into_endpoint()
            .context("decode UDP peer relay endpoint")?;
        let bind_endpoint = relay_bind_endpoint(&endpoint, &self.bind_addr_ports)
            .await
            .context("resolve UDP peer relay bind endpoint")?;
        Ok((endpoint, bind_endpoint))
    }

    fn spawn_allocation_responder(
        &self,
        mut events: mpsc::UnboundedReceiver<direct_udp::PeerRelayAllocationEvent>,
    ) {
        let allocator = self.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let allocator = allocator.clone();
                tokio::spawn(async move {
                    if bounded_peer_relay_allocation_attempt(
                        PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT,
                        allocator.answer_allocation_once(event),
                    )
                    .await
                    .is_err()
                    {
                        allocator.log_allocation_diagnostic(
                            "answer_retry_deferred",
                            allocator.allocation_state(),
                        );
                    }
                });
            }
        });
    }
}

async fn bounded_peer_relay_allocation_attempt<T>(
    timeout: Duration,
    attempt: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, attempt)
        .await
        .context("UDP peer relay allocation attempt timed out")?
}

async fn relay_bind_endpoint(
    advertised_endpoint: &UDPRelayEndpoint,
    bind_addr_ports: &[String],
) -> Result<UDPRelayEndpoint> {
    if bind_addr_ports.is_empty() {
        return Ok(advertised_endpoint.clone());
    }

    let mut resolved = Vec::new();
    for addr_port in bind_addr_ports {
        let addrs = lookup_host(addr_port.as_str())
            .await
            .with_context(|| format!("resolve UDP peer relay bind addr {addr_port:?}"))?;
        for addr in addrs {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }
    if resolved.is_empty() {
        return Err(anyhow!(
            "UDP peer relay bind addr list resolved to no addresses"
        ));
    }

    let mut endpoint = advertised_endpoint.clone();
    endpoint.addr_ports = resolved;
    Ok(endpoint)
}

#[derive(Debug, Serialize)]
struct PeerRelayAllocationRequest {
    client_disco: [DiscoPublic; 2],
    generation: u32,
}

#[derive(Debug, Deserialize)]
struct PeerRelayAllocationResponse {
    #[allow(dead_code)]
    generation: u32,
    endpoint: PeerRelayEndpointResponse,
}

#[derive(Debug, Deserialize)]
struct PeerRelayEndpointResponse {
    server_disco: DiscoPublic,
    client_disco: [DiscoPublic; 2],
    lamport_id: u64,
    vni: u32,
    bind_lifetime_ns: u64,
    steady_state_lifetime_ns: u64,
    addr_ports: Vec<String>,
}

impl PeerRelayEndpointResponse {
    fn try_into_endpoint(self) -> Result<UDPRelayEndpoint> {
        let mut addr_ports = Vec::with_capacity(self.addr_ports.len());
        for addr in self.addr_ports {
            addr_ports.push(
                addr.parse::<SocketAddr>()
                    .with_context(|| format!("parse UDP peer relay addr:port {addr:?}"))?,
            );
        }
        Ok(UDPRelayEndpoint {
            server_disco: self.server_disco,
            client_disco: self.client_disco,
            lamport_id: self.lamport_id,
            vni: self.vni,
            bind_lifetime: Duration::from_nanos(self.bind_lifetime_ns),
            steady_state_lifetime: Duration::from_nanos(self.steady_state_lifetime_ns),
            addr_ports,
        })
    }
}

pub async fn run_coordinator_loop(
    runtime: TailnetRuntime,
    config: TailnetConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = wait_for_shutdown(shutdown_rx.clone()) => return Ok(()),
            result = run_coordinator_once(runtime.clone(), &config) => {
                if let Err(err) = result {
                    tracing::warn!(
                        environment_id = %config.environment_id,
                        error = %err,
                        "gateway tailnet coordinator disconnected; retrying"
                    );
                }
            }
        }

        tokio::select! {
            _ = wait_for_shutdown(shutdown_rx.clone()) => return Ok(()),
            _ = tokio::time::sleep(COORDINATOR_RETRY_DELAY) => {}
        }

        if *shutdown_rx.borrow_and_update() {
            return Ok(());
        }
    }
}

async fn run_coordinator_once(runtime: TailnetRuntime, config: &TailnetConfig) -> Result<()> {
    let conn = runtime.conn();
    let peer_relay_allocator = runtime.peer_relay_allocator;
    let mut coordinator = connect_coordinator(config).await?;
    let peer_relay_reconciler = peer_relay_allocator
        .as_ref()
        .map(PeerRelayAllocator::spawn_reconciler);
    let (node_tx, node_rx) = mpsc::unbounded_channel();
    conn.set_node_callback(move |node| {
        let _ = node_tx.send(node.clone());
    });

    let update_conn = conn.clone();
    let handlers = CoordinatorHandlers {
        on_peers: move |nodes: &[Node]| {
            let peer_count = nodes.len();
            let peer_endpoint_count = nodes.iter().map(|node| node.endpoints.len()).sum::<usize>();
            tracing::debug!(
                peer_count,
                peer_endpoint_count,
                "gateway tailnet peer update received"
            );
            if let Err(err) = update_conn.update_peers(nodes) {
                tracing::warn!(error = %err, "apply tailnet peer update failed");
            }
            if let Some(allocator) = &peer_relay_allocator {
                allocator.observe_peers(nodes);
            }
        },
        on_derp_map: |_| {
            tracing::debug!("ignoring coordinator DERP map for gateway-local DERP target");
        },
    };
    let result = coordinator
        .run_with_node_updates(node_rx, handlers)
        .await
        .map_err(anyhow::Error::from)
        .context("run typed tailnet coordinator");
    if let Some(reconciler) = peer_relay_reconciler {
        reconciler.abort();
    }
    conn.clear_node_callback();
    result
}

async fn connect_coordinator(
    config: &TailnetConfig,
) -> Result<codewire_client::CoordinatorPeerSession> {
    let client = CodewireClient::new(
        CodewireClientConfig::new(&config.coordinator_url)
            .context("parse coordinator service origin")?,
        StaticTokenProvider::new(config.gateway_token.clone())
            .context("validate gateway sidecar credential")?,
    )
    .context("construct shared Codewire client")?;
    client
        .connect_primary_coordinator_direct_with_setup_timeout(
            PrimaryCoordinateIdentity::sidecar(config.environment_id),
            COORDINATOR_SETUP_TIMEOUT,
        )
        .await
        .context("set up typed Connect tailnet coordinator")
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn derp_target(raw: &str) -> Result<DerpTarget> {
    let parsed = Url::parse(raw).with_context(|| format!("parse DERP URL {raw:?}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("DERP URL {raw:?} has no host"))?
        .to_string();
    let scheme = parsed.scheme();
    let port = parsed.port().unwrap_or(match scheme {
        "http" | "ws" => 80,
        _ => 443,
    });
    let transport = match scheme {
        "http" | "ws" => DerpTransport::Plain,
        "https" | "wss" => DerpTransport::Tls {
            skip_verify: port != 443,
        },
        other => return Err(anyhow!("unsupported DERP URL scheme {other:?}")),
    };
    Ok(DerpTarget {
        host,
        port,
        transport,
    })
}

fn derp_target_from_config(config: &GatewayConfig, tailnet: &TailnetConfig) -> Result<DerpTarget> {
    let raw = config
        .derp_url
        .as_deref()
        .or(config.api_url.as_deref())
        .unwrap_or(tailnet.coordinator_url.as_str());
    derp_target(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DockerProxyConfig;
    use codewire_gateway_proto::DaemonAuthToken;
    use uuid::Uuid;

    fn gateway_config(
        api_url: Option<&str>,
        derp_url: Option<&str>,
        coordinator_url: &str,
        tailnet: TailnetConfig,
    ) -> GatewayConfig {
        GatewayConfig {
            shim_addr: "127.0.0.1:7777".into(),
            daemon_connect_timeout: Duration::from_secs(60),
            ssh_listen_addr: "127.0.0.1:2222".into(),
            readyz_listen_addr: "127.0.0.1:2223".into(),
            host_key_path: "/tmp/key".into(),
            listener_self_check_interval: None,
            api_url: api_url.map(str::to_string),
            binding_url: None,
            coordinator_url: Some(coordinator_url.into()),
            daemon_auth_token: DaemonAuthToken::new("gateway-tailnet-test-token").unwrap(),
            derp_url: derp_url.map(str::to_string),
            stun: None,
            stun_servers: Vec::new(),
            tailnet_udp_listen_addr: None,
            tailnet_direct_udp_advertise_endpoints: Vec::new(),
            udp_relay_allocator_url: None,
            udp_relay_allocator_token: None,
            udp_relay_bind_addrs: Vec::new(),
            tailnet: Some(tailnet),
            docker_proxy: Some(DockerProxyConfig {
                listen_sock: "/codewire/run/docker.sock".into(),
                upstream_sock: "/var/run/docker/docker.sock".into(),
            }),
            debug_tailnet: false,
        }
    }

    fn tailnet_config(coordinator_url: &str) -> TailnetConfig {
        TailnetConfig {
            environment_id: Uuid::new_v4(),
            gateway_token: "test-token".into(),
            coordinator_url: coordinator_url.into(),
        }
    }

    #[tokio::test]
    async fn relay_bind_endpoint_overrides_advertised_addr_ports() {
        let advertised = UDPRelayEndpoint {
            server_disco: DiscoPrivate::generate(&mut OsRng).public(),
            client_disco: [
                DiscoPrivate::generate(&mut OsRng).public(),
                DiscoPrivate::generate(&mut OsRng).public(),
            ],
            lamport_id: 1,
            vni: 42,
            bind_lifetime: Duration::from_secs(10),
            steady_state_lifetime: Duration::from_secs(60),
            addr_ports: vec!["192.0.2.35:41641".parse().unwrap()],
        };

        let bind = relay_bind_endpoint(&advertised, &["127.0.0.1:41641".into()])
            .await
            .unwrap();

        assert_eq!(bind.addr_ports, vec!["127.0.0.1:41641".parse().unwrap()]);
        assert_eq!(bind.vni, advertised.vni);
        assert_eq!(
            advertised.addr_ports,
            vec!["192.0.2.35:41641".parse().unwrap()]
        );
    }

    #[test]
    fn derp_target_prefers_explicit_derp_url() {
        let tailnet = tailnet_config("https://api.example");
        let config = gateway_config(
            Some("https://api.example"),
            Some("https://derp.example:8443"),
            &tailnet.coordinator_url,
            tailnet.clone(),
        );
        let target = derp_target_from_config(&config, &tailnet).unwrap();
        assert_eq!(
            target,
            DerpTarget {
                host: "derp.example".into(),
                port: 8443,
                transport: DerpTransport::Tls { skip_verify: true },
            }
        );
    }

    #[test]
    fn derp_target_keeps_dev_cluster_derp_on_tls() {
        let target = derp_target("https://codewire-derp.dev.svc.cluster.local:8443").unwrap();
        assert_eq!(
            target,
            DerpTarget {
                host: "codewire-derp.dev.svc.cluster.local".into(),
                port: 8443,
                transport: DerpTransport::Tls { skip_verify: true },
            }
        );
    }

    #[test]
    fn derp_target_uses_plain_only_for_cleartext_schemes() {
        let target = derp_target("http://codewire-derp.dev.svc.cluster.local:8080").unwrap();
        assert_eq!(
            target,
            DerpTarget {
                host: "codewire-derp.dev.svc.cluster.local".into(),
                port: 8080,
                transport: DerpTransport::Plain,
            }
        );
    }

    #[test]
    fn derp_target_uses_webpki_tls_for_default_https() {
        let target = derp_target("https://derp.codewire.sh").unwrap();
        assert_eq!(
            target,
            DerpTarget {
                host: "derp.codewire.sh".into(),
                port: 443,
                transport: DerpTransport::Tls { skip_verify: false },
            }
        );
    }

    #[test]
    fn derp_target_falls_back_to_api_then_coordinator_url() {
        let tailnet = tailnet_config("https://coordinator.example/path");
        let config = gateway_config(
            Some("https://api.example"),
            None,
            &tailnet.coordinator_url,
            tailnet.clone(),
        );
        assert_eq!(
            derp_target_from_config(&config, &tailnet).unwrap().host,
            "api.example"
        );

        let mut config = config;
        config.api_url = None;
        assert_eq!(
            derp_target_from_config(&config, &tailnet).unwrap().host,
            "coordinator.example"
        );
    }

    #[test]
    fn peer_relay_endpoint_response_converts_to_tailnet_descriptor() {
        let server_disco = DiscoPublic::from_raw([0x11; 32]);
        let local_disco = DiscoPublic::from_raw([0x22; 32]);
        let peer_disco = DiscoPublic::from_raw([0x33; 32]);
        let response = PeerRelayEndpointResponse {
            server_disco,
            client_disco: [local_disco, peer_disco],
            lamport_id: 42,
            vni: 7,
            bind_lifetime_ns: 3_000_000_000,
            steady_state_lifetime_ns: 60_000_000_000,
            addr_ports: vec!["192.0.2.34:41641".into()],
        };

        let endpoint = response.try_into_endpoint().unwrap();

        assert_eq!(endpoint.server_disco, server_disco);
        assert_eq!(endpoint.client_disco, [local_disco, peer_disco]);
        assert_eq!(endpoint.lamport_id, 42);
        assert_eq!(endpoint.vni, 7);
        assert_eq!(endpoint.bind_lifetime, Duration::from_secs(3));
        assert_eq!(endpoint.steady_state_lifetime, Duration::from_secs(60));
        assert_eq!(
            endpoint.addr_ports,
            vec!["192.0.2.34:41641".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn peer_relay_allocation_tracker_recovers_without_a_peer_update() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![key],
            "the first observed peer starts one allocation"
        );
        assert!(
            tracker
                .begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing)
                .is_empty()
        );

        let failure = tracker.finish_failure(key);
        assert_eq!(failure.attempts, 1);
        assert_eq!(failure.failures, 1);
        assert!(
            tracker
                .begin_pending(
                    now + PEER_RELAY_ALLOCATION_RETRY_DELAY - Duration::from_millis(1),
                    |_| direct_udp::PeerRelayEndpointState::Missing
                )
                .is_empty(),
            "the retry cadence still suppresses rapid duplicates"
        );
        assert_eq!(
            tracker.begin_pending(
                now + PEER_RELAY_ALLOCATION_RETRY_DELAY + Duration::from_millis(1),
                |_| direct_udp::PeerRelayEndpointState::Missing,
            ),
            vec![key],
            "the failed first attempt retries without another peer snapshot"
        );
    }

    #[test]
    fn peer_relay_allocation_tracker_preserves_unverified_relay_notification_retry() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![key]
        );
        let success = tracker.finish_success(key, now);
        assert_eq!(success.queued_count, 1);
        assert!(
            tracker
                .begin_pending(now + PEER_RELAY_ALLOCATION_RETRY_DELAY * 4, |_| {
                    direct_udp::PeerRelayEndpointState::Negotiating
                })
                .is_empty(),
            "a fresh negotiating relay leaves bind and CallMeMaybe retry ownership to codewire-tailnet"
        );
    }

    #[test]
    fn peer_relay_allocation_tracker_reallocates_after_endpoint_expiry() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![key]
        );
        tracker.finish_success(key, now);
        assert!(
            tracker
                .begin_pending(now + Duration::from_millis(100), |_| {
                    direct_udp::PeerRelayEndpointState::Negotiating
                })
                .is_empty()
        );
        assert!(
            tracker
                .begin_pending(now + Duration::from_millis(200), |_| {
                    direct_udp::PeerRelayEndpointState::Active
                })
                .is_empty()
        );
        assert_eq!(
            tracker.begin_pending(now + Duration::from_secs(2), |_| {
                direct_udp::PeerRelayEndpointState::Missing
            }),
            vec![key],
            "an observed relay that expires is reallocated without another peer snapshot"
        );
    }

    #[test]
    fn peer_relay_allocation_tracker_retries_when_tailnet_never_registers_success() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![key]
        );
        tracker.finish_success(key, now);
        assert!(
            tracker
                .begin_pending(
                    now + PEER_RELAY_REGISTRATION_GRACE - Duration::from_millis(1),
                    |_| direct_udp::PeerRelayEndpointState::Missing
                )
                .is_empty()
        );
        assert_eq!(
            tracker.begin_pending(
                now + PEER_RELAY_REGISTRATION_GRACE + Duration::from_millis(1),
                |_| direct_udp::PeerRelayEndpointState::Missing,
            ),
            vec![key],
            "a successful HTTP response cannot leave an unregistered relay permanently queued"
        );
    }

    #[test]
    fn peer_relay_allocation_tracker_preserves_in_flight_across_remove_readd() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![key]
        );
        tracker.replace_peers([]);
        assert_eq!(tracker.state().in_flight_count, 1);
        tracker.replace_peers([key]);
        assert!(
            tracker
                .begin_pending(now + Duration::from_secs(1), |_| {
                    direct_udp::PeerRelayEndpointState::Missing
                })
                .is_empty(),
            "re-adding the same peer cannot duplicate its active allocation"
        );

        tracker.replace_peers([]);
        let success = tracker.finish_success(key, now + Duration::from_secs(1));
        assert_eq!(success.in_flight_count, 0);
        assert_eq!(
            success.queued_count, 0,
            "a completion for a peer that remains absent cannot resurrect queued state"
        );
    }

    #[test]
    fn peer_relay_allocation_tracker_starts_fresh_allocation_after_disco_rotation() {
        let peer = NodePublic::from_raw([0x11; 32]);
        let old_key = PeerRelayKey {
            peer,
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let new_key = PeerRelayKey {
            peer,
            peer_disco: DiscoPublic::from_raw([0x33; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([old_key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![old_key]
        );
        tracker.finish_success(old_key, now);
        assert!(
            tracker
                .begin_pending(now + Duration::from_millis(100), |_| {
                    direct_udp::PeerRelayEndpointState::Active
                })
                .is_empty()
        );

        tracker.replace_peers([new_key]);
        assert_eq!(
            tracker.begin_pending(now + Duration::from_millis(200), |key| {
                assert_eq!(key, new_key);
                direct_udp::PeerRelayEndpointState::Missing
            }),
            vec![new_key],
            "a new disco identity for the same node must start a new relay allocation"
        );
    }

    #[tokio::test]
    async fn peer_relay_allocation_attempt_timeout_allows_tracker_retry() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        tracker.replace_peers([key]);
        assert_eq!(
            tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
            vec![key]
        );
        let error = bounded_peer_relay_allocation_attempt(
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        tracker.finish_failure(key);
        assert_eq!(
            tracker.begin_pending(
                now + PEER_RELAY_ALLOCATION_RETRY_DELAY + Duration::from_millis(1),
                |_| direct_udp::PeerRelayEndpointState::Missing,
            ),
            vec![key],
            "the timed-out in-flight reservation is released for a bounded retry"
        );
    }

    #[test]
    fn peer_relay_allocator_without_static_endpoint_forces_udp_and_keeps_stun_advertising() {
        let tailnet = tailnet_config("https://api.example");
        let mut config = gateway_config(
            Some("https://api.example"),
            Some("https://derp.example"),
            &tailnet.coordinator_url,
            tailnet.clone(),
        );
        config.stun = Some(StunConfig {
            host: "stun.codewire-dev.sh".into(),
            port: 3478,
        });
        config.udp_relay_allocator_url = Some(
            "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations"
                .into(),
        );

        assert!(force_direct_udp_transport(&config));
        assert_eq!(
            configured_stun_servers(&config),
            vec![StunConfig {
                host: "stun.codewire-dev.sh".into(),
                port: 3478,
            }]
        );
    }
}
