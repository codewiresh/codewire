use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use codewire_tailnet::conn::{Conn, Options, PeerTransport, Transport};
use codewire_tailnet::coordinator::{COORDINATOR_SETUP_TIMEOUT, CoordinatorClient, Handlers};
use codewire_tailnet::coordinator_connect::{CoordinatorConnectClient, HelloIdentity};
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
use uuid::Uuid;

use crate::config::{CoordinateTransport, GatewayConfig, StunConfig, TailnetConfig};

const COORDINATOR_RETRY_DELAY: Duration = Duration::from_secs(5);
const PEER_RELAY_ALLOCATION_RETRY_DELAY: Duration = Duration::from_secs(30);

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
    if let (Some(allocator), Some(handle)) = (&peer_relay_allocator, &direct_udp_handle)
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
    in_flight: HashSet<PeerRelayKey>,
    last_started: HashMap<PeerRelayKey, Instant>,
}

impl PeerRelayAllocationTracker {
    fn begin(&mut self, key: PeerRelayKey, now: Instant) -> bool {
        if self.in_flight.contains(&key) {
            return false;
        }
        if self
            .last_started
            .get(&key)
            .is_some_and(|last| now.duration_since(*last) < PEER_RELAY_ALLOCATION_RETRY_DELAY)
        {
            return false;
        }
        self.in_flight.insert(key);
        self.last_started.insert(key, now);
        true
    }

    fn finish(&mut self, key: PeerRelayKey) {
        self.in_flight.remove(&key);
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

    fn request_for_peers(&self, nodes: &[Node]) {
        for node in nodes {
            if node.key.is_zero() || node.disco_key.is_zero() || node.disco_key == self.local_disco
            {
                continue;
            }
            if self.handle.path_for_peer(&node.key).transport == PeerTransport::PeerRelay {
                continue;
            }
            let key = PeerRelayKey {
                peer: node.key,
                peer_disco: node.disco_key,
            };
            if !self.begin_allocation(key) {
                continue;
            }
            let allocator = self.clone();
            tokio::spawn(async move {
                if let Err(err) = allocator.allocate_once(key).await {
                    tracing::debug!(
                        peer = ?key.peer,
                        error = %err,
                        "rust gateway UDP peer relay allocation failed"
                    );
                }
                allocator.finish_allocation(key);
            });
        }
    }

    fn begin_allocation(&self, key: PeerRelayKey) -> bool {
        self.allocations.lock().unwrap().begin(key, Instant::now())
    }

    fn finish_allocation(&self, key: PeerRelayKey) {
        self.allocations.lock().unwrap().finish(key);
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
            generation = event.generation,
            "rust gateway UDP peer relay allocation request accepted"
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
            generation = event.generation,
            "rust gateway UDP peer relay allocation response queued"
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
        tracing::info!(
            generation = response.generation,
            relay_vni = response.endpoint.vni,
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
                    if let Err(err) = allocator.answer_allocation_once(event).await {
                        tracing::debug!(
                            error = %err,
                            "rust gateway UDP peer relay allocation response failed"
                        );
                    }
                });
            }
        });
    }
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
    let selected = select_coordinator_client(config).await?;
    let (node_tx, node_rx) = mpsc::unbounded_channel();
    conn.set_node_callback(move |node| {
        let _ = node_tx.send(node.clone());
    });

    let update_conn = conn.clone();
    let handlers = Handlers {
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
                allocator.request_for_peers(nodes);
            }
        },
        on_derp_map: |_| {
            tracing::debug!("ignoring coordinator DERP map for gateway-local DERP target");
        },
    };
    let result = match selected {
        SelectedCoordinatorClient::WebSocket(mut client) => client
            .run_with_node_updates(node_rx, handlers)
            .await
            .map_err(anyhow::Error::from),
        SelectedCoordinatorClient::Connect(mut client) => client
            .run_with_node_updates(node_rx, handlers)
            .await
            .map_err(anyhow::Error::from),
    }
    .context("run tailnet coordinator");
    conn.clear_node_callback();
    result
}

enum SelectedSetup<C, W> {
    Connect(C),
    WebSocket(W),
}

enum SelectedCoordinatorClient {
    Connect(Box<CoordinatorConnectClient>),
    WebSocket(Box<CoordinatorClient>),
}

async fn select_setup<C, W, CF, WF, CFut, WFut>(
    mode: CoordinateTransport,
    setup_timeout: Duration,
    connect: CF,
    websocket: WF,
) -> Result<SelectedSetup<C, W>>
where
    CF: FnOnce() -> CFut,
    WF: FnOnce() -> WFut,
    CFut: std::future::Future<Output = Result<C>>,
    WFut: std::future::Future<Output = Result<W>>,
{
    async fn bounded<T>(
        transport: &str,
        setup_timeout: Duration,
        setup: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        tokio::time::timeout(setup_timeout, setup)
            .await
            .with_context(|| {
                format!("{transport} coordinator setup timed out after {setup_timeout:?}")
            })?
    }

    match mode {
        CoordinateTransport::Ws => bounded("WebSocket", setup_timeout, websocket())
            .await
            .map(SelectedSetup::WebSocket),
        CoordinateTransport::Connect => bounded("Connect", setup_timeout, connect())
            .await
            .map(SelectedSetup::Connect),
        CoordinateTransport::Auto => match bounded("Connect", setup_timeout, connect()).await {
            Ok(client) => Ok(SelectedSetup::Connect(client)),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "gateway Connect coordinator setup failed; falling back to WebSocket"
                );
                bounded("WebSocket", setup_timeout, websocket())
                    .await
                    .map(SelectedSetup::WebSocket)
            }
        },
    }
}

async fn select_coordinator_client(config: &TailnetConfig) -> Result<SelectedCoordinatorClient> {
    let connect_url = config.coordinator_url.clone();
    let connect_token = config.gateway_token.clone();
    let environment_id = config.environment_id;
    let websocket_url = config.coordinator_url.clone();
    let websocket_token = config.gateway_token.clone();

    match select_setup(
        config.coordinate_transport,
        COORDINATOR_SETUP_TIMEOUT,
        move || async move {
            CoordinatorConnectClient::connect(
                &connect_url,
                &connect_token,
                HelloIdentity::sidecar(environment_id),
            )
            .await
            .context("set up Connect tailnet coordinator")
        },
        move || async move {
            let url = gateway_coordinator_url(&websocket_url, environment_id)?;
            CoordinatorClient::connect(&url, &websocket_token)
                .await
                .context("set up WebSocket tailnet coordinator")
        },
    )
    .await?
    {
        SelectedSetup::Connect(client) => Ok(SelectedCoordinatorClient::Connect(Box::new(client))),
        SelectedSetup::WebSocket(client) => {
            Ok(SelectedCoordinatorClient::WebSocket(Box::new(client)))
        }
    }
}

/// Exercise the production coordinator selector without starting the DERP and
/// WireGuard data plane. This is compiled only for the disposable KIND proof.
#[cfg(feature = "kind-e2e")]
#[doc(hidden)]
pub async fn coordinator_selector_probe(config: &TailnetConfig) -> Result<CoordinateTransport> {
    Ok(match select_coordinator_client(config).await? {
        SelectedCoordinatorClient::Connect(_) => CoordinateTransport::Connect,
        SelectedCoordinatorClient::WebSocket(_) => CoordinateTransport::Ws,
    })
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

fn gateway_coordinator_url(base: &str, environment_id: Uuid) -> Result<String> {
    let mut url = Url::parse(base).with_context(|| format!("parse coordinator URL {base:?}"))?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        "wss" | "ws" => url.scheme(),
        other => return Err(anyhow!("unsupported coordinator URL scheme {other:?}")),
    }
    .to_string();
    url.set_scheme(&scheme)
        .map_err(|_| anyhow!("set coordinator URL scheme to {scheme:?}"))?;

    let existing = url
        .query_pairs()
        .filter(|(key, _)| key != "sidecar_id")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in existing {
            query.append_pair(&key, &value);
        }
        query.append_pair("sidecar_id", &environment_id.to_string());
    }

    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DockerProxyConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn gateway_config(
        api_url: Option<&str>,
        derp_url: Option<&str>,
        coordinator_url: &str,
        tailnet: TailnetConfig,
    ) -> GatewayConfig {
        GatewayConfig {
            shim_addr: "127.0.0.1:7777".into(),
            ssh_listen_addr: "127.0.0.1:2222".into(),
            readyz_listen_addr: "127.0.0.1:2223".into(),
            host_key_path: "/tmp/key".into(),
            listener_self_check_interval: None,
            api_url: api_url.map(str::to_string),
            binding_url: None,
            coordinator_url: Some(coordinator_url.into()),
            coordinate_transport: CoordinateTransport::Ws,
            daemon_auth_token: None,
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
            coordinate_transport: CoordinateTransport::Ws,
        }
    }

    #[tokio::test]
    async fn coordinator_selector_forced_modes_use_only_the_requested_setup() {
        let connect_calls = Arc::new(AtomicUsize::new(0));
        let websocket_calls = Arc::new(AtomicUsize::new(0));
        let connect_count = connect_calls.clone();
        let websocket_count = websocket_calls.clone();
        let selected = select_setup(
            CoordinateTransport::Connect,
            Duration::from_secs(1),
            move || async move {
                connect_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, anyhow::Error>("connect")
            },
            move || async move {
                websocket_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, anyhow::Error>("ws")
            },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::Connect("connect")));
        assert_eq!(connect_calls.load(Ordering::SeqCst), 1);
        assert_eq!(websocket_calls.load(Ordering::SeqCst), 0);

        let connect_calls = Arc::new(AtomicUsize::new(0));
        let websocket_calls = Arc::new(AtomicUsize::new(0));
        let connect_count = connect_calls.clone();
        let websocket_count = websocket_calls.clone();
        let selected = select_setup(
            CoordinateTransport::Ws,
            Duration::from_secs(1),
            move || async move {
                connect_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, anyhow::Error>("connect")
            },
            move || async move {
                websocket_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, anyhow::Error>("ws")
            },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::WebSocket("ws")));
        assert_eq!(connect_calls.load(Ordering::SeqCst), 0);
        assert_eq!(websocket_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn coordinator_selector_auto_falls_back_only_during_connect_setup() {
        let websocket_calls = Arc::new(AtomicUsize::new(0));
        let websocket_count = websocket_calls.clone();
        let selected = select_setup(
            CoordinateTransport::Auto,
            Duration::from_secs(1),
            || async { Err::<(), _>(anyhow!("Connect setup failed")) },
            move || async move {
                websocket_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, anyhow::Error>("ws")
            },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::WebSocket("ws")));
        assert_eq!(websocket_calls.load(Ordering::SeqCst), 1);

        let websocket_calls = Arc::new(AtomicUsize::new(0));
        let websocket_count = websocket_calls.clone();
        let selected = select_setup(
            CoordinateTransport::Auto,
            Duration::from_secs(1),
            || async { Ok::<_, anyhow::Error>("established-connect") },
            move || async move {
                websocket_count.fetch_add(1, Ordering::SeqCst);
                Ok::<_, anyhow::Error>("ws")
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            selected,
            SelectedSetup::Connect("established-connect")
        ));

        let later_stream_result = Err::<(), _>(anyhow!("established stream disconnected"));
        assert!(later_stream_result.is_err());
        assert_eq!(
            websocket_calls.load(Ordering::SeqCst),
            0,
            "a post-setup disconnect returns to the outer reconnect loop without inline WS demotion"
        );
    }

    #[tokio::test]
    async fn coordinator_selector_bounds_stalled_connect_and_websocket_setup() {
        let setup_timeout = Duration::from_millis(20);
        let selected = select_setup(
            CoordinateTransport::Auto,
            setup_timeout,
            std::future::pending::<Result<&'static str>>,
            || async { Ok::<_, anyhow::Error>("ws") },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::WebSocket("ws")));

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            select_setup(
                CoordinateTransport::Auto,
                setup_timeout,
                std::future::pending::<Result<&'static str>>,
                std::future::pending::<Result<&'static str>>,
            ),
        )
        .await
        .expect("both setup attempts must fail finitely");
        assert!(result.is_err());
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
        let tailnet = tailnet_config("https://api.example/api/v1/internal/gateway/coordinate");
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
    fn peer_relay_allocation_tracker_rate_limits_repeated_peer_updates() {
        let key = PeerRelayKey {
            peer: NodePublic::from_raw([0x11; 32]),
            peer_disco: DiscoPublic::from_raw([0x22; 32]),
        };
        let mut tracker = PeerRelayAllocationTracker::default();
        let now = Instant::now();

        assert!(tracker.begin(key, now));
        assert!(
            !tracker.begin(key, now + Duration::from_secs(1)),
            "in-flight allocation should suppress duplicate peer updates"
        );

        tracker.finish(key);
        assert!(
            !tracker.begin(key, now + Duration::from_secs(1)),
            "recently attempted allocation should stay rate-limited after completion"
        );
        assert!(
            tracker.begin(
                key,
                now + PEER_RELAY_ALLOCATION_RETRY_DELAY + Duration::from_millis(1)
            ),
            "allocation can retry after the cooldown"
        );
    }

    #[test]
    fn peer_relay_allocator_without_static_endpoint_forces_udp_and_keeps_stun_advertising() {
        let tailnet = tailnet_config("https://api.example/api/v1/internal/gateway/coordinate");
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

    #[test]
    fn coordinator_url_uses_websocket_scheme_and_replaces_sidecar_id() {
        let env_id = Uuid::new_v4();
        let url = gateway_coordinator_url(
            "https://api.example/api/v1/internal/gateway/coordinate?sidecar_id=old&x=1",
            env_id,
        )
        .unwrap();
        assert_eq!(
            url,
            format!("wss://api.example/api/v1/internal/gateway/coordinate?x=1&sidecar_id={env_id}")
        );
    }
}
