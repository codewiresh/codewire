use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use codewire_client::CodewireClient;
use codewire_tailnet::conn::{Conn, Options as ConnOptions, PeerPath, PeerTransport};
use codewire_tailnet::coordinator::{CoordinatorClient, Handlers};
use codewire_tailnet::coordinator_connect::{CoordinatorConnectClient, HelloIdentity};
use codewire_tailnet::derp_transport::{DerpTarget, DerpTransport, connect_derp_transport};
use codewire_tailnet::direct_udp;
use codewire_tailnet::disco::DiscoPrivate;
use codewire_tailnet::node::{Node, NodePublic, prefix_from_uuid};
use codewire_tailnet::wg::{PublicKey, StaticSecret};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;
use uuid::Uuid;

pub(crate) const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const DEFAULT_DIRECT_WAIT: Duration = Duration::from_secs(2);
const DEFAULT_DIRECT_PROBE_PERIOD: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshTransportMode {
    Auto,
    Tailnet,
    WebSocket,
}

impl SshTransportMode {
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("CW_SSH_TRANSPORT")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "auto" => Ok(Self::Auto),
            "tailnet" | "wg" | "wireguard" => Ok(Self::Tailnet),
            "websocket" | "ws" => Ok(Self::WebSocket),
            value => anyhow::bail!(
                "invalid CW_SSH_TRANSPORT {value:?} (expected auto, tailnet, or websocket)"
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinateTransportMode {
    Ws,
    Connect,
    Auto,
}

impl CoordinateTransportMode {
    pub fn from_env() -> anyhow::Result<Self> {
        let value = std::env::var_os("CW_COORDINATE_TRANSPORT").unwrap_or_default();
        let value = value
            .to_str()
            .ok_or_else(|| anyhow!("CW_COORDINATE_TRANSPORT must be valid UTF-8"))?;
        match value {
            "" | "auto" => Ok(Self::Auto),
            "ws" => Ok(Self::Ws),
            "connect" => Ok(Self::Connect),
            value => anyhow::bail!(
                "invalid CW_COORDINATE_TRANSPORT {value:?} (expected ws, connect, or auto)"
            ),
        }
    }
}

pub async fn pipe_shell_stdio(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    mode: SshTransportMode,
) -> anyhow::Result<()> {
    match mode {
        SshTransportMode::WebSocket => {
            return pipe_websocket_stdio(client, org_id, environment_id).await;
        }
        SshTransportMode::Tailnet => {
            let tailnet = connect_tailnet_ssh(client, org_id, environment_id).await?;
            return tailnet.pipe_stdio().await;
        }
        SshTransportMode::Auto => {}
    }

    match connect_tailnet_ssh(client, org_id, environment_id).await {
        Ok(tailnet) => tailnet.pipe_stdio().await,
        Err(err) => {
            if std::env::var_os("CW_DEBUG_TAILNET").is_some() {
                eprintln!("cw tailnet: tailnet SSH failed, falling back to WebSocket: {err:#}");
            }
            pipe_websocket_stdio(client, org_id, environment_id).await
        }
    }
}

struct TailnetSshConnection {
    stream: Option<codewire_tailnet::netstack::TcpStream>,
    _conn: Arc<Conn>,
    coordinator_task: tokio::task::JoinHandle<()>,
}

impl TailnetSshConnection {
    async fn pipe_stdio(mut self) -> anyhow::Result<()> {
        let stream = self.stream.take().expect("tailnet stream present");
        pipe_stream_stdio(stream).await
    }
}

impl Drop for TailnetSshConnection {
    fn drop(&mut self) {
        self.coordinator_task.abort();
    }
}

async fn connect_tailnet_ssh(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<TailnetSshConnection> {
    let peer_timeout = duration_from_env("CW_TAILNET_PEER_TIMEOUT", DEFAULT_PEER_TIMEOUT, false);
    let dial_timeout = duration_from_env("CW_TAILNET_DIAL_TIMEOUT", DEFAULT_DIAL_TIMEOUT, false);
    let direct_wait = duration_from_env("CW_TAILNET_DIRECT_WAIT", DEFAULT_DIRECT_WAIT, true);
    let force_derp = std::env::var_os("CW_DERP_ONLY").is_some();
    let expected_transport = expected_transport_from_env()?;

    let session =
        connect_tailnet_session(client, org_id, environment_id, peer_timeout, force_derp).await?;
    wait_for_preferred_path(
        &session.conn,
        &session.peer,
        direct_wait,
        expected_transport,
    )
    .await?;

    let agent_addr = prefix_from_uuid(&session.environment_uuid);
    let dst = SocketAddr::new(agent_addr.addr(), 22);
    let stream = tokio::time::timeout(dial_timeout, session.conn.dial_context_tcp(dst))
        .await
        .with_context(|| {
            format!(
                "tailnet TCP dial timed out after {}",
                humantime(dial_timeout)
            )
        })?
        .with_context(|| format!("tailnet TCP dial to {dst}"))?;

    Ok(TailnetSshConnection {
        stream: Some(stream),
        _conn: session.conn,
        coordinator_task: session.coordinator_task,
    })
}

struct TailnetSession {
    environment_uuid: Uuid,
    conn: Arc<Conn>,
    peer: Node,
    coordinator_task: tokio::task::JoinHandle<()>,
    derp_map: Option<Value>,
}

async fn connect_tailnet_session(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    peer_timeout: Duration,
    force_derp: bool,
) -> anyhow::Result<TailnetSession> {
    let environment_uuid = Uuid::parse_str(environment_id)
        .with_context(|| format!("parse environment ID {environment_id:?}"))?;
    let coordinate_transport = CoordinateTransportMode::from_env()?;
    let websocket_coordinator_url = coordinator_url(client.server_url(), org_id, environment_id)?;
    let connect_coordinator_url = client.server_url().as_str().to_owned();
    let hello = HelloIdentity::client(org_id, environment_uuid);
    let token = client.bearer_token().await?;

    let derp_map = fetch_initial_derp_map(
        coordinate_transport,
        &websocket_coordinator_url,
        &connect_coordinator_url,
        token.expose_secret(),
        hello.clone(),
        peer_timeout,
    )
    .await
    .context("fetch coordinator DERP map")?;
    let derp_target = derp_target_from_map(derp_map.as_ref())
        .unwrap_or_else(|| derp_target_from_platform_url(client.server_url()));
    let stun_servers = if force_derp {
        Vec::new()
    } else {
        resolve_stun_servers(stun_servers_from_map(derp_map.as_ref()))
            .await
            .context("resolve DERP map STUN servers")?
    };
    let suppress_peer_direct_udp = suppress_peer_direct_udp_from_env(force_derp);

    let client_id = Uuid::new_v4();
    let client_addr = prefix_from_uuid(&client_id);
    let secret = StaticSecret::random_from_rng(OsRng);
    let local_node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
    let disco_private = DiscoPrivate::generate(&mut OsRng);
    let fallback_transport = connect_derp_transport(&derp_target, &secret)
        .await
        .context("connect DERP relay")?;

    let (transport, endpoints) = if force_derp {
        (fallback_transport, Vec::new())
    } else {
        let (transport, handle) = direct_udp::wrap_transport(
            fallback_transport,
            tailnet_direct_udp_options(
                local_node_key,
                disco_private.clone(),
                stun_servers,
                suppress_peer_direct_udp,
            ),
        )
        .await
        .context("bind direct UDP transport")?;
        (transport, handle.advertised_endpoints())
    };

    let mut conn_options = ConnOptions::new(client_id);
    conn_options.addresses = vec![client_addr];
    conn_options.endpoints = endpoints;
    conn_options.private_key = Some(secret);
    conn_options.disco_private = Some(disco_private);
    let conn = Arc::new(Conn::new(conn_options, transport).context("create tailnet conn")?);
    conn.set_preferred_derp(1);

    let target_peer = Arc::new(Mutex::new(None::<Node>));
    let target_notify = Arc::new(Notify::new());
    // Complete only transport/stream setup before spawning. This is the
    // auto-fallback boundary: once a stream is established, a disconnect ends
    // this coordinator task just as it did on the WebSocket-only path and does
    // not demote a future session away from Connect.
    let coordinator = select_coordinator_client(
        coordinate_transport,
        &websocket_coordinator_url,
        &connect_coordinator_url,
        token.expose_secret(),
        hello,
        peer_timeout,
    )
    .await
    .context("set up coordinator session")?;
    let coordinator_task = spawn_coordinator_task(
        conn.clone(),
        coordinator,
        environment_uuid,
        target_peer.clone(),
        target_notify.clone(),
        suppress_peer_direct_udp,
    );

    let peer = wait_for_target_peer(target_peer, target_notify, peer_timeout)
        .await
        .with_context(|| format!("wait for environment peer {environment_id}"))?;

    Ok(TailnetSession {
        environment_uuid,
        conn,
        peer,
        coordinator_task,
        derp_map,
    })
}

fn suppress_peer_direct_udp_from_env(force_derp: bool) -> bool {
    !force_derp && std::env::var_os("CW_TAILNET_SUPPRESS_PEER_DIRECT_UDP").is_some()
}

fn tailnet_direct_udp_options(
    local_node_key: NodePublic,
    local_disco: DiscoPrivate,
    stun_servers: Vec<SocketAddr>,
    suppress_peer_direct_udp: bool,
) -> direct_udp::Options {
    direct_udp::Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Vec::new(),
        local_node_key,
        local_disco,
    )
    .with_stun_servers(stun_servers)
    .with_peer_direct_udp_enabled(!suppress_peer_direct_udp)
}

fn spawn_coordinator_task(
    conn: Arc<Conn>,
    coordinator: SelectedCoordinatorClient,
    environment_uuid: Uuid,
    target_peer: Arc<Mutex<Option<Node>>>,
    target_notify: Arc<Notify>,
    suppress_peer_direct_udp: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (node_tx, node_rx) = mpsc::unbounded_channel();
        conn.set_node_callback(move |node| {
            let _ = node_tx.send(node.clone());
        });

        let update_conn = conn.clone();
        let handlers = Handlers {
            on_peers: move |nodes: &[Node]| {
                let nodes = maybe_suppress_peer_direct_udp(nodes, suppress_peer_direct_udp);
                let _ = update_conn.update_peers(&nodes);
                if let Some(peer) = nodes.iter().find(|node| node.id == environment_uuid) {
                    *target_peer.lock().unwrap() = Some(peer.clone());
                    target_notify.notify_waiters();
                }
            },
            on_derp_map: |_| {},
        };
        match coordinator {
            SelectedCoordinatorClient::WebSocket(mut client) => {
                let _ = client.run_with_node_updates(node_rx, handlers).await;
            }
            SelectedCoordinatorClient::Connect(mut client) => {
                let _ = client.run_with_node_updates(node_rx, handlers).await;
            }
        }
        conn.clear_node_callback();
    })
}

enum SelectedSetup<C, W> {
    Connect(C),
    WebSocket(W),
}

enum SelectedCoordinatorClient {
    Connect(Box<CoordinatorConnectClient>),
    WebSocket(Box<CoordinatorClient>),
}

async fn select_coordinate_setup<C, W, CF, WF, CFut, WFut>(
    mode: CoordinateTransportMode,
    connect: CF,
    websocket: WF,
) -> anyhow::Result<SelectedSetup<C, W>>
where
    CF: FnOnce() -> CFut,
    WF: FnOnce() -> WFut,
    CFut: std::future::Future<Output = anyhow::Result<C>>,
    WFut: std::future::Future<Output = anyhow::Result<W>>,
{
    match mode {
        CoordinateTransportMode::Ws => websocket().await.map(SelectedSetup::WebSocket),
        CoordinateTransportMode::Connect => connect().await.map(SelectedSetup::Connect),
        CoordinateTransportMode::Auto => match connect().await {
            Ok(client) => Ok(SelectedSetup::Connect(client)),
            Err(err) => {
                if std::env::var_os("CW_DEBUG_TAILNET").is_some() {
                    eprintln!(
                        "cw tailnet: native gRPC coordinator setup failed, falling back to WebSocket: {err:#}"
                    );
                }
                websocket().await.map(SelectedSetup::WebSocket)
            }
        },
    }
}

async fn select_coordinator_client(
    mode: CoordinateTransportMode,
    websocket_url: &str,
    connect_url: &str,
    token: &str,
    hello: HelloIdentity,
    timeout: Duration,
) -> anyhow::Result<SelectedCoordinatorClient> {
    match select_coordinate_setup(
        mode,
        || async {
            CoordinatorConnectClient::connect_public_edge_grpc_with_setup_timeout(
                connect_url,
                token,
                hello,
                timeout,
            )
            .await
            .context("set up native gRPC coordinator")
        },
        || async {
            CoordinatorClient::connect_with_setup_timeout(websocket_url, token, timeout)
                .await
                .context("set up WebSocket coordinator")
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

fn maybe_suppress_peer_direct_udp(nodes: &[Node], suppress: bool) -> Vec<Node> {
    if !suppress {
        return nodes.to_vec();
    }
    nodes
        .iter()
        .cloned()
        .map(|mut node| {
            node.endpoints.clear();
            node
        })
        .collect()
}

async fn wait_for_target_peer(
    target_peer: Arc<Mutex<Option<Node>>>,
    target_notify: Arc<Notify>,
    timeout: Duration,
) -> anyhow::Result<Node> {
    if let Some(peer) = target_peer.lock().unwrap().clone() {
        return Ok(peer);
    }
    tokio::time::timeout(timeout, async {
        loop {
            target_notify.notified().await;
            if let Some(peer) = target_peer.lock().unwrap().clone() {
                return peer;
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow!(
            "timeout waiting for peer update after {}",
            humantime(timeout)
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedTransport {
    Any,
    DirectUdp,
    PeerRelay,
    DerpRelay,
}

impl ExpectedTransport {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "any" => Ok(Self::Any),
            "direct_udp" => Ok(Self::DirectUdp),
            "peer_relay" | "udp_relay" => Ok(Self::PeerRelay),
            "derp" | "derp_relay" => Ok(Self::DerpRelay),
            value => anyhow::bail!(
                "invalid transport {value:?} (expected any, direct_udp, udp_relay, or derp)"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::DirectUdp => "direct_udp",
            Self::PeerRelay => "udp_relay",
            Self::DerpRelay => "derp",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TailnetDiagnosticOptions {
    pub peer_timeout: Duration,
    pub direct_wait: Duration,
    pub force_derp: bool,
    pub expected_transport: ExpectedTransport,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnvironmentTailnetDiagnostic {
    pub environment_id: String,
    pub server_url: String,
    pub forced_derp: bool,
    pub direct_wait: String,
    pub stages: Vec<TailnetDiagnosticStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<TailnetDerpMapDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<TailnetPeerDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_path: Option<TailnetPathDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_path: Option<TailnetPathDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TailnetDiagnosticStage {
    pub name: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TailnetDerpMapDiagnostic {
    pub regions: usize,
    pub derp_nodes: usize,
    pub stun_nodes: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TailnetPeerDiagnostic {
    pub id: String,
    pub preferred_derp: i32,
    pub endpoints: Vec<String>,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TailnetPathDiagnostic {
    pub ready: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub transport: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derp_region_id: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

pub async fn diagnose_environment_tailnet(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
    options: TailnetDiagnosticOptions,
) -> EnvironmentTailnetDiagnostic {
    let mut diagnostic = EnvironmentTailnetDiagnostic {
        environment_id: environment_id.to_string(),
        server_url: client.server_url().to_string(),
        forced_derp: options.force_derp,
        direct_wait: humantime(options.direct_wait),
        stages: Vec::new(),
        derp_map: None,
        peer: None,
        direct_path: None,
        final_path: None,
    };

    let started = Instant::now();
    let session = match connect_tailnet_session(
        client,
        org_id,
        environment_id,
        options.peer_timeout,
        options.force_derp,
    )
    .await
    {
        Ok(session) => {
            diagnostic.derp_map = derp_map_diagnostic(session.derp_map.as_ref());
            diagnostic.peer = Some(peer_diagnostic(&session.peer));
            diagnostic.stages.push(stage_ok(
                "session",
                "connected to coordinator and peer",
                started,
            ));
            session
        }
        Err(err) => {
            diagnostic
                .stages
                .push(stage_fail("session", err.to_string(), started));
            return diagnostic;
        }
    };

    let initial_path = probe_path_diagnostic(&session.conn, &session.peer);
    diagnostic.direct_path = Some(initial_path.clone());
    let wait_started = Instant::now();
    match wait_for_preferred_path(
        &session.conn,
        &session.peer,
        options.direct_wait,
        options.expected_transport,
    )
    .await
    {
        Ok(()) => {
            let final_path = probe_path_diagnostic(&session.conn, &session.peer);
            diagnostic.final_path = Some(final_path.clone());
            diagnostic.stages.push(stage_ok(
                "path",
                format!(
                    "transport={} expected={}",
                    final_path.transport,
                    options.expected_transport.as_str()
                ),
                wait_started,
            ));
        }
        Err(err) => diagnostic
            .stages
            .push(stage_fail("path", err.to_string(), wait_started)),
    }
    if diagnostic.final_path.is_none() {
        diagnostic.final_path = Some(probe_path_diagnostic(&session.conn, &session.peer));
    }
    diagnostic
}

async fn wait_for_preferred_path(
    conn: &Conn,
    peer: &Node,
    wait: Duration,
    expected: ExpectedTransport,
) -> anyhow::Result<()> {
    if wait.is_zero() || std::env::var_os("CW_DERP_ONLY").is_some() {
        return validate_expected_path(conn, peer, expected);
    }

    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let path = conn.probe_peer_path(peer)?;
        if preferred_transport_ready(expected, path.transport) {
            debug_path_probe(path.transport);
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            debug_path_probe(path.transport);
            validate_expected_path(conn, peer, expected)?;
            return Ok(());
        }
        tokio::time::sleep(DEFAULT_DIRECT_PROBE_PERIOD).await;
    }
}

fn preferred_transport_ready(expected: ExpectedTransport, actual: PeerTransport) -> bool {
    match expected {
        ExpectedTransport::Any => actual == PeerTransport::DirectUdp,
        ExpectedTransport::DirectUdp => actual == PeerTransport::DirectUdp,
        ExpectedTransport::PeerRelay => actual == PeerTransport::PeerRelay,
        ExpectedTransport::DerpRelay => actual == PeerTransport::DerpRelay,
    }
}

fn validate_expected_path(
    conn: &Conn,
    peer: &Node,
    expected: ExpectedTransport,
) -> anyhow::Result<()> {
    let path = conn.probe_peer_path(peer)?;
    match (expected, path.transport) {
        (ExpectedTransport::Any, _) => Ok(()),
        (ExpectedTransport::DirectUdp, PeerTransport::DirectUdp) => Ok(()),
        (ExpectedTransport::PeerRelay, PeerTransport::PeerRelay) => Ok(()),
        (ExpectedTransport::DerpRelay, PeerTransport::DerpRelay) => Ok(()),
        (ExpectedTransport::DirectUdp, other) => {
            anyhow::bail!(
                "expected direct_udp transport, got {}",
                transport_name(other)
            )
        }
        (ExpectedTransport::PeerRelay, other) => {
            anyhow::bail!(
                "expected udp_relay transport, got {}",
                transport_name(other)
            )
        }
        (ExpectedTransport::DerpRelay, other) => {
            anyhow::bail!("expected derp transport, got {}", transport_name(other))
        }
    }
}

fn derp_map_diagnostic(map: Option<&Value>) -> Option<TailnetDerpMapDiagnostic> {
    let regions = map?.get("Regions")?.as_object()?;
    let mut derp_nodes = 0usize;
    let mut stun_nodes = 0usize;
    for region in regions.values() {
        let Some(nodes) = region.get("Nodes").and_then(Value::as_array) else {
            continue;
        };
        for node in nodes {
            let stun_only = node
                .get("STUNOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !stun_only {
                derp_nodes += 1;
            }
            if node.get("STUNPort").and_then(Value::as_i64).is_some() {
                stun_nodes += 1;
            }
        }
    }
    Some(TailnetDerpMapDiagnostic {
        regions: regions.len(),
        derp_nodes,
        stun_nodes,
    })
}

fn peer_diagnostic(peer: &Node) -> TailnetPeerDiagnostic {
    TailnetPeerDiagnostic {
        id: peer.id.to_string(),
        preferred_derp: peer.preferred_derp,
        endpoints: peer
            .endpoints
            .iter()
            .map(|endpoint| endpoint.0.to_string())
            .collect(),
        addresses: peer
            .addresses
            .iter()
            .map(|address| address.to_string())
            .collect(),
    }
}

fn probe_path_diagnostic(conn: &Conn, peer: &Node) -> TailnetPathDiagnostic {
    match conn.probe_peer_path(peer) {
        Ok(path) => {
            let ready = path.transport != PeerTransport::Unknown;
            path_diagnostic(path, ready, String::new())
        }
        Err(err) => TailnetPathDiagnostic {
            ready: false,
            transport: String::new(),
            endpoint: String::new(),
            derp_region_id: None,
            error: err.to_string(),
        },
    }
}

fn path_diagnostic(path: PeerPath, ready: bool, error: String) -> TailnetPathDiagnostic {
    TailnetPathDiagnostic {
        ready,
        transport: transport_name(path.transport).to_string(),
        endpoint: path
            .endpoint
            .map(|endpoint| endpoint.to_string())
            .unwrap_or_default(),
        derp_region_id: path.derp_region_id,
        error,
    }
}

fn stage_ok(
    name: impl Into<String>,
    detail: impl Into<String>,
    started: Instant,
) -> TailnetDiagnosticStage {
    TailnetDiagnosticStage {
        name: name.into(),
        status: "ok",
        detail: detail.into(),
        duration_ms: Some(started.elapsed().as_millis()),
    }
}

fn stage_fail(
    name: impl Into<String>,
    detail: impl Into<String>,
    started: Instant,
) -> TailnetDiagnosticStage {
    TailnetDiagnosticStage {
        name: name.into(),
        status: "fail",
        detail: detail.into(),
        duration_ms: Some(started.elapsed().as_millis()),
    }
}

fn expected_transport_from_env() -> anyhow::Result<ExpectedTransport> {
    ExpectedTransport::parse(&std::env::var("CW_TAILNET_EXPECTED_TRANSPORT").unwrap_or_default())
        .map_err(|err| anyhow!("invalid CW_TAILNET_EXPECTED_TRANSPORT: {err}"))
}

fn debug_path_probe(transport: PeerTransport) {
    if std::env::var_os("CW_DEBUG_TAILNET").is_some() {
        eprintln!(
            "cw tailnet: path probe transport={}",
            transport_name(transport)
        );
    }
}

fn transport_name(transport: PeerTransport) -> &'static str {
    match transport {
        PeerTransport::DirectUdp => "direct_udp",
        PeerTransport::PeerRelay => "udp_relay",
        PeerTransport::DerpRelay => "derp",
        PeerTransport::Unknown => "unknown",
    }
}

async fn pipe_stream_stdio<S>(stream: S) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut stream_rx, mut stream_tx) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    let stdin_to_stream = async {
        tokio::io::copy(&mut stdin, &mut stream_tx)
            .await
            .context("copy stdin to SSH stream")?;
        let _ = stream_tx.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    let stream_to_stdout = async {
        tokio::io::copy(&mut stream_rx, &mut stdout)
            .await
            .context("copy SSH stream to stdout")?;
        let _ = stdout.flush().await;
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(stdin_to_stream);
    tokio::pin!(stream_to_stdout);

    tokio::select! {
        result = &mut stdin_to_stream => {
            result?;
            (&mut stream_to_stdout).await?;
        }
        result = &mut stream_to_stdout => result?,
    };
    Ok(())
}

async fn pipe_websocket_stdio(
    client: &CodewireClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<()> {
    let token = client.bearer_token().await?;
    let url = ssh_proxy_url(client.server_url(), org_id, environment_id)?;
    let mut request = url
        .into_client_request()
        .map_err(|err| anyhow!("invalid WebSocket request: {err}"))?;
    let headers = request.headers_mut();
    headers.insert("Sec-WebSocket-Protocol", HeaderValue::from_static("ssh"));
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {}", token.expose_secret()))
            .context("build authorization header")?,
    );
    let (ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .context("connect SSH WebSocket proxy")?;
    let (mut ws_tx, mut ws_rx) = ws.split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut deferred_stdin = Vec::new();

    let mut initial = vec![0u8; 32 * 1024];
    let n = tokio::io::AsyncReadExt::read(&mut stdin, &mut initial).await?;
    if n == 0 {
        let _ = ws_tx.close().await;
        return Ok(());
    }
    let initial = &initial[..n];
    // OpenSSH may pipeline KEXINIT with its identification string. The
    // WebSocket fallback bridges to a russh server behind Kubernetes, so keep
    // the SSH identification exchange ordered before forwarding deferred KEX.
    let initial_send_len = ssh_identification_prefix_len(initial).unwrap_or(initial.len());
    ws_tx
        .send(Message::Binary(initial[..initial_send_len].to_vec().into()))
        .await
        .context("write SSH WebSocket frame")?;
    deferred_stdin.extend_from_slice(&initial[initial_send_len..]);

    if !deferred_stdin.is_empty() {
        while let Some(frame) = ws_rx.next().await {
            match write_websocket_ssh_frame(&mut stdout, frame.context("read SSH WebSocket frame")?)
                .await?
            {
                WebsocketFrameDisposition::Data => break,
                WebsocketFrameDisposition::Skip => {}
                WebsocketFrameDisposition::Closed => return Ok(()),
            }
        }
    }

    let stdin_to_ws = async {
        if !deferred_stdin.is_empty() {
            ws_tx
                .send(Message::Binary(deferred_stdin.into()))
                .await
                .context("write SSH WebSocket frame")?;
        }
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await?;
            if n == 0 {
                let _ = ws_tx.close().await;
                return Ok::<(), anyhow::Error>(());
            }
            ws_tx
                .send(Message::Binary(buf[..n].to_vec().into()))
                .await
                .context("write SSH WebSocket frame")?;
        }
    };
    let ws_to_stdout = async {
        while let Some(frame) = ws_rx.next().await {
            if matches!(
                write_websocket_ssh_frame(&mut stdout, frame.context("read SSH WebSocket frame")?)
                    .await?,
                WebsocketFrameDisposition::Closed
            ) {
                break;
            }
        }
        stdout.flush().await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(stdin_to_ws);
    tokio::pin!(ws_to_stdout);

    tokio::select! {
        result = &mut stdin_to_ws => {
            result?;
            (&mut ws_to_stdout).await
        }
        result = &mut ws_to_stdout => result,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebsocketFrameDisposition {
    Data,
    Skip,
    Closed,
}

async fn write_websocket_ssh_frame<W>(
    stdout: &mut W,
    frame: Message,
) -> anyhow::Result<WebsocketFrameDisposition>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    match frame {
        Message::Binary(data) => {
            tokio::io::AsyncWriteExt::write_all(stdout, &data).await?;
            stdout.flush().await?;
            Ok(WebsocketFrameDisposition::Data)
        }
        Message::Text(data) => {
            tokio::io::AsyncWriteExt::write_all(stdout, data.as_bytes()).await?;
            stdout.flush().await?;
            Ok(WebsocketFrameDisposition::Data)
        }
        Message::Close(_) => Ok(WebsocketFrameDisposition::Closed),
        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
            Ok(WebsocketFrameDisposition::Skip)
        }
    }
}

fn ssh_identification_prefix_len(bytes: &[u8]) -> Option<usize> {
    if !bytes.starts_with(b"SSH-") {
        return None;
    }
    bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|idx| idx + 1)
}

#[derive(Deserialize)]
struct CoordinateResponse {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    derp_map: Option<Value>,
}

fn derp_target_from_platform_url(url: &Url) -> DerpTarget {
    let host = url.host_str().unwrap_or("localhost").to_string();
    let port = url.port().unwrap_or(match url.scheme() {
        "http" | "ws" => 80,
        _ => 443,
    });
    let transport = match url.scheme() {
        "http" | "ws" => DerpTransport::Plain,
        _ => DerpTransport::Tls {
            skip_verify: port != 443,
        },
    };
    DerpTarget {
        host,
        port,
        transport,
    }
}

async fn fetch_initial_derp_map(
    mode: CoordinateTransportMode,
    websocket_url: &str,
    connect_url: &str,
    token: &str,
    hello: HelloIdentity,
    timeout: Duration,
) -> anyhow::Result<Option<Value>> {
    match select_coordinate_setup(
        mode,
        || fetch_initial_derp_map_connect(connect_url, token, hello, timeout),
        || fetch_initial_derp_map_websocket(websocket_url, token, timeout),
    )
    .await?
    {
        SelectedSetup::Connect(map) | SelectedSetup::WebSocket(map) => Ok(map),
    }
}

async fn fetch_initial_derp_map_websocket(
    coordinator_url: &str,
    token: &str,
    timeout: Duration,
) -> anyhow::Result<Option<Value>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut request = coordinator_url
        .into_client_request()
        .map_err(|err| anyhow!("invalid coordinator WebSocket request: {err}"))?;
    let headers = request.headers_mut();
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("coordinate"),
    );
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).context("build authorization header")?,
    );

    let (mut ws, _) = tokio::time::timeout_at(deadline, tokio_tungstenite::connect_async(request))
        .await
        .with_context(|| format!("coordinator connect timed out after {}", humantime(timeout)))?
        .context("connect coordinator")?;

    for _ in 0..8 {
        let frame = tokio::time::timeout_at(deadline, ws.next())
            .await
            .with_context(|| format!("DERP map wait timed out after {}", humantime(timeout)))?;
        let Some(frame) = frame else {
            return Ok(None);
        };
        let frame = frame.context("read coordinator frame")?;
        let payload = match frame {
            Message::Text(text) => text.to_string(),
            Message::Binary(bytes) => String::from_utf8(bytes.to_vec()).unwrap_or_default(),
            Message::Close(_) => return Ok(None),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
        };
        let Ok(response) = serde_json::from_str::<CoordinateResponse>(&payload) else {
            continue;
        };
        if response.typ == "derp_map" {
            let _ = ws.close(None).await;
            return Ok(response.derp_map);
        }
    }
    Ok(None)
}

async fn fetch_initial_derp_map_connect(
    coordinator_url: &str,
    token: &str,
    hello: HelloIdentity,
    timeout: Duration,
) -> anyhow::Result<Option<Value>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut coordinator = CoordinatorConnectClient::connect_public_edge_grpc_with_setup_timeout(
        coordinator_url,
        token,
        hello,
        timeout,
    )
    .await
    .context("connect coordinator over native gRPC")?;

    let (derp_map_tx, derp_map_rx) = tokio::sync::oneshot::channel();
    let mut derp_map_tx = Some(derp_map_tx);
    let run = coordinator.run(Handlers {
        on_peers: |_| {},
        on_derp_map: move |map: &Value| {
            if let Some(tx) = derp_map_tx.take() {
                let _ = tx.send(map.clone());
            }
        },
    });
    tokio::pin!(run);

    let map = tokio::time::timeout_at(deadline, async {
        tokio::select! {
            result = &mut run => {
                result.context("read initial native gRPC coordinator stream")?;
                anyhow::bail!("native gRPC coordinator stream closed before DERP map")
            }
            result = derp_map_rx => result.context("native gRPC coordinator stream closed before DERP map"),
        }
    })
    .await
    .with_context(|| format!("DERP map wait timed out after {}", humantime(timeout)))??;

    Ok(Some(map))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StunServer {
    host: String,
    port: u16,
}

fn derp_target_from_map(map: Option<&Value>) -> Option<DerpTarget> {
    let regions = map?.get("Regions")?.as_object()?;
    let mut region_keys = regions.keys().collect::<Vec<_>>();
    region_keys.sort();
    for key in region_keys {
        let nodes = regions.get(key)?.get("Nodes")?.as_array()?;
        for node in nodes {
            if node
                .get("STUNOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let host = node.get("HostName")?.as_str()?.trim();
            if host.is_empty() {
                continue;
            }
            let port = node
                .get("DERPPort")
                .and_then(Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .unwrap_or(443);
            let insecure = node
                .get("InsecureForTests")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            return Some(DerpTarget {
                host: host.to_string(),
                port,
                transport: DerpTransport::Tls {
                    skip_verify: insecure || port != 443,
                },
            });
        }
    }
    None
}

fn stun_servers_from_map(map: Option<&Value>) -> Vec<StunServer> {
    let Some(regions) = map
        .and_then(|map| map.get("Regions"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    for region in regions.values() {
        let Some(nodes) = region.get("Nodes").and_then(Value::as_array) else {
            continue;
        };
        for node in nodes {
            if !node
                .get("STUNOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let Some(host) = node.get("HostName").and_then(Value::as_str) else {
                continue;
            };
            let host = host.trim();
            if host.is_empty() {
                continue;
            }
            let Some(port) = node
                .get("STUNPort")
                .and_then(Value::as_i64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
            else {
                continue;
            };
            let server = StunServer {
                host: host.to_string(),
                port,
            };
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
}

async fn resolve_stun_servers(servers: Vec<StunServer>) -> anyhow::Result<Vec<SocketAddr>> {
    let mut resolved = Vec::new();
    for server in servers {
        let addrs = lookup_host((server.host.as_str(), server.port))
            .await
            .with_context(|| format!("resolve STUN host {}:{}", server.host, server.port))?;
        for addr in addrs {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }
    Ok(resolved)
}

fn coordinator_url(server_url: &Url, org_id: &str, environment_id: &str) -> anyhow::Result<String> {
    websocket_path_url(
        server_url,
        &format!("api/v1/organizations/{org_id}/environments/{environment_id}/coordinate"),
    )
}

fn ssh_proxy_url(server_url: &Url, org_id: &str, environment_id: &str) -> anyhow::Result<String> {
    websocket_path_url(
        server_url,
        &format!("api/v1/organizations/{org_id}/environments/{environment_id}/ssh-proxy"),
    )
}

fn websocket_path_url(server_url: &Url, path: &str) -> anyhow::Result<String> {
    let mut url = server_url.clone();
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        "wss" | "ws" => url.scheme(),
        other => anyhow::bail!("unsupported server URL scheme {other:?}"),
    }
    .to_string();
    url.set_scheme(&scheme)
        .map_err(|_| anyhow!("set URL scheme to {scheme:?}"))?;
    let base_path = url.path().trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let joined = if base_path.is_empty() {
        format!("/{path}")
    } else {
        format!("{base_path}/{path}")
    };
    url.set_path(&joined);
    url.set_query(None);
    Ok(url.into())
}

fn duration_from_env(name: &str, fallback: Duration, allow_zero: bool) -> Duration {
    let value = std::env::var(name).unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return fallback;
    }
    match parse_duration(value) {
        Ok(duration) if (allow_zero || !duration.is_zero()) => duration,
        _ => fallback,
    }
}

pub(crate) fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("empty duration");
    }
    let split_at = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    if split_at == 0 {
        anyhow::bail!("duration missing number");
    }
    let amount = value[..split_at].parse::<u64>()?;
    let unit = value[split_at..].trim();
    match unit {
        "" | "s" => Ok(Duration::from_secs(amount)),
        "ms" => Ok(Duration::from_millis(amount)),
        "m" => Ok(Duration::from_secs(amount.saturating_mul(60))),
        _ => anyhow::bail!("unsupported duration unit"),
    }
}

pub(crate) fn humantime(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Environment variables are process-global. Keep the selector test from
    // racing any future tests that exercise the same variable.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    async fn accept_http2_settings(socket: &mut tokio::net::TcpStream) {
        let mut preface = [0_u8; 24];
        socket.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        let mut header = [0_u8; 9];
        socket.read_exact(&mut header).await.unwrap();
        let payload_len =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        assert_eq!(header[3], 4, "first client frame must be SETTINGS");
        let mut payload = vec![0_u8; payload_len];
        socket.read_exact(&mut payload).await.unwrap();
        socket
            .write_all(&[
                0, 0, 0, 4, 0, 0, 0, 0, 0, // server SETTINGS
                0, 0, 0, 4, 1, 0, 0, 0, 0, // ACK client SETTINGS
            ])
            .await
            .unwrap();
    }

    #[test]
    fn websocket_urls_preserve_platform_base_path() {
        let base = Url::parse("https://codewire.test/base").unwrap();
        assert_eq!(
            coordinator_url(&base, "org_123", "env_456").unwrap(),
            "wss://codewire.test/base/api/v1/organizations/org_123/environments/env_456/coordinate"
        );
        assert_eq!(
            ssh_proxy_url(&base, "org_123", "env_456").unwrap(),
            "wss://codewire.test/base/api/v1/organizations/org_123/environments/env_456/ssh-proxy"
        );
    }

    #[test]
    fn ssh_identification_prefix_splits_pipelined_kexinit() {
        let pipelined = b"SSH-2.0-OpenSSH_10.3\r\n\0\0\x06\x84";

        assert_eq!(
            ssh_identification_prefix_len(pipelined),
            Some(b"SSH-2.0-OpenSSH_10.3\r\n".len())
        );
    }

    #[test]
    fn ssh_identification_prefix_waits_for_complete_line() {
        assert_eq!(ssh_identification_prefix_len(b"SSH-2.0-OpenSSH_10.3"), None);
        assert_eq!(ssh_identification_prefix_len(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn derp_map_extracts_relay_target_and_stun_nodes() {
        let map = json!({
            "Regions": {
                "1": {
                    "Nodes": [
                        {
                            "HostName": "derp.codewire.test",
                            "DERPPort": 8443,
                            "STUNPort": -1,
                            "InsecureForTests": true
                        },
                        {
                            "HostName": "stun.codewire.test",
                            "STUNOnly": true,
                            "STUNPort": 3478
                        }
                    ]
                }
            }
        });

        assert_eq!(
            derp_target_from_map(Some(&map)),
            Some(DerpTarget {
                host: "derp.codewire.test".into(),
                port: 8443,
                transport: DerpTransport::Tls { skip_verify: true },
            })
        );
        assert_eq!(
            stun_servers_from_map(Some(&map)),
            vec![StunServer {
                host: "stun.codewire.test".into(),
                port: 3478,
            }]
        );
    }

    #[test]
    fn ssh_transport_mode_env_matches_go_aliases() {
        unsafe {
            std::env::remove_var("CW_SSH_TRANSPORT");
        }
        assert_eq!(
            SshTransportMode::from_env().unwrap(),
            SshTransportMode::Auto
        );
        unsafe {
            std::env::set_var("CW_SSH_TRANSPORT", "wireguard");
        }
        assert_eq!(
            SshTransportMode::from_env().unwrap(),
            SshTransportMode::Tailnet
        );
        unsafe {
            std::env::set_var("CW_SSH_TRANSPORT", "ws");
        }
        assert_eq!(
            SshTransportMode::from_env().unwrap(),
            SshTransportMode::WebSocket
        );
        unsafe {
            std::env::remove_var("CW_SSH_TRANSPORT");
        }
    }

    #[test]
    fn coordinate_transport_mode_accepts_only_exact_values_and_defaults_to_auto() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("CW_COORDINATE_TRANSPORT");
        }
        assert_eq!(
            CoordinateTransportMode::from_env().unwrap(),
            CoordinateTransportMode::Auto
        );

        for (value, expected) in [
            ("ws", CoordinateTransportMode::Ws),
            ("connect", CoordinateTransportMode::Connect),
            ("auto", CoordinateTransportMode::Auto),
        ] {
            unsafe {
                std::env::set_var("CW_COORDINATE_TRANSPORT", value);
            }
            assert_eq!(CoordinateTransportMode::from_env().unwrap(), expected);
        }

        for value in ["WS", "websocket", " connect", "tailnet"] {
            unsafe {
                std::env::set_var("CW_COORDINATE_TRANSPORT", value);
            }
            assert!(CoordinateTransportMode::from_env().is_err(), "{value:?}");
        }
        unsafe {
            std::env::remove_var("CW_COORDINATE_TRANSPORT");
        }
    }

    #[tokio::test]
    async fn coordinate_auto_prefers_native_grpc_and_falls_back_only_on_setup_failure() {
        let selected = select_coordinate_setup(
            CoordinateTransportMode::Auto,
            || async { Ok::<_, anyhow::Error>("grpc") },
            || async { Err::<&str, _>(anyhow!("WebSocket must not run")) },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::Connect("grpc")));

        let selected = select_coordinate_setup(
            CoordinateTransportMode::Auto,
            || async { Err::<&str, _>(anyhow!("native gRPC setup failed")) },
            || async { Ok::<_, anyhow::Error>("ws") },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::WebSocket("ws")));
    }

    #[tokio::test]
    async fn coordinate_forced_modes_do_not_cross_fallback_boundary() {
        let selected = select_coordinate_setup(
            CoordinateTransportMode::Connect,
            || async { Ok::<_, anyhow::Error>("grpc") },
            || async { Err::<&str, _>(anyhow!("WebSocket must not run")) },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::Connect("grpc")));

        let selected = select_coordinate_setup(
            CoordinateTransportMode::Ws,
            || async { Err::<&str, _>(anyhow!("Connect must not run")) },
            || async { Ok::<_, anyhow::Error>("ws") },
        )
        .await
        .unwrap();
        assert!(matches!(selected, SelectedSetup::WebSocket("ws")));
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tokio-tungstenite's handshake callback error type.
    async fn coordinate_auto_falls_back_before_derp_map_when_native_grpc_is_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            // Simulate a disabled native gRPC route at the protocol boundary:
            // the h2c client reaches the local server, but setup is rejected
            // before any response message (and therefore before a DERP map).
            let (mut connect_socket, _) = listener.accept().await.unwrap();
            let mut h2_preface = [0_u8; 24];
            connect_socket.read_exact(&mut h2_preface).await.unwrap();
            assert_eq!(&h2_preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            drop(connect_socket);

            let (websocket_socket, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                websocket_socket,
                |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        HeaderValue::from_static("coordinate"),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
            websocket
                .send(Message::Text(
                    serde_json::to_string(&json!({
                        "type": "derp_map",
                        "derp_map": {"Regions": {}}
                    }))
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
        });

        let map = fetch_initial_derp_map(
            CoordinateTransportMode::Auto,
            &format!("ws://{addr}/api/v1/coordinate"),
            &format!("http://{addr}"),
            "test-token",
            HelloIdentity::client("org-test", Uuid::new_v4()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        assert_eq!(map, Some(json!({"Regions": {}})));
        fixture.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tokio-tungstenite's handshake callback error type.
    async fn coordinate_auto_falls_back_when_http2_accepts_then_stalls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut connect_socket, _) = listener.accept().await.unwrap();
            accept_http2_settings(&mut connect_socket).await;

            let (websocket_socket, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                websocket_socket,
                |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        HeaderValue::from_static("coordinate"),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
            websocket
                .send(Message::Text(
                    serde_json::to_string(&json!({
                        "type": "derp_map",
                        "derp_map": {"Regions": {}}
                    }))
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
        });

        let map = fetch_initial_derp_map(
            CoordinateTransportMode::Auto,
            &format!("ws://{addr}/api/v1/coordinate"),
            &format!("http://{addr}"),
            "test-token",
            HelloIdentity::client("org-test", Uuid::new_v4()),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        assert_eq!(map, Some(json!({"Regions": {}})));
        fixture.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tokio-tungstenite's handshake callback error type.
    async fn coordinate_auto_fails_finitely_when_connect_and_websocket_setup_stall() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut connect_socket, _) = listener.accept().await.unwrap();
            accept_http2_settings(&mut connect_socket).await;

            let (websocket_socket, _) = listener.accept().await.unwrap();
            let _websocket = tokio_tungstenite::accept_hdr_async(
                websocket_socket,
                |_: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        HeaderValue::from_static("coordinate"),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
            std::future::pending::<()>().await;
        });

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            fetch_initial_derp_map(
                CoordinateTransportMode::Auto,
                &format!("ws://{addr}/api/v1/coordinate"),
                &format!("http://{addr}"),
                "test-token",
                HelloIdentity::client("org-test", Uuid::new_v4()),
                Duration::from_millis(100),
            ),
        )
        .await
        .expect("both stalled transports must fail finitely");
        assert!(result.is_err());
        fixture.abort();
    }

    #[test]
    fn expected_transport_env_accepts_transport_ladder_names() {
        unsafe {
            std::env::remove_var("CW_TAILNET_EXPECTED_TRANSPORT");
        }
        assert_eq!(
            expected_transport_from_env().unwrap(),
            ExpectedTransport::Any
        );
        unsafe {
            std::env::set_var("CW_TAILNET_EXPECTED_TRANSPORT", "direct_udp");
        }
        assert_eq!(
            expected_transport_from_env().unwrap(),
            ExpectedTransport::DirectUdp
        );
        unsafe {
            std::env::set_var("CW_TAILNET_EXPECTED_TRANSPORT", "udp_relay");
        }
        assert_eq!(
            expected_transport_from_env().unwrap(),
            ExpectedTransport::PeerRelay
        );
        unsafe {
            std::env::set_var("CW_TAILNET_EXPECTED_TRANSPORT", "derp");
        }
        assert_eq!(
            expected_transport_from_env().unwrap(),
            ExpectedTransport::DerpRelay
        );
        unsafe {
            std::env::set_var("CW_TAILNET_EXPECTED_TRANSPORT", "derp_relay");
        }
        assert_eq!(
            expected_transport_from_env().unwrap(),
            ExpectedTransport::DerpRelay
        );
        unsafe {
            std::env::remove_var("CW_TAILNET_EXPECTED_TRANSPORT");
        }
    }

    #[test]
    fn auto_transport_waits_for_direct_udp_before_relay_fallbacks() {
        assert!(preferred_transport_ready(
            ExpectedTransport::Any,
            PeerTransport::DirectUdp
        ));
        assert!(!preferred_transport_ready(
            ExpectedTransport::Any,
            PeerTransport::PeerRelay
        ));
        assert!(!preferred_transport_ready(
            ExpectedTransport::Any,
            PeerTransport::DerpRelay
        ));
    }

    #[test]
    fn transport_names_use_current_ladder_terms() {
        assert_eq!(transport_name(PeerTransport::DirectUdp), "direct_udp");
        assert_eq!(transport_name(PeerTransport::PeerRelay), "udp_relay");
        assert_eq!(transport_name(PeerTransport::DerpRelay), "derp");
    }

    #[test]
    fn explicit_expected_transport_accepts_exact_ladder_step() {
        assert!(preferred_transport_ready(
            ExpectedTransport::DirectUdp,
            PeerTransport::DirectUdp
        ));
        assert!(preferred_transport_ready(
            ExpectedTransport::PeerRelay,
            PeerTransport::PeerRelay
        ));
        assert!(preferred_transport_ready(
            ExpectedTransport::DerpRelay,
            PeerTransport::DerpRelay
        ));
        assert!(!preferred_transport_ready(
            ExpectedTransport::DirectUdp,
            PeerTransport::PeerRelay
        ));
        assert!(!preferred_transport_ready(
            ExpectedTransport::PeerRelay,
            PeerTransport::DerpRelay
        ));
    }

    #[test]
    fn suppress_peer_direct_udp_clears_only_peer_endpoints() {
        let id = uuid::Uuid::new_v4();
        let node = Node {
            id,
            as_of: chrono::Utc::now(),
            key: NodePublic::from_raw([1; 32]),
            disco_key: DiscoPrivate::generate(&mut rand::rngs::OsRng).public(),
            preferred_derp: 1,
            derp_latency: None,
            endpoints: vec![codewire_tailnet::node::AddrPort(
                "192.0.2.36:33123".parse().unwrap(),
            )],
            addresses: vec![prefix_from_uuid(&id)],
        };

        let unchanged = maybe_suppress_peer_direct_udp(std::slice::from_ref(&node), false);
        assert_eq!(unchanged[0].endpoints.len(), 1);

        let suppressed = maybe_suppress_peer_direct_udp(std::slice::from_ref(&node), true);
        assert!(suppressed[0].endpoints.is_empty());
        assert_eq!(suppressed[0].addresses, node.addresses);
        assert_eq!(suppressed[0].key, node.key);
    }

    #[test]
    fn suppress_peer_direct_udp_env_selects_relay_only_options() {
        unsafe {
            std::env::remove_var("CW_TAILNET_SUPPRESS_PEER_DIRECT_UDP");
        }
        assert!(!suppress_peer_direct_udp_from_env(false));
        let enabled = tailnet_direct_udp_options(
            NodePublic::from_raw([2; 32]),
            DiscoPrivate::generate(&mut rand::rngs::OsRng),
            Vec::new(),
            false,
        );
        assert!(enabled.peer_direct_udp_enabled);

        unsafe {
            std::env::set_var("CW_TAILNET_SUPPRESS_PEER_DIRECT_UDP", "1");
        }
        assert!(suppress_peer_direct_udp_from_env(false));
        let relay_only = tailnet_direct_udp_options(
            NodePublic::from_raw([3; 32]),
            DiscoPrivate::generate(&mut rand::rngs::OsRng),
            Vec::new(),
            suppress_peer_direct_udp_from_env(false),
        );
        assert!(!relay_only.peer_direct_udp_enabled);

        unsafe {
            std::env::remove_var("CW_TAILNET_SUPPRESS_PEER_DIRECT_UDP");
        }
    }
}
