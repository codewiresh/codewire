use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
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
use codewire_workspace_access::peer_relay::{
    PEER_RELAY_ALLOCATION_ATTEMPT_TIMEOUT, PeerRelayAllocator, PeerRelayBackend,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::lookup_host;
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::config::{GatewayConfig, StunConfig, TailnetConfig};

const COORDINATOR_RETRY_DELAY: Duration = Duration::from_secs(5);

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
                Arc::new(HttpPeerRelayBackend::new(
                    url.clone(),
                    config.udp_relay_allocator_token.clone(),
                )),
                "rust gateway",
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

/// The gateway's allocation path: the internal allocator, with the global
/// allocator token.
struct HttpPeerRelayBackend {
    client: reqwest::Client,
    url: Arc<str>,
    token: Option<Arc<str>>,
}

impl HttpPeerRelayBackend {
    fn new(url: String, token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: Arc::from(url),
            token: token.map(Arc::from),
        }
    }
}

#[async_trait]
impl PeerRelayBackend for HttpPeerRelayBackend {
    async fn allocate(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Result<UDPRelayEndpoint> {
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
        response
            .endpoint
            .try_into_endpoint()
            .context("decode UDP peer relay endpoint")
    }
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
            ssh_listen_addr: "127.0.0.1:2222".into(),
            readyz_listen_addr: "127.0.0.1:2223".into(),
            host_key_path: "/tmp/key".into(),
            listener_self_check_interval: None,
            api_url: api_url.map(str::to_string),
            binding_url: None,
            binding_tls_roots_file: None,
            coordinator_url: Some(coordinator_url.into()),
            daemon_auth_token: Some(DaemonAuthToken::new("gateway-tailnet-test-token").unwrap()),
            derp_url: derp_url.map(str::to_string),
            stun: None,
            stun_servers: Vec::new(),
            tailnet_udp_listen_addr: None,
            tailnet_direct_udp_advertise_endpoints: Vec::new(),
            udp_relay_allocator_url: None,
            udp_relay_allocator_token: None,
            udp_relay_bind_addrs: Vec::new(),
            tailnet: Some(tailnet),
            credentials: None,
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
