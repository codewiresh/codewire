//! Generated Connect-RPC coordinator ownership for the one Rust client core.
//!
//! Both primary and Mesh callers use the audience-owned
//! `codewire.internal.v1` services. This module owns generated stub
//! construction, auth injection, protocol selection, TLS, and retry/setup
//! policy; `codewire-tailnet` remains the packet and node-mechanics crate.

use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use codewire_proto::codewire::internal::v1::{
    CoordinateHello, CoordinatePing, CoordinateProof, CoordinateRequest, CoordinateResponse,
    CoordinateResponseView, CoordinatorServiceClient, MeshCoordinateHello, MeshCoordinateRole,
    MeshCoordinateSubscribe, MeshCoordinatorServiceClient, MeshCoordinatorServiceCoordinateRequest,
    MeshCoordinatorServiceCoordinateResponse, MeshCoordinatorServiceCoordinateResponseView,
    coordinate_response, mesh_coordinator_service_coordinate_request,
    mesh_coordinator_service_coordinate_response,
};
use codewire_tailnet::dns::absolute_dns_name;
use codewire_tailnet::node::Node;
use connectrpc::Protocol;
use connectrpc::client::{
    BidiStream, ClientConfig, ClientTransport, Http2Connection, SharedHttp2Connection,
};
use tokio::sync::mpsc;
use uuid::Uuid;

const COORDINATOR_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const HTTP2_REQUEST_BUFFER: usize = 32;
const MAX_DERP_MAP_BYTES: usize = 256 * 1024;
const MAX_RESOLVED_COORDINATOR_ADDRESSES: usize = 16;
/// Maximum transport and hello-first setup time for a coordinator stream.
pub const COORDINATOR_SETUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Callbacks supplied by the tailnet data-plane owner.
pub struct Handlers<P, D>
where
    P: FnMut(&[Node]),
    D: FnMut(&serde_json::Value),
{
    /// Receives the complete peer snapshot after an update or removal.
    pub on_peers: P,
    /// Receives the opaque Tailscale DERP map.
    pub on_derp_map: D,
}

type CoordinateStream = BidiStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    CoordinateRequest,
    CoordinateResponseView<'static>,
>;

type MeshCoordinateStream = BidiStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    MeshCoordinatorServiceCoordinateRequest,
    MeshCoordinatorServiceCoordinateResponseView<'static>,
>;

fn usable_setup_response(response: CoordinateResponse) -> Option<CoordinateResponse> {
    response.msg.is_some().then_some(response)
}

fn usable_mesh_setup_response(
    response: MeshCoordinatorServiceCoordinateResponse,
) -> Option<MeshCoordinatorServiceCoordinateResponse> {
    response.msg.is_some().then_some(response)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinatorWireProtocol {
    DirectConnect,
    PublicEdgeGrpc,
}

impl CoordinatorWireProtocol {
    fn connectrpc(self) -> Protocol {
        match self {
            Self::DirectConnect => Protocol::Connect,
            Self::PublicEdgeGrpc => Protocol::Grpc,
        }
    }
}

/// How a TLS dial looks up the coordinator URL's host. TLS verification and
/// the HTTP authority use the host as configured either way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostLookup {
    AsConfigured,
    /// As an absolute DNS name, so no resolver search domain is tried
    /// (#2701, see [`codewire_tailnet::dns`]).
    Absolute,
}

impl HostLookup {
    fn name(self, host: &str) -> Cow<'_, str> {
        match self {
            Self::AsConfigured => Cow::Borrowed(host),
            Self::Absolute => absolute_dns_name(host),
        }
    }
}

/// Errors from the Connect coordinator client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The shared token provider could not resolve the current credential.
    #[error("credential: {0}")]
    Credential(#[from] crate::ClientError),
    /// Connect-RPC transport, protocol, or server error.
    #[error("connect: {0}")]
    Connect(#[from] connectrpc::ConnectError),
    /// DERP-map or node JSON conversion error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Malformed or unsupported coordinator URL.
    #[error("invalid url: {0}")]
    Url(String),
    /// Transport setup did not produce a usable coordinator response in time.
    #[error("coordinator setup timed out after {0:?}")]
    SetupTimeout(Duration),
    /// The first usable setup response violated the coordinator contract.
    #[error("coordinator setup response is invalid")]
    InvalidSetupResponse,
    /// A coordinator DERP map exceeded the bounded client contract.
    #[error("coordinator DERP map exceeds its size limit")]
    DerpMapTooLarge,
    /// Configured extra trust roots for the coordinator are unusable.
    #[error("coordinator trust roots are unusable")]
    Trust,
}

impl crate::CodewireClient {
    /// Open the primary coordinator through the public native-gRPC edge.
    pub async fn connect_primary_coordinator(
        &self,
        identity: PrimaryCoordinateIdentity,
    ) -> Result<CoordinatorPeerSession, Error> {
        self.connect_primary_coordinator_with_setup_timeout(identity, COORDINATOR_SETUP_TIMEOUT)
            .await
    }

    /// Open the primary public edge with one explicit setup bound.
    pub async fn connect_primary_coordinator_with_setup_timeout(
        &self,
        identity: PrimaryCoordinateIdentity,
        setup_timeout: Duration,
    ) -> Result<CoordinatorPeerSession, Error> {
        let token = self.bearer_token().await?;
        CoordinatorPeerSession::connect_public_edge_grpc_with_setup_timeout(
            self.config.server_url().as_str(),
            token.expose_secret(),
            identity,
            setup_timeout,
        )
        .await
    }

    /// Open the primary coordinator directly over cluster-local h2c Connect.
    pub async fn connect_primary_coordinator_direct(
        &self,
        identity: PrimaryCoordinateIdentity,
    ) -> Result<CoordinatorPeerSession, Error> {
        self.connect_primary_coordinator_direct_with_setup_timeout(
            identity,
            COORDINATOR_SETUP_TIMEOUT,
        )
        .await
    }

    /// Open the primary cluster-local service with one explicit setup bound.
    pub async fn connect_primary_coordinator_direct_with_setup_timeout(
        &self,
        identity: PrimaryCoordinateIdentity,
        setup_timeout: Duration,
    ) -> Result<CoordinatorPeerSession, Error> {
        let token = self.bearer_token().await?;
        CoordinatorPeerSession::connect_with_setup_timeout(
            self.config.server_url().as_str(),
            token.expose_secret(),
            identity,
            setup_timeout,
        )
        .await
    }

    /// Open the separately deployed Mesh coordinator using the configured
    /// Mesh origin and the shared token provider.
    pub async fn connect_mesh_coordinator(
        &self,
        identity: MeshCoordinateIdentity,
    ) -> Result<MeshCoordinatorPeerSession, Error> {
        self.connect_mesh_coordinator_with_setup_timeout(identity, COORDINATOR_SETUP_TIMEOUT)
            .await
    }

    /// Open the Mesh coordinator with one explicit setup bound.
    ///
    /// Hosted TLS origins use native gRPC; local and cluster-local cleartext
    /// origins use h2c Connect. The generated client owns the RPC path.
    pub async fn connect_mesh_coordinator_with_setup_timeout(
        &self,
        identity: MeshCoordinateIdentity,
        setup_timeout: Duration,
    ) -> Result<MeshCoordinatorPeerSession, Error> {
        let token = self.bearer_token().await?;
        MeshCoordinatorPeerSession::connect_with_setup_timeout(
            self.config.mesh_url().as_str(),
            token.expose_secret(),
            identity,
            setup_timeout,
        )
        .await
    }
}

/// The identity carried in the hello-first Connect stream contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimaryCoordinateIdentity {
    org_id: Option<String>,
    environment_id: Uuid,
}

impl PrimaryCoordinateIdentity {
    /// Identify a user-facing coordinate client in one organization and
    /// environment.
    pub fn client(org_id: impl Into<String>, environment_id: Uuid) -> Self {
        Self {
            org_id: Some(org_id.into()),
            environment_id,
        }
    }

    /// Identify an environment sidecar. Its bearer token carries and is
    /// checked against the same environment id by the server.
    pub fn sidecar(environment_id: Uuid) -> Self {
        Self {
            org_id: None,
            environment_id,
        }
    }

    fn into_hello(self) -> CoordinateHello {
        CoordinateHello {
            org_id: self.org_id.unwrap_or_default(),
            environment_id: self.environment_id.to_string(),
            ..Default::default()
        }
    }
}

/// The identity carried by the hello-first Mesh coordinate contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshCoordinateIdentity {
    org_id: String,
    network_id: String,
    role: MeshCoordinateRole,
}

impl MeshCoordinateIdentity {
    /// Join one Mesh network as a regular peer.
    pub fn peer(org_id: impl Into<String>, network_id: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            network_id: network_id.into(),
            role: MeshCoordinateRole::Peer,
        }
    }

    /// Join one Mesh network as a dial-only subscriber.
    pub fn dial(org_id: impl Into<String>, network_id: impl Into<String>) -> Self {
        Self {
            org_id: org_id.into(),
            network_id: network_id.into(),
            role: MeshCoordinateRole::Dial,
        }
    }

    fn into_hello(self) -> MeshCoordinateHello {
        MeshCoordinateHello {
            org_id: self.org_id,
            network_id: self.network_id,
            role: self.role.into(),
            ..Default::default()
        }
    }
}

/// An async client connected to the coordinator over native Connect bidi.
pub struct CoordinatorPeerSession {
    stream: CoordinateStream,
    peers: BTreeMap<Uuid, Node>,
    pending_responses: VecDeque<CoordinateResponse>,
}

/// Heartbeat observations from the feature-gated disposable KIND smoke.
#[cfg(feature = "kind-e2e")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KindE2eHeartbeatStats {
    /// Typed `CoordinatePing` requests sent as HTTP/2 DATA by the WI-4 client.
    pub sent: usize,
    /// Typed `CoordinatePing` responses received as HTTP/2 DATA from the coordinator.
    pub received: usize,
}

impl CoordinatorPeerSession {
    /// Dial the coordinator and start `Coordinate`, sending `identity` as the
    /// first message before returning.
    ///
    /// `url` is an API/coordinator origin. The generated client owns the RPC
    /// path. `http://` uses prior-knowledge h2c. `https://` uses WebPKI roots
    /// and requires HTTP/2 through TLS ALPN. Both transports send HTTP/2
    /// keepalive PINGs every 15 seconds, including while idle.
    pub async fn connect(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
    ) -> Result<Self, Error> {
        Self::connect_with_setup_timeout(url, bearer_token, identity, COORDINATOR_SETUP_TIMEOUT)
            .await
    }

    /// Connect directly with an explicit setup bound.
    ///
    /// The timer covers the HTTP/2 transport, RPC setup, hello send, and first
    /// usable response. It is discarded before this method returns.
    pub async fn connect_with_setup_timeout(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::DirectConnect,
            None,
            setup_timeout,
            HostLookup::AsConfigured,
        )
        .await
    }

    /// Dial the public coordinator edge with native gRPC.
    ///
    /// The CLI uses this explicit entry point because the public nginx edge
    /// speaks gRPC to the coordinator. Sidecars and direct h2c callers keep
    /// using [`Self::connect`], whose default remains the Connect protocol.
    /// No runtime entry point exposes gRPC-Web.
    pub async fn connect_public_edge_grpc(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
    ) -> Result<Self, Error> {
        Self::connect_public_edge_grpc_with_setup_timeout(
            url,
            bearer_token,
            identity,
            COORDINATOR_SETUP_TIMEOUT,
        )
        .await
    }

    /// Connect to the public gRPC edge with an explicit setup bound.
    pub async fn connect_public_edge_grpc_with_setup_timeout(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::PublicEdgeGrpc,
            None,
            setup_timeout,
            HostLookup::AsConfigured,
        )
        .await
    }

    /// Dial the public coordinator edge from a Sandbox daemon. It trusts the
    /// WebPKI roots plus `extra_roots`, for an edge served by a
    /// deployment-owned authority (a local cluster); no extra root changes
    /// nothing. It looks up the URL's host as an absolute DNS name, so the
    /// Pod resolver's search domains are never tried (#2701); TLS
    /// verification and the HTTP authority keep the host as configured.
    pub async fn connect_public_edge_grpc_absolute(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        extra_roots: Vec<rustls_pki_types::CertificateDer<'static>>,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for root in extra_roots {
            roots.add(root).map_err(|_| Error::Trust)?;
        }
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::PublicEdgeGrpc,
            Some(coordinator_tls_config_with_roots(roots)?),
            setup_timeout,
            HostLookup::Absolute,
        )
        .await
    }

    /// Connect with one explicit trust anchor for the disposable KIND ingress.
    ///
    /// This is unavailable in normal builds: runtime clients continue to use
    /// the fixed WebPKI root set from [`Self::connect`].
    #[cfg(feature = "kind-e2e")]
    pub async fn connect_for_kind_e2e(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        root_certificate_der: Vec<u8>,
    ) -> Result<Self, Error> {
        let tls_config = coordinator_tls_config_with_root(root_certificate_der)?;
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::DirectConnect,
            Some(tls_config),
            COORDINATOR_SETUP_TIMEOUT,
            HostLookup::AsConfigured,
        )
        .await
    }

    /// Connect with native gRPC and one explicit KIND trust anchor.
    ///
    /// This narrow smoke-only entry point proves the coordinator's public
    /// gRPC edge without changing the runtime client's Connect default or
    /// exposing gRPC-Web as a selectable transport.
    #[cfg(feature = "kind-e2e")]
    pub async fn connect_for_kind_e2e_grpc(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        root_certificate_der: Vec<u8>,
    ) -> Result<Self, Error> {
        let tls_config = coordinator_tls_config_with_root(root_certificate_der)?;
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::PublicEdgeGrpc,
            Some(tls_config),
            COORDINATOR_SETUP_TIMEOUT,
            HostLookup::AsConfigured,
        )
        .await
    }

    async fn connect_bounded(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        protocol: CoordinatorWireProtocol,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        setup_timeout: Duration,
        lookup: HostLookup,
    ) -> Result<Self, Error> {
        tokio::time::timeout(
            setup_timeout,
            Self::connect_inner(url, bearer_token, identity, protocol, tls_config, lookup),
        )
        .await
        .map_err(|_| Error::SetupTimeout(setup_timeout))?
    }

    async fn connect_inner(
        url: &str,
        bearer_token: &str,
        identity: PrimaryCoordinateIdentity,
        protocol: CoordinatorWireProtocol,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        lookup: HostLookup,
    ) -> Result<Self, Error> {
        let base_uri = coordinator_origin(url)?;
        let scheme = base_uri
            .scheme_str()
            .ok_or_else(|| Error::Url("coordinator URL must include a scheme".into()))?;

        let connection = match scheme {
            "http" => http2_builder().connect_plaintext(base_uri.clone()).await?,
            "https" => {
                let tls_config = tls_config.unwrap_or(coordinator_tls_config()?);
                http2_builder()
                    .connect_with_connector(
                        tower::service_fn(move |uri| {
                            connect_ring_tls(uri, Arc::clone(&tls_config), lookup)
                        }),
                        base_uri.clone(),
                    )
                    .await?
            }
            other => {
                return Err(Error::Url(format!(
                    "unsupported coordinator URL scheme {other:?}"
                )));
            }
        };

        let mut config = ClientConfig::new(base_uri).with_protocol(protocol.connectrpc());
        if !bearer_token.is_empty() {
            config = config.with_default_header(
                http::header::AUTHORIZATION,
                format!("Bearer {bearer_token}"),
            );
        }
        let client = CoordinatorServiceClient::new(connection.shared(HTTP2_REQUEST_BUFFER), config);
        let mut stream = client.coordinate().await?;
        stream.send(primary_request(identity.into_hello())).await?;
        let first_response = loop {
            let response = stream
                .message::<CoordinateResponse>()
                .await?
                .ok_or_else(|| {
                    connectrpc::ConnectError::unavailable("coordinate stream closed during setup")
                })?
                .to_owned_message();
            if let Some(response) = usable_setup_response(response) {
                break response;
            }
        };

        Ok(Self {
            stream,
            peers: BTreeMap::new(),
            pending_responses: VecDeque::from([first_response]),
        })
    }

    /// Send this client's current node to the coordinator.
    pub async fn update_node(&mut self, node: &Node) -> Result<(), Error> {
        self.stream
            .send(primary_request(node_to_proto(node)?))
            .await?;
        Ok(())
    }

    /// The current known peer set, most recently delivered to `on_peers`.
    pub fn peers(&self) -> Vec<Node> {
        self.peers.values().cloned().collect()
    }

    /// Drive the receive loop until the Connect stream closes.
    pub async fn run<P, D>(&mut self, mut handlers: Handlers<P, D>) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        self.run_inner(None, None, &mut handlers, COORDINATOR_HEARTBEAT_INTERVAL)
            .await
    }

    /// Drive the receive loop while publishing local node updates.
    pub async fn run_with_node_updates<P, D>(
        &mut self,
        node_updates: mpsc::UnboundedReceiver<Node>,
        mut handlers: Handlers<P, D>,
    ) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        self.run_inner(
            Some(node_updates),
            None,
            &mut handlers,
            COORDINATOR_HEARTBEAT_INTERVAL,
        )
        .await
    }

    /// Drive the receive loop while publishing local node updates and
    /// re-proving an environment peer's session in-band: each token received
    /// on `proofs` is sent at once as a `CoordinateProof`. The coordinator
    /// ends a session whose last proven token has lapsed.
    pub async fn run_with_node_updates_and_proofs<P, D>(
        &mut self,
        node_updates: mpsc::UnboundedReceiver<Node>,
        proofs: mpsc::UnboundedReceiver<crate::BearerToken>,
        mut handlers: Handlers<P, D>,
    ) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        self.run_inner(
            Some(node_updates),
            Some(proofs),
            &mut handlers,
            COORDINATOR_HEARTBEAT_INTERVAL,
        )
        .await
    }

    /// The DERP map the coordinator sent while the session was set up, if
    /// its first response was one. It stays queued, so the receive loop still
    /// delivers it to `on_derp_map`.
    pub fn setup_derp_map(&self) -> Option<serde_json::Value> {
        match self.pending_responses.front().map(|response| &response.msg) {
            Some(Some(coordinate_response::Msg::DerpMap(derp))) => {
                decode_derp_map(&derp.derp_map_json).ok()
            }
            _ => None,
        }
    }

    /// Drive the stream for a bounded KIND probe and count typed heartbeats.
    ///
    /// The normal client surface stays unbounded; this hook exists only for
    /// the disposable ingress test so it can prove end-to-end DATA frames,
    /// rather than merely proving that an HTTP connection remained open.
    #[cfg(feature = "kind-e2e")]
    pub async fn run_for_kind_e2e<P, D>(
        &mut self,
        duration: Duration,
        mut handlers: Handlers<P, D>,
    ) -> Result<KindE2eHeartbeatStats, Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        let mut stats = KindE2eHeartbeatStats::default();
        while let Some(response) = self.pending_responses.pop_front() {
            if matches!(response.msg, Some(coordinate_response::Msg::Ping(_))) {
                stats.received += 1;
            }
            handle_response(&mut self.peers, response, &mut handlers)?;
        }

        let deadline = tokio::time::sleep(duration);
        tokio::pin!(deadline);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + COORDINATOR_HEARTBEAT_INTERVAL,
            COORDINATOR_HEARTBEAT_INTERVAL,
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                response = self.stream.message::<CoordinateResponse>() => {
                    let Some(response) = response? else {
                        return Err(connectrpc::ConnectError::unavailable(
                            "coordinate stream closed during KIND probe",
                        ).into());
                    };
                    let response = response.to_owned_message();
                    if matches!(response.msg, Some(coordinate_response::Msg::Ping(_))) {
                        stats.received += 1;
                    }
                    handle_response(&mut self.peers, response, &mut handlers)?;
                }
                _ = heartbeat.tick() => {
                    self.stream.send(primary_request(CoordinatePing::default())).await?;
                    stats.sent += 1;
                }
                () = &mut deadline => return Ok(stats),
            }
        }
    }

    /// Half-close and drain the KIND probe stream to a clean RPC end.
    #[cfg(feature = "kind-e2e")]
    pub async fn finish_for_kind_e2e(&mut self) -> Result<(), Error> {
        self.stream.close_send();
        while self.stream.message::<CoordinateResponse>().await?.is_some() {}
        Ok(())
    }

    async fn run_inner<P, D>(
        &mut self,
        node_updates: Option<mpsc::UnboundedReceiver<Node>>,
        proofs: Option<mpsc::UnboundedReceiver<crate::BearerToken>>,
        handlers: &mut Handlers<P, D>,
        heartbeat_interval: Duration,
    ) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        let mut node_updates = node_updates;
        let mut proofs = proofs;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + heartbeat_interval,
            heartbeat_interval,
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        while let Some(response) = self.pending_responses.pop_front() {
            handle_response(&mut self.peers, response, handlers)?;
        }

        loop {
            tokio::select! {
                biased;
                response = self.stream.message::<CoordinateResponse>() => {
                    let Some(response) = response? else {
                        return Ok(());
                    };
                    handle_response(&mut self.peers, response.to_owned_message(), handlers)?;
                }
                maybe = async {
                    node_updates.as_mut().expect("guarded node update receiver").recv().await
                }, if node_updates.is_some() => {
                    match maybe {
                        Some(node) => self.update_node(&node).await?,
                        None => node_updates = None,
                    }
                }
                maybe = async {
                    proofs.as_mut().expect("guarded proof receiver").recv().await
                }, if proofs.is_some() => {
                    match maybe {
                        Some(token) => {
                            self.stream
                                .send(primary_request(CoordinateProof {
                                    peer_token: token.expose_secret().to_owned(),
                                    ..Default::default()
                                }))
                                .await?;
                        }
                        None => proofs = None,
                    }
                }
                _ = heartbeat.tick() => {
                self.stream.send(primary_request(CoordinatePing::default())).await?;
                }
            }
        }
    }
}

/// A typed non-browser session with the separately deployed Mesh coordinator.
pub struct MeshCoordinatorPeerSession {
    stream: MeshCoordinateStream,
    peers: BTreeMap<Uuid, Node>,
    pending_responses: VecDeque<MeshCoordinatorServiceCoordinateResponse>,
}

impl MeshCoordinatorPeerSession {
    /// Dial the configured Mesh origin and send the required hello first.
    pub async fn connect(
        url: &str,
        bearer_token: &str,
        identity: MeshCoordinateIdentity,
    ) -> Result<Self, Error> {
        Self::connect_with_setup_timeout(url, bearer_token, identity, COORDINATOR_SETUP_TIMEOUT)
            .await
    }

    /// Dial the Mesh coordinator with one explicit transport/setup bound.
    pub async fn connect_with_setup_timeout(
        url: &str,
        bearer_token: &str,
        identity: MeshCoordinateIdentity,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        tokio::time::timeout(
            setup_timeout,
            Self::connect_inner(url, bearer_token, identity, None, None),
        )
        .await
        .map_err(|_| Error::SetupTimeout(setup_timeout))?
    }

    /// Dial a Mesh coordinator using an already-resolved, bounded address set
    /// while retaining the configured URL authority for HTTP and TLS.
    ///
    /// Isolated host transports use this after resolving through their
    /// admitted resolver, so the credential-owning process never falls back to
    /// libc name resolution or a Tokio blocking resolver thread.
    pub async fn connect_resolved_with_setup_timeout(
        url: &str,
        bearer_token: &str,
        identity: MeshCoordinateIdentity,
        addresses: Vec<SocketAddr>,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        let addresses = validated_resolved_addresses(url, addresses)?;
        tokio::time::timeout(
            setup_timeout,
            Self::connect_inner(url, bearer_token, identity, None, Some(addresses)),
        )
        .await
        .map_err(|_| Error::SetupTimeout(setup_timeout))?
    }

    /// Connect to the public Mesh gRPC route with one disposable KIND root.
    #[cfg(feature = "kind-e2e")]
    pub async fn connect_for_kind_e2e_grpc(
        url: &str,
        bearer_token: &str,
        identity: MeshCoordinateIdentity,
        root_certificate_der: Vec<u8>,
    ) -> Result<Self, Error> {
        let tls_config = coordinator_tls_config_with_root(root_certificate_der)?;
        tokio::time::timeout(
            COORDINATOR_SETUP_TIMEOUT,
            Self::connect_inner(url, bearer_token, identity, Some(tls_config), None),
        )
        .await
        .map_err(|_| Error::SetupTimeout(COORDINATOR_SETUP_TIMEOUT))?
    }

    async fn connect_inner(
        url: &str,
        bearer_token: &str,
        identity: MeshCoordinateIdentity,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        resolved_addresses: Option<Arc<[SocketAddr]>>,
    ) -> Result<Self, Error> {
        let base_uri = coordinator_origin(url)?;
        let scheme = base_uri
            .scheme_str()
            .ok_or_else(|| Error::Url("Mesh coordinator URL must include a scheme".into()))?;

        let (connection, protocol) = match scheme {
            "http" => (
                match resolved_addresses.clone() {
                    Some(addresses) => {
                        http2_builder()
                            .connect_with_connector(
                                tower::service_fn(move |uri| {
                                    connect_resolved_plain(uri, Arc::clone(&addresses))
                                }),
                                base_uri.clone(),
                            )
                            .await?
                    }
                    None => http2_builder().connect_plaintext(base_uri.clone()).await?,
                },
                Protocol::Connect,
            ),
            "https" => (
                {
                    let tls_config = match tls_config {
                        Some(tls_config) => tls_config,
                        None => coordinator_tls_config()?,
                    };
                    match resolved_addresses {
                        Some(addresses) => {
                            http2_builder()
                                .connect_with_connector(
                                    tower::service_fn(move |uri| {
                                        connect_ring_tls_resolved(
                                            uri,
                                            Arc::clone(&tls_config),
                                            Arc::clone(&addresses),
                                        )
                                    }),
                                    base_uri.clone(),
                                )
                                .await?
                        }
                        None => {
                            http2_builder()
                                .connect_with_connector(
                                    tower::service_fn(move |uri| {
                                        connect_ring_tls(
                                            uri,
                                            Arc::clone(&tls_config),
                                            HostLookup::AsConfigured,
                                        )
                                    }),
                                    base_uri.clone(),
                                )
                                .await?
                        }
                    }
                },
                Protocol::Grpc,
            ),
            other => {
                return Err(Error::Url(format!(
                    "unsupported Mesh coordinator URL scheme {other:?}"
                )));
            }
        };

        let mut config = ClientConfig::new(base_uri).with_protocol(protocol);
        if !bearer_token.is_empty() {
            config = config.with_default_header(
                http::header::AUTHORIZATION,
                format!("Bearer {bearer_token}"),
            );
        }
        let client =
            MeshCoordinatorServiceClient::new(connection.shared(HTTP2_REQUEST_BUFFER), config);
        let mut stream = client.coordinate().await?;
        stream.send(mesh_request(identity.into_hello())).await?;
        let first_response = loop {
            let response = stream
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await?
                .ok_or_else(|| {
                    connectrpc::ConnectError::unavailable(
                        "Mesh coordinate stream closed during setup",
                    )
                })?
                .to_owned_message();
            if let Some(response) = usable_mesh_setup_response(response) {
                break response;
            }
        };

        Ok(Self {
            stream,
            peers: BTreeMap::new(),
            pending_responses: VecDeque::from([first_response]),
        })
    }

    /// Publish this peer's current node.
    pub async fn update_node(&mut self, node: &Node) -> Result<(), Error> {
        self.stream.send(mesh_request(node_to_proto(node)?)).await?;
        Ok(())
    }

    /// Consume the DERP map received while establishing this exact session.
    ///
    /// Enrollment credentials are one-use, so a peer must build its transport
    /// from this setup response instead of opening a second coordinator
    /// connection merely to discover relay configuration.
    pub fn take_setup_derp_map(&mut self) -> Result<serde_json::Value, Error> {
        take_mesh_setup_derp_map(&mut self.pending_responses)
    }

    /// Subscribe a dial-only session to one target node.
    pub async fn subscribe(&mut self, target_node: impl Into<String>) -> Result<(), Error> {
        self.stream
            .send(mesh_request(MeshCoordinateSubscribe {
                target_node: target_node.into(),
                ..Default::default()
            }))
            .await?;
        Ok(())
    }

    /// The current known Mesh peer set.
    pub fn peers(&self) -> Vec<Node> {
        self.peers.values().cloned().collect()
    }

    /// Drive the Mesh receive loop until the stream closes.
    pub async fn run<P, D>(&mut self, mut handlers: Handlers<P, D>) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        self.run_inner(None, &mut handlers).await
    }

    /// Drive the Mesh receive loop while publishing local node updates.
    pub async fn run_with_node_updates<P, D>(
        &mut self,
        node_updates: mpsc::UnboundedReceiver<Node>,
        mut handlers: Handlers<P, D>,
    ) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        self.run_inner(Some(node_updates), &mut handlers).await
    }

    /// Drive a bounded disposable KIND Mesh probe.
    #[cfg(feature = "kind-e2e")]
    pub async fn run_for_kind_e2e<P, D>(
        &mut self,
        duration: Duration,
        mut handlers: Handlers<P, D>,
    ) -> Result<KindE2eHeartbeatStats, Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        let mut stats = KindE2eHeartbeatStats::default();
        while let Some(response) = self.pending_responses.pop_front() {
            let response = mesh_response_to_primary(response);
            if matches!(response.msg, Some(coordinate_response::Msg::Ping(_))) {
                stats.received += 1;
            }
            handle_response(&mut self.peers, response, &mut handlers)?;
        }

        let deadline = tokio::time::sleep(duration);
        tokio::pin!(deadline);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + COORDINATOR_HEARTBEAT_INTERVAL,
            COORDINATOR_HEARTBEAT_INTERVAL,
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                response = self.stream.message::<MeshCoordinatorServiceCoordinateResponse>() => {
                    let Some(response) = response? else {
                        return Err(connectrpc::ConnectError::unavailable(
                            "Mesh coordinate stream closed during KIND probe",
                        ).into());
                    };
                    let response =
                        mesh_response_to_primary(response.to_owned_message());
                    if matches!(response.msg, Some(coordinate_response::Msg::Ping(_))) {
                        stats.received += 1;
                    }
                    handle_response(&mut self.peers, response, &mut handlers)?;
                }
                _ = heartbeat.tick() => {
                    self.stream.send(mesh_request(CoordinatePing::default())).await?;
                    stats.sent += 1;
                }
                () = &mut deadline => return Ok(stats),
            }
        }
    }

    /// Half-close and drain a disposable KIND Mesh stream.
    #[cfg(feature = "kind-e2e")]
    pub async fn finish_for_kind_e2e(&mut self) -> Result<(), Error> {
        self.stream.close_send();
        while self
            .stream
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await?
            .is_some()
        {}
        Ok(())
    }

    async fn run_inner<P, D>(
        &mut self,
        node_updates: Option<mpsc::UnboundedReceiver<Node>>,
        handlers: &mut Handlers<P, D>,
    ) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        let mut node_updates = node_updates;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + COORDINATOR_HEARTBEAT_INTERVAL,
            COORDINATOR_HEARTBEAT_INTERVAL,
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        while let Some(response) = self.pending_responses.pop_front() {
            handle_response(
                &mut self.peers,
                mesh_response_to_primary(response),
                handlers,
            )?;
        }

        loop {
            tokio::select! {
                biased;
                response = self.stream.message::<MeshCoordinatorServiceCoordinateResponse>() => {
                    let Some(response) = response? else {
                        return Ok(());
                    };
                    handle_response(
                        &mut self.peers,
                        mesh_response_to_primary(response.to_owned_message()),
                        handlers,
                    )?;
                }
                maybe = async {
                    node_updates.as_mut().expect("guarded node update receiver").recv().await
                }, if node_updates.is_some() => {
                    match maybe {
                        Some(node) => self.update_node(&node).await?,
                        None => node_updates = None,
                    }
                }
                _ = heartbeat.tick() => {
                    self.stream.send(mesh_request(CoordinatePing::default())).await?;
                }
            }
        }
    }
}

fn take_mesh_setup_derp_map(
    pending: &mut VecDeque<MeshCoordinatorServiceCoordinateResponse>,
) -> Result<serde_json::Value, Error> {
    let response = pending.pop_front().ok_or(Error::InvalidSetupResponse)?;
    let Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(derp)) = response.msg
    else {
        pending.push_front(response);
        return Err(Error::InvalidSetupResponse);
    };
    decode_derp_map(&derp.derp_map_json)
}

fn decode_derp_map(bytes: &[u8]) -> Result<serde_json::Value, Error> {
    if bytes.len() > MAX_DERP_MAP_BYTES {
        return Err(Error::DerpMapTooLarge);
    }
    serde_json::from_slice(bytes).map_err(Error::from)
}

fn coordinator_tls_config() -> Result<Arc<rustls::ClientConfig>, Error> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    coordinator_tls_config_with_roots(roots)
}

#[cfg(feature = "kind-e2e")]
fn coordinator_tls_config_with_root(
    root_certificate_der: Vec<u8>,
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(root_certificate_der))
        .map_err(|error| Error::Url(format!("invalid KIND root certificate: {error}")))?;
    coordinator_tls_config_with_roots(roots)
}

fn coordinator_tls_config_with_roots(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, Error> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| Error::Url(format!("unsupported TLS protocol configuration: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

async fn connect_ring_tls(
    uri: http::Uri,
    config: Arc<rustls::ClientConfig>,
    lookup: HostLookup,
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS URI has no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let tcp = tokio::net::TcpStream::connect((lookup.name(&host).as_ref(), port)).await?;
    // The server name comes from the URI, never from the looked-up name.
    finish_ring_tls(&uri, config, tcp).await
}

async fn connect_resolved_plain(
    uri: http::Uri,
    addresses: Arc<[SocketAddr]>,
) -> Result<hyper_util::rt::TokioIo<tokio::net::TcpStream>, io::Error> {
    ensure_resolved_connector_port(&uri, &addresses)?;
    connect_resolved_tcp(&addresses)
        .await
        .map(hyper_util::rt::TokioIo::new)
}

async fn connect_ring_tls_resolved(
    uri: http::Uri,
    config: Arc<rustls::ClientConfig>,
    addresses: Arc<[SocketAddr]>,
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    ensure_resolved_connector_port(&uri, &addresses)?;
    let tcp = connect_resolved_tcp(&addresses).await?;
    finish_ring_tls(&uri, config, tcp).await
}

async fn finish_ring_tls(
    uri: &http::Uri,
    config: Arc<rustls::ClientConfig>,
    tcp: tokio::net::TcpStream,
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS URI has no host"))?
        .to_owned();
    let server_name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS URI host is not a DNS name",
        )
    })?;
    tcp.set_nodelay(true)?;
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .map_err(io::Error::other)?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(io::Error::other(
            "coordinator TLS peer did not negotiate HTTP/2",
        ));
    }
    Ok(hyper_util::rt::TokioIo::new(tls))
}

async fn connect_resolved_tcp(addresses: &[SocketAddr]) -> io::Result<tokio::net::TcpStream> {
    let mut last_error = None;
    for address in addresses {
        match tokio::net::TcpStream::connect(*address).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolved coordinator address set is empty",
        )
    }))
}

fn validated_resolved_addresses(
    url: &str,
    addresses: Vec<SocketAddr>,
) -> Result<Arc<[SocketAddr]>, Error> {
    let uri = coordinator_origin(url)?;
    let port = coordinator_port(&uri)?;
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_COORDINATOR_ADDRESSES {
        return Err(Error::Url(
            "resolved coordinator address set is empty or exceeds its limit".into(),
        ));
    }
    if addresses.iter().any(|address| {
        address.port() != port || address.ip().is_unspecified() || address.ip().is_multicast()
    }) {
        return Err(Error::Url(
            "resolved coordinator address does not match the configured authority".into(),
        ));
    }
    let mut addresses = addresses;
    addresses.sort_unstable();
    addresses.dedup();
    Ok(Arc::from(addresses))
}

fn ensure_resolved_connector_port(uri: &http::Uri, addresses: &[SocketAddr]) -> io::Result<()> {
    let port = coordinator_port(uri).map_err(io::Error::other)?;
    if addresses.is_empty() || addresses.iter().any(|address| address.port() != port) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolved coordinator address port mismatch",
        ));
    }
    Ok(())
}

fn coordinator_port(uri: &http::Uri) -> Result<u16, Error> {
    uri.port_u16()
        .or_else(|| match uri.scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        })
        .ok_or_else(|| Error::Url("coordinator URL has no supported port".into()))
}

fn handle_response<P, D>(
    peers: &mut BTreeMap<Uuid, Node>,
    response: CoordinateResponse,
    handlers: &mut Handlers<P, D>,
) -> Result<(), Error>
where
    P: FnMut(&[Node]),
    D: FnMut(&serde_json::Value),
{
    match response.msg {
        Some(coordinate_response::Msg::PeerUpdate(update)) => {
            let nodes = update
                .nodes
                .into_iter()
                .map(proto_to_node)
                .collect::<Result<Vec<_>, _>>();
            let Ok(nodes) = nodes else {
                return Ok(());
            };
            for node in nodes {
                peers.insert(node.id, node);
            }
            let snapshot = peers.values().cloned().collect::<Vec<_>>();
            (handlers.on_peers)(&snapshot);
        }
        Some(coordinate_response::Msg::PeerRemove(remove)) => {
            let Ok(peer_id) = Uuid::parse_str(&remove.peer_id) else {
                return Ok(());
            };
            peers.remove(&peer_id);
            let snapshot = peers.values().cloned().collect::<Vec<_>>();
            (handlers.on_peers)(&snapshot);
        }
        Some(coordinate_response::Msg::DerpMap(derp)) => {
            let map = decode_derp_map(&derp.derp_map_json)?;
            (handlers.on_derp_map)(&map);
        }
        Some(coordinate_response::Msg::Ping(_)) | None => {}
    }
    Ok(())
}

fn coordinator_origin(url: &str) -> Result<http::Uri, Error> {
    let parsed = url
        .parse::<http::Uri>()
        .map_err(|error| Error::Url(error.to_string()))?;
    let scheme = parsed
        .scheme_str()
        .ok_or_else(|| Error::Url("coordinator URL must include a scheme".into()))?;
    let authority = parsed
        .authority()
        .ok_or_else(|| Error::Url("coordinator URL must include an authority".into()))?;
    format!("{scheme}://{authority}")
        .parse()
        .map_err(|error: http::uri::InvalidUri| Error::Url(error.to_string()))
}

fn http2_builder() -> connectrpc::client::Http2ConnectionBuilder {
    Http2Connection::builder()
        .keep_alive_interval(COORDINATOR_HEARTBEAT_INTERVAL)
        .keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
}

fn primary_request(
    message: impl Into<Option<codewire_proto::codewire::internal::v1::coordinate_request::Msg>>,
) -> CoordinateRequest {
    CoordinateRequest {
        msg: message.into(),
        ..Default::default()
    }
}

fn mesh_request(
    message: impl Into<Option<mesh_coordinator_service_coordinate_request::Msg>>,
) -> MeshCoordinatorServiceCoordinateRequest {
    MeshCoordinatorServiceCoordinateRequest {
        msg: message.into(),
        ..Default::default()
    }
}

fn mesh_response_to_primary(
    response: MeshCoordinatorServiceCoordinateResponse,
) -> CoordinateResponse {
    let msg = match response.msg {
        Some(mesh_coordinator_service_coordinate_response::Msg::PeerUpdate(update)) => {
            coordinate_response::Msg::PeerUpdate(update)
        }
        Some(mesh_coordinator_service_coordinate_response::Msg::PeerRemove(remove)) => {
            coordinate_response::Msg::PeerRemove(remove)
        }
        Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(derp)) => {
            coordinate_response::Msg::DerpMap(derp)
        }
        Some(mesh_coordinator_service_coordinate_response::Msg::Ping(ping)) => {
            coordinate_response::Msg::Ping(ping)
        }
        None => {
            return CoordinateResponse::default();
        }
    };
    CoordinateResponse {
        msg: Some(msg),
        ..Default::default()
    }
}
fn node_to_proto(
    node: &Node,
) -> Result<codewire_proto::codewire::internal::v1::CoordinateNode, serde_json::Error> {
    Ok(codewire_proto::codewire::internal::v1::CoordinateNode {
        id: node.id.to_string(),
        as_of: Some(buffa_types::Timestamp {
            seconds: node.as_of.timestamp(),
            nanos: node.as_of.timestamp_subsec_nanos() as i32,
            ..Default::default()
        })
        .into(),
        key: json_wire_string(&node.key)?,
        disco_key: json_wire_string(&node.disco_key)?,
        preferred_derp: node.preferred_derp,
        derp_latency: node
            .derp_latency
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        endpoints: node
            .endpoints
            .iter()
            .map(|endpoint| endpoint.0.to_string())
            .collect(),
        addresses: node.addresses.iter().map(ToString::to_string).collect(),
        ..Default::default()
    })
}

fn proto_to_node(
    node: codewire_proto::codewire::internal::v1::CoordinateNode,
) -> Result<Node, serde_json::Error> {
    let timestamp = node
        .as_of
        .as_option()
        .ok_or_else(|| node_conversion_error("coordinate node omitted as_of"))?;
    let nanos = u32::try_from(timestamp.nanos)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)
        .ok_or_else(|| node_conversion_error("coordinate node has invalid timestamp nanos"))?;
    let as_of = chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp.seconds, nanos)
        .ok_or_else(|| node_conversion_error("coordinate node has invalid timestamp"))?;

    Ok(Node {
        id: Uuid::parse_str(&node.id)
            .map_err(|_| node_conversion_error("coordinate node has invalid id"))?,
        as_of,
        key: json_wire_value(node.key)?,
        disco_key: json_wire_value(node.disco_key)?,
        preferred_derp: node.preferred_derp,
        derp_latency: (!node.derp_latency.is_empty())
            .then(|| node.derp_latency.into_iter().collect()),
        endpoints: node
            .endpoints
            .into_iter()
            .map(json_wire_value)
            .collect::<Result<_, _>>()?,
        addresses: node
            .addresses
            .into_iter()
            .map(json_wire_value)
            .collect::<Result<_, _>>()?,
    })
}

fn json_wire_string<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| node_conversion_error("tailnet wire value is not a string"))
}

fn json_wire_value<T: serde::de::DeserializeOwned>(value: String) -> Result<T, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(value))
}

fn node_conversion_error(message: &'static str) -> serde_json::Error {
    serde_json::Error::io(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::codewire::internal::v1::{
        CoordinateDerpMap, CoordinatePeerRemove, CoordinatePeerUpdate,
    };
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use std::future::Future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_WALL_BOUND: Duration = Duration::from_secs(10);

    async fn test_bounded<F>(label: &str, future: F) -> F::Output
    where
        F: Future,
    {
        tokio::time::timeout(TEST_WALL_BOUND, future)
            .await
            .unwrap_or_else(|_| panic!("{label} exceeded the {TEST_WALL_BOUND:?} test bound"))
    }

    fn sample_node(id: Uuid, derp: i32) -> Node {
        Node {
            id,
            as_of: "2026-07-12T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x11; 32]),
            disco_key: DiscoPublic::from_raw([0x22; 32]),
            preferred_derp: derp,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&id)],
        }
    }

    #[test]
    fn coordinator_origin_accepts_service_origins() {
        assert_eq!(
            coordinator_origin("http://coordinator:8090").unwrap(),
            "http://coordinator:8090/".parse::<http::Uri>().unwrap()
        );
        assert_eq!(
            coordinator_origin("https://api.example.invalid").unwrap(),
            "https://api.example.invalid/".parse::<http::Uri>().unwrap()
        );
    }

    #[test]
    fn resolved_coordinator_addresses_are_authority_bound_and_bounded() {
        let addresses = validated_resolved_addresses(
            "https://mesh.example.com:8443/path",
            vec![
                "[2001:db8::1]:8443".parse().unwrap(),
                "192.0.2.10:8443".parse().unwrap(),
                "192.0.2.10:8443".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(
            validated_resolved_addresses(
                "https://mesh.example.com:8443",
                vec!["192.0.2.10:443".parse().unwrap()]
            )
            .is_err()
        );
        assert!(
            validated_resolved_addresses(
                "https://mesh.example.com",
                vec!["0.0.0.0:443".parse().unwrap()]
            )
            .is_err()
        );
        assert!(validated_resolved_addresses("https://mesh.example.com", Vec::new()).is_err());
    }

    // The setup deadline runs on a controlled clock. It starts when the
    // client starts dialing, so on a wall clock a loaded host could spend
    // the whole second before the HTTP/2 exchange this test is about. A
    // pending blocking task holds the paused clock still while the real
    // loopback exchange happens; once the peer has acknowledged SETTINGS it
    // is released, and the idle runtime advances straight to the deadline.
    #[tokio::test(start_paused = true)]
    async fn setup_times_out_after_http2_accepts_but_never_responds() {
        let listener = test_bounded(
            "HTTP/2 listener bind",
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_clock, clock_held) = std::sync::mpsc::channel::<()>();
        // Waits on the real clock: if the exchange never happens, the clock
        // moves again after the same test bound and the test fails, not hangs.
        let clock_hold = tokio::task::spawn_blocking(move || {
            let _ = clock_held.recv_timeout(TEST_WALL_BOUND);
        });
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(test_bounded("HTTP/2 peer task", async move {
            ready_tx.send(()).expect("HTTP/2 test remains active");
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut preface = [0_u8; 24];
            socket.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

            let mut header = [0_u8; 9];
            socket.read_exact(&mut header).await.unwrap();
            let payload_len =
                usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
            assert_eq!(header[3], 4, "first client frame must be SETTINGS");
            assert_eq!(&header[5..], &[0, 0, 0, 0], "SETTINGS uses stream zero");
            let mut payload = vec![0_u8; payload_len];
            socket.read_exact(&mut payload).await.unwrap();

            // Complete the HTTP/2 settings exchange, then deliberately never
            // send response headers or DATA for Coordinate.
            socket
                .write_all(&[
                    0, 0, 0, 4, 0, 0, 0, 0, 0, // server SETTINGS
                    0, 0, 0, 4, 1, 0, 0, 0, 0, // ACK client SETTINGS
                ])
                .await
                .unwrap();
            let _ = accepted_tx.send(());
            std::future::pending::<()>().await;
        }));

        test_bounded("HTTP/2 peer readiness", ready_rx)
            .await
            .expect("HTTP/2 peer reports readiness");
        let setup_timeout = Duration::from_secs(1);
        let url = format!("http://{addr}");
        let client = tokio::spawn(async move {
            CoordinatorPeerSession::connect_with_setup_timeout(
                &url,
                "",
                PrimaryCoordinateIdentity::sidecar(Uuid::new_v4()),
                setup_timeout,
            )
            .await
        });
        test_bounded("HTTP/2 SETTINGS exchange", accepted_rx)
            .await
            .expect("HTTP/2 peer accepted the connection");
        release_clock.send(()).expect("clock hold remains active");
        clock_hold.await.expect("clock hold ends");
        let error = test_bounded("stalled Coordinate setup", client)
            .await
            .expect("coordinator setup task remains joinable")
            .err()
            .expect("stalled Coordinate setup must fail");
        assert!(matches!(error, Error::SetupTimeout(value) if value == setup_timeout));
        server.abort();
        let join_error = test_bounded("HTTP/2 peer cancellation", server)
            .await
            .expect_err("stalled HTTP/2 peer is cancelled");
        assert!(join_error.is_cancelled());
    }

    #[tokio::test]
    async fn setup_skips_empty_response_until_typed_variant() {
        let mut responses = VecDeque::from([
            CoordinateResponse::default(),
            CoordinateResponse {
                msg: CoordinatePing::default().into(),
                ..Default::default()
            },
        ]);

        let response = loop {
            let candidate = responses.pop_front().unwrap();
            if let Some(response) = usable_setup_response(candidate) {
                break response;
            }
        };
        assert!(matches!(
            response.msg,
            Some(coordinate_response::Msg::Ping(_))
        ));
        assert!(responses.is_empty());
    }

    #[test]
    fn runtime_protocol_choices_keep_direct_connect_and_public_edge_grpc_narrow() {
        assert_eq!(
            CoordinatorWireProtocol::DirectConnect.connectrpc(),
            Protocol::Connect
        );
        assert_eq!(
            CoordinatorWireProtocol::PublicEdgeGrpc.connectrpc(),
            Protocol::Grpc
        );
    }

    #[test]
    fn only_the_sandbox_dial_looks_up_the_coordinator_as_an_absolute_name() {
        let host = "ingress-nginx-controller.ingress-nginx.svc.cluster.local";
        assert_eq!(
            HostLookup::Absolute.name(host),
            "ingress-nginx-controller.ingress-nginx.svc.cluster.local."
        );
        assert_eq!(HostLookup::AsConfigured.name(host), host);
        assert_eq!(HostLookup::Absolute.name("localhost"), "localhost");
    }

    #[test]
    fn mesh_setup_derp_map_is_consumed_from_the_live_session_only() {
        let expected = serde_json::json!({"Regions": {"1": {"RegionID": 1}}});
        let mut pending = VecDeque::from([MeshCoordinatorServiceCoordinateResponse {
            msg: CoordinateDerpMap {
                derp_map_json: serde_json::to_vec(&expected).unwrap(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }]);
        assert_eq!(take_mesh_setup_derp_map(&mut pending).unwrap(), expected);
        assert!(pending.is_empty());

        let first = MeshCoordinatorServiceCoordinateResponse {
            msg: CoordinatePing::default().into(),
            ..Default::default()
        };
        let mut pending = VecDeque::from([first.clone()]);
        assert!(matches!(
            take_mesh_setup_derp_map(&mut pending),
            Err(Error::InvalidSetupResponse)
        ));
        assert_eq!(pending.pop_front(), Some(first));

        assert!(matches!(
            decode_derp_map(&vec![b' '; MAX_DERP_MAP_BYTES + 1]),
            Err(Error::DerpMapTooLarge)
        ));
    }

    #[test]
    fn hello_identity_preserves_client_and_sidecar_addressing() {
        let environment_id = Uuid::new_v4();
        let client = PrimaryCoordinateIdentity::client("org-1", environment_id).into_hello();
        assert_eq!(client.org_id, "org-1");
        assert_eq!(client.environment_id, environment_id.to_string());

        let sidecar = PrimaryCoordinateIdentity::sidecar(environment_id).into_hello();
        assert!(sidecar.org_id.is_empty());
        assert_eq!(sidecar.environment_id, environment_id.to_string());
    }

    #[test]
    fn node_proto_boundary_round_trips() {
        let node = sample_node(Uuid::new_v4(), 7);
        let roundtrip = proto_to_node(node_to_proto(&node).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(roundtrip).unwrap(),
            serde_json::to_value(node).unwrap()
        );
    }

    // Full response-loop behavior is exercised against the real WI-3 server
    // from codewire-coordinator's hermetic tests. Keep the skip-unknown rule
    // pinned here because protobuf can preserve an unknown future oneof as no
    // currently-known variant.
    #[test]
    fn future_unknown_response_variant_is_ignored() {
        let mut peers = BTreeMap::new();
        let mut peer_calls = 0;
        let mut derp_calls = 0;
        handle_response(
            &mut peers,
            CoordinateResponse::default(),
            &mut Handlers {
                on_peers: |_: &[Node]| peer_calls += 1,
                on_derp_map: |_: &serde_json::Value| derp_calls += 1,
            },
        )
        .unwrap();
        assert_eq!(peer_calls, 0);
        assert_eq!(derp_calls, 0);

        let peer = sample_node(Uuid::new_v4(), 7);
        let update = CoordinateResponse {
            msg: CoordinatePeerUpdate {
                nodes: vec![node_to_proto(&peer).unwrap()],
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        assert!(matches!(
            update.msg,
            Some(coordinate_response::Msg::PeerUpdate(_))
        ));

        let remove = CoordinateResponse {
            msg: CoordinatePeerRemove {
                peer_id: peer.id.to_string(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        assert!(matches!(
            remove.msg,
            Some(coordinate_response::Msg::PeerRemove(_))
        ));
    }
}
