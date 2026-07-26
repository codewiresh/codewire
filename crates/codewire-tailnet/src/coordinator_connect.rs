//! Native Connect-RPC flavor of the coordinator client.
//!
//! This client mirrors [`crate::coordinator::CoordinatorClient`]'s functional
//! surface while using the typed `coordinator.v1.CoordinatorService/Coordinate`
//! bidi stream. It sends the required [`HelloIdentity`] first, then carries
//! node updates, peer updates/removals, DERP-map callbacks, and typed 15-second
//! heartbeats over one HTTP/2 stream.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use codewire_proto::coordinator::v1::{
    coordinate_response, CoordinateRequest, CoordinateResponse, CoordinateResponseView,
    CoordinatorServiceClient, Hello, Ping,
};
use connectrpc::client::{
    BidiStream, ClientConfig, ClientTransport, Http2Connection, SharedHttp2Connection,
};
use connectrpc::Protocol;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::coordinator::{Handlers, COORDINATOR_SETUP_TIMEOUT};
use crate::node::Node;

const COORDINATOR_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const HTTP2_REQUEST_BUFFER: usize = 32;

type CoordinateStream = BidiStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    CoordinateRequest,
    CoordinateResponseView<'static>,
>;

fn usable_setup_response(response: CoordinateResponse) -> Option<CoordinateResponse> {
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

/// Errors from the Connect coordinator client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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
}

/// The identity carried in the hello-first Connect stream contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelloIdentity {
    org_id: Option<String>,
    environment_id: Uuid,
}

impl HelloIdentity {
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

    fn into_hello(self) -> Hello {
        Hello {
            org_id: self.org_id.unwrap_or_default(),
            environment_id: self.environment_id.to_string(),
            ..Default::default()
        }
    }
}

/// An async client connected to the coordinator over native Connect bidi.
pub struct CoordinatorConnectClient {
    stream: CoordinateStream,
    peers: BTreeMap<Uuid, Node>,
    pending_responses: VecDeque<CoordinateResponse>,
}

/// Heartbeat observations from the feature-gated disposable KIND smoke.
#[cfg(feature = "kind-e2e")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KindE2eHeartbeatStats {
    /// Typed `Ping` requests sent as HTTP/2 DATA by the WI-4 client.
    pub sent: usize,
    /// Typed `Ping` responses received as HTTP/2 DATA from the coordinator.
    pub received: usize,
}

impl CoordinatorConnectClient {
    /// Dial the coordinator and start `Coordinate`, sending `identity` as the
    /// first message before returning.
    ///
    /// `url` may be an API/coordinator origin or an existing coordinate URL;
    /// only its scheme and authority are used because the generated client
    /// owns the RPC path. `http://` uses prior-knowledge h2c. `https://` uses
    /// WebPKI roots and requires HTTP/2 through TLS ALPN. Both transports send
    /// HTTP/2 keepalive PINGs every 15 seconds, including while idle.
    pub async fn connect(
        url: &str,
        bearer_token: &str,
        identity: HelloIdentity,
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
        identity: HelloIdentity,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::DirectConnect,
            None,
            setup_timeout,
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
        identity: HelloIdentity,
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
        identity: HelloIdentity,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::connect_bounded(
            url,
            bearer_token,
            identity,
            CoordinatorWireProtocol::PublicEdgeGrpc,
            None,
            setup_timeout,
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
        identity: HelloIdentity,
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
        identity: HelloIdentity,
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
        )
        .await
    }

    async fn connect_bounded(
        url: &str,
        bearer_token: &str,
        identity: HelloIdentity,
        protocol: CoordinatorWireProtocol,
        tls_config: Option<Arc<rustls::ClientConfig>>,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        tokio::time::timeout(
            setup_timeout,
            Self::connect_inner(url, bearer_token, identity, protocol, tls_config),
        )
        .await
        .map_err(|_| Error::SetupTimeout(setup_timeout))?
    }

    async fn connect_inner(
        url: &str,
        bearer_token: &str,
        identity: HelloIdentity,
        protocol: CoordinatorWireProtocol,
        tls_config: Option<Arc<rustls::ClientConfig>>,
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
                            connect_ring_tls(uri, Arc::clone(&tls_config))
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
        stream.send(request(identity.into_hello())).await?;
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
        self.stream.send(request(node_to_proto(node)?)).await?;
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
        self.run_inner(None, &mut handlers, COORDINATOR_HEARTBEAT_INTERVAL)
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
            &mut handlers,
            COORDINATOR_HEARTBEAT_INTERVAL,
        )
        .await
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
                    self.stream.send(request(Ping::default())).await?;
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
        handlers: &mut Handlers<P, D>,
        heartbeat_interval: Duration,
    ) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        let mut node_updates = node_updates;
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
                _ = heartbeat.tick() => {
                self.stream.send(request(Ping::default())).await?;
                }
            }
        }
    }
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
) -> Result<
    hyper_util::rt::TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    io::Error,
> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS URI has no host"))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let server_name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS URI host is not a DNS name",
        )
    })?;
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
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
            let map = serde_json::from_slice(&derp.derp_map_json)?;
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

fn request(
    message: impl Into<Option<codewire_proto::coordinator::v1::coordinate_request::Msg>>,
) -> CoordinateRequest {
    CoordinateRequest {
        msg: message.into(),
        ..Default::default()
    }
}

fn node_to_proto(node: &Node) -> Result<codewire_proto::coordinator::v1::Node, serde_json::Error> {
    serde_json::from_value(serde_json::to_value(node)?)
}

fn proto_to_node(node: codewire_proto::coordinator::v1::Node) -> Result<Node, serde_json::Error> {
    let mut value = serde_json::to_value(node)?;
    let Some(object) = value.as_object_mut() else {
        return serde_json::from_value(value);
    };
    for (proto, tailnet) in [
        ("asOf", "as_of"),
        ("discoKey", "disco_key"),
        ("preferredDerp", "preferred_derp"),
        ("derpLatency", "derp_latency"),
    ] {
        if let Some(value) = object.remove(proto) {
            object.insert(tailnet.to_owned(), value);
        }
    }
    object
        .entry("endpoints".to_owned())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    object
        .entry("addresses".to_owned())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    serde_json::from_value(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{prefix_from_uuid, DiscoPublic, NodePublic};
    use codewire_proto::coordinator::v1::{PeerRemove, PeerUpdate};
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
    fn coordinate_url_is_reduced_to_connect_origin() {
        assert_eq!(
            coordinator_origin(
                "http://coordinator:8090/api/v1/internal/gateway/coordinate?sidecar_id=x"
            )
            .unwrap(),
            "http://coordinator:8090/".parse::<http::Uri>().unwrap()
        );
        assert_eq!(
            coordinator_origin("https://api.example.invalid/api/v1/coordinate").unwrap(),
            "https://api.example.invalid/".parse::<http::Uri>().unwrap()
        );
    }

    #[tokio::test]
    async fn setup_times_out_after_http2_accepts_but_never_responds() {
        let listener = test_bounded(
            "HTTP/2 listener bind",
            tokio::net::TcpListener::bind("127.0.0.1:0"),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
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
            CoordinatorConnectClient::connect_with_setup_timeout(
                &url,
                "",
                HelloIdentity::sidecar(Uuid::new_v4()),
                setup_timeout,
            )
            .await
        });
        test_bounded("HTTP/2 SETTINGS exchange", accepted_rx)
            .await
            .expect("HTTP/2 peer accepted the connection");
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
                msg: Ping::default().into(),
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
    fn hello_identity_preserves_client_and_sidecar_addressing() {
        let environment_id = Uuid::new_v4();
        let client = HelloIdentity::client("org-1", environment_id).into_hello();
        assert_eq!(client.org_id, "org-1");
        assert_eq!(client.environment_id, environment_id.to_string());

        let sidecar = HelloIdentity::sidecar(environment_id).into_hello();
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
            msg: PeerUpdate {
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
            msg: PeerRemove {
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
