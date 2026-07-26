//! Coordinator HTTP/WebSocket client (#47).
//!
//! This is plain JSON over a WebSocket — no Tailscale protocol. The client
//! connects, registers its [`Node`], streams node updates as its local
//! connectivity changes, and receives the peer `[]Node` stream from the
//! coordinator.
//!
//! ## Wire protocol (mirrors the Go gateway's `runCoordinator`)
//!
//! Transport: WebSocket with the `coordinate` subprotocol and an
//! `Authorization: Bearer <token>` header. Text frames carry JSON.
//!
//! Client → coordinator (one envelope):
//! ```json
//! {"type":"node","node": <Node>}
//! ```
//!
//! Coordinator → client (tagged by `type`):
//! ```json
//! {"type":"peer_update","nodes":[<Node>, ...]}
//! {"type":"peer_remove","peer_id":"<uuid>"}
//! {"type":"derp_map","derp_map":{...}}   // sent first; opaque to us
//! ```
//!
//! ## API shape (mirrors `Conn::SetNodeCallback` / `Conn::UpdatePeers`)
//!
//! - [`CoordinatorClient::connect`] dials, performs the WS handshake, and
//!   waits for the first recognized coordinator response within the shared
//!   setup budget.
//! - [`CoordinatorClient::update_node`] sends a `{"type":"node",...}` frame
//!   (the analogue of the gateway's `SetNodeCallback` firing).
//! - [`CoordinatorClient::run`] drives the read loop: it maintains the
//!   peer map (apply `peer_update`, drop on `peer_remove`) and invokes the
//!   caller's `on_peers` callback with the full peer slice — the analogue
//!   of `Conn::UpdatePeers`. `derp_map` is surfaced raw via `on_derp_map`
//!   so the consumer decides whether to apply it (the Go sidecar
//!   deliberately ignores the server map and derives its own).
//!
//! Scope: this is the #47 app-level client. Reconnect/backoff loops
//! (the gateway's `coordinatorLoop`) and NATS cross-replica fan-out live
//! on the server; a consumer wraps [`CoordinatorClient::run`] in its own
//! retry loop. Deferred to #59: TLS root configuration knobs and the
//! direct-path DERP-map application.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use crate::node::Node;

const COORDINATOR_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Maximum time allowed for coordinator transport setup through the first
/// recognized server response.
pub const COORDINATOR_SETUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Errors from the coordinator client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// WebSocket transport/handshake error.
    #[error("websocket: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    /// JSON (de)serialization error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Malformed coordinator URL.
    #[error("invalid url: {0}")]
    Url(String),
    /// The peer connection closed.
    #[error("connection closed")]
    Closed,
    /// Transport setup did not produce a usable coordinator response in time.
    #[error("coordinator setup timed out after {0:?}")]
    SetupTimeout(Duration),
}

/// The client → coordinator envelope. Mirrors Go's `coordinateMsg`.
///
/// Only `type:"node"` is sent today; `node` is always present so the JSON
/// matches the gateway's `{type, node}` struct byte-for-byte.
#[derive(Serialize)]
struct CoordinateMsg<'a> {
    #[serde(rename = "type")]
    typ: &'a str,
    node: &'a Node,
}

/// The coordinator → client envelope. Mirrors Go's `coordinateResp`.
///
/// `derp_map` is kept as raw JSON: the wire shape is a Tailscale
/// `tailcfg.DERPMap`, which the coordinator client does not model. The
/// consumer decides whether to apply it.
#[derive(Deserialize)]
struct CoordinateResp {
    #[serde(rename = "type")]
    typ: String,
    #[serde(default)]
    nodes: Vec<Node>,
    #[serde(default)]
    peer_id: Option<String>,
    #[serde(default)]
    derp_map: Option<serde_json::Value>,
}

/// Callbacks the consumer supplies to [`CoordinatorClient::run`].
///
/// `on_peers` is the analogue of `Conn::UpdatePeers`: it receives the full
/// current peer set after every `peer_update` / `peer_remove`. `on_derp_map`
/// receives the raw server DERP map (the Go sidecar ignores it).
pub struct Handlers<P, D>
where
    P: FnMut(&[Node]),
    D: FnMut(&serde_json::Value),
{
    /// Invoked with the full peer slice after each update/removal.
    pub on_peers: P,
    /// Invoked with the raw server DERP map.
    pub on_derp_map: D,
}

/// An async client connected to the coordinator over WebSocket.
pub struct CoordinatorClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Current known peers, keyed by node id. Mirrors the gateway's
    /// `peers map[uuid.UUID]*tailnet.Node`.
    peers: BTreeMap<Uuid, Node>,
    pending_responses: VecDeque<CoordinateResp>,
}

impl CoordinatorClient {
    /// Dial `url` (a `ws://`/`wss://` coordinate endpoint), perform the
    /// WebSocket handshake, and wait for the first usable coordinator
    /// response. Setup is bounded by [`COORDINATOR_SETUP_TIMEOUT`].
    pub async fn connect(url: &str, bearer_token: &str) -> Result<Self, Error> {
        Self::connect_with_setup_timeout(url, bearer_token, COORDINATOR_SETUP_TIMEOUT).await
    }

    /// Connect with an explicit setup bound.
    ///
    /// Callers with a stricter operation-level budget may shorten the shared
    /// 15-second maximum. The returned stream has no absolute lifetime
    /// deadline.
    pub async fn connect_with_setup_timeout(
        url: &str,
        bearer_token: &str,
        setup_timeout: Duration,
    ) -> Result<Self, Error> {
        tokio::time::timeout(setup_timeout, Self::connect_inner(url, bearer_token))
            .await
            .map_err(|_| Error::SetupTimeout(setup_timeout))?
    }

    async fn connect_inner(url: &str, bearer_token: &str) -> Result<Self, Error> {
        let mut request = url
            .into_client_request()
            .map_err(|e| Error::Url(e.to_string()))?;
        let headers = request.headers_mut();
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("coordinate"),
        );
        if !bearer_token.is_empty() {
            let val = format!("Bearer {bearer_token}");
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&val).map_err(|e| Error::Url(e.to_string()))?,
            );
        }

        let (mut ws, _resp) = tokio_tungstenite::connect_async(request).await?;
        loop {
            let frame = ws.next().await.ok_or(Error::Closed)??;
            match decode_message(frame) {
                DecodedMessage::Response(response) => {
                    return Ok(Self {
                        ws,
                        peers: BTreeMap::new(),
                        pending_responses: VecDeque::from([response]),
                    });
                }
                DecodedMessage::Closed => return Err(Error::Closed),
                DecodedMessage::Ignored => {}
            }
        }
    }

    /// Send a `{"type":"node","node":<node>}` frame to the coordinator.
    ///
    /// The analogue of the gateway's `SetNodeCallback` firing: call this on
    /// connect and whenever local connectivity (endpoints / preferred DERP)
    /// changes.
    pub async fn update_node(&mut self, node: &Node) -> Result<(), Error> {
        let msg = CoordinateMsg { typ: "node", node };
        let payload = serde_json::to_string(&msg)?;
        self.ws.send(Message::Text(payload.into())).await?;
        Ok(())
    }

    /// The current known peer set (full slice), most recently delivered to
    /// `on_peers`. Useful for tests and consumers that poll.
    pub fn peers(&self) -> Vec<Node> {
        self.peers.values().cloned().collect()
    }

    /// Drive the read loop until the connection closes.
    ///
    /// For each `peer_update` the nodes are merged into the peer map and the
    /// full slice is handed to `handlers.on_peers` (mirroring the gateway's
    /// `UpdatePeers(peerSlice(peers))`). `peer_remove` drops the peer and
    /// re-delivers the slice. `derp_map` is passed raw to `on_derp_map`.
    /// Ping/pong/close are handled by the transport; on a clean close this
    /// returns `Ok(())`.
    pub async fn run<P, D>(&mut self, mut handlers: Handlers<P, D>) -> Result<(), Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        self.run_inner(None, &mut handlers, COORDINATOR_HEARTBEAT_INTERVAL)
            .await
    }

    /// Drive the read loop while also publishing local node updates.
    ///
    /// This is the Rust equivalent of the Go sidecar's `SetNodeCallback`
    /// writing `type:"node"` frames while the coordinator read loop continues.
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

        while let Some(response) = self.pending_responses.pop_front() {
            self.handle_response(response, handlers);
        }

        loop {
            tokio::select! {
                maybe = async {
                    node_updates.as_mut().expect("guarded node update receiver").recv().await
                }, if node_updates.is_some() => {
                    match maybe {
                        Some(node) => self.update_node(&node).await?,
                        None => node_updates = None,
                    }
                }
                _ = heartbeat.tick() => {
                    self.ws.send(Message::Ping(Vec::new().into())).await?;
                }
                frame = self.ws.next() => {
                    let Some(frame) = frame else { return Ok(()); };
                    if !self.handle_message(frame?, &mut *handlers)? {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn handle_message<P, D>(
        &mut self,
        msg: Message,
        handlers: &mut Handlers<P, D>,
    ) -> Result<bool, Error>
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        match decode_message(msg) {
            DecodedMessage::Response(response) => {
                self.handle_response(response, handlers);
                Ok(true)
            }
            DecodedMessage::Closed => Ok(false),
            DecodedMessage::Ignored => Ok(true),
        }
    }

    fn handle_response<P, D>(&mut self, resp: CoordinateResp, handlers: &mut Handlers<P, D>)
    where
        P: FnMut(&[Node]),
        D: FnMut(&serde_json::Value),
    {
        match resp.typ.as_str() {
            "peer_update" => {
                for n in resp.nodes {
                    self.peers.insert(n.id, n);
                }
                let slice = self.peers();
                (handlers.on_peers)(&slice);
            }
            "peer_remove" => {
                if let Some(pid) = resp.peer_id.as_deref() {
                    if let Ok(id) = Uuid::parse_str(pid) {
                        self.peers.remove(&id);
                        let slice = self.peers();
                        (handlers.on_peers)(&slice);
                    }
                }
            }
            "derp_map" => {
                if let Some(dm) = resp.derp_map.as_ref() {
                    (handlers.on_derp_map)(dm);
                }
            }
            _ => {}
        }
    }
}

enum DecodedMessage {
    Response(CoordinateResp),
    Closed,
    Ignored,
}

fn decode_message(msg: Message) -> DecodedMessage {
    let data: Vec<u8> = match msg {
        Message::Text(text) => text.as_bytes().to_vec(),
        Message::Binary(bytes) => bytes.to_vec(),
        Message::Close(_) => return DecodedMessage::Closed,
        // Ping/Pong/Frame are handled by tungstenite internally.
        _ => return DecodedMessage::Ignored,
    };

    // Match the Go client: silently skip frames that don't parse or name a
    // response type this client can use.
    let Ok(response) = serde_json::from_slice::<CoordinateResp>(&data) else {
        return DecodedMessage::Ignored;
    };
    if matches!(
        response.typ.as_str(),
        "peer_update" | "peer_remove" | "derp_map"
    ) {
        DecodedMessage::Response(response)
    } else {
        DecodedMessage::Ignored
    }
}

#[cfg(test)]
// The handshake-callback signature required by `accept_hdr_async` returns a
// large `ErrorResponse` by value — tungstenite's API, not ours, so the lint
// can't be satisfied by boxing here.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use crate::node::{prefix_from_uuid, DiscoPublic, Node, NodePublic};
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_tungstenite::tungstenite::Message as SrvMessage;

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
            as_of: "2026-06-19T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x11; 32]),
            disco_key: DiscoPublic::from_raw([0x22; 32]),
            preferred_derp: derp,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&id)],
        }
    }

    type Req = tokio_tungstenite::tungstenite::handshake::server::Request;
    type Resp = tokio_tungstenite::tungstenite::handshake::server::Response;

    /// Handshake callback mirroring the original coordinator `websocket.Accept`
    /// with `Subprotocols: ["coordinate"]`: echo the negotiated subprotocol
    /// back so the strict tungstenite client accepts the handshake.
    fn echo_coordinate(
        req: &Req,
        mut resp: Resp,
    ) -> Result<Resp, tokio_tungstenite::tungstenite::handshake::server::ErrorResponse> {
        if req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|p| p.to_str().ok())
            == Some("coordinate")
        {
            resp.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_static("coordinate"),
            );
        }
        Ok(resp)
    }

    /// A hand-rolled in-process mock coordinator: accepts one WS connection,
    /// sends a derp_map then a peer_update, reads the client's node
    /// register frame, then sends a peer_remove. Records the raw register
    /// frame so the test can assert the envelope byte-exactly. Also asserts
    /// the client sent the `coordinate` subprotocol + Bearer auth header.
    async fn mock_coordinator(
        listener: TcpListener,
        peer: Node,
        captured: Arc<Mutex<Option<String>>>,
    ) {
        let (stream, _) = listener.accept().await.unwrap();
        let auth_ok = Arc::new(Mutex::new(false));
        let subproto_ok = Arc::new(Mutex::new(false));
        let auth_ok2 = auth_ok.clone();
        let sub2 = subproto_ok.clone();
        let callback = move |req: &Req, resp: Resp| {
            *sub2.lock().unwrap() = req
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|p| p.to_str().ok())
                == Some("coordinate");
            *auth_ok2.lock().unwrap() = req
                .headers()
                .get("Authorization")
                .and_then(|a| a.to_str().ok())
                == Some("Bearer test-token");
            echo_coordinate(req, resp)
        };
        let mut ws = tokio_tungstenite::accept_hdr_async(stream, callback)
            .await
            .unwrap();
        assert!(*subproto_ok.lock().unwrap(), "coordinate subprotocol sent");
        assert!(
            *auth_ok.lock().unwrap(),
            "bearer auth header must be present and correct"
        );

        // 1) derp_map first (opaque map), like sendDERPMap.
        let dm = serde_json::json!({"type":"derp_map","derp_map":{"Regions":{}}});
        ws.send(SrvMessage::Text(dm.to_string().into()))
            .await
            .unwrap();

        // 2) peer_update with the agent/sidecar node.
        let pu = serde_json::json!({"type":"peer_update","nodes":[peer]});
        ws.send(SrvMessage::Text(pu.to_string().into()))
            .await
            .unwrap();

        // 3) Read the client's register frame and capture it raw.
        if let Some(Ok(SrvMessage::Text(t))) = ws.next().await {
            *captured.lock().unwrap() = Some(t.to_string());
        }

        // 4) peer_remove the peer.
        let pr = serde_json::json!({"type":"peer_remove","peer_id": peer.id.to_string()});
        ws.send(SrvMessage::Text(pr.to_string().into()))
            .await
            .unwrap();

        ws.send(SrvMessage::Close(None)).await.unwrap();
    }

    #[tokio::test]
    async fn register_and_receive_roundtrip() {
        let peer_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let self_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let peer = sample_node(peer_id, 7);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(None));

        let srv = tokio::spawn(mock_coordinator(listener, peer.clone(), captured.clone()));

        let url = format!("ws://{addr}/api/v1/tailnet/coordinate");
        let mut client = CoordinatorClient::connect(&url, "test-token")
            .await
            .unwrap();

        // Register our node — analogue of SetNodeCallback firing on connect.
        let my_node = sample_node(self_id, 3);
        client.update_node(&my_node).await.unwrap();

        // Collect peer-slice snapshots and derp maps via the callbacks.
        let snapshots: Arc<Mutex<Vec<Vec<Node>>>> = Arc::new(Mutex::new(Vec::new()));
        let derp_maps: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let snaps2 = snapshots.clone();
        let derp2 = derp_maps.clone();

        client
            .run(Handlers {
                on_peers: |peers: &[Node]| snaps2.lock().unwrap().push(peers.to_vec()),
                on_derp_map: |dm: &serde_json::Value| derp2.lock().unwrap().push(dm.clone()),
            })
            .await
            .unwrap();

        srv.await.unwrap();

        // The server received our register frame, byte-exact against the Go
        // gateway envelope shape: {"type":"node","node":<my_node>} with the
        // Go field ordering (type first, then node in struct order). This is
        // a hard-coded literal — using serde_json::json! would reorder keys
        // and hide an ordering regression.
        let raw = captured.lock().unwrap().clone().expect("register captured");
        let expected = concat!(
            "{\"type\":\"node\",\"node\":{",
            "\"id\":\"00112233-4455-6677-8899-aabbccddeeff\",",
            "\"as_of\":\"2026-06-19T12:00:00Z\",",
            "\"key\":\"nodekey:1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"disco_key\":\"discokey:2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"preferred_derp\":3,",
            "\"endpoints\":[],",
            "\"addresses\":[\"fd7a:115c:a1e0:11:2233:4455:6677:8899/128\"]",
            "}}"
        );
        assert_eq!(raw, expected, "register envelope must match Go shape");

        // derp_map callback fired once.
        assert_eq!(derp_maps.lock().unwrap().len(), 1, "one derp_map");

        // Peer slice progression: after peer_update we have [peer]; after
        // peer_remove we have [].
        let snaps = snapshots.lock().unwrap();
        assert_eq!(snaps.len(), 2, "peer_update then peer_remove");
        assert_eq!(snaps[0].len(), 1);
        assert_eq!(snaps[0][0].id, peer_id);
        assert_eq!(snaps[0][0].preferred_derp, 7);
        assert_eq!(snaps[1].len(), 0, "peer removed");
    }

    #[tokio::test]
    async fn skips_unparseable_and_unknown_frames() {
        // A server that sends garbage, then an unknown type, then closes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(stream, echo_coordinate)
                .await
                .unwrap();
            ws.send(SrvMessage::Text(
                serde_json::json!({"type":"derp_map","derp_map":{"Regions":{}}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            ws.send(SrvMessage::Text("not json".into())).await.unwrap();
            ws.send(SrvMessage::Text(
                serde_json::json!({"type":"unknown"}).to_string().into(),
            ))
            .await
            .unwrap();
            ws.send(SrvMessage::Close(None)).await.unwrap();
        });

        let url = format!("ws://{addr}/coordinate");
        let mut client = CoordinatorClient::connect(&url, "").await.unwrap();
        let mut peer_calls = 0;
        client
            .run(Handlers {
                on_peers: |_: &[Node]| peer_calls += 1,
                on_derp_map: |_: &serde_json::Value| {},
            })
            .await
            .unwrap();
        srv.await.unwrap();
        assert_eq!(peer_calls, 0, "no peer callbacks for junk/unknown frames");
    }

    #[tokio::test]
    async fn run_with_node_updates_sends_heartbeat_pings_while_idle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(stream, echo_coordinate)
                .await
                .unwrap();
            ws.send(SrvMessage::Text(
                serde_json::json!({"type":"derp_map","derp_map":{"Regions":{}}})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
            let msg = tokio::time::timeout(Duration::from_secs(1), ws.next())
                .await
                .expect("client heartbeat ping")
                .expect("websocket frame")
                .expect("valid websocket frame");
            assert!(
                matches!(msg, SrvMessage::Ping(_)),
                "expected heartbeat ping, got {msg:?}"
            );
            ws.send(SrvMessage::Close(None)).await.unwrap();
        });

        let url = format!("ws://{addr}/coordinate");
        let mut client = CoordinatorClient::connect(&url, "").await.unwrap();
        let (_tx, rx) = mpsc::unbounded_channel::<Node>();

        client
            .run_inner(
                Some(rx),
                &mut Handlers {
                    on_peers: |_: &[Node]| {},
                    on_derp_map: |_: &serde_json::Value| {},
                },
                Duration::from_millis(25),
            )
            .await
            .unwrap();
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_setup_times_out_after_handshake_without_a_usable_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _websocket = tokio_tungstenite::accept_hdr_async(stream, echo_coordinate)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        let timeout = Duration::from_millis(25);
        let error = CoordinatorClient::connect_with_setup_timeout(
            &format!("ws://{addr}/coordinate"),
            "",
            timeout,
        )
        .await
        .err()
        .expect("stalled WebSocket setup must fail");
        assert!(matches!(error, Error::SetupTimeout(value) if value == timeout));
        server.abort();
    }

    #[tokio::test]
    async fn established_websocket_outlives_setup_and_unary_budgets_and_keeps_heartbeating() {
        let listener = test_bounded("WebSocket listener bind", TcpListener::bind("127.0.0.1:0"))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let setup_timeout = Duration::from_secs(1);
        // Preserve the policy ordering without making successful loopback I/O
        // race a scheduler-sized setup budget. The third heartbeat still
        // arrives after both the setup and unary boundaries.
        let unary_budget = Duration::from_secs(2);
        let heartbeat_interval = Duration::from_millis(750);
        let (ready_tx, ready_rx) = oneshot::channel();
        let server = tokio::spawn(test_bounded("WebSocket server task", async move {
            ready_tx.send(()).expect("WebSocket test remains active");
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_hdr_async(stream, echo_coordinate)
                .await
                .unwrap();
            websocket
                .send(SrvMessage::Text(
                    serde_json::json!({"type":"derp_map","derp_map":{"Regions":{}}})
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
            for heartbeat in 1..=3 {
                let message = websocket
                    .next()
                    .await
                    .expect("WebSocket frame")
                    .expect("valid WebSocket frame");
                assert!(
                    matches!(message, SrvMessage::Ping(_)),
                    "expected heartbeat {heartbeat}, got {message:?}"
                );
            }
            websocket.send(SrvMessage::Close(None)).await.unwrap();
        }));

        test_bounded("WebSocket server readiness", ready_rx)
            .await
            .expect("WebSocket server reports readiness");

        let mut client = test_bounded(
            "WebSocket coordinator setup",
            CoordinatorClient::connect_with_setup_timeout(
                &format!("ws://{addr}/coordinate"),
                "",
                setup_timeout,
            ),
        )
        .await
        .unwrap();
        let established_at = tokio::time::Instant::now();
        let (_tx, rx) = mpsc::unbounded_channel::<Node>();
        let mut handlers = Handlers {
            on_peers: |_: &[Node]| {},
            on_derp_map: |_: &serde_json::Value| {},
        };
        test_bounded(
            "established WebSocket lifecycle",
            client.run_inner(Some(rx), &mut handlers, heartbeat_interval),
        )
        .await
        .unwrap();

        let established_lifetime = tokio::time::Instant::now() - established_at;
        assert!(established_lifetime > setup_timeout);
        assert!(established_lifetime > unary_budget);
        test_bounded("WebSocket server join", server).await.unwrap();
    }
}
