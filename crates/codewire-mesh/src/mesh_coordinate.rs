//! Typed non-browser Mesh coordinate service.
//!
//! Authentication is resolved from the credential presented at stream setup.
//! The generated hello, node, subscription, and response messages are the only
//! wire contract; no runtime-token exchange or WebSocket adapter is involved.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_proto::codewire::internal::v1::{
    CoordinateDerpMap, CoordinateNode, CoordinatePeerRemove, CoordinatePeerUpdate, CoordinatePing,
    MeshAuthorizationCredentialKind, MeshAuthorizationPrincipalKind, MeshCoordinateHello,
    MeshCoordinateRole, MeshCoordinatorService, MeshCoordinatorServiceCoordinateRequest,
    MeshCoordinatorServiceCoordinateResponse, mesh_coordinator_service_coordinate_request,
    mesh_coordinator_service_coordinate_response,
};
use codewire_server_core::AppError;
use codewire_server_core::connect::rpc_app_error;
use codewire_tailnet::node::Node;
use connectrpc::{ConnectError, InboundStream, RequestContext, ServiceResult, ServiceStream};
use futures_util::StreamExt;
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;

use crate::mesh_authorization::forwarded_mesh_credential;
use crate::server::AppState;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

pub(crate) fn router(state: AppState) -> connectrpc::Router {
    connectrpc::Router::new().add_service(Arc::new(MeshCoordinateService { state }))
}

struct MeshCoordinateService {
    state: AppState,
}

#[allow(refining_impl_trait)]
impl MeshCoordinatorService for MeshCoordinateService {
    async fn coordinate(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<MeshCoordinatorServiceCoordinateRequest>,
    ) -> ServiceResult<ServiceStream<MeshCoordinatorServiceCoordinateResponse>> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("hello is required"))??
            .to_owned_message();
        let hello = match first.msg {
            Some(mesh_coordinator_service_coordinate_request::Msg::Hello(hello)) => *hello,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "hello must be the first message",
                ));
            }
        };
        let peer = authorize(&self.state, &ctx, hello)
            .await
            .map_err(|error| rpc_app_error(&error, &ctx))?;
        let derp_map = derp_map_from_base_url(
            self.state
                .config
                .derp_url
                .as_deref()
                .unwrap_or(&self.state.config.base_url),
        )
        .map_err(ConnectError::internal)?;

        let (responses_tx, responses_rx) = mpsc::channel(32);
        let state = self.state.mesh_coordinate.clone();
        tokio::spawn(run_session(requests, responses_tx, state, peer, derp_map));

        let output = futures_util::stream::unfold(responses_rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        connectrpc::Response::stream_ok(output)
    }
}

#[derive(Clone)]
pub(crate) struct MeshCoordinateState {
    inner: Arc<Mutex<Registry>>,
}

impl MeshCoordinateState {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Registry::default())),
        }
    }
}

#[derive(Default)]
struct Registry {
    peers: HashMap<Uuid, Peer>,
    tunnels: HashMap<Uuid, Uuid>,
}

struct Peer {
    session_id: Uuid,
    network_id: String,
    node: Option<Node>,
    tx: mpsc::Sender<CoordinateEvent>,
}

enum CoordinateEvent {
    Update(Vec<Node>),
    Remove(Uuid),
}

#[derive(Clone)]
struct AuthorizedPeer {
    peer_id: Uuid,
    network_id: String,
    role: MeshCoordinateRole,
}

async fn authorize(
    state: &AppState,
    ctx: &RequestContext,
    hello: MeshCoordinateHello,
) -> Result<AuthorizedPeer, AppError> {
    let org_id = required(&hello.org_id, "org_id")?;
    let network_id = required(&hello.network_id, "network_id")?;
    let role = hello
        .role
        .as_known()
        .ok_or_else(|| AppError::BadRequest("coordinate role is required".into()))?;
    let credential =
        forwarded_mesh_credential(ctx.headers()).map_err(|_| AppError::Unauthorized)?;
    let authorization = state
        .product
        .authorize_coordinate(&org_id, &network_id, credential)
        .await?;

    match role {
        MeshCoordinateRole::Peer
            if authorization.principal_kind == MeshAuthorizationPrincipalKind::Environment
                && authorization.credential_kind
                    == MeshAuthorizationCredentialKind::EnvironmentToken => {}
        MeshCoordinateRole::Dial
            if authorization.principal_kind == MeshAuthorizationPrincipalKind::User
                && matches!(
                    authorization.credential_kind.as_known(),
                    Some(
                        MeshAuthorizationCredentialKind::OauthBearer
                            | MeshAuthorizationCredentialKind::ApiKey
                    )
                ) => {}
        _ => return Err(AppError::Forbidden),
    }

    let peer_id = match role {
        MeshCoordinateRole::Peer => {
            stable_peer_id(&network_id, "environment", &authorization.principal_id)
        }
        MeshCoordinateRole::Dial => Uuid::new_v4(),
        MeshCoordinateRole::Unspecified => unreachable!("validated above"),
    };
    Ok(AuthorizedPeer {
        peer_id,
        network_id,
        role,
    })
}

fn required(value: &str, field: &'static str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{field} is required").into()));
    }
    Ok(value.to_owned())
}

async fn run_session(
    mut requests: InboundStream<MeshCoordinatorServiceCoordinateRequest>,
    responses: mpsc::Sender<Result<MeshCoordinatorServiceCoordinateResponse, ConnectError>>,
    state: MeshCoordinateState,
    peer: AuthorizedPeer,
    derp_map: JsonValue,
) {
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let session_id = register(&state, &peer, events_tx);
    let initial = response(CoordinateDerpMap {
        derp_map_json: serde_json::to_vec(&derp_map).unwrap_or_default(),
        ..Default::default()
    });
    if responses.send(Ok(initial)).await.is_err() {
        deregister(&state, peer.peer_id, session_id);
        return;
    }

    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
        HEARTBEAT_INTERVAL,
    );
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            message = requests.next() => {
                let Some(message) = message else {
                    break;
                };
                let Ok(message) = message else {
                    break;
                };
                let message = message.to_owned_message();
                match message.msg {
                    Some(mesh_coordinator_service_coordinate_request::Msg::Node(node)) => {
                        match proto_node_to_tailnet(*node) {
                            Ok(mut node) => {
                                node.id = peer.peer_id;
                                update_node(&state, peer.peer_id, session_id, node);
                            }
                            Err(error) => {
                                if responses.send(Err(error)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Some(mesh_coordinator_service_coordinate_request::Msg::Subscribe(subscribe)) => {
                        if peer.role != MeshCoordinateRole::Dial {
                            if responses
                                .send(Err(ConnectError::permission_denied(
                                    "only dial sessions may subscribe",
                                )))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        let target = subscribe.target_node.trim();
                        if target.is_empty() {
                            if responses
                                .send(Err(ConnectError::invalid_argument(
                                    "target_node is required",
                                )))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        let target_id = stable_peer_id(&peer.network_id, "environment", target);
                        add_tunnel(&state, peer.peer_id, target_id);
                    }
                    Some(mesh_coordinator_service_coordinate_request::Msg::Ping(_)) => {}
                    Some(mesh_coordinator_service_coordinate_request::Msg::Hello(_)) | None => {
                        if responses
                            .send(Err(ConnectError::invalid_argument(
                                "hello is allowed only as the first message",
                            )))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            event = events_rx.recv() => {
                let Some(event) = event else {
                    break;
                };
                let result = match event {
                    CoordinateEvent::Update(nodes) => nodes
                        .into_iter()
                        .map(tailnet_node_to_proto)
                        .collect::<Result<Vec<_>, _>>()
                        .map(|nodes| response(CoordinatePeerUpdate {
                            nodes,
                            ..Default::default()
                        })),
                    CoordinateEvent::Remove(peer_id) => Ok(response(CoordinatePeerRemove {
                        peer_id: peer_id.to_string(),
                        ..Default::default()
                    })),
                };
                if responses.send(result).await.is_err() {
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if responses
                    .send(Ok(response(CoordinatePing::default())))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    deregister(&state, peer.peer_id, session_id);
}

fn register(
    state: &MeshCoordinateState,
    peer: &AuthorizedPeer,
    tx: mpsc::Sender<CoordinateEvent>,
) -> Uuid {
    let session_id = Uuid::new_v4();
    let mut registry = state.inner.lock().unwrap();
    registry.peers.insert(
        peer.peer_id,
        Peer {
            session_id,
            network_id: peer.network_id.clone(),
            node: None,
            tx,
        },
    );
    session_id
}

fn deregister(state: &MeshCoordinateState, peer_id: Uuid, session_id: Uuid) {
    let updates = {
        let mut registry = state.inner.lock().unwrap();
        if registry
            .peers
            .get(&peer_id)
            .is_none_or(|peer| peer.session_id != session_id)
        {
            return;
        }
        registry.peers.remove(&peer_id);
        let affected = registry
            .tunnels
            .iter()
            .filter_map(|(dial, target)| {
                ((*dial == peer_id) || (*target == peer_id)).then_some((*dial, *target))
            })
            .collect::<Vec<_>>();
        let mut updates = Vec::new();
        for (dial, target) in affected {
            registry.tunnels.remove(&dial);
            let recipient = if dial == peer_id { target } else { dial };
            if let Some(peer) = registry.peers.get(&recipient) {
                updates.push(peer.tx.clone());
            }
        }
        updates
    };
    for tx in updates {
        let _ = tx.try_send(CoordinateEvent::Remove(peer_id));
    }
}

fn update_node(state: &MeshCoordinateState, peer_id: Uuid, session_id: Uuid, node: Node) {
    let updates = {
        let mut registry = state.inner.lock().unwrap();
        let Some(peer) = registry.peers.get_mut(&peer_id) else {
            return;
        };
        if peer.session_id != session_id {
            return;
        }
        peer.node = Some(node);
        tunnel_updates(&registry, peer_id)
    };
    send_updates(peer_id, updates);
}

fn add_tunnel(state: &MeshCoordinateState, dial_id: Uuid, target_id: Uuid) {
    let updates = {
        let mut registry = state.inner.lock().unwrap();
        let same_network = match (registry.peers.get(&dial_id), registry.peers.get(&target_id)) {
            (Some(dial), Some(target)) => dial.network_id == target.network_id,
            (Some(_), None) => true,
            _ => false,
        };
        if !same_network {
            return;
        }
        registry.tunnels.insert(dial_id, target_id);
        tunnel_updates(&registry, dial_id)
    };
    send_updates(dial_id, updates);
}

fn tunnel_updates(
    registry: &Registry,
    changed: Uuid,
) -> Vec<(mpsc::Sender<CoordinateEvent>, Vec<Node>)> {
    let mut updates = Vec::new();
    for (dial_id, target_id) in &registry.tunnels {
        if *dial_id != changed && *target_id != changed {
            continue;
        }
        if let (Some(dial), Some(target)) =
            (registry.peers.get(dial_id), registry.peers.get(target_id))
            && dial.network_id == target.network_id
        {
            if let Some(target_node) = target.node.clone() {
                updates.push((dial.tx.clone(), vec![target_node]));
            }
            if let Some(dial_node) = dial.node.clone() {
                updates.push((target.tx.clone(), vec![dial_node]));
            }
        }
    }
    updates
}

fn send_updates(source: Uuid, updates: Vec<(mpsc::Sender<CoordinateEvent>, Vec<Node>)>) {
    for (tx, nodes) in updates {
        if tx.try_send(CoordinateEvent::Update(nodes)).is_err() {
            tracing::warn!(%source, "Mesh coordinator dropped update for slow peer");
        }
    }
}

fn response(
    message: impl Into<Option<mesh_coordinator_service_coordinate_response::Msg>>,
) -> MeshCoordinatorServiceCoordinateResponse {
    MeshCoordinatorServiceCoordinateResponse {
        msg: message.into(),
        ..Default::default()
    }
}

fn stable_peer_id(network_id: &str, principal_kind: &str, principal_id: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(network_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(principal_kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(principal_id.as_bytes());
    let sum = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&sum[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn proto_node_to_tailnet(node: CoordinateNode) -> Result<Node, ConnectError> {
    let mut value =
        serde_json::to_value(node).map_err(|_| ConnectError::invalid_argument("invalid node"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| ConnectError::invalid_argument("invalid node"))?;
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
        .or_insert_with(|| JsonValue::Array(Vec::new()));
    object
        .entry("addresses".to_owned())
        .or_insert_with(|| JsonValue::Array(Vec::new()));
    serde_json::from_value(value).map_err(|_| ConnectError::invalid_argument("invalid node"))
}

fn tailnet_node_to_proto(node: Node) -> Result<CoordinateNode, ConnectError> {
    serde_json::from_value(
        serde_json::to_value(node).map_err(|_| ConnectError::internal("encode node"))?,
    )
    .map_err(|_| ConnectError::internal("encode node"))
}

fn derp_map_from_base_url(base_url: &str) -> Result<JsonValue, String> {
    let url = Url::parse(base_url.trim()).map_err(|error| error.to_string())?;
    let hostname = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "base URL has no hostname".to_string())?;
    let port = match url.port() {
        Some(port) => i64::from(port),
        None => match url.scheme() {
            "http" => 80,
            "https" => 443,
            scheme => return Err(format!("unsupported base URL scheme {scheme:?}")),
        },
    };
    let mut node = JsonMap::new();
    node.insert("Name".to_owned(), JsonValue::String("1a".to_owned()));
    node.insert("RegionID".to_owned(), JsonValue::from(1));
    node.insert(
        "HostName".to_owned(),
        JsonValue::String(hostname.to_owned()),
    );
    node.insert("DERPPort".to_owned(), JsonValue::from(port));
    node.insert("STUNPort".to_owned(), JsonValue::from(-1));
    if url.scheme() == "http" {
        node.insert("InsecureForTests".to_owned(), JsonValue::Bool(true));
    }
    Ok(serde_json::json!({
        "Regions": {
            "1": {
                "RegionID": 1,
                "RegionCode": "cw",
                "RegionName": "Codewire Embedded",
                "Nodes": [JsonValue::Object(node)],
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_proto::codewire::internal::v1::{
        MeshCoordinatorServiceClient, mesh_coordinator_service_coordinate_response,
    };
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use connectrpc::Protocol;
    use connectrpc::client::{ClientConfig, HttpClient};

    use crate::config::{AuthMode, Config, LocalMeshAuthorizationConfig};
    use crate::mesh_authorization::hash_local_environment_token;
    use crate::store::{MemoryStore, MeshStore};

    fn config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            base_url: "http://mesh.test".to_owned(),
            auth_mode: AuthMode::None,
            auth_token: None,
            derp_url: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_allowed_groups: Vec::new(),
            database_url: None,
            mesh_authorization: None,
            local_authorization: Some(LocalMeshAuthorizationConfig {
                organization_id: "org-test".to_owned(),
                api_key_hash: codewire_server_core::auth::hash_api_key("cw_test"),
                environment_id: "environment-test".to_owned(),
                environment_token_hash: hash_local_environment_token("environment-token"),
            }),
        }
    }

    async fn start() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_owned("network-test", "org-test")
            .await
            .unwrap();
        let app = crate::server::router_with_store(config(), store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            codewire_server_core::serve_with_listener_h2_keepalive(
                app,
                listener,
                codewire_server_core::Http2KeepaliveConfig::new(
                    Duration::from_secs(15),
                    Duration::from_secs(20),
                ),
            )
            .await
            .unwrap();
        });
        (address, task)
    }

    fn client(
        address: std::net::SocketAddr,
        token: &str,
    ) -> MeshCoordinatorServiceClient<HttpClient> {
        client_with_protocol(address, token, Protocol::Connect)
    }

    fn client_with_protocol(
        address: std::net::SocketAddr,
        token: &str,
        protocol: Protocol,
    ) -> MeshCoordinatorServiceClient<HttpClient> {
        MeshCoordinatorServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(format!("http://{address}").parse().unwrap())
                .with_protocol(protocol)
                .with_default_header(axum::http::header::AUTHORIZATION, format!("Bearer {token}")),
        )
    }

    fn request(
        message: impl Into<Option<mesh_coordinator_service_coordinate_request::Msg>>,
    ) -> MeshCoordinatorServiceCoordinateRequest {
        MeshCoordinatorServiceCoordinateRequest {
            msg: message.into(),
            ..Default::default()
        }
    }

    async fn response(
        stream: &mut connectrpc::client::BidiStream<
            <HttpClient as connectrpc::client::ClientTransport>::ResponseBody,
            MeshCoordinatorServiceCoordinateRequest,
            codewire_proto::codewire::internal::v1::MeshCoordinatorServiceCoordinateResponseView<
                'static,
            >,
        >,
    ) -> MeshCoordinatorServiceCoordinateResponse {
        tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("Mesh coordinate response timed out")
            .expect("Mesh coordinate response failed")
            .expect("Mesh coordinate response ended")
            .to_owned_message()
    }

    fn hello(role: MeshCoordinateRole) -> MeshCoordinateHello {
        MeshCoordinateHello {
            org_id: "org-test".to_owned(),
            network_id: "network-test".to_owned(),
            role: role.into(),
            ..Default::default()
        }
    }

    fn node() -> Node {
        let id = Uuid::new_v4();
        Node {
            id,
            as_of: "2026-07-29T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x11; 32]),
            disco_key: DiscoPublic::from_raw([0x22; 32]),
            preferred_derp: 1,
            derp_latency: None,
            endpoints: Vec::new(),
            addresses: vec![prefix_from_uuid(&id)],
        }
    }

    #[tokio::test]
    async fn target_publication_after_subscription_notifies_dial() {
        let state = MeshCoordinateState::new();
        let network_id = "network-test".to_owned();
        let dial_id = Uuid::new_v4();
        let target_id = stable_peer_id(&network_id, "environment", "environment-test");
        let (dial_tx, mut dial_rx) = mpsc::channel(4);
        let (target_tx, _target_rx) = mpsc::channel(4);
        register(
            &state,
            &AuthorizedPeer {
                peer_id: dial_id,
                network_id: network_id.clone(),
                role: MeshCoordinateRole::Dial,
            },
            dial_tx,
        );
        let target_session = register(
            &state,
            &AuthorizedPeer {
                peer_id: target_id,
                network_id,
                role: MeshCoordinateRole::Peer,
            },
            target_tx,
        );

        add_tunnel(&state, dial_id, target_id);
        assert!(
            dial_rx.try_recv().is_err(),
            "subscription without a target node must not invent an update"
        );

        let target_node = node();
        update_node(&state, target_id, target_session, target_node.clone());
        let event = tokio::time::timeout(Duration::from_secs(1), dial_rx.recv())
            .await
            .expect("target publication must notify the subscribed dial")
            .expect("dial event channel remains open");
        let CoordinateEvent::Update(nodes) = event else {
            panic!("target publication must produce a typed update");
        };
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, target_node.id);
    }

    #[tokio::test]
    async fn typed_coordinate_auth_recovery_and_protocol_are_deterministic() {
        let (address, server) = start().await;
        let mut first_peer = client(address, "environment-token")
            .coordinate()
            .await
            .unwrap();
        first_peer
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        assert!(matches!(
            response(&mut first_peer).await.msg,
            Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(
                _
            ))
        ));

        let mut replacement_peer = client(address, "environment-token")
            .coordinate()
            .await
            .unwrap();
        replacement_peer
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        let _ = response(&mut replacement_peer).await;
        first_peer.close_send();

        let mut dial = client(address, "cw_test").coordinate().await.unwrap();
        dial.send(request(hello(MeshCoordinateRole::Dial)))
            .await
            .unwrap();
        let _ = response(&mut dial).await;

        dial.send(request(
            codewire_proto::codewire::internal::v1::MeshCoordinateSubscribe {
                target_node: "environment-test".to_owned(),
                ..Default::default()
            },
        ))
        .await
        .unwrap();
        replacement_peer
            .send(request(tailnet_node_to_proto(node()).unwrap()))
            .await
            .unwrap();
        let update = response(&mut dial).await;
        let Some(mesh_coordinator_service_coordinate_response::Msg::PeerUpdate(update)) =
            update.msg
        else {
            panic!("expected typed peer update");
        };
        assert_eq!(update.nodes.len(), 1);
        assert_eq!(
            update.nodes[0].id,
            stable_peer_id("network-test", "environment", "environment-test").to_string()
        );

        replacement_peer.close_send();
        let remove = response(&mut dial).await;
        assert!(matches!(
            remove.msg,
            Some(mesh_coordinator_service_coordinate_response::Msg::PeerRemove(_))
        ));
        dial.close_send();
        server.abort();
    }

    #[tokio::test]
    async fn typed_coordinate_rejects_wrong_credential_role() {
        let (address, server) = start().await;
        let mut peer_with_api_key = client(address, "cw_test").coordinate().await.unwrap();
        peer_with_api_key
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        let error = peer_with_api_key
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);

        let mut dial_with_environment_token = client(address, "environment-token")
            .coordinate()
            .await
            .unwrap();
        dial_with_environment_token
            .send(request(hello(MeshCoordinateRole::Dial)))
            .await
            .unwrap();
        let error = dial_with_environment_token
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);
        server.abort();
    }

    #[tokio::test]
    async fn typed_coordinate_requires_hello_and_exact_org_network_binding() {
        let (address, server) = start().await;

        let mut missing_hello = client(address, "cw_test").coordinate().await.unwrap();
        missing_hello
            .send(request(CoordinatePing::default()))
            .await
            .unwrap();
        let error = missing_hello
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);

        let mut wrong_org = client(address, "cw_test").coordinate().await.unwrap();
        let mut wrong_org_hello = hello(MeshCoordinateRole::Dial);
        wrong_org_hello.org_id = "org-other".to_owned();
        wrong_org.send(request(wrong_org_hello)).await.unwrap();
        let error = wrong_org
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);

        let mut wrong_network = client(address, "cw_test").coordinate().await.unwrap();
        let mut wrong_network_hello = hello(MeshCoordinateRole::Dial);
        wrong_network_hello.network_id = "network-other".to_owned();
        wrong_network
            .send(request(wrong_network_hello))
            .await
            .unwrap();
        let error = wrong_network
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::NotFound);
        server.abort();
    }

    #[tokio::test]
    async fn typed_coordinate_explicitly_admits_native_grpc() {
        let (address, server) = start().await;
        let mut peer = client_with_protocol(address, "environment-token", Protocol::Grpc)
            .coordinate()
            .await
            .unwrap();
        peer.send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        assert!(matches!(
            response(&mut peer).await.msg,
            Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(
                _
            ))
        ));
        server.abort();
    }
}
