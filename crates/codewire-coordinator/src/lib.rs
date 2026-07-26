//! Rust implementation of the standalone tailnet coordinate service.
//!
//! This crate preserves the WebSocket/JSON surface from the original Go
//! coordinator. It supports the same optional NATS/KV cross-replica plane
//! while preserving a no-NATS mode for local contract tests.

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_nats::jetstream;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use codewire_server_core::auth::{
    AuthState, AuthUser, Authentication, CredentialContext, require_auth,
};
use codewire_tailnet::node::Node;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

mod connect;
mod session;
mod sidecar_token;

use session::{
    SessionInput, SessionOutput, SessionPeer, SessionSink, SessionSource, run_peer_session,
};

const SCOPE_COORDINATE: &str = "coordinate";
const COORDINATOR_BUCKET: &str = "coordinator-nodes";
const COORDINATOR_BUCKET_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const SIDECAR_KV_REFRESH: Duration = Duration::from_secs(5 * 60);
const WEBSOCKET_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Shared coordinator service state.
#[derive(Clone)]
pub struct CoordinatorState {
    pool: PgPool,
    session_secret: Arc<str>,
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
}

impl CoordinatorState {
    /// Construct coordinator state from the shared database pool and session
    /// secret used to verify sidecar coordinate tokens.
    pub fn new(pool: PgPool, session_secret: String) -> Self {
        Self {
            pool,
            session_secret: Arc::from(session_secret),
            peers: Arc::new(PeerRegistry::default()),
            coordination: None,
        }
    }

    /// Attach the optional cross-replica NATS/JetStream plane.
    pub async fn with_nats_client(mut self, client: async_nats::Client) -> anyhow::Result<Self> {
        self.coordination = Some(CoordinationPlane::setup(client).await?);
        Ok(self)
    }
}

#[derive(Clone)]
struct CoordinationPlane {
    client: async_nats::Client,
    kv: jetstream::kv::Store,
}

impl CoordinationPlane {
    async fn setup(client: async_nats::Client) -> anyhow::Result<Arc<Self>> {
        let js = jetstream::new(client.clone());
        let kv = match js.get_key_value(COORDINATOR_BUCKET).await {
            Ok(kv) => kv,
            Err(get_err) => match js
                .create_key_value(jetstream::kv::Config {
                    bucket: COORDINATOR_BUCKET.to_string(),
                    description:
                        "Latest sidecar WireGuard node per environment (cross-replica coordinator)"
                            .to_string(),
                    max_age: COORDINATOR_BUCKET_TTL,
                    ..Default::default()
                })
                .await
            {
                Ok(kv) => kv,
                Err(create_err) => js.get_key_value(COORDINATOR_BUCKET).await.map_err(|retry_err| {
                    anyhow::anyhow!(
                        "setup coordinator KV failed: get={get_err}; create={create_err}; retry={retry_err}"
                    )
                })?,
            },
        };
        Ok(Arc::new(Self { client, kv }))
    }

    async fn subscribe_agent(&self, env_id: Uuid) -> anyhow::Result<async_nats::Subscriber> {
        self.subscribe(agent_subject(env_id)).await
    }

    async fn subscribe_clients(&self, env_id: Uuid) -> anyhow::Result<async_nats::Subscriber> {
        self.subscribe(clients_subject(env_id)).await
    }

    async fn subscribe_remove(&self, env_id: Uuid) -> anyhow::Result<async_nats::Subscriber> {
        self.subscribe(remove_subject(env_id)).await
    }

    async fn subscribe(&self, subject: String) -> anyhow::Result<async_nats::Subscriber> {
        let sub = self.client.subscribe(subject).await?;
        self.client.flush().await?;
        Ok(sub)
    }

    async fn publish_client_node(&self, env_id: Uuid, node: &Node) -> anyhow::Result<()> {
        self.publish_node(clients_subject(env_id), node).await
    }

    async fn publish_sidecar_node(&self, env_id: Uuid, node: &Node) -> anyhow::Result<()> {
        self.publish_node(agent_subject(env_id), node).await
    }

    async fn publish_node(&self, subject: String, node: &Node) -> anyhow::Result<()> {
        let data = serde_json::to_vec(node)?;
        self.client.publish(subject, Bytes::from(data)).await?;
        Ok(())
    }

    async fn publish_remove(&self, env_id: Uuid, peer_id: Uuid) -> anyhow::Result<()> {
        self.client
            .publish(remove_subject(env_id), Bytes::from(peer_id.to_string()))
            .await?;
        Ok(())
    }

    async fn put_sidecar_node(&self, env_id: Uuid, node: &Node) -> anyhow::Result<()> {
        let data = serde_json::to_vec(node)?;
        self.kv
            .put(sidecar_key(env_id), Bytes::from(data))
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    async fn get_sidecar_node(&self, env_id: Uuid) -> anyhow::Result<Option<Node>> {
        let Some(data) = self.kv.get(sidecar_key(env_id)).await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&data)?))
    }
}

fn agent_subject(env_id: Uuid) -> String {
    format!("coord.agent.{env_id}")
}

fn clients_subject(env_id: Uuid) -> String {
    format!("coord.clients.{env_id}")
}

fn remove_subject(env_id: Uuid) -> String {
    format!("coord.remove.{env_id}")
}

fn sidecar_key(env_id: Uuid) -> String {
    format!("env.{env_id}.sidecar")
}

/// Build the Rust coordinator's route surface on the same paths as the Go
/// coordinator.
pub fn router(state: CoordinatorState, auth: AuthState) -> Router {
    router_with_connect(state, auth, connect::enabled())
}

fn router_with_connect(state: CoordinatorState, auth: AuthState, serve_connect: bool) -> Router {
    let client = Router::new()
        .route(
            "/api/v1/organizations/{org_id}/environments/{env_id}/coordinate",
            get(client_coordinate),
        )
        .route_layer(middleware::from_fn_with_state(auth.clone(), require_auth));

    let sidecar = Router::new().route(
        "/api/v1/internal/gateway/coordinate",
        get(sidecar_coordinate),
    );

    let app = client.merge(sidecar);
    let app = if serve_connect {
        let connect_routes: Router<CoordinatorState> =
            connect::router(state.clone(), auth).with_state(());
        app.merge(connect_routes)
    } else {
        app
    };
    app.with_state(state)
}

#[derive(Debug, Deserialize)]
struct SidecarQuery {
    sidecar_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoordinateMsg {
    #[serde(rename = "type")]
    typ: String,
    node: Option<Node>,
}

#[derive(Debug, Serialize)]
struct CoordinateResp {
    #[serde(rename = "type")]
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    nodes: Option<Vec<Node>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn json_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

fn text_error(status: StatusCode, detail: &'static str) -> Response {
    (status, detail).into_response()
}

async fn client_coordinate(
    State(state): State<CoordinatorState>,
    Path((org_id, env_id)): Path<(String, String)>,
    user: AuthUser,
    credential: CredentialContext,
    ws: WebSocketUpgrade,
) -> Response {
    let authentication = Authentication { user, credential };
    let sidecar_id = match authorize_client(&state, &authentication, &org_id, &env_id).await {
        Ok(sidecar_id) => sidecar_id,
        Err(resp) => return resp,
    };
    let client_id = Uuid::new_v4();
    ws.protocols(["coordinate"]).on_upgrade(move |socket| {
        run_peer_socket(
            socket,
            state.peers.clone(),
            state.coordination.clone(),
            client_id,
            Some(sidecar_id),
            PeerKind::Client,
        )
    })
}

async fn sidecar_coordinate(
    State(state): State<CoordinatorState>,
    req: axum::extract::Request,
) -> Response {
    let (mut parts, _body) = req.into_parts();
    let query = match Query::<SidecarQuery>::from_request_parts(&mut parts, &state).await {
        Ok(Query(query)) => query,
        Err(_) => {
            return json_error(StatusCode::BAD_REQUEST, "sidecar_id required");
        }
    };

    let sidecar_id = match query.sidecar_id.as_deref().map(str::trim) {
        Some("") | None => {
            return json_error(StatusCode::BAD_REQUEST, "sidecar_id required");
        }
        Some(raw) => match Uuid::parse_str(raw) {
            Ok(id) => id,
            Err(_) => {
                return json_error(StatusCode::BAD_REQUEST, "invalid sidecar_id");
            }
        },
    };

    let token = match bearer_token(&parts.headers) {
        Some(token) => token,
        None => {
            return json_error(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    };

    if let Err(resp) = authorize_sidecar(&state, sidecar_id, token).await {
        return resp;
    }

    let ws = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(ws) => ws,
        Err(rejection) => return rejection.into_response(),
    };
    ws.protocols(["coordinate"]).on_upgrade(move |socket| {
        run_peer_socket(
            socket,
            state.peers.clone(),
            state.coordination.clone(),
            sidecar_id,
            None,
            PeerKind::Sidecar,
        )
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

async fn authorize_client(
    state: &CoordinatorState,
    authentication: &Authentication,
    org_id: &str,
    env_id: &str,
) -> Result<Uuid, Response> {
    let user = &authentication.user;
    let role = match get_user_org_role(&state.pool, org_id, user).await {
        Ok(role) => role,
        Err(sqlx::Error::RowNotFound) => {
            return Err(text_error(StatusCode::NOT_FOUND, "organization not found"));
        }
        Err(err) => {
            tracing::error!(error = ?err, "coordinator org role lookup failed");
            return Err(text_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    require_environment_access(&state.pool, env_id, &user.user_id, &role).await?;

    let row: Option<(String, String)> = match sqlx::query_as(
        r#"
        SELECT state, type
          FROM environments
         WHERE id = $1
           AND org_id = $2
        "#,
    )
    .bind(env_id)
    .bind(org_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(err) => {
            tracing::error!(error = ?err, "coordinator environment lookup failed");
            return Err(text_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    let Some((env_state, env_type)) = row else {
        return Err(text_error(StatusCode::NOT_FOUND, "environment not found"));
    };
    if env_state != "running" {
        return Err(text_error(
            StatusCode::BAD_REQUEST,
            "environment must be running",
        ));
    }
    if env_type != "sandbox" {
        return Err(text_error(
            StatusCode::BAD_REQUEST,
            "only supported for sandbox environments",
        ));
    }

    Uuid::parse_str(env_id)
        .map_err(|_| text_error(StatusCode::BAD_REQUEST, "invalid environment id"))
}

async fn get_user_org_role(
    pool: &PgPool,
    org_id: &str,
    user: &AuthUser,
) -> Result<String, sqlx::Error> {
    if let Some(api_key_org_id) = user.org_id.as_deref()
        && api_key_org_id != org_id
    {
        return Err(sqlx::Error::RowNotFound);
    }

    sqlx::query_scalar(
        r#"
        SELECT role
          FROM org_members
         WHERE org_id = $1
           AND user_id = $2
        "#,
    )
    .bind(org_id)
    .bind(&user.user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(sqlx::Error::RowNotFound)
}

async fn require_environment_access(
    pool: &PgPool,
    env_id: &str,
    user_id: &str,
    role: &str,
) -> Result<(), Response> {
    let created_by: Option<String> =
        match sqlx::query_scalar("SELECT created_by FROM environments WHERE id = $1")
            .bind(env_id)
            .fetch_optional(pool)
            .await
        {
            Ok(row) => row,
            Err(err) => {
                tracing::error!(error = ?err, "coordinator creator lookup failed");
                return Err(text_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                ));
            }
        };

    let Some(created_by) = created_by else {
        return Err(text_error(StatusCode::NOT_FOUND, "environment not found"));
    };
    if created_by == user_id || role == "owner" || role == "admin" {
        return Ok(());
    }

    let permission: Option<String> = match sqlx::query_scalar(
        r#"
        SELECT permission
          FROM environment_access
         WHERE environment_id = $1
           AND user_id = $2
        "#,
    )
    .bind(env_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        Err(err) => {
            tracing::error!(error = ?err, "coordinator access lookup failed");
            return Err(text_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    if permission.as_deref().map(permission_level).unwrap_or(0) < permission_level("operator") {
        return Err(json_error(StatusCode::FORBIDDEN, "access denied"));
    }

    Ok(())
}

fn permission_level(permission: &str) -> i32 {
    match permission {
        "viewer" => 1,
        "operator" => 2,
        "owner" => 3,
        _ => 0,
    }
}

async fn authorize_sidecar(
    state: &CoordinatorState,
    sidecar_id: Uuid,
    token: &str,
) -> Result<(), Response> {
    let claims = sidecar_token::validate(&state.session_secret, token)
        .map_err(|_| json_error(StatusCode::UNAUTHORIZED, "invalid sidecar token"))?;
    if claims.scope != SCOPE_COORDINATE {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "invalid sidecar token scope",
        ));
    }

    let env_id: Option<String> = match sqlx::query_scalar(
        r#"
        SELECT id
          FROM environments
         WHERE id = $1
           AND state NOT IN ('destroyed', 'destroying')
        "#,
    )
    .bind(&claims.environment_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(env_id) => env_id,
        Err(err) => {
            tracing::error!(error = ?err, "coordinator sidecar environment lookup failed");
            return Err(text_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error",
            ));
        }
    };

    let Some(env_id) = env_id else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "invalid or expired sidecar token",
        ));
    };
    if env_id != sidecar_id.to_string() {
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "sidecar_id does not match token",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PeerKind {
    Client,
    Sidecar,
}

#[derive(Clone, Copy)]
enum Transport {
    WebSocket,
    Connect,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::WebSocket => "ws",
            Self::Connect => "connect",
        }
    }
}

impl PeerKind {
    fn as_str(self) -> &'static str {
        match self {
            PeerKind::Client => "client",
            PeerKind::Sidecar => "sidecar",
        }
    }
}

async fn run_peer_socket(
    socket: WebSocket,
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
    peer_id: Uuid,
    sidecar_id: Option<Uuid>,
    kind: PeerKind,
) {
    let env_id = sidecar_id.unwrap_or(peer_id);
    let (sender, receiver) = socket.split();
    run_peer_session(
        WebSocketSource { receiver, peer_id },
        WebSocketSink {
            sender,
            env_id,
            peer_id,
            kind,
        },
        peers,
        coordination,
        SessionPeer {
            peer_id,
            sidecar_id,
            kind,
            transport: Transport::WebSocket,
        },
    )
    .await;
}

struct WebSocketSource {
    receiver: futures_util::stream::SplitStream<WebSocket>,
    peer_id: Uuid,
}

impl SessionSource for WebSocketSource {
    async fn next(&mut self) -> Option<SessionInput> {
        match self.receiver.next().await {
            Some(Ok(message)) => decode_websocket_frame(message),
            None => None,
            Some(Err(err)) => {
                tracing::warn!(
                    error = ?err,
                    peer_id = %self.peer_id,
                    "coordinator websocket read failed"
                );
                None
            }
        }
    }
}

fn decode_websocket_frame(message: Message) -> Option<SessionInput> {
    match message {
        Message::Text(text) => Some(
            decode_peer_frame(text.as_bytes())
                .map(SessionInput::Node)
                .unwrap_or(SessionInput::Noop),
        ),
        Message::Binary(bytes) => Some(
            decode_peer_frame(&bytes)
                .map(SessionInput::Node)
                .unwrap_or(SessionInput::Noop),
        ),
        Message::Ping(_) => Some(SessionInput::Ping),
        Message::Pong(_) => Some(SessionInput::Noop),
        Message::Close(_) => None,
    }
}

struct WebSocketSink {
    sender: futures_util::stream::SplitSink<WebSocket, Message>,
    env_id: Uuid,
    peer_id: Uuid,
    kind: PeerKind,
}

impl SessionSink for WebSocketSink {
    async fn send(&mut self, output: SessionOutput) -> bool {
        match output {
            SessionOutput::DerpMap(derp_map) => {
                let response = CoordinateResp {
                    typ: "derp_map",
                    nodes: None,
                    peer_id: None,
                    derp_map: Some(derp_map),
                };
                if let Err(err) = send_response(&mut self.sender, response).await {
                    tracing::warn!(
                        error = ?err,
                        peer_id = %self.peer_id,
                        "coordinator derp_map send failed"
                    );
                    return false;
                }
                true
            }
            SessionOutput::Peer(event) => send_response(&mut self.sender, event.into_response())
                .await
                .is_ok(),
            SessionOutput::Heartbeat => {
                if let Err(err) = self.sender.send(Message::Ping(Bytes::new())).await {
                    tracing::warn!(
                        error = ?err,
                        env_id = %self.env_id,
                        peer_id = %self.peer_id,
                        kind = self.kind.as_str(),
                        "coordinator websocket heartbeat failed"
                    );
                    return false;
                }
                true
            }
        }
    }
}

fn decode_peer_frame(data: &[u8]) -> Option<Node> {
    let Ok(msg) = serde_json::from_slice::<CoordinateMsg>(data) else {
        return None;
    };
    if msg.typ != "node" {
        return None;
    }
    msg.node
}

#[cfg(test)]
fn handle_peer_frame(peers: &PeerRegistry, peer_id: Uuid, data: &[u8]) -> Option<Node> {
    let mut node = decode_peer_frame(data)?;
    node.id = peer_id;
    peers.update_node(peer_id, node.clone());
    Some(node)
}

fn spawn_node_subscription(
    mut sub: async_nats::Subscriber,
    tx: mpsc::UnboundedSender<PeerEvent>,
    env_id: Uuid,
    source: &'static str,
) {
    tokio::spawn(async move {
        while let Some(msg) = sub.next().await {
            match serde_json::from_slice::<Node>(msg.payload.as_ref()) {
                Ok(node) => {
                    log_node(
                        "coordinator NATS node received",
                        env_id,
                        node.id,
                        if source == "agent" {
                            PeerKind::Sidecar
                        } else {
                            PeerKind::Client
                        },
                        &node,
                        None,
                    );
                    let _ = tx.send(PeerEvent::Update(vec![node]));
                }
                Err(err) => {
                    tracing::warn!(error = ?err, %env_id, source, "coordinator NATS node decode failed");
                }
            }
        }
    });
}

fn spawn_remove_subscription(
    mut sub: async_nats::Subscriber,
    tx: mpsc::UnboundedSender<PeerEvent>,
    env_id: Uuid,
) {
    tokio::spawn(async move {
        while let Some(msg) = sub.next().await {
            let Ok(peer_id) = std::str::from_utf8(msg.payload.as_ref()) else {
                tracing::warn!(%env_id, "coordinator NATS remove payload was not UTF-8");
                continue;
            };
            match Uuid::parse_str(peer_id) {
                Ok(peer_id) => {
                    tracing::info!(
                        %env_id,
                        %peer_id,
                        "coordinator NATS peer remove received"
                    );
                    let _ = tx.send(PeerEvent::Remove(peer_id));
                }
                Err(err) => {
                    tracing::warn!(error = ?err, %env_id, "coordinator NATS remove payload was not a UUID");
                }
            }
        }
    });
}

async fn send_response(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    resp: CoordinateResp,
) -> Result<(), axum::Error> {
    let payload = serde_json::to_string(&resp).map_err(axum::Error::new)?;
    sender.send(Message::Text(payload.into())).await
}

#[derive(Clone, Debug)]
struct DerpMapConfig {
    derp_host: String,
    derp_port: u16,
    derp_insecure: bool,
    stun_servers: Vec<StunServerConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StunServerConfig {
    host: String,
    port: u16,
}

fn derp_map_config_from_env() -> DerpMapConfig {
    let stun_port = env_port("STUN_PORT", 3478);
    let mut stun_servers = Vec::new();
    if let Some(host) = env_string("STUN_HOST") {
        push_stun_server(
            &mut stun_servers,
            StunServerConfig {
                host,
                port: stun_port,
            },
        );
    }
    if let Some(raw) = env_string("STUN_SERVERS") {
        for entry in raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            if let Some(server) = parse_stun_server_entry(entry, 3478) {
                push_stun_server(&mut stun_servers, server);
            }
        }
    }

    DerpMapConfig {
        derp_host: env_string("DERP_HOST").unwrap_or_else(|| "derp.codewire.sh".to_string()),
        derp_port: env_port("DERP_PORT", 443),
        derp_insecure: env_bool("DERP_INSECURE"),
        stun_servers,
    }
}

fn push_stun_server(servers: &mut Vec<StunServerConfig>, server: StunServerConfig) {
    if !servers
        .iter()
        .any(|existing| existing.host == server.host && existing.port == server.port)
    {
        servers.push(server);
    }
}

fn parse_stun_server_entry(value: &str, default_port: u16) -> Option<StunServerConfig> {
    let value = value
        .strip_prefix("stun://")
        .or_else(|| value.strip_prefix("stun:"))
        .unwrap_or(value)
        .trim();
    if value.is_empty() {
        return None;
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port.parse::<u16>().ok().filter(|port| *port != 0)?,
            None if rest.is_empty() => default_port,
            _ => return None,
        };
        return Some(StunServerConfig {
            host: host.into(),
            port,
        });
    }

    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) => {
            (host, port.parse::<u16>().ok().filter(|port| *port != 0)?)
        }
        _ => (value, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some(StunServerConfig {
        host: host.into(),
        port,
    })
}

fn env_string(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_port(name: &str, default: u16) -> u16 {
    env_string(name)
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|v| *v != 0)
        .unwrap_or(default)
}

fn env_bool(name: &str) -> bool {
    env_string(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn build_derp_map(cfg: DerpMapConfig) -> serde_json::Value {
    let mut nodes = vec![json!({
        "Name": "1a",
        "RegionID": 1,
        "HostName": cfg.derp_host,
        "DERPPort": cfg.derp_port,
        "STUNPort": -1,
        "InsecureForTests": cfg.derp_insecure,
    })];

    for (idx, server) in cfg.stun_servers.iter().enumerate() {
        nodes.push(json!({
            "Name": if idx == 0 { "1s".to_string() } else { format!("1s{}", idx + 1) },
            "RegionID": 1,
            "HostName": server.host,
            "STUNOnly": true,
            "STUNPort": server.port,
        }));
    }

    json!({
        "Regions": {
            "1": {
                "RegionID": 1,
                "RegionCode": "cw",
                "RegionName": "Codewire Embedded",
                "Nodes": nodes,
            }
        }
    })
}

#[derive(Clone, Debug)]
enum PeerEvent {
    Update(Vec<Node>),
    Remove(Uuid),
}

impl PeerEvent {
    fn log_send(
        &self,
        env_id: Uuid,
        target_id: Uuid,
        target_kind: PeerKind,
        source: &'static str,
        transport: Transport,
    ) {
        match self {
            PeerEvent::Update(nodes) => {
                tracing::info!(
                    %env_id,
                    %target_id,
                    target_kind = target_kind.as_str(),
                    source,
                    transport = transport.as_str(),
                    node_count = nodes.len(),
                    "coordinator peer_update sent"
                );
                let node_kind = match target_kind {
                    PeerKind::Client => PeerKind::Sidecar,
                    PeerKind::Sidecar => PeerKind::Client,
                };
                for node in nodes {
                    log_node(
                        "coordinator peer_update node",
                        env_id,
                        node.id,
                        node_kind,
                        node,
                        Some(transport),
                    );
                }
            }
            PeerEvent::Remove(peer_id) => {
                tracing::info!(
                    %env_id,
                    %target_id,
                    target_kind = target_kind.as_str(),
                    source,
                    transport = transport.as_str(),
                    %peer_id,
                    "coordinator peer_remove sent"
                );
            }
        }
    }

    fn into_response(self) -> CoordinateResp {
        match self {
            PeerEvent::Update(nodes) => CoordinateResp {
                typ: "peer_update",
                nodes: Some(nodes),
                peer_id: None,
                derp_map: None,
            },
            PeerEvent::Remove(peer_id) => CoordinateResp {
                typ: "peer_remove",
                nodes: None,
                peer_id: Some(peer_id.to_string()),
                derp_map: None,
            },
        }
    }
}

fn log_node(
    message: &'static str,
    env_id: Uuid,
    peer_id: Uuid,
    kind: PeerKind,
    node: &Node,
    transport: Option<Transport>,
) {
    if let Some(transport) = transport {
        tracing::info!(
            %env_id,
            %peer_id,
            kind = kind.as_str(),
            transport = transport.as_str(),
            preferred_derp = node.preferred_derp,
            endpoint_count = node.endpoints.len(),
            address_count = node.addresses.len(),
            endpoints = ?node.endpoints,
            addresses = ?node.addresses,
            "{}",
            message
        );
    } else {
        tracing::info!(
            %env_id,
            %peer_id,
            kind = kind.as_str(),
            preferred_derp = node.preferred_derp,
            endpoint_count = node.endpoints.len(),
            address_count = node.addresses.len(),
            endpoints = ?node.endpoints,
            addresses = ?node.addresses,
            "{}",
            message
        );
    }
}

#[derive(Default)]
struct PeerRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    peers: HashMap<Uuid, Peer>,
    tunnels: HashMap<Uuid, Uuid>,
}

struct Peer {
    node: Option<Node>,
    tx: mpsc::UnboundedSender<PeerEvent>,
}

impl PeerRegistry {
    fn register(&self, id: Uuid) -> mpsc::UnboundedReceiver<PeerEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.peers.insert(id, Peer { node: None, tx });
        Self::send_all_client_peers(&inner, id);
        rx
    }

    fn add_tunnel(&self, client_id: Uuid, sidecar_id: Uuid) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.tunnels.insert(client_id, sidecar_id);

        if let Some(agent_node) = inner
            .peers
            .get(&sidecar_id)
            .and_then(|peer| peer.node.clone())
            && let Some(client) = inner.peers.get(&client_id)
        {
            let _ = client.tx.send(PeerEvent::Update(vec![agent_node]));
        }
        Self::send_all_client_peers(&inner, sidecar_id);
    }

    fn update_node(&self, id: Uuid, node: Node) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(peer) = inner.peers.get_mut(&id) else {
            return;
        };
        peer.node = Some(node.clone());

        let tunnels: Vec<(Uuid, Uuid)> = inner
            .tunnels
            .iter()
            .map(|(src, dst)| (*src, *dst))
            .collect();
        for (src, dst) in tunnels {
            if src == id {
                Self::send_all_client_peers(&inner, dst);
            }
            if dst == id
                && let Some(client) = inner.peers.get(&src)
            {
                let _ = client.tx.send(PeerEvent::Update(vec![node.clone()]));
            }
        }
    }

    fn deregister(&self, id: Uuid) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.peers.remove(&id);

        let tunnels: Vec<(Uuid, Uuid)> = inner
            .tunnels
            .iter()
            .map(|(src, dst)| (*src, *dst))
            .collect();
        for (src, dst) in tunnels {
            if src == id {
                inner.tunnels.remove(&src);
                if let Some(peer) = inner.peers.get(&dst) {
                    let _ = peer.tx.send(PeerEvent::Remove(id));
                }
            } else if dst == id
                && let Some(peer) = inner.peers.get(&src)
            {
                // Keep the association while the client remains connected so
                // a replacement sidecar can immediately receive its node.
                let _ = peer.tx.send(PeerEvent::Remove(id));
            }
        }
    }

    fn send_all_client_peers(inner: &RegistryInner, sidecar_id: Uuid) {
        let Some(sidecar) = inner.peers.get(&sidecar_id) else {
            return;
        };
        let nodes: Vec<Node> = inner
            .tunnels
            .iter()
            .filter_map(|(client_id, dst)| {
                if *dst == sidecar_id {
                    inner
                        .peers
                        .get(client_id)
                        .and_then(|peer| peer.node.clone())
                } else {
                    None
                }
            })
            .collect();
        if !nodes.is_empty() {
            let _ = sidecar.tx.send(PeerEvent::Update(nodes));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use codewire_tailnet::coordinator::Handlers;
    use codewire_tailnet::coordinator_connect::{CoordinatorConnectClient, HelloIdentity};
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use futures_util::Stream;
    use sqlx::postgres::PgPoolOptions;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct TestPeerState {
        peers: Arc<PeerRegistry>,
        coordination: Option<Arc<CoordinationPlane>>,
        peer_id: Uuid,
        sidecar_id: Option<Uuid>,
        kind: PeerKind,
    }

    #[derive(Debug, Deserialize)]
    struct TestCoordinateResp {
        #[serde(rename = "type")]
        typ: String,
        #[serde(default)]
        nodes: Vec<Node>,
        #[serde(default)]
        peer_id: Option<String>,
        #[serde(default)]
        derp_map: Option<serde_json::Value>,
    }

    fn lazy_pool() -> PgPool {
        PgPoolOptions::new()
            .connect_lazy("postgres://codewire:codewire@127.0.0.1:1/codewire")
            .unwrap()
    }

    fn test_app() -> Router {
        let pool = lazy_pool();
        let auth = AuthState { pool: pool.clone() };
        router(CoordinatorState::new(pool, "secret".into()), auth)
    }

    async fn body_text(resp: Response) -> String {
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
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

    async fn test_peer_coordinate(
        State(state): State<TestPeerState>,
        ws: WebSocketUpgrade,
    ) -> Response {
        ws.protocols(["coordinate"]).on_upgrade(move |socket| {
            run_peer_socket(
                socket,
                state.peers,
                state.coordination,
                state.peer_id,
                state.sidecar_id,
                state.kind,
            )
        })
    }

    async fn spawn_test_peer(
        port: u16,
        state: TestPeerState,
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/coordinate", get(test_peer_coordinate))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, task)
    }

    async fn spawn_test_connect_peer(
        state: CoordinatorState,
        client_peer_id: Uuid,
    ) -> (std::net::SocketAddr, JoinHandle<()>) {
        let app = codewire_server_core::AppBuilder::new("coordinator-cross-replica-connect-test")
            .with_routes(connect::fixed_test_router(state, client_peer_id))
            .into_router();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
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
        (addr, task)
    }

    async fn wait_connect_derp_map(client: &mut CoordinatorConnectClient) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut tx = Some(tx);
        let run = client.run(Handlers {
            on_peers: |_: &[Node]| {},
            on_derp_map: move |_: &serde_json::Value| {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(());
                }
            },
        });
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => panic!("Connect stream ended before derp_map: {result:?}"),
            result = rx => result.expect("DERP-map callback sender dropped"),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timed out waiting for Connect derp_map"),
        }
    }

    async fn wait_connect_peer(client: &mut CoordinatorConnectClient, expected_id: Uuid) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut tx = Some(tx);
        let run = client.run(Handlers {
            on_peers: move |nodes: &[Node]| {
                if nodes.iter().any(|node| node.id == expected_id)
                    && let Some(tx) = tx.take()
                {
                    let _ = tx.send(());
                }
            },
            on_derp_map: |_: &serde_json::Value| {},
        });
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => panic!("Connect stream ended before peer update: {result:?}"),
            result = rx => result.expect("peer callback sender dropped"),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("timed out waiting for Connect peer {expected_id}"),
        }
    }

    async fn connect_test_ws(
        addr: std::net::SocketAddr,
    ) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
        let mut request = format!("ws://{addr}/coordinate")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("coordinate"),
        );
        let (ws, resp) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some("coordinate")
        );
        ws
    }

    async fn next_coord_resp<S>(ws: &mut S) -> TestCoordinateResp
    where
        S: Stream<Item = Result<ClientMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match frame {
            ClientMessage::Text(text) => serde_json::from_slice(text.as_bytes()).unwrap(),
            ClientMessage::Binary(data) => serde_json::from_slice(&data).unwrap(),
            other => panic!("unexpected websocket frame: {other:?}"),
        }
    }

    async fn read_until_peer_update<S>(ws: &mut S, expected_id: Uuid) -> Vec<Node>
    where
        S: Stream<Item = Result<ClientMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        loop {
            let resp = next_coord_resp(ws).await;
            if resp.typ == "peer_update" && resp.nodes.iter().any(|node| node.id == expected_id) {
                return resp.nodes;
            }
        }
    }

    async fn read_until_peer_remove<S>(ws: &mut S, expected_id: Uuid) -> String
    where
        S: Stream<Item = Result<ClientMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        loop {
            let resp = next_coord_resp(ws).await;
            if resp.typ == "peer_remove"
                && resp.peer_id.as_deref() == Some(&expected_id.to_string())
            {
                return resp.peer_id.unwrap();
            }
        }
    }

    fn node_frame(node: &Node) -> ClientMessage {
        ClientMessage::Text(
            serde_json::json!({
                "type": "node",
                "node": node,
            })
            .to_string()
            .into(),
        )
    }

    #[test]
    fn derp_map_contains_relay_region_for_go_tailcfg() {
        let derp_map = build_derp_map(DerpMapConfig {
            derp_host: "derp.example.com".into(),
            derp_port: 443,
            derp_insecure: false,
            stun_servers: Vec::new(),
        });

        let relay = &derp_map["Regions"]["1"]["Nodes"][0];
        assert_eq!(relay["Name"], "1a");
        assert_eq!(relay["RegionID"], 1);
        assert_eq!(relay["HostName"], "derp.example.com");
        assert_eq!(relay["DERPPort"], 443);
        assert_eq!(relay["STUNPort"], -1);
        assert_eq!(relay["InsecureForTests"], false);
    }

    #[test]
    fn derp_map_adds_stun_node_when_configured() {
        let derp_map = build_derp_map(DerpMapConfig {
            derp_host: "derp.example.com".into(),
            derp_port: 8443,
            derp_insecure: true,
            stun_servers: vec![StunServerConfig {
                host: "stun.example.com".into(),
                port: 3478,
            }],
        });

        let nodes = derp_map["Regions"]["1"]["Nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["HostName"], "derp.example.com");
        assert_eq!(nodes[0]["DERPPort"], 8443);
        assert_eq!(nodes[0]["InsecureForTests"], true);
        assert_eq!(nodes[1]["Name"], "1s");
        assert_eq!(nodes[1]["HostName"], "stun.example.com");
        assert_eq!(nodes[1]["STUNOnly"], true);
        assert_eq!(nodes[1]["STUNPort"], 3478);
    }

    #[test]
    fn derp_map_adds_multiple_stun_nodes_when_configured() {
        let derp_map = build_derp_map(DerpMapConfig {
            derp_host: "derp.example.com".into(),
            derp_port: 443,
            derp_insecure: false,
            stun_servers: vec![
                StunServerConfig {
                    host: "stun.codewire-dev.sh".into(),
                    port: 3478,
                },
                StunServerConfig {
                    host: "stun.l.google.com".into(),
                    port: 19302,
                },
            ],
        });

        let nodes = derp_map["Regions"]["1"]["Nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[1]["Name"], "1s");
        assert_eq!(nodes[1]["HostName"], "stun.codewire-dev.sh");
        assert_eq!(nodes[1]["STUNPort"], 3478);
        assert_eq!(nodes[2]["Name"], "1s2");
        assert_eq!(nodes[2]["HostName"], "stun.l.google.com");
        assert_eq!(nodes[2]["STUNPort"], 19302);
    }

    #[test]
    fn coordination_subjects_match_go_contract() {
        let env_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        assert_eq!(
            agent_subject(env_id),
            "coord.agent.12345678-1234-5678-1234-567812345678"
        );
        assert_eq!(
            clients_subject(env_id),
            "coord.clients.12345678-1234-5678-1234-567812345678"
        );
        assert_eq!(
            remove_subject(env_id),
            "coord.remove.12345678-1234-5678-1234-567812345678"
        );
        assert_eq!(
            sidecar_key(env_id),
            "env.12345678-1234-5678-1234-567812345678.sidecar"
        );
    }

    #[tokio::test]
    async fn peer_frame_returns_node_for_cross_replica_publish() {
        let registry = PeerRegistry::default();
        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let _client_rx = registry.register(client_id);
        let mut incoming = sample_node(Uuid::new_v4(), 3);
        incoming.preferred_derp = 7;
        let payload = serde_json::json!({
            "type": "node",
            "node": incoming,
        });

        let got = handle_peer_frame(
            &registry,
            client_id,
            serde_json::to_vec(&payload).unwrap().as_ref(),
        )
        .unwrap();

        assert_eq!(got.id, client_id);
        assert_eq!(got.preferred_derp, 7);
    }

    #[test]
    fn websocket_adapter_yields_for_ignored_open_frames() {
        for frame in [
            Message::Text("not-json".into()),
            Message::Binary(Bytes::from_static(b"not-json")),
            Message::Pong(Bytes::new()),
        ] {
            assert!(matches!(
                decode_websocket_frame(frame),
                Some(SessionInput::Noop)
            ));
        }

        assert!(matches!(
            decode_websocket_frame(Message::Ping(Bytes::new())),
            Some(SessionInput::Ping)
        ));
        assert!(decode_websocket_frame(Message::Close(None)).is_none());
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn coordination_plane_round_trips_nats_and_kv() {
        let nats_url =
            std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
        let client = async_nats::connect(nats_url).await.unwrap();
        let plane = CoordinationPlane::setup(client).await.unwrap();

        let env_id = Uuid::new_v4();
        let sidecar_node = sample_node(env_id, 11);
        plane.put_sidecar_node(env_id, &sidecar_node).await.unwrap();
        let got = plane.get_sidecar_node(env_id).await.unwrap().unwrap();
        assert_eq!(got.id, env_id);
        assert_eq!(got.preferred_derp, 11);

        let mut agent_sub = plane.subscribe_agent(env_id).await.unwrap();
        plane
            .publish_sidecar_node(env_id, &sidecar_node)
            .await
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(5), agent_sub.next())
            .await
            .unwrap()
            .unwrap();
        let got: Node = serde_json::from_slice(msg.payload.as_ref()).unwrap();
        assert_eq!(got.id, env_id);

        let client_id = Uuid::new_v4();
        let mut remove_sub = plane.subscribe_remove(env_id).await.unwrap();
        plane.publish_remove(env_id, client_id).await.unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(5), remove_sub.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            std::str::from_utf8(msg.payload.as_ref()).unwrap(),
            client_id.to_string()
        );

        plane.kv.delete(sidecar_key(env_id)).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn mixed_transport_cross_replica_fanout_round_trips_over_nats() {
        let nats_url =
            std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
        let sidecar_plane =
            CoordinationPlane::setup(async_nats::connect(nats_url.clone()).await.unwrap())
                .await
                .unwrap();
        let client_plane = CoordinationPlane::setup(async_nats::connect(nats_url).await.unwrap())
            .await
            .unwrap();

        let env_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        let sidecar_node = sample_node(env_id, 11);
        let client_node = sample_node(client_id, 7);

        let (sidecar_addr, sidecar_server) = spawn_test_peer(
            0,
            TestPeerState {
                peers: Arc::new(PeerRegistry::default()),
                coordination: Some(sidecar_plane.clone()),
                peer_id: env_id,
                sidecar_id: None,
                kind: PeerKind::Sidecar,
            },
        )
        .await;
        let mut client_state = CoordinatorState::new(lazy_pool(), "test-secret".into());
        client_state.coordination = Some(client_plane);
        let (client_addr, client_server) = spawn_test_connect_peer(client_state, client_id).await;

        let mut sidecar_ws = connect_test_ws(sidecar_addr).await;
        let mut client = CoordinatorConnectClient::connect(
            &format!("http://{client_addr}"),
            "",
            HelloIdentity::client("org-1", env_id),
        )
        .await
        .unwrap();

        let sidecar_derp = next_coord_resp(&mut sidecar_ws).await;
        assert_eq!(sidecar_derp.typ, "derp_map");
        assert!(sidecar_derp.derp_map.unwrap()["Regions"]["1"].is_object());
        wait_connect_derp_map(&mut client).await;

        sidecar_ws.send(node_frame(&sidecar_node)).await.unwrap();
        wait_connect_peer(&mut client, env_id).await;
        let kv_node = sidecar_plane
            .get_sidecar_node(env_id)
            .await
            .unwrap()
            .expect("sidecar node must be persisted in coordinator KV");
        assert_eq!(kv_node.id, env_id);
        assert_eq!(kv_node.preferred_derp, 11);

        client.update_node(&client_node).await.unwrap();
        let nodes = read_until_peer_update(&mut sidecar_ws, client_id).await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, client_id);
        assert_eq!(nodes[0].preferred_derp, 7);

        drop(client);
        assert_eq!(
            read_until_peer_remove(&mut sidecar_ws, client_id).await,
            client_id.to_string()
        );

        sidecar_ws.close(None).await.unwrap();
        sidecar_plane.kv.delete(sidecar_key(env_id)).await.ok();
        sidecar_server.abort();
        client_server.abort();
    }

    #[tokio::test]
    async fn sidecar_coordinate_requires_sidecar_id_before_upgrade() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/internal/gateway/coordinate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_text(resp).await, r#"{"error":"sidecar_id required"}"#);
    }

    #[tokio::test]
    async fn sidecar_coordinate_rejects_bad_uuid_before_auth() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/internal/gateway/coordinate?sidecar_id=not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_text(resp).await, r#"{"error":"invalid sidecar_id"}"#);
    }

    #[tokio::test]
    async fn sidecar_coordinate_requires_bearer_after_sidecar_id() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri(
                        "/api/v1/internal/gateway/coordinate?sidecar_id=00000000-0000-0000-0000-000000000002",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_text(resp).await, r#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn sidecar_coordinate_rejects_garbage_bearer_without_db() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri(
                        "/api/v1/internal/gateway/coordinate?sidecar_id=00000000-0000-0000-0000-000000000002",
                    )
                    .header(AUTHORIZATION, "Bearer not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_text(resp).await,
            r#"{"error":"invalid sidecar token"}"#
        );
    }

    #[tokio::test]
    async fn client_coordinate_requires_auth() {
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .uri(
                        "/api/v1/organizations/00000000-0000-0000-0000-000000000000/environments/00000000-0000-0000-0000-000000000001/coordinate",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn registry_exchanges_nodes_when_sidecar_registers_first() {
        let registry = PeerRegistry::default();
        let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let mut sidecar_rx = registry.register(sidecar_id);
        let mut client_rx = registry.register(client_id);
        registry.add_tunnel(client_id, sidecar_id);

        let sidecar_node = sample_node(sidecar_id, 1);
        registry.update_node(sidecar_id, sidecar_node);
        match client_rx.recv().await.unwrap() {
            PeerEvent::Update(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, sidecar_id);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let client_node = sample_node(client_id, 2);
        registry.update_node(client_id, client_node);
        match sidecar_rx.recv().await.unwrap() {
            PeerEvent::Update(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, client_id);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        registry.deregister(client_id);
        match sidecar_rx.recv().await.unwrap() {
            PeerEvent::Remove(peer_id) => assert_eq!(peer_id, client_id),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn registry_replays_published_client_when_sidecar_registers_late() {
        let registry = PeerRegistry::default();
        let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let _client_rx = registry.register(client_id);
        registry.add_tunnel(client_id, sidecar_id);

        registry.update_node(client_id, sample_node(client_id, 2));
        let mut sidecar_rx = registry.register(sidecar_id);

        match sidecar_rx.recv().await.unwrap() {
            PeerEvent::Update(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, client_id);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn registry_replays_connected_client_when_sidecar_reregisters() {
        let registry = PeerRegistry::default();
        let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let mut client_rx = registry.register(client_id);
        let mut sidecar_rx = registry.register(sidecar_id);
        registry.add_tunnel(client_id, sidecar_id);
        registry.update_node(client_id, sample_node(client_id, 2));
        assert!(matches!(
            sidecar_rx.recv().await,
            Some(PeerEvent::Update(nodes)) if nodes.len() == 1 && nodes[0].id == client_id
        ));

        registry.deregister(sidecar_id);
        assert!(matches!(
            client_rx.recv().await,
            Some(PeerEvent::Remove(peer_id)) if peer_id == sidecar_id
        ));

        let mut reconnected_sidecar_rx = registry.register(sidecar_id);
        assert!(matches!(
            reconnected_sidecar_rx.recv().await,
            Some(PeerEvent::Update(nodes)) if nodes.len() == 1 && nodes[0].id == client_id
        ));

        registry.deregister(client_id);
        assert!(matches!(
            reconnected_sidecar_rx.recv().await,
            Some(PeerEvent::Remove(peer_id)) if peer_id == client_id
        ));

        registry.deregister(sidecar_id);
        let mut final_sidecar_rx = registry.register(sidecar_id);
        assert!(final_sidecar_rx.try_recv().is_err());
    }
}
