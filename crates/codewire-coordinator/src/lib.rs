//! Rust implementation of the standalone tailnet coordinate service.
//!
//! The generated `codewire.internal.v1.CoordinatorService` owns the
//! non-browser coordination surface. The optional NATS/KV plane preserves
//! cross-replica peer state while local contract tests may run without NATS.

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_nats::jetstream;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use bytes::Bytes;
use codewire_server_core::auth::{AuthState, AuthUser, Authentication};
use codewire_tailnet::node::Node;
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

mod connect;
mod node_keys;
mod peer;
mod session;

pub use node_keys::router as derp_verify_router;

const COORDINATOR_BUCKET: &str = "coordinator-nodes";
const COORDINATOR_BUCKET_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const SIDECAR_KV_REFRESH: Duration = Duration::from_secs(5 * 60);
const COORDINATE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Shared coordinator service state.
#[derive(Clone)]
pub struct CoordinatorState {
    pool: PgPool,
    session_secret: Arc<str>,
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
    derp_map: DerpMap,
}

impl CoordinatorState {
    /// Construct coordinator state from the shared database pool, the session
    /// secret used to verify sidecar coordinate tokens, and the DERP map every
    /// session advertises.
    pub fn new(pool: PgPool, session_secret: String, derp_map: DerpMap) -> Self {
        Self {
            pool,
            session_secret: Arc::from(session_secret),
            peers: Arc::new(PeerRegistry::default()),
            coordination: None,
            derp_map,
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
    /// Node keys of live sessions on every replica (`node_keys`).
    node_keys: jetstream::kv::Store,
}

impl CoordinationPlane {
    async fn setup(client: async_nats::Client) -> anyhow::Result<Arc<Self>> {
        let js = jetstream::new(client.clone());
        let kv = key_value_bucket(
            &js,
            COORDINATOR_BUCKET,
            "Latest sidecar WireGuard node per environment (cross-replica coordinator)",
            COORDINATOR_BUCKET_TTL,
        )
        .await?;
        let node_keys = key_value_bucket(
            &js,
            node_keys::NODE_KEY_BUCKET,
            "Node keys of live coordinator sessions, for DERP client admission",
            node_keys::NODE_KEY_TTL,
        )
        .await?;
        Ok(Arc::new(Self {
            client,
            kv,
            node_keys,
        }))
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

    /// Records the environment peer's node stamped with the operation
    /// generation it proved, so a reader can ignore a node from a generation
    /// that has moved on.
    async fn put_sidecar_node(
        &self,
        env_id: Uuid,
        generation: i64,
        node: &Node,
    ) -> anyhow::Result<()> {
        let data = serde_json::to_vec(&StampedNode {
            generation,
            node: node.clone(),
        })?;
        self.kv
            .put(sidecar_key(env_id), Bytes::from(data))
            .await
            .map(|_| ())
            .map_err(Into::into)
    }

    /// The recorded environment peer node and its generation.
    async fn get_sidecar_node(&self, env_id: Uuid) -> anyhow::Result<Option<(i64, Node)>> {
        let Some(data) = self.kv.get(sidecar_key(env_id)).await? else {
            return Ok(None);
        };
        let stamped: StampedNode = serde_json::from_slice(&data)?;
        Ok(Some((stamped.generation, stamped.node)))
    }

    /// Deletes the recorded environment peer node when it is still the one
    /// stamped with `generation`, so a revoked generation leaves no node for
    /// clients to dial.
    async fn delete_sidecar_node(&self, env_id: Uuid, generation: i64) -> anyhow::Result<()> {
        if let Some((stamped, _)) = self.get_sidecar_node(env_id).await?
            && stamped <= generation
        {
            self.kv.delete(sidecar_key(env_id)).await?;
        }
        Ok(())
    }
}

async fn key_value_bucket(
    js: &jetstream::Context,
    bucket: &str,
    description: &str,
    max_age: Duration,
) -> anyhow::Result<jetstream::kv::Store> {
    match js.get_key_value(bucket).await {
        Ok(kv) => Ok(kv),
        Err(get_err) => match js
            .create_key_value(jetstream::kv::Config {
                bucket: bucket.to_string(),
                description: description.to_string(),
                max_age,
                ..Default::default()
            })
            .await
        {
            Ok(kv) => Ok(kv),
            Err(create_err) => js.get_key_value(bucket).await.map_err(|retry_err| {
                anyhow::anyhow!(
                    "setup coordinator KV {bucket} failed: get={get_err}; create={create_err}; retry={retry_err}"
                )
            }),
        },
    }
}

#[derive(serde::Deserialize, Serialize)]
struct StampedNode {
    generation: i64,
    node: Node,
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

/// Build the typed coordinator service route surface.
pub fn router(state: CoordinatorState, auth: AuthState) -> Router {
    let connect_routes: Router<CoordinatorState> =
        connect::router(state.clone(), auth).with_state(());
    connect_routes.with_state(state)
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

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn authorize_client(
    state: &CoordinatorState,
    authentication: &Authentication,
    org_id: &str,
    env_id: &str,
) -> Result<Uuid, Response> {
    client_environment_access(state, &authentication.user, org_id, env_id).await
}

/// Whether `user` may reach the environment as a client: a member of its
/// organization (an API key only in its own), with environment access at
/// operator or above, and the environment a running sandbox. Checked when a
/// client joins and on every re-check while its session lives (#3828).
#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
pub(crate) async fn client_environment_access(
    state: &CoordinatorState,
    user: &AuthUser,
    org_id: &str,
    env_id: &str,
) -> Result<Uuid, Response> {
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

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
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

#[derive(Clone, Copy)]
enum PeerKind {
    Client,
    Sidecar,
}

#[derive(Clone, Copy)]
enum Transport {
    Connect,
}

impl Transport {
    fn as_str(self) -> &'static str {
        "connect"
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

/// The DERP map every peer session is sent first: one region with the
/// deployment's DERP relay and any STUN servers. Built once at startup.
#[derive(Clone, Debug)]
pub struct DerpMap(Arc<serde_json::Value>);

/// Why the coordinator could not build its DERP map.
#[derive(Debug, thiserror::Error)]
pub enum DerpMapConfigError {
    /// There is no default relay: one would send every peer of this
    /// deployment through another operator's relay.
    #[error(
        "DERP_HOST is required: the DERP relay the coordinator advertises to every peer (docs/CONFIGURATION.md)"
    )]
    MissingHost,
}

impl DerpMap {
    /// Read `DERP_HOST`, `DERP_PORT`, `DERP_INSECURE`, `STUN_HOST`,
    /// `STUN_PORT` and `STUN_SERVERS` from the environment.
    pub fn from_env() -> Result<Self, DerpMapConfigError> {
        DerpMapConfig::from_lookup(|name| env::var(name).ok()).map(Self::from_config)
    }

    fn from_config(config: DerpMapConfig) -> Self {
        Self(Arc::new(build_derp_map(config)))
    }

    fn to_json(&self) -> serde_json::Value {
        self.0.as_ref().clone()
    }
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

impl DerpMapConfig {
    /// Read the settings through `lookup`, the environment outside tests.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, DerpMapConfigError> {
        let stun_port = port_setting(&lookup, "STUN_PORT", 3478);
        let mut stun_servers = Vec::new();
        if let Some(host) = setting(&lookup, "STUN_HOST") {
            push_stun_server(
                &mut stun_servers,
                StunServerConfig {
                    host,
                    port: stun_port,
                },
            );
        }
        if let Some(raw) = setting(&lookup, "STUN_SERVERS") {
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

        Ok(DerpMapConfig {
            derp_host: setting(&lookup, "DERP_HOST").ok_or(DerpMapConfigError::MissingHost)?,
            derp_port: port_setting(&lookup, "DERP_PORT", 443),
            derp_insecure: bool_setting(&lookup, "DERP_INSECURE"),
            stun_servers,
        })
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

fn setting(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn port_setting(lookup: &impl Fn(&str) -> Option<String>, name: &str, default: u16) -> u16 {
    setting(lookup, name)
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|v| *v != 0)
        .unwrap_or(default)
}

fn bool_setting(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> bool {
    setting(lookup, name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// A DERP map for tests, naming a relay that never resolves.
#[cfg(test)]
pub(crate) fn test_derp_map() -> DerpMap {
    DerpMap::from_config(DerpMapConfig {
        derp_host: "derp.example.invalid".into(),
        derp_port: 443,
        derp_insecure: false,
        stun_servers: Vec::new(),
    })
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
    /// The session that owns this entry. Only it updates or removes it.
    owner: Uuid,
    /// An environment peer's proven `(generation, expiry)`. A second session
    /// for the same environment replaces this one only with a newer rank.
    rank: Option<(i64, i64)>,
}

/// One session's registry entry.
struct Registration {
    events: mpsc::UnboundedReceiver<PeerEvent>,
    owner: Uuid,
}

impl PeerRegistry {
    /// Registers a session for `id`. An environment peer (`rank` set)
    /// replaces an existing session for the same environment only when its
    /// rank is strictly newer; otherwise it is refused (`None`).
    fn register(&self, id: Uuid, rank: Option<(i64, i64)>) -> Option<Registration> {
        let (tx, rx) = mpsc::unbounded_channel();
        let owner = Uuid::new_v4();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let (Some(existing), Some(rank)) =
            (inner.peers.get(&id).and_then(|peer| peer.rank), rank)
            && rank <= existing
        {
            return None;
        }
        // Replacing drops the previous session's sender, which ends it.
        inner.peers.insert(
            id,
            Peer {
                node: None,
                tx,
                owner,
                rank,
            },
        );
        Self::send_all_client_peers(&inner, id);
        Some(Registration { events: rx, owner })
    }

    /// Raises the owner's proven rank after an in-band proof.
    fn raise_rank(&self, id: Uuid, owner: Uuid, rank: (i64, i64)) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(peer) = inner.peers.get_mut(&id)
            && peer.owner == owner
            && peer.rank.is_some_and(|current| rank > current)
        {
            peer.rank = Some(rank);
        }
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

    fn update_node(&self, id: Uuid, owner: Uuid, node: Node) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(peer) = inner.peers.get_mut(&id) else {
            return;
        };
        if peer.owner != owner {
            return;
        }
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

    /// Removes the entry only while `owner` still owns it: a session that was
    /// replaced never tears down its replacement.
    fn deregister(&self, id: Uuid, owner: Uuid) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.peers.get(&id).is_none_or(|peer| peer.owner != owner) {
            return;
        }
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

    /// Whether a session on this replica has sent a node with `key`.
    fn knows_key(&self, key: &codewire_tailnet::node::NodePublic) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .peers
            .values()
            .any(|peer| peer.node.as_ref().is_some_and(|node| node.key == *key))
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
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};

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

    fn lookup<'a>(settings: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            settings
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn derp_map_config_refuses_a_missing_or_blank_host() {
        for settings in [
            &[][..],
            &[("DERP_HOST", "")][..],
            &[("DERP_HOST", "   "), ("DERP_PORT", "8443")][..],
        ] {
            let error = DerpMapConfig::from_lookup(lookup(settings)).unwrap_err();
            assert!(matches!(error, DerpMapConfigError::MissingHost));
            let message = error.to_string();
            assert!(message.contains("DERP_HOST"), "{message}");
            assert!(message.contains("docs/CONFIGURATION.md"), "{message}");
        }
    }

    #[test]
    fn derp_map_config_reads_the_configured_relay() {
        let config = DerpMapConfig::from_lookup(lookup(&[
            ("DERP_HOST", " derp.example.com "),
            ("STUN_HOST", "stun.example.com"),
        ]))
        .unwrap();
        assert_eq!(config.derp_host, "derp.example.com");
        assert_eq!(config.derp_port, 443);
        assert!(!config.derp_insecure);
        assert_eq!(
            config.stun_servers,
            vec![StunServerConfig {
                host: "stun.example.com".into(),
                port: 3478,
            }]
        );
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
    #[ignore = "requires NATS_URL pointing at a JetStream-enabled NATS server"]
    async fn coordination_plane_round_trips_nats_and_kv() {
        let nats_url =
            std::env::var("NATS_URL").expect("set NATS_URL to a JetStream-enabled NATS server");
        let client = async_nats::connect(nats_url).await.unwrap();
        let plane = CoordinationPlane::setup(client).await.unwrap();

        let env_id = Uuid::new_v4();
        let sidecar_node = sample_node(env_id, 11);
        plane
            .put_sidecar_node(env_id, 3, &sidecar_node)
            .await
            .unwrap();
        let (generation, got) = plane.get_sidecar_node(env_id).await.unwrap().unwrap();
        assert_eq!(generation, 3);
        assert_eq!(got.id, env_id);
        assert_eq!(got.preferred_derp, 11);
        // A revocation for an older generation leaves a newer node in place;
        // the stamped generation's revocation removes it.
        plane.delete_sidecar_node(env_id, 2).await.unwrap();
        assert!(plane.get_sidecar_node(env_id).await.unwrap().is_some());
        plane.delete_sidecar_node(env_id, 3).await.unwrap();
        assert!(plane.get_sidecar_node(env_id).await.unwrap().is_none());
        plane
            .put_sidecar_node(env_id, 3, &sidecar_node)
            .await
            .unwrap();

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

        // #2844: a node key is registered for its session, survives another
        // session's teardown, and goes with its own.
        let mut raw = [0u8; 32];
        raw[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        raw[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let key = codewire_tailnet::node::NodePublic::from_raw(raw);
        let (owner, other) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(!plane.node_key_registered(&key).await.unwrap());
        plane.put_node_key(&key, owner).await.unwrap();
        assert!(plane.node_key_registered(&key).await.unwrap());
        plane.delete_node_key(&key, other).await.unwrap();
        assert!(plane.node_key_registered(&key).await.unwrap());
        plane.delete_node_key(&key, owner).await.unwrap();
        assert!(!plane.node_key_registered(&key).await.unwrap());
    }

    fn register(registry: &PeerRegistry, id: Uuid, rank: Option<(i64, i64)>) -> Registration {
        registry.register(id, rank).expect("registration accepted")
    }

    #[tokio::test]
    async fn registry_exchanges_nodes_when_sidecar_registers_first() {
        let registry = PeerRegistry::default();
        let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let mut sidecar = register(&registry, sidecar_id, Some((1, 100)));
        let mut client = register(&registry, client_id, None);
        registry.add_tunnel(client_id, sidecar_id);

        registry.update_node(sidecar_id, sidecar.owner, sample_node(sidecar_id, 1));
        match client.events.recv().await.unwrap() {
            PeerEvent::Update(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, sidecar_id);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        registry.update_node(client_id, client.owner, sample_node(client_id, 2));
        match sidecar.events.recv().await.unwrap() {
            PeerEvent::Update(nodes) => {
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].id, client_id);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        registry.deregister(client_id, client.owner);
        match sidecar.events.recv().await.unwrap() {
            PeerEvent::Remove(peer_id) => assert_eq!(peer_id, client_id),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn registry_replays_published_client_when_sidecar_registers_late() {
        let registry = PeerRegistry::default();
        let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let client_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let client = register(&registry, client_id, None);
        registry.add_tunnel(client_id, sidecar_id);

        registry.update_node(client_id, client.owner, sample_node(client_id, 2));
        let mut sidecar = register(&registry, sidecar_id, Some((1, 100)));

        match sidecar.events.recv().await.unwrap() {
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
        let mut client = register(&registry, client_id, None);
        let mut sidecar = register(&registry, sidecar_id, Some((1, 100)));
        registry.add_tunnel(client_id, sidecar_id);
        registry.update_node(client_id, client.owner, sample_node(client_id, 2));
        assert!(matches!(
            sidecar.events.recv().await,
            Some(PeerEvent::Update(nodes)) if nodes.len() == 1 && nodes[0].id == client_id
        ));

        registry.deregister(sidecar_id, sidecar.owner);
        assert!(matches!(
            client.events.recv().await,
            Some(PeerEvent::Remove(peer_id)) if peer_id == sidecar_id
        ));

        let mut reconnected = register(&registry, sidecar_id, Some((1, 100)));
        assert!(matches!(
            reconnected.events.recv().await,
            Some(PeerEvent::Update(nodes)) if nodes.len() == 1 && nodes[0].id == client_id
        ));

        registry.deregister(client_id, client.owner);
        assert!(matches!(
            reconnected.events.recv().await,
            Some(PeerEvent::Remove(peer_id)) if peer_id == client_id
        ));

        registry.deregister(sidecar_id, reconnected.owner);
        let mut final_sidecar = register(&registry, sidecar_id, Some((1, 100)));
        assert!(final_sidecar.events.try_recv().is_err());
    }

    #[test]
    fn registry_ranks_environment_peers_and_scopes_teardown_to_the_owner() {
        let registry = PeerRegistry::default();
        let env_id = Uuid::new_v4();
        let first = register(&registry, env_id, Some((4, 1_000)));
        // Equal or older proofs are refused.
        assert!(registry.register(env_id, Some((4, 1_000))).is_none());
        assert!(registry.register(env_id, Some((4, 999))).is_none());
        assert!(registry.register(env_id, Some((3, 9_999))).is_none());
        // A raised rank refuses what would have outranked the original.
        registry.raise_rank(env_id, first.owner, (4, 1_500));
        assert!(registry.register(env_id, Some((4, 1_200))).is_none());
        // A newer proof replaces the holder; the replaced owner can neither
        // update nor remove its replacement.
        let second = register(&registry, env_id, Some((5, 100)));
        registry.raise_rank(env_id, first.owner, (9, 9_999));
        registry.deregister(env_id, first.owner);
        assert!(registry.register(env_id, Some((5, 50))).is_none());
        registry.deregister(env_id, second.owner);
        assert!(registry.register(env_id, Some((1, 1))).is_some());
    }
}
