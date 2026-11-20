//! Typed non-browser Mesh coordinate service.
//!
//! Authentication is resolved from the credential presented at stream setup.
//! The generated hello, node, subscription, and response messages are the only
//! wire contract; no runtime-token exchange or WebSocket adapter is involved.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

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
use tokio::sync::{Notify, mpsc};
use url::Url;
use uuid::Uuid;

use crate::environment_members::EnvironmentMember;
use crate::mesh_authorization::forwarded_mesh_credential;
use crate::server::AppState;

pub(crate) mod shared;

use shared::net_key;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// A node whose session has sent nothing for this long lists offline
/// (#2697). Every Mesh client pings every 15 s, so this is three missed
/// beats, measured end to end through the ingress proxy. The session itself
/// is never ended for silence: a local VM's transport cannot rejoin within
/// its generation, so a node that wakes from a sleep must find its session
/// still there.
const OFFLINE_AFTER: Duration = Duration::from_secs(45);

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
            &self.state.config.stun_servers,
        )
        .map_err(ConnectError::internal)?;

        let (responses_tx, responses_rx) = mpsc::channel(32);
        let state = self.state.mesh_coordinate.clone();
        let product = self.state.product.clone();
        tokio::spawn(async move {
            let last_heard = run_session(requests, responses_tx, state, &peer, derp_map).await;
            // An offline node shows when it was last heard from (#2697).
            if let Some(node_name) = &peer.node_name
                && let Err(error) = product
                    .mark_node_seen(&peer.network_id, node_name, last_heard)
                    .await
            {
                tracing::warn!(%error, "Mesh node last-seen write failed");
            }
        });

        let output = futures_util::stream::unfold(responses_rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        connectrpc::Response::stream_ok(output)
    }
}

#[derive(Clone)]
pub(crate) struct MeshCoordinateState {
    inner: Arc<Mutex<Registry>>,
    offline_after: Duration,
    /// The registry shared with the other replicas, once Mesh has reached
    /// NATS (#3542). Without it this process's registry is the whole registry.
    shared: Arc<std::sync::OnceLock<Arc<shared::Shared>>>,
    /// Set when Mesh is configured to share its registry, reached or not.
    shared_configured: bool,
}

impl MeshCoordinateState {
    /// The registry. Every reader tolerates a half-applied change (an edge to
    /// a peer that is gone, a peer without its edges), so a panic while it was
    /// held must not take every later session down with it.
    fn registry(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the view of the other replicas may answer for them now.
    fn view_current(&self) -> bool {
        self.shared
            .get()
            .is_some_and(|shared| shared.view_current())
    }

    pub(crate) fn new() -> Self {
        Self::offline_after(OFFLINE_AFTER)
    }

    /// A coordinator that lists a node offline once its session has been
    /// silent for `offline_after`.
    pub(crate) fn offline_after(offline_after: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Registry::default())),
            offline_after,
            shared: Arc::new(std::sync::OnceLock::new()),
            shared_configured: false,
        }
    }

    /// Whether a node last heard at `last_heard` is online now.
    pub(crate) fn heard_recently(&self, last_heard: DateTime<Utc>) -> bool {
        Utc::now()
            .signed_duration_since(last_heard)
            .to_std()
            .map_or(true, |silent| silent <= self.offline_after)
    }

    /// When the live session of this registered node last heard from it, or
    /// `None` with no live session (#2697). A session on another replica
    /// answers from its shared record, at most [`shared::REFRESH_INTERVAL`]
    /// old (#3542).
    pub(crate) fn node_last_heard(
        &self,
        network_id: &str,
        node_name: &str,
    ) -> Option<DateTime<Utc>> {
        let peer_id = stable_peer_id(network_id, "peer", node_name);
        let registry = self.registry();
        registry
            .peers
            .get(&peer_id)
            .filter(|peer| peer.network_id == network_id)
            .map(|peer| peer.last_heard)
            .or_else(|| {
                registry
                    .remote
                    .peers
                    .get(&peer_id)
                    .filter(|peer| peer.network_id == network_id)
                    .map(|peer| peer.last_heard)
            })
    }

    /// Whether a live session has sent a node with `key`: DERP serves only
    /// such keys (#2844). Another replica's session counts only while this
    /// replica's view of the shared registry is current and its record is
    /// fresh and not draining, so a key revoked while the view could not
    /// follow is refused, never admitted (#3542).
    pub(crate) fn knows_key(&self, key: &codewire_tailnet::node::NodePublic) -> bool {
        let registry = self.registry();
        let has_key = |node: Option<&Node>| node.is_some_and(|node| node.key == *key);
        if registry
            .peers
            .values()
            .any(|peer| has_key(peer.node.as_ref()))
        {
            return true;
        }
        let Some(shared) = self.shared.get().filter(|shared| shared.view_current()) else {
            return false;
        };
        let (timing, now) = (shared.timing(), Utc::now());
        registry.remote.peers.values().any(|peer| {
            has_key(peer.node.as_ref())
                && !peer.draining
                && peer.fresh(&timing, now)
                && !registry.remote.retired.contains(&net_key(&peer.network_id))
        })
    }

    /// Drop active sessions and reject sessions authorized before deletion but
    /// not yet registered. The store permanently reserves this network name.
    /// With a shared registry every replica does the same; `Err` means the
    /// other replicas could not be told, and a retry finishes the job.
    pub(crate) async fn revoke_network(
        &self,
        network_id: &str,
    ) -> Result<(), shared::CoordinationError> {
        self.retire_locally(network_id);
        match self.shared.get() {
            Some(shared) => shared.retire_network(network_id).await,
            None if self.shared_configured => Err(shared::CoordinationError::NotConnected),
            None => Ok(()),
        }
    }

    fn retire_locally(&self, network_id: &str) {
        let (removed, edges) = {
            let mut registry = self.registry();
            registry.retired_networks.insert(network_id.to_owned());
            let removed = registry
                .peers
                .iter()
                .filter_map(|(id, peer)| (peer.network_id == network_id).then_some(*id))
                .collect::<HashSet<_>>();
            for id in &removed {
                if let Some(peer) = registry.peers.remove(id) {
                    peer.close.notify_one();
                }
            }
            let edges = registry
                .tunnels
                .iter()
                .filter(|(dial, target)| removed.contains(dial) || removed.contains(target))
                .copied()
                .collect::<Vec<_>>();
            for edge in &edges {
                registry.tunnels.remove(edge);
            }
            (removed, edges)
        };
        for peer_id in removed {
            self.dirty_peer(peer_id, network_id);
        }
        self.dirty_edges(&edges, network_id);
    }

    /// Disconnect the active peer addressed by this exact registered node.
    /// A later connection needs a fresh one-use enrollment and is therefore a
    /// separate authorization decision. With a shared registry the record is
    /// deleted too, and the replica holding the session ends it; `Err` means
    /// that delete failed, and a retry finishes the job.
    pub(crate) async fn revoke_node(
        &self,
        network_id: &str,
        node_name: &str,
    ) -> Result<(), shared::CoordinationError> {
        let peer_id = stable_peer_id(network_id, "peer", node_name);
        self.end_session(peer_id, |peer| peer.network_id == network_id);
        match self.shared.get() {
            Some(shared) => shared.delete_peer(network_id, peer_id).await,
            None if self.shared_configured => Err(shared::CoordinationError::NotConnected),
            None => Ok(()),
        }
    }

    /// The streams of hosted environment members, for the recheck.
    pub(crate) fn environment_sessions(&self) -> Vec<EnvironmentSessionRef> {
        let registry = self.registry();
        registry
            .peers
            .iter()
            .filter_map(|(peer_id, peer)| {
                peer.environment
                    .clone()
                    .map(|session| EnvironmentSessionRef {
                        peer_id: *peer_id,
                        session_id: peer.session_id,
                        session,
                    })
            })
            .collect()
    }

    /// Records that orchestration confirmed this exact session at `at`.
    pub(crate) fn confirm_environment_session(
        &self,
        peer_id: Uuid,
        session_id: Uuid,
        at: tokio::time::Instant,
    ) {
        let mut registry = self.registry();
        if let Some(environment) = registry
            .peers
            .get_mut(&peer_id)
            .filter(|peer| peer.session_id == session_id)
            .and_then(|peer| peer.environment.as_mut())
        {
            environment.verified_at = at;
        }
    }

    /// Ends this exact session: no newer session of the node is touched.
    pub(crate) fn end_environment_session(&self, peer_id: Uuid, session_id: Uuid) {
        self.end_session(peer_id, |peer| peer.session_id == session_id);
    }

    /// Removes the peer when `selected` holds, ends its stream, and tells its
    /// tunnel partners.
    fn end_session(&self, peer_id: Uuid, selected: impl FnOnce(&Peer) -> bool) {
        let (network_id, updates, edges) = {
            let mut registry = self.registry();
            if !registry.peers.get(&peer_id).is_some_and(selected) {
                return;
            }
            let Some(peer) = registry.peers.remove(&peer_id) else {
                return;
            };
            peer.close.notify_one();
            let (updates, edges) = remove_tunnels(&mut registry, peer_id);
            (peer.network_id, updates, edges)
        };
        self.dirty_peer(peer_id, &network_id);
        self.dirty_edges(&edges, &network_id);
        for tx in updates {
            // A partner whose queue is full or gone is ending or behind; it
            // learns of the removal from its next session's updates.
            let _ = tx.try_send(CoordinateEvent::Remove(peer_id));
        }
    }
}

#[derive(Default)]
struct Registry {
    peers: HashMap<Uuid, Peer>,
    /// Subscriptions as (subscriber, target) edges. A dial session holds at
    /// most one; a peer at most [`MAX_PEER_SUBSCRIPTIONS`] (#3350).
    tunnels: HashSet<(Uuid, Uuid)>,
    retired_networks: HashSet<String>,
    /// The other replicas' sessions and subscriptions (#3542).
    remote: shared::Remote,
}

/// One end of a subscription, on this replica or another.
struct Member<'a> {
    network_id: &'a str,
    node: Option<&'a Node>,
    /// Present for a session on this replica, the only kind it can tell.
    tx: Option<&'a mpsc::Sender<CoordinateEvent>>,
    /// A stopping replica's session: its partners keep the node they have,
    /// and nobody is sent it anew.
    draining: bool,
}

impl Registry {
    /// A member on this replica, or on another while `remote_current` (the
    /// view is current) and its record is fresh and its network not retired:
    /// the same gate DERP admission uses.
    fn member(&self, peer_id: Uuid, remote_current: bool) -> Option<Member<'_>> {
        if let Some(peer) = self.peers.get(&peer_id) {
            return Some(Member {
                network_id: &peer.network_id,
                node: peer.node.as_ref(),
                tx: Some(&peer.tx),
                draining: false,
            });
        }
        if !remote_current {
            return None;
        }
        let now = Utc::now();
        self.remote
            .peers
            .get(&peer_id)
            .filter(|peer| {
                peer.fresh(&self.remote.timing, now)
                    && !self.remote.retired.contains(&net_key(&peer.network_id))
            })
            .map(|peer| Member {
                network_id: &peer.network_id,
                node: peer.node.as_ref(),
                tx: None,
                draining: peer.draining,
            })
    }
}

struct Peer {
    session_id: Uuid,
    network_id: String,
    /// When this session last received a message.
    last_heard: DateTime<Utc>,
    node: Option<Node>,
    tx: mpsc::Sender<CoordinateEvent>,
    /// Ends this session's stream when it is revoked or replaced.
    close: Arc<Notify>,
    /// A hosted environment member and when orchestration last confirmed it.
    environment: Option<EnvironmentSession>,
    /// The node this session speaks for; a dial session has none.
    node_name: Option<String>,
    /// When the session registered, on the monotonic clock: of two sessions
    /// of one node the later registration is the newer, compared on the
    /// NATS server's clock (#3542).
    registered: tokio::time::Instant,
    /// The revision of this session's shared record, once written (#3542).
    revision: Option<u64>,
    /// When the record was last written, or the session registered.
    shared_at: tokio::time::Instant,
}

/// A hosted environment member's stream (#3350): the Pod and generation it
/// was admitted for, and the last time orchestration confirmed them.
#[derive(Clone, Debug)]
pub(crate) struct EnvironmentSession {
    pub member: EnvironmentMember,
    pub verified_at: tokio::time::Instant,
}

/// One environment member's live stream, as the recheck sees it.
#[derive(Clone, Debug)]
pub(crate) struct EnvironmentSessionRef {
    pub peer_id: Uuid,
    pub session_id: Uuid,
    pub session: EnvironmentSession,
}

enum CoordinateEvent {
    Update(Vec<Node>),
    Remove(Uuid),
}

#[derive(Clone)]
struct AuthorizedPeer {
    peer_id: Uuid,
    network_id: String,
    /// The registered node this session speaks for; a dial session has none.
    node_name: Option<String>,
    role: MeshCoordinateRole,
    environment: Option<EnvironmentMember>,
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
    // A hosted environment's code is redeemed by orchestration, never here.
    if let Some(code) = credential.environment_enrollment_code() {
        if role != MeshCoordinateRole::Peer {
            return Err(AppError::Forbidden);
        }
        let member = state
            .product
            .redeem_environment_enrollment(&org_id, &network_id, code)
            .await?;
        return Ok(AuthorizedPeer {
            peer_id: stable_peer_id(&member.network_id, "peer", &member.node_name),
            network_id: member.network_id.clone(),
            node_name: Some(member.node_name.clone()),
            role,
            environment: Some(member),
        });
    }
    let node_enrollment = credential.node_enrollment_code().is_some();
    let (peer_id, node_name) = match role {
        MeshCoordinateRole::Peer if !node_enrollment => return Err(AppError::Forbidden),
        MeshCoordinateRole::Peer => {
            let redeemed = state
                .product
                .redeem_coordinate_enrollment(&org_id, &network_id, &credential)
                .await?;
            (
                stable_peer_id(&network_id, "peer", &redeemed.node.name),
                Some(redeemed.node.name),
            )
        }
        MeshCoordinateRole::Dial if node_enrollment => return Err(AppError::Forbidden),
        MeshCoordinateRole::Dial => {
            let authorization = state
                .product
                .authorize_coordinate(&org_id, &network_id, credential)
                .await?;
            if authorization.principal_kind != MeshAuthorizationPrincipalKind::User
                || !matches!(
                    authorization.credential_kind.as_known(),
                    Some(
                        MeshAuthorizationCredentialKind::OauthBearer
                            | MeshAuthorizationCredentialKind::ApiKey
                    )
                )
            {
                return Err(AppError::Forbidden);
            }
            (Uuid::new_v4(), None)
        }
        MeshCoordinateRole::Unspecified => unreachable!("validated above"),
    };
    Ok(AuthorizedPeer {
        peer_id,
        network_id,
        node_name,
        role,
        environment: None,
    })
}

fn required(value: &str, field: &'static str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("{field} is required").into()));
    }
    Ok(value.to_owned())
}

/// Serves one session until it ends, and returns when it last received a
/// message.
async fn run_session(
    mut requests: InboundStream<MeshCoordinatorServiceCoordinateRequest>,
    responses: mpsc::Sender<Result<MeshCoordinatorServiceCoordinateResponse, ConnectError>>,
    state: MeshCoordinateState,
    peer: &AuthorizedPeer,
    derp_map: JsonValue,
) -> DateTime<Utc> {
    let mut last_heard = Utc::now();
    let (events_tx, mut events_rx) = mpsc::channel(64);
    let Some((session_id, close)) = register(&state, peer, events_tx) else {
        let _ = responses
            .send(Err(ConnectError::permission_denied(
                "Mesh network was deleted",
            )))
            .await;
        return last_heard;
    };
    let initial = response(CoordinateDerpMap {
        derp_map_json: serde_json::to_vec(&derp_map).unwrap_or_default(),
        ..Default::default()
    });
    if responses.send(Ok(initial)).await.is_err() {
        deregister(&state, peer.peer_id, session_id);
        return last_heard;
    }

    let mut heartbeat = tokio::time::interval_at(
        tokio::time::Instant::now() + HEARTBEAT_INTERVAL,
        HEARTBEAT_INTERVAL,
    );
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // An ended membership wins over anything else ready at once. The
            // stream ends cleanly, as a revoked node's always has; the next
            // enrollment says why.
            biased;
            () = close.notified() => break,
            message = requests.next() => {
                let Some(message) = message else {
                    break;
                };
                let Ok(message) = message else {
                    break;
                };
                last_heard = Utc::now();
                heard(&state, peer.peer_id, session_id, last_heard);
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
                        // A user's dial session reaches one node; a member
                        // reaches other members of its own network (#3350).
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
                        let target_id = stable_peer_id(&peer.network_id, "peer", target);
                        let refused = match add_tunnel(&state, peer.peer_id, target_id, peer.role) {
                            Ok(()) => None,
                            Err(SubscribeError::Itself) => Some(ConnectError::invalid_argument(
                                "a node cannot subscribe to itself",
                            )),
                            Err(SubscribeError::TooMany) => Some(ConnectError::resource_exhausted(
                                "this node already reaches as many members as it may",
                            )),
                        };
                        if let Some(error) = refused
                            && responses.send(Err(error)).await.is_err()
                        {
                            break;
                        }
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
    last_heard
}

/// Records that this exact session received a message at `at`.
/// Ends this replica's sessions whose node, or for a dial session whose
/// network, the store no longer has, and deletes their records. A revocation
/// whose shared delete was lost after the store committed is so cut off
/// within one [`shared::REFRESH_INTERVAL`] (#3542). A store error ends
/// nothing: the next pass asks again.
pub(crate) async fn recheck_store(state: &AppState) {
    for (peer_id, session_id, network_id, node_name) in state.mesh_coordinate.local_sessions() {
        match state
            .product
            .session_still_registered(&network_id, node_name.as_deref())
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(%peer_id, "Mesh ended a session the store no longer has");
                state
                    .mesh_coordinate
                    .end_session(peer_id, |peer| peer.session_id == session_id);
                if let Some(shared) = state.mesh_coordinate.shared.get()
                    && let Err(error) = shared.delete_peer(&network_id, peer_id).await
                {
                    tracing::warn!(%error, "Mesh could not delete an ended session's record");
                }
            }
            Err(error) => tracing::warn!(%error, "Mesh could not recheck a session"),
        }
    }
}

/// Runs [`recheck_store`] every [`shared::REFRESH_INTERVAL`].
pub(crate) fn spawn_store_recheck(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(shared::REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            recheck_store(&state).await;
        }
    })
}

fn heard(state: &MeshCoordinateState, peer_id: Uuid, session_id: Uuid, at: DateTime<Utc>) {
    let mut registry = state.registry();
    if let Some(peer) = registry
        .peers
        .get_mut(&peer_id)
        .filter(|peer| peer.session_id == session_id)
    {
        peer.last_heard = at;
    }
}

fn register(
    state: &MeshCoordinateState,
    peer: &AuthorizedPeer,
    tx: mpsc::Sender<CoordinateEvent>,
) -> Option<(Uuid, Arc<Notify>)> {
    let session_id = Uuid::new_v4();
    let close = Arc::new(Notify::new());
    let mut registry = state.registry();
    if registry.retired_networks.contains(&peer.network_id)
        || registry.remote.retired.contains(&net_key(&peer.network_id))
    {
        return None;
    }
    let replaced = registry.peers.insert(
        peer.peer_id,
        Peer {
            session_id,
            network_id: peer.network_id.clone(),
            last_heard: Utc::now(),
            node: None,
            tx,
            close: close.clone(),
            environment: peer.environment.clone().map(|member| EnvironmentSession {
                member,
                verified_at: tokio::time::Instant::now(),
            }),
            node_name: peer.node_name.clone(),
            registered: tokio::time::Instant::now(),
            revision: None,
            shared_at: tokio::time::Instant::now(),
        },
    );
    drop(registry);
    // The node's newer session replaces an older one, which ends.
    if let Some(replaced) = replaced {
        replaced.close.notify_one();
    }
    state.dirty_peer(peer.peer_id, &peer.network_id);
    Some((session_id, close))
}

fn deregister(state: &MeshCoordinateState, peer_id: Uuid, session_id: Uuid) {
    let (network_id, updates, edges) = {
        let mut registry = state.registry();
        if registry
            .peers
            .get(&peer_id)
            .is_none_or(|peer| peer.session_id != session_id)
        {
            return;
        }
        let Some(peer) = registry.peers.remove(&peer_id) else {
            return;
        };
        let (updates, edges) = remove_tunnels(&mut registry, peer_id);
        (peer.network_id, updates, edges)
    };
    state.dirty_peer(peer_id, &network_id);
    state.dirty_edges(&edges, &network_id);
    for tx in updates {
        // As in `end_session`: a partner that can't take it is ending or
        // behind.
        let _ = tx.try_send(CoordinateEvent::Remove(peer_id));
    }
}

fn update_node(state: &MeshCoordinateState, peer_id: Uuid, session_id: Uuid, node: Node) {
    let updates = {
        let mut registry = state.registry();
        let Some(peer) = registry.peers.get_mut(&peer_id) else {
            return;
        };
        if peer.session_id != session_id {
            return;
        }
        peer.node = Some(node);
        let network_id = peer.network_id.clone();
        (
            network_id,
            tunnel_updates(&registry, peer_id, state.view_current()),
        )
    };
    state.dirty_peer(peer_id, &updates.0);
    send_updates(peer_id, updates.1);
}

/// Ends `peer_id`'s own subscriptions, and returns the other ends on this
/// replica to tell that it is gone and the removed edges this replica wrote.
/// Other members' subscriptions to `peer_id` stay, and those members are told
/// too: a subscription is its subscriber's, so a target that ends and registers
/// again (a Sandbox stopped and started) reaches its subscribers as it reaches
/// one made before it registered (#5642).
fn remove_tunnels(
    registry: &mut Registry,
    peer_id: Uuid,
) -> (Vec<mpsc::Sender<CoordinateEvent>>, Vec<(Uuid, Uuid)>) {
    let own = |(dial, _): &(Uuid, Uuid)| *dial == peer_id;
    let local = registry
        .tunnels
        .iter()
        .filter(|edge| own(edge))
        .copied()
        .collect::<Vec<_>>();
    let remote = registry
        .remote
        .tunnels
        .keys()
        .filter(|edge| own(edge))
        .copied()
        .collect::<Vec<_>>();
    for edge in local.iter().chain(&remote) {
        registry.tunnels.remove(edge);
        registry.remote.tunnels.remove(edge);
    }
    let subscribers = registry
        .tunnels
        .iter()
        .chain(registry.remote.tunnels.keys())
        .filter(|(_, target)| *target == peer_id)
        .map(|(dial, _)| *dial);
    let targets = local.iter().chain(&remote).map(|(_, target)| *target);
    let updates = targets
        .chain(subscribers)
        .collect::<HashSet<_>>()
        .into_iter()
        .filter_map(|recipient| registry.peers.get(&recipient).map(|peer| peer.tx.clone()))
        .collect();
    (updates, local)
}

/// Subscriptions one peer session may hold: each is another member of its
/// own network it can reach (#3350).
pub(crate) const MAX_PEER_SUBSCRIPTIONS: usize = 64;

#[derive(Debug, PartialEq, Eq)]
enum SubscribeError {
    /// A node never subscribes to itself.
    Itself,
    /// The peer already holds [`MAX_PEER_SUBSCRIPTIONS`].
    TooMany,
}

/// Subscribes `dial_id` to `target_id`. A dial session's subscription
/// replaces its previous one; a peer adds one, up to its limit. Both ends must
/// be in one network: a target id is derived from the subscriber's own network,
/// so another network's node is never addressed.
fn add_tunnel(
    state: &MeshCoordinateState,
    dial_id: Uuid,
    target_id: Uuid,
    role: MeshCoordinateRole,
) -> Result<(), SubscribeError> {
    if dial_id == target_id {
        return Err(SubscribeError::Itself);
    }
    let (network_id, replaced, updates) = {
        let mut registry = state.registry();
        let network_id = match (
            registry.peers.get(&dial_id),
            registry.member(target_id, state.view_current()),
        ) {
            (Some(dial), Some(target)) if dial.network_id == target.network_id => {
                dial.network_id.clone()
            }
            (Some(dial), None) => dial.network_id.clone(),
            _ => return Ok(()),
        };
        let mut replaced = Vec::new();
        if role == MeshCoordinateRole::Dial {
            replaced = registry
                .tunnels
                .iter()
                .filter(|(dial, target)| *dial == dial_id && *target != target_id)
                .copied()
                .collect();
            registry.tunnels.retain(|(dial, _)| *dial != dial_id);
        } else if !registry.tunnels.contains(&(dial_id, target_id))
            && registry
                .tunnels
                .iter()
                .filter(|(dial, _)| *dial == dial_id)
                .count()
                >= MAX_PEER_SUBSCRIPTIONS
        {
            return Err(SubscribeError::TooMany);
        }
        registry.tunnels.insert((dial_id, target_id));
        (
            network_id,
            replaced,
            tunnel_updates(&registry, dial_id, state.view_current()),
        )
    };
    state.dirty_edges(&replaced, &network_id);
    state.dirty_edges(&[(dial_id, target_id)], &network_id);
    send_updates(dial_id, updates);
    Ok(())
}

fn tunnel_updates(
    registry: &Registry,
    changed: Uuid,
    remote_current: bool,
) -> Vec<(mpsc::Sender<CoordinateEvent>, Vec<Node>)> {
    let mut updates = Vec::new();
    for (dial_id, target_id) in registry
        .tunnels
        .iter()
        .chain(registry.remote.tunnels.keys())
    {
        if *dial_id != changed && *target_id != changed {
            continue;
        }
        // Each replica tells only its own sessions; the other end's replica
        // tells its own when it sees the same record.
        if let (Some(dial), Some(target)) = (
            registry.member(*dial_id, remote_current),
            registry.member(*target_id, remote_current),
        ) && dial.network_id == target.network_id
        {
            if let (Some(tx), Some(node), false) = (dial.tx, target.node, target.draining) {
                updates.push((tx.clone(), vec![node.clone()]));
            }
            if let (Some(tx), Some(node), false) = (target.tx, dial.node, dial.draining) {
                updates.push((tx.clone(), vec![node.clone()]));
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

pub(crate) fn tailnet_node_to_proto(node: Node) -> Result<CoordinateNode, ConnectError> {
    serde_json::from_value(
        serde_json::to_value(node).map_err(|_| ConnectError::internal("encode node"))?,
    )
    .map_err(|_| ConnectError::internal("encode node"))
}

fn derp_map_from_base_url(
    base_url: &str,
    stun_servers: &[crate::config::StunServerConfig],
) -> Result<JsonValue, String> {
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
    let mut nodes = vec![JsonValue::Object(node)];
    for (index, server) in stun_servers.iter().enumerate() {
        nodes.push(serde_json::json!({
            "Name": if index == 0 { "1s".to_owned() } else { format!("1s{}", index + 1) },
            "RegionID": 1,
            "HostName": server.host,
            "STUNOnly": true,
            "STUNPort": server.port,
        }));
    }
    Ok(serde_json::json!({
        "Regions": {
            "1": {
                "RegionID": 1,
                "RegionCode": "cw",
                "RegionName": "Codewire Embedded",
                "Nodes": nodes,
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod store;
    use codewire_proto::codewire::internal::v1::{
        MeshCoordinatorServiceClient, mesh_coordinator_service_coordinate_response,
    };
    use codewire_proto::codewire::v1::{
        JoinMeshNetworkRequest, ListMeshNodesRequest, MeshNetworkServiceClient,
        MeshNodeServiceClient, RevokeMeshNodeRequest,
    };
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use connectrpc::Protocol;
    use connectrpc::client::{ClientConfig, HttpClient};

    use crate::config::{Config, LocalMeshAuthorizationConfig};
    use crate::store::{
        Invite, MemoryStore, MeshStore, NETWORK_ROLE_MEMBER, NodeEnrollment, NodeRecord,
    };

    fn config() -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            base_url: "http://mesh.test".to_owned(),
            derp_url: None,
            stun_servers: Vec::new(),
            database_url: None,
            mesh_authorization: None,
            derp_verify_addr: None,
            local_authorization: Some(LocalMeshAuthorizationConfig {
                organization_id: "org-test".to_owned(),
                api_key_hash: codewire_server_core::auth::hash_api_key("cw_test"),
            }),
            nats: None,
        }
    }

    async fn start() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "local-owner:org-test",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        start_with_store(store).await
    }

    async fn start_with_store(
        store: Arc<MemoryStore>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        serve(crate::server::router_with_store(config(), store)).await
    }

    async fn serve(app: axum::Router) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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

    async fn seed_enrollment(store: &MemoryStore, code: &str, node_name: &str) {
        store
            .node_enrollment_create(NodeEnrollment {
                id: format!("enrollment-{}", code.trim_start_matches("cw_enr_")),
                network_id: "network-test".to_owned(),
                owner_subject: "local-owner:org-test".to_owned(),
                issued_by: "local-owner:org-test".to_owned(),
                node_name: node_name.to_owned(),
                token_hash: format!("{:x}", Sha256::digest(code.as_bytes())),
                uses_remaining: 1,
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                created_at: chrono::Utc::now(),
                redeemed_at: None,
            })
            .await
            .unwrap();
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

    fn node_client(
        address: std::net::SocketAddr,
        token: &str,
    ) -> MeshNodeServiceClient<HttpClient> {
        MeshNodeServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(format!("http://{address}").parse().unwrap())
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

    /// Clients name a member by this id (#3350); it must never change.
    #[test]
    fn a_members_peer_id_is_pinned() {
        assert_eq!(
            stable_peer_id("network-test", "peer", "app-2").to_string(),
            "360189e4-fc1d-53e5-ba42-755ed27d23ce"
        );
    }

    /// #2844: DERP admits a member's key while its session lives.
    #[tokio::test]
    async fn derp_lookup_knows_a_live_member_key_until_its_session_ends() {
        let state = MeshCoordinateState::new();
        let peer = AuthorizedPeer {
            peer_id: Uuid::new_v4(),
            network_id: "network-test".to_owned(),
            node_name: None,
            role: MeshCoordinateRole::Peer,
            environment: None,
        };
        let member = node();
        assert!(!state.knows_key(&member.key));
        let (tx, _rx) = mpsc::channel(4);
        let session_id = register(&state, &peer, tx).expect("registered").0;
        assert!(!state.knows_key(&member.key), "no node sent yet");
        update_node(&state, peer.peer_id, session_id, member.clone());
        assert!(state.knows_key(&member.key));
        assert!(!state.knows_key(&NodePublic::from_raw([0x33; 32])));
        deregister(&state, peer.peer_id, session_id);
        assert!(!state.knows_key(&member.key));
    }

    /// #2844: DERP's own verifier, calling Mesh's admission listener, knows a
    /// member's key while its session lives.
    #[tokio::test]
    async fn derp_admission_call_knows_a_live_member_key() {
        use codewire_derp::{HttpKeyVerifier, KeyVerifier as _, Verdict};

        let state = MeshCoordinateState::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = crate::derp_verify::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let verifier = HttpKeyVerifier::parse(&format!("http://{addr}")).unwrap();
        let member = node();
        let key = codewire_tailnet::derp::NodePublic::from_raw(*member.key.as_bytes());
        assert_eq!(verifier.verify(&key).await, Verdict::Unknown);

        let peer = AuthorizedPeer {
            peer_id: Uuid::new_v4(),
            network_id: "network-test".to_owned(),
            node_name: None,
            role: MeshCoordinateRole::Peer,
            environment: None,
        };
        let (tx, _rx) = mpsc::channel(4);
        let session_id = register(&state, &peer, tx).expect("registered").0;
        update_node(&state, peer.peer_id, session_id, member);
        assert_eq!(verifier.verify(&key).await, Verdict::Known);
        deregister(&state, peer.peer_id, session_id);
        assert_eq!(verifier.verify(&key).await, Verdict::Unknown);
        server.abort();
    }

    #[tokio::test]
    async fn network_deletion_closes_existing_and_rejects_delayed_sessions() {
        let state = MeshCoordinateState::new();
        let peer = AuthorizedPeer {
            peer_id: Uuid::new_v4(),
            network_id: "deleted".to_owned(),
            node_name: None,
            role: MeshCoordinateRole::Dial,
            environment: None,
        };
        let (tx, mut rx) = mpsc::channel(4);
        assert!(register(&state, &peer, tx).is_some());
        let retained = AuthorizedPeer {
            peer_id: Uuid::new_v4(),
            network_id: "retained".to_owned(),
            node_name: None,
            role: MeshCoordinateRole::Dial,
            environment: None,
        };
        let (retained_tx, mut retained_rx) = mpsc::channel(4);
        assert!(register(&state, &retained, retained_tx).is_some());
        state.revoke_network("deleted").await.unwrap();
        assert!(rx.recv().await.is_none());
        assert!(matches!(
            retained_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let (delayed_tx, _) = mpsc::channel(4);
        assert!(register(&state, &peer, delayed_tx).is_none());
    }

    #[tokio::test]
    async fn target_publication_after_subscription_notifies_dial() {
        let state = MeshCoordinateState::new();
        let network_id = "network-test".to_owned();
        let dial_id = Uuid::new_v4();
        let target_id = stable_peer_id(&network_id, "peer", "environment-test");
        let (dial_tx, mut dial_rx) = mpsc::channel(4);
        let (target_tx, _target_rx) = mpsc::channel(4);
        register(
            &state,
            &AuthorizedPeer {
                peer_id: dial_id,
                network_id: network_id.clone(),
                node_name: None,
                role: MeshCoordinateRole::Dial,
                environment: None,
            },
            dial_tx,
        );
        let target_session = register(
            &state,
            &AuthorizedPeer {
                peer_id: target_id,
                network_id,
                node_name: None,
                role: MeshCoordinateRole::Peer,
                environment: None,
            },
            target_tx,
        )
        .unwrap()
        .0;

        add_tunnel(&state, dial_id, target_id, MeshCoordinateRole::Dial).unwrap();
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

    /// #5642: a subscription is its subscriber's. When the target's session
    /// ends (a Sandbox stopped), the subscriber is told it is gone and keeps
    /// the subscription, so the target's next registration reaches it without
    /// a new subscription. A member of another network registering under the
    /// same node name never does, and the subscriber's own end takes the
    /// subscription with it.
    #[tokio::test]
    async fn a_subscription_outlives_its_targets_session_and_gets_its_next_one() {
        fn member(network_id: &str, name: &str) -> AuthorizedPeer {
            AuthorizedPeer {
                peer_id: stable_peer_id(network_id, "peer", name),
                network_id: network_id.to_owned(),
                node_name: Some(name.to_owned()),
                role: MeshCoordinateRole::Peer,
                environment: None,
            }
        }
        fn node_with_key(byte: u8) -> Node {
            Node {
                key: NodePublic::from_raw([byte; 32]),
                ..node()
            }
        }
        async fn next(rx: &mut mpsc::Receiver<CoordinateEvent>) -> CoordinateEvent {
            tokio::time::timeout(Duration::from_secs(30), rx.recv())
                .await
                .expect("an event within the hang guard")
                .expect("the event channel stays open")
        }
        let state = MeshCoordinateState::new();
        let (b, a) = (member("network-n", "b"), member("network-n", "a"));
        let (b_tx, mut b_rx) = mpsc::channel(8);
        let b_session = register(&state, &b, b_tx).unwrap().0;
        let (a_tx, _a_rx) = mpsc::channel(8);
        let first = register(&state, &a, a_tx).unwrap().0;
        update_node(&state, a.peer_id, first, node_with_key(0x11));
        add_tunnel(&state, b.peer_id, a.peer_id, MeshCoordinateRole::Peer).unwrap();
        let CoordinateEvent::Update(nodes) = next(&mut b_rx).await else {
            panic!("the subscription delivers the target's node");
        };
        assert_eq!(nodes[0].key, NodePublic::from_raw([0x11; 32]));

        // A stops: B is told, and keeps its subscription.
        deregister(&state, a.peer_id, first);
        assert!(matches!(next(&mut b_rx).await, CoordinateEvent::Remove(id) if id == a.peer_id));
        assert!(state.registry().tunnels.contains(&(b.peer_id, a.peer_id)));

        // A node of the same name in another network is another member.
        let elsewhere = member("network-m", "a");
        let (other_tx, _other_rx) = mpsc::channel(8);
        let other = register(&state, &elsewhere, other_tx).unwrap().0;
        update_node(&state, elsewhere.peer_id, other, node_with_key(0x44));
        assert!(
            b_rx.try_recv().is_err(),
            "another network's member reached B"
        );

        // A starts again with a new key: B gets it without subscribing again.
        let (a_tx, _a_rx) = mpsc::channel(8);
        let second = register(&state, &a, a_tx).unwrap().0;
        update_node(&state, a.peer_id, second, node_with_key(0x33));
        let CoordinateEvent::Update(nodes) = next(&mut b_rx).await else {
            panic!("A's next registration reaches its subscriber");
        };
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].key, NodePublic::from_raw([0x33; 32]));

        // B's own end takes its subscription.
        deregister(&state, b.peer_id, b_session);
        assert!(!state.registry().tunnels.contains(&(b.peer_id, a.peer_id)));
    }

    #[tokio::test]
    async fn typed_coordinate_auth_recovery_and_protocol_are_deterministic() {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "local-owner:org-test",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        seed_enrollment(&store, "cw_enr_recovery-first", "environment-test").await;
        seed_enrollment(&store, "cw_enr_recovery-replacement", "environment-test").await;
        let (address, server) = start_with_store(store).await;
        let mut first_peer = client(address, "cw_enr_recovery-first")
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

        let mut replacement_peer = client(address, "cw_enr_recovery-replacement")
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
            stable_peer_id("network-test", "peer", "environment-test").to_string()
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
    async fn one_use_enrollment_opens_one_named_peer_and_revocation_closes_it() {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "local-owner:org-test",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        let code = "cw_enr_coordinate-once";
        let standby_code = "cw_enr_coordinate-standby";
        let node_name = "native-environment";
        seed_enrollment(&store, code, node_name).await;
        seed_enrollment(&store, standby_code, node_name).await;
        let (address, server) = start_with_store(Arc::clone(&store)).await;

        let mut peer = client(address, code).coordinate().await.unwrap();
        peer.send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        assert!(matches!(
            response(&mut peer).await.msg,
            Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(
                _
            ))
        ));
        let registered = store
            .node_get("network-test", node_name)
            .await
            .unwrap()
            .expect("coordinate enrollment did not register its fixed node");
        assert_eq!(registered.enrollment_id, "enrollment-coordinate-once");
        assert_eq!(registered.peer_url, "");

        let mut replay = client(address, code).coordinate().await.unwrap();
        replay
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        let error = replay
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);

        node_client(address, "cw_test")
            .revoke_mesh_node(RevokeMeshNodeRequest {
                org_id: "org-test".to_owned(),
                network_id: "network-test".to_owned(),
                node_name: node_name.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            store
                .node_get("network-test", node_name)
                .await
                .unwrap()
                .is_none()
        );
        let standby = store
            .node_enrollment_get_by_token_hash(&format!(
                "{:x}",
                Sha256::digest(standby_code.as_bytes())
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(standby.uses_remaining, 0);
        let mut revoked_standby = client(address, standby_code).coordinate().await.unwrap();
        revoked_standby
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        assert_eq!(
            revoked_standby
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::PermissionDenied
        );
        let ended = tokio::time::timeout(
            Duration::from_secs(2),
            peer.message::<MeshCoordinatorServiceCoordinateResponse>(),
        )
        .await
        .expect("revocation did not close the active coordinate stream")
        .expect("revoked coordinate stream returned a transport error");
        assert!(ended.is_none(), "revoked coordinate stream remained active");
        server.abort();
    }

    async fn stored_last_seen(store: &MemoryStore) -> chrono::DateTime<chrono::Utc> {
        store
            .node_get("network-test", "silent")
            .await
            .unwrap()
            .expect("the silent node stays registered")
            .last_seen_at
    }

    /// #2697: a node is online only while its session is live and recently
    /// heard. A node that goes silent lists offline after the window, with
    /// when it was last heard, but its session is never ended: once it pings
    /// again it lists online. A node that keeps pinging stays online. When a
    /// session ends, its last-heard time is kept in the store.
    #[tokio::test]
    async fn a_silent_node_lists_offline_and_comes_back_when_it_pings() {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "local-owner:org-test",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        seed_enrollment(&store, "cw_enr_liveness-live", "live").await;
        seed_enrollment(&store, "cw_enr_liveness-silent", "silent").await;
        let offline_after = Duration::from_millis(600);
        let (address, server) = serve(crate::server::router_with_store_offline_after(
            config(),
            Arc::clone(&store) as crate::store::SharedStore,
            offline_after,
        ))
        .await;
        let list = || async {
            node_client(address, "cw_test")
                .list_mesh_nodes(ListMeshNodesRequest {
                    org_id: "org-test".to_owned(),
                    network_id: "network-test".to_owned(),
                    ..Default::default()
                })
                .await
                .unwrap()
                .into_owned()
                .nodes
                .into_iter()
                .map(|node| (node.name.clone(), node))
                .collect::<HashMap<_, _>>()
        };
        let listed_last_seen = |node: &codewire_proto::codewire::v1::MeshNode| {
            let listed = node.last_seen_at.as_option().expect("last seen");
            chrono::DateTime::from_timestamp(listed.seconds, listed.nanos as u32).unwrap()
        };

        let mut live = client(address, "cw_enr_liveness-live")
            .coordinate()
            .await
            .unwrap();
        live.send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        response(&mut live).await;
        let mut silent = client(address, "cw_enr_liveness-silent")
            .coordinate()
            .await
            .unwrap();
        silent
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        response(&mut silent).await;
        let nodes = list().await;
        assert!(nodes["live"].connected && nodes["silent"].connected);
        let registered = stored_last_seen(&store).await;

        // The live node pings faster than the window. The silent one sends
        // one ping, then nothing, and never closes its stream.
        let pinger = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(150)).await;
                if live.send(request(CoordinatePing::default())).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let pinged_at = chrono::Utc::now();
        silent
            .send(request(CoordinatePing::default()))
            .await
            .unwrap();
        tokio::time::sleep(offline_after * 2).await;

        let nodes = list().await;
        assert!(nodes["live"].connected, "a pinging node went offline");
        let offline = &nodes["silent"];
        assert!(!offline.connected, "a silent node still lists online");
        let heard = listed_last_seen(offline);
        assert!(
            registered < pinged_at
                && heard >= pinged_at
                && heard <= pinged_at + chrono::Duration::milliseconds(500),
            "an offline node lists its last message: {heard} vs {pinged_at}"
        );
        // Silence never ends the session: nothing arrives, and the stream
        // stays open.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                silent.message::<MeshCoordinatorServiceCoordinateResponse>(),
            )
            .await
            .is_err(),
            "a silent session was ended or sent something"
        );

        // Waking, it pings on the same session and lists online again.
        let woke_at = chrono::Utc::now();
        silent
            .send(request(CoordinatePing::default()))
            .await
            .unwrap();
        let back = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let nodes = list().await;
                if nodes["silent"].connected {
                    break nodes;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a node that pinged again did not list online");
        assert!(listed_last_seen(&back["silent"]) >= woke_at);

        // A session that ends writes its last-heard time to the store.
        drop(silent);
        let stored = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let stored = stored_last_seen(&store).await;
                if stored >= woke_at {
                    break stored;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the session's end did not record when it was last heard");
        let nodes = list().await;
        assert!(!nodes["silent"].connected);
        assert_eq!(listed_last_seen(&nodes["silent"]), stored);
        pinger.abort();
        server.abort();
    }

    #[tokio::test]
    async fn enrollment_coordinate_setup_rejects_scope_role_and_unnamed_capabilities() {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "local-owner:org-test",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        for (code, node_name) in [
            ("cw_enr_wrong-role", "role-node"),
            ("cw_enr_wrong-org", "org-node"),
            ("cw_enr_wrong-network", "network-node"),
            ("cw_enr_unnamed", ""),
            ("cw_enr_owned", "owned-node"),
        ] {
            seed_enrollment(&store, code, node_name).await;
        }
        store
            .node_register(NodeRecord {
                network_id: "network-test".to_owned(),
                name: "owned-node".to_owned(),
                peer_url: "https://existing.mesh.test".to_owned(),
                github_id: None,
                owner_subject: "different-owner".to_owned(),
                authorized_by: "different-owner".to_owned(),
                enrollment_id: "existing-enrollment".to_owned(),
                authorized_at: chrono::Utc::now(),
                last_seen_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let (address, server) = start_with_store(Arc::clone(&store)).await;

        let mut wrong_role = client(address, "cw_enr_wrong-role")
            .coordinate()
            .await
            .unwrap();
        wrong_role
            .send(request(hello(MeshCoordinateRole::Dial)))
            .await
            .unwrap();
        assert_eq!(
            wrong_role
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::PermissionDenied
        );

        let mut wrong_org = client(address, "cw_enr_wrong-org")
            .coordinate()
            .await
            .unwrap();
        let mut wrong_org_hello = hello(MeshCoordinateRole::Peer);
        wrong_org_hello.org_id = "org-other".to_owned();
        wrong_org.send(request(wrong_org_hello)).await.unwrap();
        assert_eq!(
            wrong_org
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::PermissionDenied
        );

        let mut wrong_network = client(address, "cw_enr_wrong-network")
            .coordinate()
            .await
            .unwrap();
        let mut wrong_network_hello = hello(MeshCoordinateRole::Peer);
        wrong_network_hello.network_id = "network-other".to_owned();
        wrong_network
            .send(request(wrong_network_hello))
            .await
            .unwrap();
        assert_eq!(
            wrong_network
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::PermissionDenied
        );

        let mut unnamed = client(address, "cw_enr_unnamed")
            .coordinate()
            .await
            .unwrap();
        unnamed
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        assert_eq!(
            unnamed
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::PermissionDenied
        );

        let mut owned = client(address, "cw_enr_owned").coordinate().await.unwrap();
        owned
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        assert_eq!(
            owned
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::AlreadyExists
        );
        let existing = store
            .node_get("network-test", "owned-node")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(existing.owner_subject, "different-owner");
        assert_eq!(existing.enrollment_id, "existing-enrollment");

        for (code, node_name) in [
            ("cw_enr_wrong-role", "role-node"),
            ("cw_enr_wrong-org", "org-node"),
            ("cw_enr_wrong-network", "network-node"),
            ("cw_enr_unnamed", ""),
            ("cw_enr_owned", "owned-node"),
        ] {
            let enrollment = store
                .node_enrollment_get_by_token_hash(&format!(
                    "{:x}",
                    Sha256::digest(code.as_bytes())
                ))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                enrollment.uses_remaining, 1,
                "rejected coordinate setup consumed {node_name:?}"
            );
        }

        let mut correctly_bound = client(address, "cw_enr_wrong-role")
            .coordinate()
            .await
            .unwrap();
        correctly_bound
            .send(request(hello(MeshCoordinateRole::Peer)))
            .await
            .unwrap();
        let _ = response(&mut correctly_bound).await;
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

        let mut dial_with_unknown_bearer = client(address, "retired-environment-bearer")
            .coordinate()
            .await
            .unwrap();
        dial_with_unknown_bearer
            .send(request(hello(MeshCoordinateRole::Dial)))
            .await
            .unwrap();
        let error = dial_with_unknown_bearer
            .message::<MeshCoordinatorServiceCoordinateResponse>()
            .await
            .unwrap_err();
        assert_eq!(error.code, connectrpc::ErrorCode::Unauthenticated);
        server.abort();
    }

    #[tokio::test]
    async fn same_org_nonmember_cannot_coordinate_until_invite_join() {
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "different-network-owner",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        let invite_code = "cw_inv_synthetic_coordinate_membership";
        store
            .invite_create(Invite {
                id: "invite-coordinate-membership".to_owned(),
                network_id: "network-test".to_owned(),
                organization_id: "org-test".to_owned(),
                created_by_user_id: "different-network-owner".to_owned(),
                code_hash: format!("{:x}", Sha256::digest(invite_code.as_bytes())),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let (address, server) = start_with_store(Arc::clone(&store)).await;

        let mut denied = client(address, "cw_test").coordinate().await.unwrap();
        denied
            .send(request(hello(MeshCoordinateRole::Dial)))
            .await
            .unwrap();
        assert_eq!(
            denied
                .message::<MeshCoordinatorServiceCoordinateResponse>()
                .await
                .unwrap_err()
                .code,
            connectrpc::ErrorCode::PermissionDenied
        );

        MeshNetworkServiceClient::new(
            HttpClient::plaintext_http2_only(),
            ClientConfig::new(format!("http://{address}").parse().unwrap())
                .with_default_header(axum::http::header::AUTHORIZATION, "Bearer cw_test"),
        )
        .join_mesh_network(JoinMeshNetworkRequest {
            invite_code: invite_code.to_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(
            store
                .network_member_get("network-test", "local-owner:org-test")
                .await
                .unwrap()
                .unwrap()
                .role,
            NETWORK_ROLE_MEMBER
        );

        let mut admitted = client(address, "cw_test").coordinate().await.unwrap();
        admitted
            .send(request(hello(MeshCoordinateRole::Dial)))
            .await
            .unwrap();
        assert!(matches!(
            response(&mut admitted).await.msg,
            Some(mesh_coordinator_service_coordinate_response::Msg::DerpMap(
                _
            ))
        ));
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
        let store = Arc::new(MemoryStore::new());
        store
            .network_create_with_owner(
                "network-test",
                "org-test",
                "local-owner:org-test",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        seed_enrollment(&store, "cw_enr_native-grpc", "grpc-node").await;
        let (address, server) = start_with_store(store).await;
        let mut peer = client_with_protocol(address, "cw_enr_native-grpc", Protocol::Grpc)
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
