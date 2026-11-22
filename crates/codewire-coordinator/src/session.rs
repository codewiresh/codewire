//! Transport-independent coordinator peer session.
//!
//! The generated Connect adapter owns the wire codec. Registry, NATS/KV
//! fanout, heartbeat cadence, and teardown live here.

use std::future::Future;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use codewire_tailnet::node::Node;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

use super::disco_bindings::disco_hex;
use super::node_bindings::{
    BindingStore, Claim, NODE_BINDING_REFRESH, Principal, Refresh, Refusal, SessionBinding,
};
use super::node_keys::{SessionNodeKey, key_hex};
use super::peer::{PeerProof, PeerVerifier, ProofError, unix_now};
use super::{
    COORDINATE_HEARTBEAT_INTERVAL, CoordinationPlane, DerpMap, PeerEvent, PeerKind, PeerRegistry,
    RemoteEvent, SIDECAR_KV_REFRESH, Transport, log_node, spawn_node_subscription,
    spawn_remove_subscription,
};
use codewire_server_core::revocation::Revocation;

mod addresses;
mod fenced;
use addresses::{AddressHolders, AddressRefusal};
use fenced::RemoteClients;
pub(crate) use fenced::{ClientNodeMessage, FencedClient, Revocations};

/// A decoded message entering the shared peer session.
pub(crate) enum SessionInput {
    Node(Node),
    Ping,
    /// A fresh peer token re-proving an environment peer's session.
    Proof(String),
    /// An open transport frame with no session-level meaning. Returning it
    /// yields control to the outer session select before reading another frame.
    Noop,
}

/// A transport-neutral message emitted by the shared peer session.
#[derive(Debug)]
pub(crate) enum SessionOutput {
    DerpMap(serde_json::Value),
    Peer(PeerEvent),
    Heartbeat,
    /// The client lost its access to the environment; the session ends.
    AccessRevoked,
    /// The credential that admitted the client was lost; the session ends.
    CredentialRevoked,
    /// The session's node key could not be bound to it; the session ends.
    NodeKeyRefused(Refusal),
    /// The session's node carried an address it may not; the session ends.
    AddressRefused(AddressRefusal),
}

/// The outcome of re-checking a client's access to its environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientRecheck {
    Allowed,
    Refused,
    /// The records could not be read; the session is kept, as an environment
    /// peer's is when its proof check is unavailable.
    Unavailable,
}

/// Re-checks a client's access while its session lives (#3828). A client is
/// authorized when it joins; without this, losing access would leave it on
/// the environment's tailnet for as long as its stream lasts.
pub(crate) trait ClientAccess: Send + Sync {
    fn recheck(&self) -> Pin<Box<dyn Future<Output = ClientRecheck> + Send + '_>>;
}

/// Decoded inbound half of a coordinator transport.
pub(crate) trait SessionSource: Send {
    async fn next(&mut self) -> Option<SessionInput>;
}

/// Encoded outbound half of a coordinator transport.
pub(crate) trait SessionSink: Send {
    /// Send one output, returning `false` when the transport is no longer
    /// writable. Adapters log codec/transport-specific failures themselves.
    async fn send(&mut self, output: SessionOutput) -> bool;
}

/// Authorized peer identity and transport for one shared session.
#[derive(Clone)]
pub(crate) struct SessionPeer {
    pub(crate) peer_id: Uuid,
    /// Who the session's node key is bound to: the signed-in user for a
    /// client, the environment itself for its daemon.
    pub(crate) principal: Principal,
    pub(crate) sidecar_id: Option<Uuid>,
    pub(crate) kind: PeerKind,
    pub(crate) transport: Transport,
    /// An environment peer's proof at connect. Required for `Sidecar`.
    pub(crate) proof: Option<PeerProof>,
}

/// What every peer session on one coordinator shares.
#[derive(Clone)]
pub(crate) struct SessionContext {
    pub(crate) peers: Arc<PeerRegistry>,
    /// The optional cross-replica NATS/KV plane.
    pub(crate) coordination: Option<Arc<CoordinationPlane>>,
    pub(crate) derp_map: DerpMap,
    pub(crate) revocations: Revocations,
}

/// The checks behind environment-peer sessions and the cadence of their
/// re-checks.
#[derive(Clone)]
pub(crate) struct PeerChecks {
    pub(crate) verifier: Arc<dyn PeerVerifier>,
    pub(crate) recheck: Duration,
}

/// Why a session ended on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerEnd {
    /// No valid proof arrived before the last proven token expired.
    ProofLapsed,
    /// The operation generation moved on or the environment is going away.
    Revoked,
    /// The peer presented an invalid proof.
    BadProof,
    /// A client's re-check refused its access to the environment.
    AccessRevoked,
    /// The credential that admitted a client was lost.
    CredentialRevoked(Revocation),
    /// The node key the peer announced was refused.
    NodeKeyRefused(Refusal),
    /// The address the peer announced was refused (#5561).
    AddressRefused(AddressRefusal),
    /// A newer session of the same principal took the node key over.
    Retired,
    /// A session that pings went quiet for [`SESSION_SILENCE_LIMIT`].
    Silent,
}

/// A session that has pinged ends when nothing arrives from it for this
/// long: three of the peer's 15 s pings, mirroring the peer's own
/// `COORDINATOR_SILENCE_LIMIT` in `codewire-client`'s `coordinator.rs`. Its
/// stream can stall at the CDN edge with no error reaching the coordinator
/// (#5120).
const SESSION_SILENCE_LIMIT: Duration = Duration::from_secs(45);

/// What one turn of the session loop decided: keep going, or end, with the
/// reason when the session ended on its own.
type Turn = ControlFlow<Option<PeerEnd>>;

/// An environment peer's current proof and the checks that re-verify it.
struct Proven {
    proof: PeerProof,
    checks: PeerChecks,
}

/// Run one authorized coordinator peer until its transport closes.
pub(crate) async fn run_peer_session<Source, Sink>(
    mut source: Source,
    mut sink: Sink,
    context: SessionContext,
    peer: SessionPeer,
    checks: Option<PeerChecks>,
    client_access: Option<Box<dyn ClientAccess>>,
    fenced: Option<FencedClient>,
) where
    Source: SessionSource,
    Sink: SessionSink,
{
    let Some(mut session) = PeerSession::start(context, peer, checks, client_access, fenced).await
    else {
        return;
    };
    if !sink
        .send(SessionOutput::DerpMap(session.derp_map.to_json()))
        .await
    {
        session.abandon().await;
        return;
    }
    tracing::info!(
        env_id = %session.env_id,
        peer_id = %session.peer.peer_id,
        kind = session.peer.kind.as_str(),
        transport = session.peer.transport.as_str(),
        "coordinator derp_map sent"
    );
    let ended = session.run(&mut source, &mut sink).await;
    session.finish(&mut sink, ended).await;
}

/// One registered peer session and everything it holds until it ends.
struct PeerSession {
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
    derp_map: DerpMap,
    peer: SessionPeer,
    env_id: Uuid,
    /// The session's registry entry owner.
    owner: Uuid,
    events: mpsc::UnboundedReceiver<PeerEvent>,
    /// Held so `remote_rx` stays open while no subscription feeds it.
    _remote_tx: mpsc::UnboundedSender<RemoteEvent>,
    remote_rx: mpsc::UnboundedReceiver<RemoteEvent>,
    /// The session's node key, admitted by DERP while the session lives.
    node_key: SessionNodeKey,
    /// The node key's binding to this session's principal and environment.
    binding: SessionBinding,
    /// The node's disco key's binding, the same way (#5962).
    disco: SessionBinding,
    /// Whether the peer pings, so its silence ends the session.
    pinged: bool,
    last_heard: Instant,
    last_sidecar_node: Arc<AsyncMutex<Option<Node>>>,
    refresh_task: Option<JoinHandle<()>>,
    proven: Option<Proven>,
    generation: i64,
    recheck_every: Duration,
    client_access: Option<Box<dyn ClientAccess>>,
    revocations: Revocations,
    /// A client's admission, fenced here.
    fenced: Option<FencedClient>,
    /// An environment session's clients from other replicas, fenced here.
    remote_clients: RemoteClients,
    /// A client's address, pinned by its first node.
    address: Option<IpAddr>,
    /// Which client holds each address an environment's session forwards.
    address_holders: AddressHolders,
}

impl PeerSession {
    /// Registers the peer and subscribes it to the cross-replica plane;
    /// `None` when it may not run.
    async fn start(
        context: SessionContext,
        peer: SessionPeer,
        checks: Option<PeerChecks>,
        client_access: Option<Box<dyn ClientAccess>>,
        fenced: Option<FencedClient>,
    ) -> Option<Self> {
        let SessionContext {
            peers,
            coordination,
            derp_map,
            revocations,
        } = context;
        let SessionPeer {
            peer_id,
            sidecar_id,
            kind,
            transport,
            proof,
            ..
        } = peer;
        let recheck_every = checks
            .as_ref()
            .map(|checks| checks.recheck)
            .unwrap_or(Duration::from_secs(3600));
        // An environment peer without a proof, or without checks, never runs.
        let proven = match (kind, proof, checks.clone()) {
            (PeerKind::Sidecar, Some(proof), Some(checks)) => Some(Proven { proof, checks }),
            (PeerKind::Sidecar, _, _) => {
                tracing::warn!(env_id = %peer_id, "coordinator environment peer without proof refused");
                return None;
            }
            (PeerKind::Client, _, _) => None,
        };
        let Some(registration) = peers.register(peer_id, proof.map(PeerProof::rank)) else {
            tracing::info!(
                env_id = %peer_id,
                "coordinator environment peer refused: a newer session holds this environment"
            );
            return None;
        };
        let owner = registration.owner;
        let node_key = SessionNodeKey::new(coordination.clone(), owner);
        let env_id = sidecar_id.unwrap_or(peer_id);
        // A client's peer id is fresh for each session; an environment
        // peer's is its environment, so its registry owner names it.
        let session_id = match kind {
            PeerKind::Client => peer_id,
            PeerKind::Sidecar => owner,
        };
        let binding = SessionBinding::new(
            binding_store(&peers, coordination.as_ref()),
            peer.principal.clone(),
            env_id,
            session_id,
        );
        let disco = SessionBinding::new(
            disco_store(&peers, coordination.as_ref()),
            peer.principal.clone(),
            env_id,
            session_id,
        );
        tracing::info!(
            %env_id,
            %peer_id,
            kind = kind.as_str(),
            has_coordination = coordination.is_some(),
            transport = transport.as_str(),
            "coordinator peer connected"
        );
        if let Some(sidecar_id) = sidecar_id {
            peers.add_tunnel(peer_id, sidecar_id);
        }

        let (remote_tx, remote_rx) = mpsc::unbounded_channel();
        let last_sidecar_node = Arc::new(AsyncMutex::new(None::<Node>));
        if let Some(coordination) = coordination.as_ref() {
            subscribe_remote(coordination, &peer, checks.as_ref(), &remote_tx).await;
        }

        let generation = proof.map(|proof| proof.generation).unwrap_or_default();
        let refresh_task = match (kind, coordination.as_ref()) {
            (PeerKind::Sidecar, Some(coordination)) => Some(spawn_sidecar_refresh(
                coordination.clone(),
                last_sidecar_node.clone(),
                peer_id,
                generation,
            )),
            _ => None,
        };
        Some(Self {
            peers,
            coordination,
            derp_map,
            peer,
            env_id,
            owner,
            events: registration.events,
            _remote_tx: remote_tx,
            remote_rx,
            node_key,
            binding,
            disco,
            pinged: false,
            last_heard: Instant::now(),
            last_sidecar_node,
            refresh_task,
            proven,
            generation,
            recheck_every,
            client_access,
            revocations,
            fenced,
            remote_clients: RemoteClients::default(),
            address: None,
            address_holders: AddressHolders::default(),
        })
    }

    /// Serves the session until its transport closes or it ends on its own.
    async fn run<Source, Sink>(&mut self, source: &mut Source, sink: &mut Sink) -> Option<PeerEnd>
    where
        Source: SessionSource,
        Sink: SessionSink,
    {
        let mut heartbeat = tokio::time::interval(COORDINATE_HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let mut recheck = tokio::time::interval(self.recheck_every);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        recheck.tick().await;
        let mut binding_refresh = tokio::time::interval(NODE_BINDING_REFRESH);
        binding_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        binding_refresh.tick().await;

        loop {
            let silence = tokio::time::sleep_until(self.last_heard + SESSION_SILENCE_LIMIT);
            let turn = tokio::select! {
                event = self.events.recv() => self.forward(sink, event, "local").await,
                event = self.remote_rx.recv() => self.forward_remote(sink, event).await,
                _ = heartbeat.tick() => {
                    if sink.send(SessionOutput::Heartbeat).await {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(None)
                    }
                }
                _ = recheck.tick(), if self.proven.is_some() || self.client_access.is_some() => {
                    self.recheck().await
                }
                _ = binding_refresh.tick() => self.refresh_binding().await,
                revocation = fenced::revoked(&mut self.fenced) => {
                    ControlFlow::Break(Some(PeerEnd::CredentialRevoked(revocation)))
                }
                peer_id = self.remote_clients.next_revoked() => {
                    self.forward(sink, Some(PeerEvent::Remove(peer_id)), "fence").await
                }
                () = silence, if self.pinged => ControlFlow::Break(Some(PeerEnd::Silent)),
                input = source.next() => self.handle_input(input).await,
            };
            if let ControlFlow::Break(ended) = turn {
                return ended;
            }
        }
    }

    /// Sends one peer event; a closed channel or transport ends the session.
    /// An environment's session forwards each address from one client at a
    /// time.
    async fn forward<Sink: SessionSink>(
        &mut self,
        sink: &mut Sink,
        event: Option<PeerEvent>,
        source: &'static str,
    ) -> Turn {
        let Some(event) = event else {
            return ControlFlow::Break(None);
        };
        let event = match (event, self.peer.kind) {
            (PeerEvent::Update(nodes), PeerKind::Sidecar) => {
                let nodes = self.address_holders.admit(self.env_id, nodes);
                if nodes.is_empty() {
                    return ControlFlow::Continue(());
                }
                PeerEvent::Update(nodes)
            }
            (PeerEvent::Remove(id), PeerKind::Sidecar) => {
                self.address_holders.release(id);
                PeerEvent::Remove(id)
            }
            (event, _) => event,
        };
        event.log_send(
            self.env_id,
            self.peer.peer_id,
            self.peer.kind,
            source,
            self.peer.transport,
        );
        if sink.send(SessionOutput::Peer(event)).await {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(None)
        }
    }

    /// Sends one event from another replica. A removal naming this session
    /// retires it; a client is sent no other removal, since it peers only
    /// with its environment. A client's node reaches an environment only once
    /// this replica's fence admits it.
    async fn forward_remote<Sink: SessionSink>(
        &mut self,
        sink: &mut Sink,
        event: Option<RemoteEvent>,
    ) -> Turn {
        let event = match event {
            Some(RemoteEvent::Client(message)) => {
                let ClientNodeMessage { node, admission } = *message;
                let forward = self
                    .remote_clients
                    .admit(&self.revocations, node.id, admission.as_ref())
                    .await;
                if !forward {
                    return ControlFlow::Continue(());
                }
                Some(PeerEvent::Update(vec![node]))
            }
            Some(RemoteEvent::Peer(event)) => Some(event),
            None => None,
        };
        match (event, self.peer.kind) {
            (Some(PeerEvent::Remove(id)), _) if id == self.binding.session() => {
                ControlFlow::Break(Some(PeerEnd::Retired))
            }
            (Some(PeerEvent::Remove(_)), PeerKind::Client) => ControlFlow::Continue(()),
            (Some(PeerEvent::Remove(id)), PeerKind::Sidecar) => {
                self.remote_clients.remove(id);
                self.forward(sink, Some(PeerEvent::Remove(id)), "remote")
                    .await
            }
            (event, _) => self.forward(sink, event, "remote").await,
        }
    }

    /// Rewrites the node key's binding; one that names another session now
    /// ends this one as a takeover would. An unreachable store keeps it.
    async fn refresh_binding(&self) -> Turn {
        let refreshed = match self.binding.refresh().await {
            Ok(Refresh::Kept) => self.disco.refresh().await,
            other => other,
        };
        match refreshed {
            Ok(Refresh::Kept) => ControlFlow::Continue(()),
            Ok(Refresh::Lost) => ControlFlow::Break(Some(PeerEnd::Retired)),
            Err(error) => {
                tracing::warn!(error = ?error, env_id = %self.env_id, peer_id = %self.peer.peer_id, "coordinator node binding refresh failed");
                ControlFlow::Continue(())
            }
        }
    }

    /// Binds the key of a node the session sent before the node reaches any
    /// peer, retiring the session it takes the key over from.
    async fn claim_node_key(&mut self, node: &Node) -> Turn {
        let refusal = match self.binding.claim(key_hex(&node.key)).await {
            Ok(Claim::Bound) => return self.claim_disco_key(node).await,
            Ok(Claim::TookOver { previous }) => {
                self.retire(previous).await;
                return self.claim_disco_key(node).await;
            }
            Ok(Claim::Refused(refusal)) => refusal,
            Err(error) => {
                tracing::warn!(error = ?error, env_id = %self.env_id, peer_id = %self.peer.peer_id, "coordinator node binding claim failed");
                Refusal::Unavailable
            }
        };
        tracing::warn!(
            env_id = %self.env_id,
            peer_id = %self.peer.peer_id,
            kind = self.peer.kind.as_str(),
            refusal = ?refusal,
            "coordinator node key refused"
        );
        ControlFlow::Break(Some(PeerEnd::NodeKeyRefused(refusal)))
    }

    /// Binds the node's disco key as its node key is bound (#5962). A new
    /// disco key releases the previous one, so a rotated key stops admitting
    /// relay allocations at once; the all-zero key means none and is never
    /// bound. A takeover is a reconnect, and the node key's claim has already
    /// retired the earlier session.
    async fn claim_disco_key(&mut self, node: &Node) -> Turn {
        if node.disco_key.is_zero() {
            return ControlFlow::Continue(());
        }
        let refusal = match self.disco.claim(disco_hex(&node.disco_key)).await {
            Ok(Claim::Bound | Claim::TookOver { .. }) => return ControlFlow::Continue(()),
            Ok(Claim::Refused(refusal)) => refusal,
            Err(error) => {
                tracing::warn!(error = ?error, env_id = %self.env_id, peer_id = %self.peer.peer_id, "coordinator disco binding claim failed");
                Refusal::Unavailable
            }
        };
        tracing::warn!(
            env_id = %self.env_id,
            peer_id = %self.peer.peer_id,
            kind = self.peer.kind.as_str(),
            refusal = ?refusal,
            "coordinator disco key refused"
        );
        ControlFlow::Break(Some(PeerEnd::NodeKeyRefused(refusal)))
    }

    /// Ends the session `previous` and tells its peers it is gone, on this
    /// replica and, through the environment's remove subject, the others.
    async fn retire(&self, previous: Uuid) {
        tracing::info!(
            env_id = %self.env_id,
            peer_id = %self.peer.peer_id,
            kind = self.peer.kind.as_str(),
            %previous,
            "coordinator node key taken over; retiring the previous session"
        );
        // An environment peer's older session here was already replaced
        // when this one registered.
        if matches!(self.peer.kind, PeerKind::Client) {
            self.peers.retire(previous);
        }
        if let Some(coordination) = self.coordination.as_ref()
            && let Err(error) = coordination.publish_remove(self.env_id, previous).await
        {
            tracing::warn!(error = ?error, env_id = %self.env_id, %previous, "coordinator retired session remove publish failed");
        }
    }

    /// Re-checks an environment peer's proof or a client's access.
    async fn recheck(&self) -> Turn {
        if let Some(Proven { proof, checks }) = self.proven.as_ref() {
            if proof.lapsed(unix_now()) {
                return ControlFlow::Break(Some(PeerEnd::ProofLapsed));
            }
            match checks
                .verifier
                .is_current(self.peer.peer_id, proof.generation)
                .await
            {
                Ok(true) | Err(ProofError::Unavailable) => {}
                Ok(false) | Err(ProofError::Refused) => {
                    return ControlFlow::Break(Some(PeerEnd::Revoked));
                }
            }
        } else if let Some(access) = self.client_access.as_deref() {
            match access.recheck().await {
                ClientRecheck::Allowed | ClientRecheck::Unavailable => {}
                ClientRecheck::Refused => return ControlFlow::Break(Some(PeerEnd::AccessRevoked)),
            }
        }
        ControlFlow::Continue(())
    }

    async fn handle_input(&mut self, input: Option<SessionInput>) -> Turn {
        if input.is_some() {
            self.last_heard = Instant::now();
        }
        match input {
            Some(SessionInput::Node(node)) => {
                if let Err(refusal) =
                    addresses::check(self.peer.kind, self.env_id, &node, &mut self.address)
                {
                    addresses::count_refusal(
                        self.env_id,
                        self.peer.peer_id,
                        None,
                        refusal.message(),
                    );
                    return ControlFlow::Break(Some(PeerEnd::AddressRefused(refusal)));
                }
                self.claim_node_key(&node).await?;
                self.node_key.observe(node.key).await;
                let admission = self.revocations.carry(self.fenced.as_ref());
                handle_node_update(
                    &self.peers,
                    self.owner,
                    self.coordination.as_deref(),
                    &self.last_sidecar_node,
                    &self.peer,
                    self.generation,
                    ClientNodeMessage { node, admission },
                )
                .await;
            }
            Some(SessionInput::Proof(token)) => return self.prove(&token).await,
            Some(SessionInput::Ping) => self.pinged = true,
            Some(SessionInput::Noop) => {}
            None => return ControlFlow::Break(None),
        }
        ControlFlow::Continue(())
    }

    /// Verifies an in-band proof; a client never proves, so it is ignored.
    async fn prove(&mut self, token: &str) -> Turn {
        let Some(Proven { proof, checks }) = self.proven.as_mut() else {
            return ControlFlow::Continue(());
        };
        match checks.verifier.verify(self.peer.peer_id, token).await {
            Ok(next) if next.generation == proof.generation => {
                let raised = PeerProof {
                    generation: proof.generation,
                    expires_at: proof.expires_at.max(next.expires_at),
                };
                self.peers
                    .raise_rank(self.peer.peer_id, self.owner, raised.rank());
                *proof = raised;
                ControlFlow::Continue(())
            }
            Err(ProofError::Unavailable) => ControlFlow::Continue(()),
            Ok(_) | Err(ProofError::Refused) => ControlFlow::Break(Some(PeerEnd::BadProof)),
        }
    }

    /// Releases what the session holds when its first send already failed.
    async fn abandon(self) {
        self.peers.deregister(self.peer.peer_id, self.owner);
        self.node_key.close().await;
        if let Some(task) = self.refresh_task {
            task.abort();
        }
    }

    /// Tears the session down after its loop ended.
    async fn finish<Sink: SessionSink>(self, sink: &mut Sink, ended: Option<PeerEnd>) {
        let SessionPeer {
            peer_id,
            sidecar_id,
            kind,
            transport,
            ..
        } = self.peer;
        tracing::info!(
            env_id = %self.env_id,
            %peer_id,
            kind = kind.as_str(),
            transport = transport.as_str(),
            ended = ?ended,
            "coordinator peer disconnected"
        );
        let reason = match ended {
            Some(PeerEnd::AccessRevoked) => Some(SessionOutput::AccessRevoked),
            Some(PeerEnd::CredentialRevoked(_)) => Some(SessionOutput::CredentialRevoked),
            Some(PeerEnd::NodeKeyRefused(refusal)) => Some(SessionOutput::NodeKeyRefused(refusal)),
            Some(PeerEnd::AddressRefused(refusal)) => Some(SessionOutput::AddressRefused(refusal)),
            _ => None,
        };
        if let Some(reason) = reason {
            // Tell the peer why before its stream closes; it may already be gone.
            let _ = sink.send(reason).await;
        }
        if let (Some(PeerEnd::CredentialRevoked(revocation)), Some(fenced)) =
            (ended, self.fenced.as_ref())
        {
            self.revocations
                .record(fenced, revocation, self.env_id)
                .await;
        }
        self.peers.deregister(peer_id, self.owner);
        self.node_key.close().await;
        self.binding.release().await;
        self.disco.release().await;
        if let (PeerKind::Client, Some(env_id), Some(coordination)) =
            (kind, sidecar_id, self.coordination.as_ref())
            && let Err(err) = coordination.publish_remove(env_id, peer_id).await
        {
            tracing::warn!(error = ?err, %env_id, %peer_id, "coordinator client remove publish failed");
        }
        if let Some(task) = self.refresh_task {
            task.abort();
        }
        // A revoked generation leaves no recorded node for clients to dial.
        if ended == Some(PeerEnd::Revoked)
            && let Some(coordination) = self.coordination.as_ref()
            && let Err(err) = coordination
                .delete_sidecar_node(peer_id, self.generation)
                .await
        {
            tracing::warn!(error = ?err, env_id = %peer_id, "coordinator revoked sidecar KV delete failed");
        }
    }
}

/// Where the session's node key bindings live: the NATS bucket every replica
/// shares, or the local registry without NATS.
fn binding_store(
    peers: &Arc<PeerRegistry>,
    coordination: Option<&Arc<CoordinationPlane>>,
) -> Arc<dyn BindingStore> {
    match coordination {
        Some(coordination) => Arc::new(coordination.node_bindings.clone()),
        None => peers.bindings.clone(),
    }
}

fn disco_store(
    peers: &Arc<PeerRegistry>,
    coordination: Option<&Arc<CoordinationPlane>>,
) -> Arc<dyn BindingStore> {
    match coordination {
        Some(coordination) => Arc::new(coordination.disco_bindings.clone()),
        None => peers.disco_bindings.clone(),
    }
}

/// Subscribes the session to the other replicas' events for its environment,
/// and hands a client the environment peer's recorded node.
async fn subscribe_remote(
    coordination: &CoordinationPlane,
    peer: &SessionPeer,
    checks: Option<&PeerChecks>,
    remote_tx: &mpsc::UnboundedSender<RemoteEvent>,
) {
    let SessionPeer {
        peer_id,
        sidecar_id,
        kind,
        transport,
        ..
    } = *peer;
    match kind {
        PeerKind::Client => {
            let Some(env_id) = sidecar_id else {
                return;
            };
            match coordination.subscribe_agent(env_id).await {
                Ok(sub) => spawn_node_subscription(sub, remote_tx.clone(), env_id, "agent"),
                Err(err) => {
                    tracing::warn!(error = ?err, %env_id, "coordinator NATS agent subscribe failed");
                }
            }
            // A newer session of this client, on any replica, retires this one.
            match coordination.subscribe_remove(env_id).await {
                Ok(sub) => spawn_remove_subscription(sub, remote_tx.clone(), env_id),
                Err(err) => {
                    tracing::warn!(error = ?err, %env_id, "coordinator NATS remove subscribe failed");
                }
            }
            match coordination.get_sidecar_node(env_id).await {
                Ok(Some((generation, node))) => {
                    if stamped_generation_current(checks, env_id, generation).await {
                        log_node(
                            "coordinator KV hit for sidecar node",
                            env_id,
                            peer_id,
                            PeerKind::Sidecar,
                            &node,
                            Some(transport),
                        );
                        let _ = remote_tx.send(RemoteEvent::Peer(PeerEvent::Update(vec![node])));
                    } else {
                        tracing::info!(%env_id, %peer_id, generation, "coordinator sidecar KV node is from a past generation");
                    }
                }
                Ok(None) => {
                    tracing::warn!(%env_id, %peer_id, "coordinator sidecar KV miss");
                }
                Err(err) => {
                    tracing::warn!(error = ?err, %env_id, %peer_id, "coordinator sidecar KV get failed");
                }
            }
        }
        PeerKind::Sidecar => {
            match coordination.subscribe_clients(peer_id).await {
                Ok(sub) => spawn_node_subscription(sub, remote_tx.clone(), peer_id, "client"),
                Err(err) => {
                    tracing::warn!(error = ?err, env_id = %peer_id, "coordinator NATS client subscribe failed");
                }
            }
            match coordination.subscribe_remove(peer_id).await {
                Ok(sub) => spawn_remove_subscription(sub, remote_tx.clone(), peer_id),
                Err(err) => {
                    tracing::warn!(error = ?err, env_id = %peer_id, "coordinator NATS remove subscribe failed");
                }
            }
        }
    }
}

/// Rewrites an environment peer's recorded node so it outlives the bucket's
/// TTL while the session lives.
fn spawn_sidecar_refresh(
    coordination: Arc<CoordinationPlane>,
    last_sidecar_node: Arc<AsyncMutex<Option<Node>>>,
    env_id: Uuid,
    generation: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SIDECAR_KV_REFRESH).await;
            let node = { last_sidecar_node.lock().await.clone() };
            let Some(node) = node else {
                tracing::warn!(%env_id, "coordinator sidecar KV refresh skipped");
                continue;
            };
            if let Err(err) = coordination
                .put_sidecar_node(env_id, generation, &node)
                .await
            {
                tracing::warn!(error = ?err, %env_id, "coordinator sidecar KV refresh failed");
            }
        }
    })
}

/// Whether a KV node stamped with `generation` belongs to the environment's
/// current generation. Without checks (hermetic tests) every node is kept;
/// when the records are unavailable the node is kept and the client's own
/// connect then fails closed if the peer is gone.
async fn stamped_generation_current(
    checks: Option<&PeerChecks>,
    env_id: Uuid,
    generation: i64,
) -> bool {
    let Some(checks) = checks else {
        return true;
    };
    !matches!(
        checks.verifier.is_current(env_id, generation).await,
        Ok(false) | Err(ProofError::Refused)
    )
}

async fn handle_node_update(
    peers: &PeerRegistry,
    owner: Uuid,
    coordination: Option<&CoordinationPlane>,
    last_sidecar_node: &Arc<AsyncMutex<Option<Node>>>,
    peer: &SessionPeer,
    generation: i64,
    update: ClientNodeMessage,
) {
    let ClientNodeMessage {
        mut node,
        admission,
    } = update;
    let SessionPeer {
        peer_id,
        sidecar_id,
        kind,
        transport,
        ..
    } = *peer;
    node.id = peer_id;
    peers.update_node(peer_id, owner, node.clone());

    match kind {
        PeerKind::Client => {
            let Some(env_id) = sidecar_id else {
                return;
            };
            log_node(
                "coordinator client node update",
                env_id,
                peer_id,
                PeerKind::Client,
                &node,
                Some(transport),
            );
            let Some(coordination) = coordination else {
                return;
            };
            let message = ClientNodeMessage { node, admission };
            if let Err(err) = coordination.publish_client_node(env_id, &message).await {
                tracing::warn!(error = ?err, %env_id, %peer_id, "coordinator client node publish failed");
            }
        }
        PeerKind::Sidecar => {
            let initial = {
                let mut last_sidecar_node = last_sidecar_node.lock().await;
                let initial = last_sidecar_node.is_none();
                *last_sidecar_node = Some(node.clone());
                initial
            };
            log_node(
                "coordinator sidecar node update",
                peer_id,
                peer_id,
                PeerKind::Sidecar,
                &node,
                Some(transport),
            );
            tracing::info!(
                env_id = %peer_id,
                %initial,
                transport = transport.as_str(),
                "coordinator sidecar node state recorded"
            );
            let Some(coordination) = coordination else {
                return;
            };
            if let Err(err) = coordination
                .put_sidecar_node(peer_id, generation, &node)
                .await
            {
                tracing::warn!(error = ?err, env_id = %peer_id, "coordinator sidecar KV put failed");
            } else {
                tracing::info!(
                    env_id = %peer_id,
                    %initial,
                    transport = transport.as_str(),
                    "coordinator sidecar KV put OK"
                );
            }
            if let Err(err) = coordination.publish_sidecar_node(peer_id, &node).await {
                tracing::warn!(error = ?err, env_id = %peer_id, "coordinator sidecar node publish failed");
            }
        }
    }
}

#[cfg(test)]
mod tests;
