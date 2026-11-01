//! Transport-independent coordinator peer session.
//!
//! The generated Connect adapter owns the wire codec. Registry, NATS/KV
//! fanout, heartbeat cadence, and teardown live here.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use codewire_tailnet::node::Node;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use uuid::Uuid;

use super::node_keys::SessionNodeKey;
use super::peer::{PeerProof, PeerVerifier, ProofError, unix_now};
use super::{
    COORDINATE_HEARTBEAT_INTERVAL, CoordinationPlane, PeerEvent, PeerKind, PeerRegistry,
    SIDECAR_KV_REFRESH, Transport, build_derp_map, derp_map_config_from_env, log_node,
    spawn_node_subscription, spawn_remove_subscription,
};

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
#[derive(Clone, Copy)]
pub(crate) struct SessionPeer {
    pub(crate) peer_id: Uuid,
    pub(crate) sidecar_id: Option<Uuid>,
    pub(crate) kind: PeerKind,
    pub(crate) transport: Transport,
    /// An environment peer's proof at connect. Required for `Sidecar`.
    pub(crate) proof: Option<PeerProof>,
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
}

/// Run one authorized coordinator peer until its transport closes.
pub(crate) async fn run_peer_session<Source, Sink>(
    mut source: Source,
    mut sink: Sink,
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
    peer: SessionPeer,
    checks: Option<PeerChecks>,
    client_access: Option<Box<dyn ClientAccess>>,
) where
    Source: SessionSource,
    Sink: SessionSink,
{
    let SessionPeer {
        peer_id,
        sidecar_id,
        kind,
        transport,
        proof,
    } = peer;
    // An environment peer without a proof, or without checks, never runs.
    let mut proof = match (kind, proof, checks.as_ref()) {
        (PeerKind::Sidecar, Some(proof), Some(_)) => Some(proof),
        (PeerKind::Sidecar, _, _) => {
            tracing::warn!(env_id = %peer_id, "coordinator environment peer without proof refused");
            return;
        }
        (PeerKind::Client, _, _) => None,
    };
    let Some(registration) = peers.register(peer_id, proof.map(PeerProof::rank)) else {
        tracing::info!(
            env_id = %peer_id,
            "coordinator environment peer refused: a newer session holds this environment"
        );
        return;
    };
    let owner = registration.owner;
    let mut events = registration.events;
    // The session's node key, admitted by DERP while the session lives.
    let node_key = SessionNodeKey::new(coordination.clone(), owner);
    let env_id = sidecar_id.unwrap_or(peer_id);
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

    let (remote_tx, mut remote_rx) = mpsc::unbounded_channel();
    let last_sidecar_node = Arc::new(AsyncMutex::new(None::<Node>));

    if let Some(coordination) = coordination.as_ref() {
        match kind {
            PeerKind::Client => {
                if let Some(env_id) = sidecar_id {
                    match coordination.subscribe_agent(env_id).await {
                        Ok(sub) => spawn_node_subscription(sub, remote_tx.clone(), env_id, "agent"),
                        Err(err) => {
                            tracing::warn!(error = ?err, %env_id, "coordinator NATS agent subscribe failed");
                        }
                    }
                    match coordination.get_sidecar_node(env_id).await {
                        Ok(Some((generation, node))) => {
                            if stamped_generation_current(checks.as_ref(), env_id, generation).await
                            {
                                log_node(
                                    "coordinator KV hit for sidecar node",
                                    env_id,
                                    peer_id,
                                    PeerKind::Sidecar,
                                    &node,
                                    Some(transport),
                                );
                                let _ = remote_tx.send(PeerEvent::Update(vec![node]));
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

    let generation = proof.map(|proof| proof.generation).unwrap_or_default();
    let refresh_task = if matches!(kind, PeerKind::Sidecar) {
        coordination.as_ref().map(|coordination| {
            let coordination = coordination.clone();
            let last_sidecar_node = last_sidecar_node.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(SIDECAR_KV_REFRESH).await;
                    let node = { last_sidecar_node.lock().await.clone() };
                    let Some(node) = node else {
                        tracing::warn!(env_id = %peer_id, "coordinator sidecar KV refresh skipped");
                        continue;
                    };
                    if let Err(err) = coordination.put_sidecar_node(peer_id, generation, &node).await {
                        tracing::warn!(error = ?err, env_id = %peer_id, "coordinator sidecar KV refresh failed");
                    }
                }
            })
        })
    } else {
        None
    };

    let derp_map = build_derp_map(derp_map_config_from_env());
    if !sink.send(SessionOutput::DerpMap(derp_map)).await {
        peers.deregister(peer_id, owner);
        node_key.close().await;
        if let Some(task) = refresh_task {
            task.abort();
        }
        return;
    }

    tracing::info!(
        %env_id,
        %peer_id,
        kind = kind.as_str(),
        transport = transport.as_str(),
        "coordinator derp_map sent"
    );

    let mut heartbeat = tokio::time::interval(COORDINATE_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let recheck_every = checks
        .as_ref()
        .map(|checks| checks.recheck)
        .unwrap_or(Duration::from_secs(3600));
    let mut recheck = tokio::time::interval(recheck_every);
    recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    recheck.tick().await;

    let mut ended = None;
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    break;
                };
                event.log_send(env_id, peer_id, kind, "local", transport);
                if !sink.send(SessionOutput::Peer(event)).await {
                    break;
                }
            }
            event = remote_rx.recv() => {
                let Some(event) = event else {
                    break;
                };
                event.log_send(env_id, peer_id, kind, "remote", transport);
                if !sink.send(SessionOutput::Peer(event)).await {
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if !sink.send(SessionOutput::Heartbeat).await {
                    break;
                }
            }
            _ = recheck.tick(), if proof.is_some() || client_access.is_some() => {
                if let Some(current) = proof {
                    if current.lapsed(unix_now()) {
                        ended = Some(PeerEnd::ProofLapsed);
                        break;
                    }
                    let checks = checks.as_ref().expect("environment peers carry checks");
                    match checks.verifier.is_current(peer_id, current.generation).await {
                        Ok(true) | Err(ProofError::Unavailable) => {}
                        Ok(false) | Err(ProofError::Refused) => {
                            ended = Some(PeerEnd::Revoked);
                            break;
                        }
                    }
                } else if let Some(access) = client_access.as_deref() {
                    match access.recheck().await {
                        ClientRecheck::Allowed | ClientRecheck::Unavailable => {}
                        ClientRecheck::Refused => {
                            ended = Some(PeerEnd::AccessRevoked);
                            break;
                        }
                    }
                }
            }
            input = source.next() => {
                match input {
                    Some(SessionInput::Node(node)) => {
                        node_key.observe(node.key).await;
                        handle_node_update(
                            &peers,
                            owner,
                            coordination.as_deref(),
                            &last_sidecar_node,
                            peer,
                            generation,
                            node,
                        ).await;
                    }
                    Some(SessionInput::Proof(token)) => {
                        let (Some(current), Some(checks)) = (proof, checks.as_ref()) else {
                            // A client never proves; ignore it.
                            continue;
                        };
                        match checks.verifier.verify(peer_id, &token).await {
                            Ok(next) if next.generation == current.generation => {
                                let raised = PeerProof {
                                    generation: current.generation,
                                    expires_at: current.expires_at.max(next.expires_at),
                                };
                                peers.raise_rank(peer_id, owner, raised.rank());
                                proof = Some(raised);
                            }
                            Err(ProofError::Unavailable) => {}
                            Ok(_) | Err(ProofError::Refused) => {
                                ended = Some(PeerEnd::BadProof);
                                break;
                            }
                        }
                    }
                    Some(SessionInput::Ping | SessionInput::Noop) => {}
                    None => break,
                }
            }
        }
    }

    tracing::info!(
        %env_id,
        %peer_id,
        kind = kind.as_str(),
        transport = transport.as_str(),
        ended = ?ended,
        "coordinator peer disconnected"
    );
    if ended == Some(PeerEnd::AccessRevoked) {
        // Tell the client why before its stream closes; it may already be gone.
        let _ = sink.send(SessionOutput::AccessRevoked).await;
    }
    peers.deregister(peer_id, owner);
    node_key.close().await;
    if let (PeerKind::Client, Some(env_id), Some(coordination)) =
        (kind, sidecar_id, coordination.as_ref())
        && let Err(err) = coordination.publish_remove(env_id, peer_id).await
    {
        tracing::warn!(error = ?err, %env_id, %peer_id, "coordinator client remove publish failed");
    }
    if let Some(task) = refresh_task {
        task.abort();
    }
    // A revoked generation leaves no recorded node for clients to dial.
    if ended == Some(PeerEnd::Revoked)
        && let Some(coordination) = coordination.as_ref()
        && let Err(err) = coordination.delete_sidecar_node(peer_id, generation).await
    {
        tracing::warn!(error = ?err, env_id = %peer_id, "coordinator revoked sidecar KV delete failed");
    }
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
    peer: SessionPeer,
    generation: i64,
    mut node: Node,
) {
    let SessionPeer {
        peer_id,
        sidecar_id,
        kind,
        transport,
        ..
    } = peer;
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
            if let Err(err) = coordination.publish_client_node(env_id, &node).await {
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
mod tests {
    use super::*;
    use codewire_tailnet::node::{DiscoPublic, NodePublic, prefix_from_uuid};
    use tokio::task::JoinHandle;

    struct ChannelSource {
        rx: mpsc::UnboundedReceiver<SessionInput>,
    }

    impl SessionSource for ChannelSource {
        async fn next(&mut self) -> Option<SessionInput> {
            self.rx.recv().await
        }
    }

    struct ChannelSink {
        tx: mpsc::UnboundedSender<SessionOutput>,
    }

    impl SessionSink for ChannelSink {
        async fn send(&mut self, output: SessionOutput) -> bool {
            self.tx.send(output).is_ok()
        }
    }

    fn spawn_session(
        peers: Arc<PeerRegistry>,
        peer_id: Uuid,
        sidecar_id: Option<Uuid>,
        kind: PeerKind,
    ) -> (
        mpsc::UnboundedSender<SessionInput>,
        mpsc::UnboundedReceiver<SessionOutput>,
        JoinHandle<()>,
    ) {
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let proof = matches!(kind, PeerKind::Sidecar).then(|| PeerProof {
            generation: 1,
            expires_at: unix_now() + 600,
        });
        let task = tokio::spawn(run_peer_session(
            ChannelSource { rx: input_rx },
            ChannelSink { tx: output_tx },
            peers,
            None,
            SessionPeer {
                peer_id,
                sidecar_id,
                kind,
                transport: Transport::Connect,
                proof,
            },
            Some(test_checks(Some(1), Duration::from_secs(3600))),
            None,
        ));
        (input_tx, output_rx, task)
    }

    use std::sync::atomic::{AtomicI64, Ordering};

    const SECRET: &str = "session-secret";

    /// Peer checks over a current generation the test can move (0 = gone).
    struct MovableVerifier {
        generation: AtomicI64,
    }

    impl PeerVerifier for MovableVerifier {
        fn verify<'a>(
            &'a self,
            env_id: Uuid,
            token: &'a str,
        ) -> crate::peer::BoxFuture<'a, Result<PeerProof, ProofError>> {
            Box::pin(async move {
                let claims = codewire_server_core::peer_token::validate(SECRET, token, unix_now())
                    .map_err(|_| ProofError::Refused)?;
                let current = match self.generation.load(Ordering::SeqCst) {
                    0 => None,
                    generation => Some(generation),
                };
                crate::peer::check_claims(&claims, env_id, current)
            })
        }

        fn is_current<'a>(
            &'a self,
            _env_id: Uuid,
            generation: i64,
        ) -> crate::peer::BoxFuture<'a, Result<bool, ProofError>> {
            Box::pin(async move { Ok(self.generation.load(Ordering::SeqCst) == generation) })
        }
    }

    fn test_checks(generation: Option<i64>, recheck: Duration) -> PeerChecks {
        movable_checks(
            Arc::new(MovableVerifier {
                generation: AtomicI64::new(generation.unwrap_or_default()),
            }),
            recheck,
        )
    }

    fn movable_checks(verifier: Arc<MovableVerifier>, recheck: Duration) -> PeerChecks {
        PeerChecks { verifier, recheck }
    }

    fn token(env_id: Uuid, generation: i64, expires_at: i64) -> String {
        codewire_server_core::peer_token::issue(SECRET, &env_id.to_string(), generation, expires_at)
            .unwrap()
    }

    fn spawn_peer(
        peers: Arc<PeerRegistry>,
        env_id: Uuid,
        proof: PeerProof,
        checks: PeerChecks,
    ) -> (
        mpsc::UnboundedSender<SessionInput>,
        mpsc::UnboundedReceiver<SessionOutput>,
        JoinHandle<()>,
    ) {
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_peer_session(
            ChannelSource { rx: input_rx },
            ChannelSink { tx: output_tx },
            peers,
            None,
            SessionPeer {
                peer_id: env_id,
                sidecar_id: None,
                kind: PeerKind::Sidecar,
                transport: Transport::Connect,
                proof: Some(proof),
            },
            Some(checks),
            None,
        ));
        (input_tx, output_rx, task)
    }

    async fn ends(task: JoinHandle<()>) {
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("session did not end")
            .expect("session task panicked");
    }

    #[tokio::test]
    async fn a_lapsed_proof_ends_the_session() {
        let env_id = Uuid::new_v4();
        let peers = Arc::new(PeerRegistry::default());
        let lapsed = PeerProof {
            generation: 1,
            expires_at: unix_now() - crate::peer::PEER_RECHECK_INTERVAL.as_secs() as i64 * 10,
        };
        let (_input, mut output, task) = spawn_peer(
            peers.clone(),
            env_id,
            lapsed,
            test_checks(Some(1), Duration::from_millis(20)),
        );
        assert!(matches!(
            next_output(&mut output).await,
            SessionOutput::DerpMap(_)
        ));
        ends(task).await;
        // Its entry is gone, so the next peer registers freely.
        assert!(peers.register(env_id, Some((1, unix_now()))).is_some());
    }

    #[tokio::test]
    async fn a_generation_change_revokes_the_session() {
        let env_id = Uuid::new_v4();
        let verifier = Arc::new(MovableVerifier {
            generation: AtomicI64::new(1),
        });
        let (_input, mut output, task) = spawn_peer(
            Arc::new(PeerRegistry::default()),
            env_id,
            PeerProof {
                generation: 1,
                expires_at: unix_now() + 600,
            },
            movable_checks(verifier.clone(), Duration::from_millis(20)),
        );
        assert!(matches!(
            next_output(&mut output).await,
            SessionOutput::DerpMap(_)
        ));
        verifier.generation.store(2, Ordering::SeqCst);
        ends(task).await;
    }

    #[tokio::test]
    async fn only_a_newer_proof_replaces_a_session_and_the_old_one_never_tears_it_down() {
        let env_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        let peers = Arc::new(PeerRegistry::default());
        let now = unix_now();
        let checks = || test_checks(Some(1), Duration::from_secs(3600));

        let (first_tx, mut first_out, first_task) = spawn_peer(
            peers.clone(),
            env_id,
            PeerProof {
                generation: 1,
                expires_at: now + 600,
            },
            checks(),
        );
        assert!(matches!(
            next_output(&mut first_out).await,
            SessionOutput::DerpMap(_)
        ));

        // An older or equal proof (a stolen token) is refused outright.
        for expires_at in [now + 300, now + 600] {
            let (_tx, mut out, task) = spawn_peer(
                peers.clone(),
                env_id,
                PeerProof {
                    generation: 1,
                    expires_at,
                },
                checks(),
            );
            ends(task).await;
            assert!(out.try_recv().is_err(), "a refused session sends nothing");
        }

        // An in-band proof raises the holder's rank, so a token that would
        // have outranked the connect-time proof no longer does.
        first_tx
            .send(SessionInput::Proof(token(env_id, 1, now + 590)))
            .unwrap();
        first_tx
            .send(SessionInput::Proof(token(env_id, 1, now + 650)))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (_tx, _out, refused) = spawn_peer(
            peers.clone(),
            env_id,
            PeerProof {
                generation: 1,
                expires_at: now + 620,
            },
            checks(),
        );
        ends(refused).await;

        // A newer proof replaces the holder, which then ends without removing
        // its replacement.
        let (second_tx, mut second_out, second_task) = spawn_peer(
            peers.clone(),
            env_id,
            PeerProof {
                generation: 1,
                expires_at: now + 700,
            },
            checks(),
        );
        assert!(matches!(
            next_output(&mut second_out).await,
            SessionOutput::DerpMap(_)
        ));
        ends(first_task).await;
        drop(first_tx);

        let (client_tx, mut client_out, client_task) =
            spawn_session(peers.clone(), client_id, Some(env_id), PeerKind::Client);
        assert!(matches!(
            next_output(&mut client_out).await,
            SessionOutput::DerpMap(_)
        ));
        second_tx
            .send(SessionInput::Node(sample_node(env_id, 4)))
            .unwrap();
        let nodes = expect_peer_update(next_output(&mut client_out).await);
        assert_eq!(nodes[0].id, env_id, "the replacement is still registered");

        drop(client_tx);
        drop(second_tx);
        ends(client_task).await;
        ends(second_task).await;
    }

    #[tokio::test]
    async fn a_bad_proof_ends_the_session() {
        let env_id = Uuid::new_v4();
        for bad in [
            token(env_id, 2, unix_now() + 600),
            token(Uuid::new_v4(), 1, unix_now() + 600),
            "not-a-token".to_owned(),
        ] {
            let (input, mut output, task) = spawn_peer(
                Arc::new(PeerRegistry::default()),
                env_id,
                PeerProof {
                    generation: 1,
                    expires_at: unix_now() + 600,
                },
                test_checks(Some(1), Duration::from_secs(3600)),
            );
            assert!(matches!(
                next_output(&mut output).await,
                SessionOutput::DerpMap(_)
            ));
            input.send(SessionInput::Proof(bad)).unwrap();
            ends(task).await;
        }
    }

    #[tokio::test]
    async fn an_environment_peer_without_proof_never_registers() {
        let env_id = Uuid::new_v4();
        let peers = Arc::new(PeerRegistry::default());
        let (_input_tx, input_rx) = mpsc::unbounded_channel();
        let (output_tx, mut output_rx) = mpsc::unbounded_channel();
        run_peer_session(
            ChannelSource { rx: input_rx },
            ChannelSink { tx: output_tx },
            peers.clone(),
            None,
            SessionPeer {
                peer_id: env_id,
                sidecar_id: None,
                kind: PeerKind::Sidecar,
                transport: Transport::Connect,
                proof: None,
            },
            Some(test_checks(Some(1), Duration::from_secs(3600))),
            None,
        )
        .await;
        assert!(output_rx.try_recv().is_err());
        assert!(peers.register(env_id, Some((1, 0))).is_some());
    }

    async fn next_output(rx: &mut mpsc::UnboundedReceiver<SessionOutput>) -> SessionOutput {
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("session output timed out")
            .expect("session output closed")
    }

    fn sample_node(id: Uuid, derp: i32) -> Node {
        Node {
            id,
            as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
            key: NodePublic::from_raw([0x11; 32]),
            disco_key: DiscoPublic::from_raw([0x22; 32]),
            preferred_derp: derp,
            derp_latency: None,
            endpoints: vec![],
            addresses: vec![prefix_from_uuid(&id)],
        }
    }

    fn expect_peer_update(output: SessionOutput) -> Vec<Node> {
        match output {
            SessionOutput::Peer(PeerEvent::Update(nodes)) => nodes,
            other => panic!("expected peer update, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn core_sends_derp_first_accumulates_peers_and_removes_on_teardown() {
        let peers = Arc::new(PeerRegistry::default());
        let sidecar_id = Uuid::parse_str("12345678-1234-5678-1234-567812345678").unwrap();
        let client_one_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let client_two_id = Uuid::parse_str("ffeeddcc-bbaa-9988-7766-554433221100").unwrap();

        let (sidecar_tx, mut sidecar_out, sidecar_task) =
            spawn_session(peers.clone(), sidecar_id, None, PeerKind::Sidecar);
        let (client_one_tx, mut client_one_out, client_one_task) = spawn_session(
            peers.clone(),
            client_one_id,
            Some(sidecar_id),
            PeerKind::Client,
        );
        let (client_two_tx, mut client_two_out, client_two_task) =
            spawn_session(peers, client_two_id, Some(sidecar_id), PeerKind::Client);

        for output in [
            next_output(&mut sidecar_out).await,
            next_output(&mut client_one_out).await,
            next_output(&mut client_two_out).await,
        ] {
            assert!(matches!(output, SessionOutput::DerpMap(_)));
        }

        sidecar_tx
            .send(SessionInput::Node(sample_node(sidecar_id, 1)))
            .unwrap();
        for output in [
            next_output(&mut client_one_out).await,
            next_output(&mut client_two_out).await,
        ] {
            let nodes = expect_peer_update(output);
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].id, sidecar_id);
        }

        client_one_tx
            .send(SessionInput::Node(sample_node(client_one_id, 2)))
            .unwrap();
        let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, client_one_id);

        client_two_tx
            .send(SessionInput::Node(sample_node(client_two_id, 3)))
            .unwrap();
        let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|node| node.id == client_one_id));
        assert!(nodes.iter().any(|node| node.id == client_two_id));

        drop(client_one_tx);
        match next_output(&mut sidecar_out).await {
            SessionOutput::Peer(PeerEvent::Remove(peer_id)) => {
                assert_eq!(peer_id, client_one_id);
            }
            other => panic!("expected peer removal, got {other:?}"),
        }

        drop(client_two_tx);
        drop(sidecar_tx);
        for task in [client_one_task, client_two_task, sidecar_task] {
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("session teardown timed out")
                .expect("session task panicked");
        }
    }

    /// A client's access as the test sets it, counting re-checks.
    struct ScriptedAccess {
        outcome: std::sync::Mutex<ClientRecheck>,
        rechecks: std::sync::atomic::AtomicUsize,
    }

    impl ClientAccess for Arc<ScriptedAccess> {
        fn recheck(&self) -> Pin<Box<dyn Future<Output = ClientRecheck> + Send + '_>> {
            self.rechecks.fetch_add(1, Ordering::SeqCst);
            let outcome = *self.outcome.lock().unwrap();
            Box::pin(async move { outcome })
        }
    }

    /// #3828: a client is re-checked while its session lives. Unreadable
    /// records keep it; a refusal tells it why and ends its session, and the
    /// environment peer is told to drop it.
    #[tokio::test]
    async fn a_refused_client_recheck_ends_the_session_and_removes_the_client() {
        let peers = Arc::new(PeerRegistry::default());
        let sidecar_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        let access = Arc::new(ScriptedAccess {
            outcome: std::sync::Mutex::new(ClientRecheck::Unavailable),
            rechecks: std::sync::atomic::AtomicUsize::new(0),
        });

        let (sidecar_tx, mut sidecar_out, sidecar_task) =
            spawn_session(peers.clone(), sidecar_id, None, PeerKind::Sidecar);
        let (client_tx, client_rx) = mpsc::unbounded_channel();
        let (client_out_tx, mut client_out) = mpsc::unbounded_channel();
        let client_task = tokio::spawn(run_peer_session(
            ChannelSource { rx: client_rx },
            ChannelSink { tx: client_out_tx },
            peers,
            None,
            SessionPeer {
                peer_id: client_id,
                sidecar_id: Some(sidecar_id),
                kind: PeerKind::Client,
                transport: Transport::Connect,
                proof: None,
            },
            Some(test_checks(Some(1), Duration::from_millis(20))),
            Some(Box::new(access.clone())),
        ));
        assert!(matches!(
            next_output(&mut sidecar_out).await,
            SessionOutput::DerpMap(_)
        ));
        assert!(matches!(
            next_output(&mut client_out).await,
            SessionOutput::DerpMap(_)
        ));
        client_tx
            .send(SessionInput::Node(sample_node(client_id, 2)))
            .unwrap();
        let nodes = expect_peer_update(next_output(&mut sidecar_out).await);
        assert_eq!(nodes[0].id, client_id);

        // Records that can't be read keep the session across re-checks.
        tokio::time::timeout(Duration::from_secs(5), async {
            while access.rechecks.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the client was not re-checked");
        assert!(!client_task.is_finished());

        *access.outcome.lock().unwrap() = ClientRecheck::Refused;
        assert!(matches!(
            next_output(&mut client_out).await,
            SessionOutput::AccessRevoked
        ));
        ends(client_task).await;
        match next_output(&mut sidecar_out).await {
            SessionOutput::Peer(PeerEvent::Remove(peer_id)) => assert_eq!(peer_id, client_id),
            other => panic!("expected the client's removal, got {other:?}"),
        }

        drop(client_tx);
        drop(sidecar_tx);
        ends(sidecar_task).await;
    }

    /// #2844: DERP's admission call, made by DERP's own verifier against the
    /// coordinator's listener, knows the key of a node a live session sent and
    /// forgets it when the session ends. A malformed key is refused.
    #[tokio::test]
    async fn derp_admission_knows_a_live_session_key_until_it_ends() {
        use codewire_derp::{HttpKeyVerifier, KeyVerifier as _, Verdict};
        use tower::ServiceExt as _;

        let peers = Arc::new(PeerRegistry::default());
        let state = crate::CoordinatorState {
            pool: sqlx::PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
            session_secret: Arc::from(SECRET),
            peers: peers.clone(),
            coordination: None,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(codewire_server_core::serve_with_listener(
            crate::derp_verify_router(state.clone()),
            listener,
        ));
        let verifier = HttpKeyVerifier::parse(&format!("http://{addr}")).unwrap();
        let derp_key = |raw: [u8; 32]| codewire_tailnet::derp::NodePublic::from_raw(raw);

        let sidecar_id = Uuid::new_v4();
        let client_id = Uuid::new_v4();
        let key = derp_key(*sample_node(client_id, 1).key.as_bytes());
        assert_eq!(verifier.verify(&key).await, Verdict::Unknown);

        let (client_tx, mut client_out, client_task) =
            spawn_session(peers.clone(), client_id, Some(sidecar_id), PeerKind::Client);
        assert!(matches!(
            next_output(&mut client_out).await,
            SessionOutput::DerpMap(_)
        ));
        client_tx
            .send(SessionInput::Node(sample_node(client_id, 1)))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while verifier.verify(&key).await != Verdict::Known {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the live session's key is registered");
        assert_eq!(
            verifier.verify(&derp_key([0x22; 32])).await,
            Verdict::Unknown
        );

        // A key that is not 32 bytes is an invalid argument.
        let response = crate::derp_verify_router(state)
            .oneshot(
                axum::http::Request::post(codewire_derp::CHECK_NODE_KEY_PATH)
                    .header("content-type", "application/json")
                    .header("connect-protocol-version", "1")
                    .body(axum::body::Body::from(r#"{"nodeKey":"AAAA"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        drop(client_tx);
        ends(client_task).await;
        assert_eq!(verifier.verify(&key).await, Verdict::Unknown);
        server.abort();
    }
}
