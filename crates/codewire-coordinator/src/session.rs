//! Transport-independent coordinator peer session.
//!
//! The WebSocket and Connect adapters own only their wire codecs. Registry,
//! NATS/KV fanout, heartbeat cadence, and teardown live here so both
//! transports execute the same peer behavior.

use std::sync::Arc;

use codewire_tailnet::node::Node;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use uuid::Uuid;

use super::{
    CoordinationPlane, PeerEvent, PeerKind, PeerRegistry, SIDECAR_KV_REFRESH, Transport,
    WEBSOCKET_HEARTBEAT_INTERVAL, build_derp_map, derp_map_config_from_env, log_node,
    spawn_node_subscription, spawn_remove_subscription,
};

/// A decoded message entering the shared peer session.
pub(crate) enum SessionInput {
    Node(Node),
    Ping,
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
}

/// Run one authorized coordinator peer until its transport closes.
pub(crate) async fn run_peer_session<Source, Sink>(
    mut source: Source,
    mut sink: Sink,
    peers: Arc<PeerRegistry>,
    coordination: Option<Arc<CoordinationPlane>>,
    peer: SessionPeer,
) where
    Source: SessionSource,
    Sink: SessionSink,
{
    let SessionPeer {
        peer_id,
        sidecar_id,
        kind,
        transport,
    } = peer;
    let mut events = peers.register(peer_id);
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
                        Ok(Some(node)) => {
                            log_node(
                                "coordinator KV hit for sidecar node",
                                env_id,
                                peer_id,
                                PeerKind::Sidecar,
                                &node,
                                Some(transport),
                            );
                            let _ = remote_tx.send(PeerEvent::Update(vec![node]));
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
                    if let Err(err) = coordination.put_sidecar_node(peer_id, &node).await {
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
        peers.deregister(peer_id);
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

    let mut heartbeat = tokio::time::interval(WEBSOCKET_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;

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
            input = source.next() => {
                match input {
                    Some(SessionInput::Node(node)) => {
                        handle_node_update(
                            &peers,
                            coordination.as_deref(),
                            &last_sidecar_node,
                            peer,
                            node,
                        ).await;
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
        "coordinator peer disconnected"
    );
    peers.deregister(peer_id);
    if let (PeerKind::Client, Some(env_id), Some(coordination)) =
        (kind, sidecar_id, coordination.as_ref())
        && let Err(err) = coordination.publish_remove(env_id, peer_id).await
    {
        tracing::warn!(error = ?err, %env_id, %peer_id, "coordinator client remove publish failed");
    }
    if let Some(task) = refresh_task {
        task.abort();
    }
}

async fn handle_node_update(
    peers: &PeerRegistry,
    coordination: Option<&CoordinationPlane>,
    last_sidecar_node: &Arc<AsyncMutex<Option<Node>>>,
    peer: SessionPeer,
    mut node: Node,
) {
    let SessionPeer {
        peer_id,
        sidecar_id,
        kind,
        transport,
    } = peer;
    node.id = peer_id;
    peers.update_node(peer_id, node.clone());

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
            if let Err(err) = coordination.put_sidecar_node(peer_id, &node).await {
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
        let task = tokio::spawn(run_peer_session(
            ChannelSource { rx: input_rx },
            ChannelSink { tx: output_tx },
            peers,
            None,
            SessionPeer {
                peer_id,
                sidecar_id,
                kind,
                transport: Transport::WebSocket,
            },
        ));
        (input_tx, output_rx, task)
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
}
