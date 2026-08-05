//! Authenticated disco handling and outbound action sealing.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::conn::WgDatagram;
use crate::derp::NodePublic as DerpPublic;
use crate::disco::{CallMeMaybeVia, Message, Ping, Pong};
use crate::node::DiscoPublic;
use crate::udp_relay;

use super::peer_relay::apply_call_me_maybe_via;
use super::state::{
    disco_message_kind, is_usable_direct_endpoint, make_ping_action, DiscoAction, DiscoPeerIndex,
    DiscoTarget, Shared, State,
};
use super::{derp_magic_addr, PeerRelayAllocationEvent, DEFAULT_DERP_REGION_ID};

pub(super) async fn handle_disco_packet(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    source_addr: Option<SocketAddr>,
    derp_source: Option<DerpPublic>,
    packet: &[u8],
) {
    let opened = match shared.local_disco.open(packet) {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(
                source = source_addr.map(|addr| addr.to_string()).as_deref().unwrap_or("derp"),
                error = %err,
                "rust tailnet ignored undecodable disco packet"
            );
            return;
        }
    };
    let message_kind = disco_message_kind(&opened.message);
    let peer_relay_notification_opened = matches!(&opened.message, Message::CallMeMaybeVia(_));
    if peer_relay_notification_opened {
        shared
            .stats
            .peer_relay_notifications_opened
            .fetch_add(1, Ordering::Relaxed);
    }
    tracing::debug!(
        source = source_addr
            .map(|addr| addr.to_string())
            .as_deref()
            .unwrap_or("derp"),
        message_kind,
        "rust tailnet disco packet opened"
    );

    let actions = {
        let mut state = shared.state.lock().unwrap();
        let peer_key = match &opened.message {
            Message::Pong(pong) => peer_key_for_pong(&state, opened.sender, &pong.tx_id),
            other => peer_key_for_message(&state, opened.sender, other, derp_source.as_ref()),
        };
        let peer_key = match peer_key {
            Some(peer_key) => peer_key,
            None => {
                if peer_relay_notification_opened {
                    shared
                        .stats
                        .peer_relay_notifications_unknown_peer
                        .fetch_add(1, Ordering::Relaxed);
                }
                tracing::debug!(
                    source = source_addr
                        .map(|addr| addr.to_string())
                        .as_deref()
                        .unwrap_or("derp"),
                    message_kind,
                    "rust tailnet ignored disco packet from unknown peer"
                );
                return;
            }
        };

        match opened.message {
            Message::Ping(ping) => {
                if let Some(addr) = source_addr {
                    if !shared.peer_direct_udp_enabled {
                        return;
                    }
                    state.verify_endpoint(peer_key, addr);
                    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                        return;
                    };
                    vec![DiscoAction {
                        target: DiscoTarget::Udp(addr),
                        peer_disco: peer.disco_key,
                        message: Message::Pong(Pong {
                            tx_id: ping.tx_id,
                            src: addr,
                        }),
                    }]
                } else if let Some(derp_source) = derp_source {
                    let source_key = *derp_source.as_bytes();
                    if source_key != peer_key {
                        return;
                    }
                    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                        return;
                    };
                    vec![DiscoAction {
                        target: DiscoTarget::Derp(peer.derp_key.clone()),
                        peer_disco: peer.disco_key,
                        message: Message::Pong(Pong {
                            tx_id: ping.tx_id,
                            src: derp_magic_addr(DEFAULT_DERP_REGION_ID),
                        }),
                    }]
                } else {
                    Vec::new()
                }
            }
            Message::Pong(pong) => {
                if shared.peer_direct_udp_enabled
                    && state.pending_tx.remove(&pong.tx_id) == Some(peer_key)
                {
                    if let Some(addr) = source_addr {
                        state.verify_endpoint(peer_key, addr);
                    }
                }
                Vec::new()
            }
            Message::CallMeMaybe(call) => {
                if source_addr.is_some() {
                    return;
                }
                let Some(derp_source) = derp_source else {
                    return;
                };
                let source_key = *derp_source.as_bytes();
                if source_key != peer_key {
                    return;
                }
                if !shared.peer_direct_udp_enabled {
                    tracing::debug!(
                        "rust tailnet ignored CallMeMaybe while direct peer UDP is disabled"
                    );
                    return;
                }
                let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                    return;
                };
                call.endpoints
                    .into_iter()
                    .filter(|addr| is_usable_direct_endpoint(*addr))
                    .map(|endpoint| {
                        make_ping_action(&mut state, &shared.local_node_key, &peer, endpoint)
                    })
                    .collect()
            }
            Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
                if source_addr.is_some() {
                    return;
                }
                let Some(derp_source) = derp_source else {
                    return;
                };
                let source_key = *derp_source.as_bytes();
                if source_key != peer_key {
                    return;
                }
                shared
                    .stats
                    .peer_relay_notifications_received
                    .fetch_add(1, Ordering::Relaxed);
                let actions = apply_call_me_maybe_via(&mut state, shared, peer_key, endpoint);
                if actions.is_empty() {
                    shared
                        .stats
                        .peer_relay_notification_no_actions
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    shared
                        .stats
                        .peer_relay_notification_actions
                        .fetch_add(actions.len() as u64, Ordering::Relaxed);
                }
                actions
            }
            Message::AllocateUDPRelayEndpointRequest(request) => {
                if source_addr.is_some() {
                    return;
                }
                let Some(derp_source) = derp_source else {
                    return;
                };
                let source_key = *derp_source.as_bytes();
                if source_key != peer_key {
                    return;
                }
                let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
                    return;
                };
                let local_disco = shared.local_disco.public();
                if !request.client_disco.contains(&opened.sender)
                    || !request.client_disco.contains(&local_disco)
                    || !request.client_disco.contains(&peer.disco_key)
                {
                    tracing::debug!(
                        "rust tailnet ignored UDP peer relay allocation request with mismatched disco keys"
                    );
                    return;
                }
                tracing::info!(
                    generation = request.generation,
                    "rust tailnet UDP peer relay allocation request received"
                );
                let _ = shared
                    .peer_relay_allocation_events
                    .send(PeerRelayAllocationEvent {
                        peer: peer.node_key,
                        peer_disco: peer.disco_key,
                        client_disco: request.client_disco,
                        generation: request.generation,
                    });
                Vec::new()
            }
            Message::BindUDPRelayEndpoint(_)
            | Message::BindUDPRelayEndpointChallenge(_)
            | Message::BindUDPRelayEndpointAnswer(_)
            | Message::AllocateUDPRelayEndpointResponse(_) => Vec::new(),
        }
    };

    send_disco_actions(shared, socket, fallback_tx, actions).await;
}

pub(super) fn peer_key_for_message(
    state: &State,
    sender: DiscoPublic,
    message: &Message,
    derp_source: Option<&DerpPublic>,
) -> Option<[u8; 32]> {
    if let Some(derp_source) = derp_source {
        let peer_key = *derp_source.as_bytes();
        let peer = state.peers_by_node.get(&peer_key)?;
        if peer.disco_key == sender {
            return Some(peer_key);
        }
    }
    if let Message::Ping(Ping {
        node_key: Some(node_key),
        ..
    }) = message
    {
        // A Ping plaintext can claim a node key, but the only authenticated
        // sender identity in a disco wrapper is the disco public key. Never
        // let an unknown disco key claim a known peer's direct endpoint.
        let peer = state.peers_by_node.get(node_key.as_bytes())?;
        if !node_key.is_zero() && peer.disco_key == sender {
            return Some(*node_key.as_bytes());
        }
    }
    if let Some(DiscoPeerIndex::Unique(peer_key)) = state.peers_by_disco.get(sender.as_bytes()) {
        return Some(*peer_key);
    }
    None
}

pub(super) fn peer_key_for_pong(
    state: &State,
    sender: DiscoPublic,
    tx_id: &[u8; 12],
) -> Option<[u8; 32]> {
    let peer_key = *state.pending_tx.get(tx_id)?;
    let peer = state.peers_by_node.get(&peer_key)?;
    if peer.disco_key == sender {
        Some(peer_key)
    } else {
        None
    }
}

pub(super) fn is_relay_control_message(message: &Message) -> bool {
    matches!(
        message,
        Message::BindUDPRelayEndpoint(_) | Message::BindUDPRelayEndpointAnswer(_)
    )
}

pub(super) async fn send_disco_actions(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    actions: Vec<DiscoAction>,
) {
    let udp_actions = actions
        .iter()
        .filter(|action| {
            matches!(
                &action.target,
                DiscoTarget::Udp(_) | DiscoTarget::Relay { .. }
            )
        })
        .count();
    let derp_actions = actions.len().saturating_sub(udp_actions);
    if !actions.is_empty() {
        tracing::debug!(
            udp_actions,
            derp_actions,
            "rust tailnet sending disco actions"
        );
    }
    for action in actions {
        let Ok(packet) =
            shared
                .local_disco
                .seal_to(&action.peer_disco, &action.message, &mut OsRng)
        else {
            continue;
        };
        match action.target {
            DiscoTarget::Udp(addr) => match socket.send_to(&packet, addr).await {
                Ok(bytes_sent) => {
                    shared.stats.disco_udp_sent.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        target = %addr,
                        bytes_sent,
                        message_kind = disco_message_kind(&action.message),
                        "rust tailnet UDP disco action sent"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        target = %addr,
                        error = %err,
                        message_kind = disco_message_kind(&action.message),
                        "rust tailnet UDP disco action send failed"
                    );
                }
            },
            DiscoTarget::Relay { addr, vni } => {
                let packet = if is_relay_control_message(&action.message) {
                    udp_relay::encode_control_packet(vni, &packet)
                } else {
                    udp_relay::encode_disco_packet(vni, &packet)
                };
                match socket.send_to(&packet, addr).await {
                    Ok(bytes_sent) => {
                        shared
                            .stats
                            .peer_relay_disco_sent
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            relay_addr = %addr,
                            relay_vni = vni,
                            bytes_sent,
                            message_kind = disco_message_kind(&action.message),
                            "rust tailnet UDP peer relay disco action sent"
                        );
                    }
                    Err(err) => {
                        shared
                            .stats
                            .peer_relay_disco_send_failures
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            relay_addr = %addr,
                            relay_vni = vni,
                            error = %err,
                            message_kind = disco_message_kind(&action.message),
                            "rust tailnet UDP peer relay disco action send failed"
                        );
                    }
                }
            }
            DiscoTarget::Derp(peer) => {
                shared.stats.disco_derp_sent.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    message_kind = disco_message_kind(&action.message),
                    "rust tailnet DERP disco action sent"
                );
                let _ = fallback_tx.send(WgDatagram { peer, data: packet });
            }
        }
    }
}
