//! STUN discovery, advertised endpoints, peer updates, and direct probing.

use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::UdpSocket;

use crate::disco::{CallMeMaybe, Message};
use crate::node::{AddrPort, Node, NodePublic};
use crate::stun;

use super::peer_relay::apply_known_peer_relay_request;
use super::state::{
    derp_public_from_node, is_acceptable_peer_endpoint, is_usable_direct_endpoint,
    ping_action_with_transaction, register_pending_transaction, DirectProbe, DirectProbeCandidate,
    DirectProbeState, DiscoAction, DiscoPeerIndex, DiscoTarget, EndpointRefresh, PeerState,
    PendingStun, Shared, State, VerifiedEndpoint,
};
use super::DIRECT_PROBE_RETRY_WINDOW;

pub(super) async fn send_stun_refresh(
    socket: &UdpSocket,
    refresh: &EndpointRefresh,
) -> Vec<PendingStun> {
    let mut pending = Vec::with_capacity(refresh.stun_servers.len());
    for server in &refresh.stun_servers {
        let request = stun::BindingRequest::new();
        match socket.send_to(&request.packet, server).await {
            Ok(_) => {
                pending.push(PendingStun {
                    server: *server,
                    transaction_id: request.transaction_id,
                    expires_at: Instant::now() + refresh.stun_timeout,
                });
            }
            Err(err) => {
                tracing::warn!(
                    server = %server,
                    error = %err,
                    "rust tailnet STUN refresh send failed"
                );
            }
        }
    }
    pending
}

pub(super) fn take_stun_response(
    pending: &mut Vec<PendingStun>,
    source: SocketAddr,
    packet: &[u8],
) -> Option<SocketAddr> {
    let now = Instant::now();
    pending.retain(|request| request.expires_at >= now);
    let mut matched = None;
    for (idx, request) in pending.iter().enumerate() {
        if request.server != source {
            continue;
        }
        if let Ok(mapped) = stun::parse_binding_response(packet, request.transaction_id) {
            matched = Some((idx, mapped));
            break;
        }
    }
    let (idx, mapped) = matched?;
    pending.remove(idx);
    Some(mapped)
}

pub(super) fn apply_discovered_endpoint(
    shared: &Shared,
    refresh: &mut EndpointRefresh,
    mapped: SocketAddr,
) {
    if !is_usable_direct_endpoint(mapped) {
        tracing::debug!(
            mapped_endpoint = %mapped,
            "rust tailnet ignored unusable STUN endpoint"
        );
        return;
    }
    refresh_advertised_endpoints(shared, refresh, vec![mapped]);
}

pub(super) fn refresh_advertised_endpoints(
    shared: &Shared,
    refresh: &mut EndpointRefresh,
    discovered: Vec<SocketAddr>,
) {
    if !shared.peer_direct_udp_enabled {
        return;
    }
    let mut current = refresh.static_endpoints.clone();
    for endpoint in discovered {
        if !current.contains(&endpoint) {
            current.push(endpoint);
        }
    }

    let advertised = refresh.endpoint_tracker.update(current);
    if advertised == shared.advertised_socket_addrs() {
        return;
    }
    tracing::info!(
        advertised_endpoint_count = advertised.len(),
        "rust tailnet advertised direct UDP endpoints changed"
    );
    shared.set_advertised_endpoints(advertised.clone());
    let _ = refresh
        .local_endpoint_updates
        .send(advertised.into_iter().map(AddrPort).collect());
}

pub(super) fn apply_peer_update(shared: &Shared, nodes: Vec<Node>) -> Vec<DiscoAction> {
    let mut state = shared.state.lock().unwrap();
    let previous = std::mem::take(&mut state.peers_by_node);
    state.peers_by_disco.clear();
    state.peers_by_endpoint.clear();
    state.peers_by_relay.clear();
    let previous_pending_tx = std::mem::take(&mut state.pending_tx);
    let now = Instant::now();
    let mut start_direct_probes = Vec::new();

    for node in nodes {
        if node.key.is_zero() || node.disco_key.is_zero() {
            continue;
        }
        let raw = *node.key.as_bytes();
        let mut endpoints = if shared.peer_direct_udp_enabled {
            node.endpoints.iter().map(|ep| ep.0).collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let public_only = state.public_peer_endpoints_only;
        endpoints.retain(|endpoint| is_acceptable_peer_endpoint(*endpoint, public_only));
        endpoints.sort_unstable();
        endpoints.dedup();
        let previous_peer = previous.get(&raw);
        let candidates_unchanged = previous_peer
            .map(|peer| peer.disco_key == node.disco_key && peer.endpoints == endpoints)
            .unwrap_or(false);
        let verified_endpoint = if shared.peer_direct_udp_enabled && candidates_unchanged {
            previous_peer
                .and_then(PeerState::active_verified_endpoint)
                .map(|addr| VerifiedEndpoint {
                    addr,
                    verified_at: now,
                })
        } else {
            None
        };
        let relay_endpoint = previous_peer
            .filter(|peer| peer.disco_key == node.disco_key)
            .and_then(|peer| peer.relay_endpoint.clone())
            .filter(|relay| relay.remote_disco == node.disco_key && relay.is_fresh(now));
        let direct_probe = if verified_endpoint.is_some() || endpoints.is_empty() {
            DirectProbeState::Inactive
        } else if candidates_unchanged {
            match previous_peer.map(|peer| peer.direct_probe.clone()) {
                Some(DirectProbeState::Active(probe)) if now < probe.expires_at => {
                    DirectProbeState::Active(probe)
                }
                Some(DirectProbeState::Active(_)) | Some(DirectProbeState::Exhausted) => {
                    DirectProbeState::Exhausted
                }
                Some(DirectProbeState::Inactive) | None => {
                    start_direct_probes.push(raw);
                    DirectProbeState::Inactive
                }
            }
        } else {
            start_direct_probes.push(raw);
            DirectProbeState::Inactive
        };
        let peer = PeerState {
            node_key: node.key,
            derp_key: derp_public_from_node(node.key),
            disco_key: node.disco_key,
            endpoints,
            verified_endpoint,
            direct_probe,
            relay_endpoint,
            preferred_derp: node.preferred_derp,
        };
        if let Some(endpoint) = verified_endpoint.map(|verified| verified.addr) {
            state.peers_by_endpoint.insert(endpoint, raw);
        }
        if let Some(relay) = &peer.relay_endpoint {
            state.peers_by_relay.insert(relay.key(), raw);
        }
        match state.peers_by_disco.get_mut(node.disco_key.as_bytes()) {
            Some(DiscoPeerIndex::Unique(existing)) if *existing == raw => {}
            Some(entry) => *entry = DiscoPeerIndex::Ambiguous,
            None => {
                state
                    .peers_by_disco
                    .insert(*node.disco_key.as_bytes(), DiscoPeerIndex::Unique(raw));
            }
        }
        state.peers_by_node.insert(raw, peer);
    }

    state.pending_tx = previous_pending_tx
        .into_iter()
        .filter(|(_, peer_key)| state.peers_by_node.contains_key(peer_key))
        .collect();

    let current_direct_transactions = state
        .peers_by_node
        .iter()
        .flat_map(|(peer_key, peer)| match &peer.direct_probe {
            DirectProbeState::Active(probe) => probe
                .candidates
                .iter()
                .map(|candidate| (candidate.tx_id, *peer_key))
                .collect::<Vec<_>>(),
            DirectProbeState::Inactive | DirectProbeState::Exhausted => Vec::new(),
        })
        .collect::<Vec<_>>();
    for peer in previous.values() {
        let DirectProbeState::Active(probe) = &peer.direct_probe else {
            continue;
        };
        for candidate in &probe.candidates {
            if !current_direct_transactions
                .iter()
                .any(|(tx_id, _)| *tx_id == candidate.tx_id)
            {
                state.pending_tx.remove(&candidate.tx_id);
            }
        }
    }
    for (tx_id, peer_key) in current_direct_transactions {
        state.pending_tx.insert(tx_id, peer_key);
    }

    let peer_count = state.peers_by_node.len();
    let peer_endpoint_count = state
        .peers_by_node
        .values()
        .map(|peer| peer.endpoints.len())
        .sum::<usize>();
    start_direct_probes.sort_unstable();
    start_direct_probes.dedup();
    let mut actions = Vec::new();
    for peer_key in start_direct_probes {
        actions.extend(start_direct_probe(
            &mut state,
            &shared.local_node_key,
            peer_key,
            now,
        ));
    }
    let pending_relay_peers = state
        .pending_peer_relays
        .keys()
        .copied()
        .filter(|peer_key| state.peers_by_node.contains_key(peer_key))
        .collect::<Vec<_>>();
    for peer_key in pending_relay_peers {
        let Some(pending) = state.pending_peer_relays.remove(&peer_key) else {
            continue;
        };
        actions.extend(apply_known_peer_relay_request(
            &mut state,
            shared,
            peer_key,
            pending.bind_endpoint,
            pending.advertise_endpoint,
            pending.response_generation,
        ));
    }
    let peers = state.peers_by_node.values().cloned().collect::<Vec<_>>();
    for peer in peers {
        if shared.peer_direct_udp_enabled {
            let advertised_endpoints = shared.advertised_socket_addrs();
            if !advertised_endpoints.is_empty() {
                actions.push(DiscoAction {
                    target: DiscoTarget::Derp(peer.derp_key.clone()),
                    peer_disco: peer.disco_key,
                    message: Message::CallMeMaybe(CallMeMaybe {
                        endpoints: advertised_endpoints,
                    }),
                });
            }
        }
    }
    tracing::debug!(
        peer_count,
        peer_endpoint_count,
        disco_action_count = actions.len(),
        advertised_endpoint_count = shared.advertised_socket_addrs().len(),
        "rust tailnet peer update applied"
    );
    actions
}

pub(super) fn start_direct_probe(
    state: &mut State,
    local_node_key: &NodePublic,
    peer_key: [u8; 32],
    now: Instant,
) -> Vec<DiscoAction> {
    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
        return Vec::new();
    };
    let mut candidates = Vec::with_capacity(peer.endpoints.len());
    let mut actions = Vec::with_capacity(peer.endpoints.len());
    for endpoint in &peer.endpoints {
        let tx_id = register_pending_transaction(state, peer_key);
        candidates.push(DirectProbeCandidate {
            endpoint: *endpoint,
            tx_id,
        });
        actions.push(ping_action_with_transaction(
            local_node_key,
            peer.disco_key,
            *endpoint,
            tx_id,
        ));
    }
    if let Some(peer) = state.peers_by_node.get_mut(&peer_key) {
        peer.direct_probe = if candidates.is_empty() {
            DirectProbeState::Inactive
        } else {
            DirectProbeState::Active(DirectProbe {
                expires_at: now + DIRECT_PROBE_RETRY_WINDOW,
                candidates,
            })
        };
    }
    actions
}

pub(super) fn retry_unverified_direct_candidates(
    shared: &Shared,
    now: Instant,
) -> Vec<DiscoAction> {
    let mut state = shared.state.lock().unwrap();
    let peer_keys = state.peers_by_node.keys().copied().collect::<Vec<_>>();
    let mut actions = Vec::new();
    let mut retired_transactions = Vec::new();

    for peer_key in peer_keys {
        let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
            continue;
        };
        let probe_state = std::mem::replace(&mut peer.direct_probe, DirectProbeState::Inactive);
        match probe_state {
            DirectProbeState::Active(probe) if peer.active_verified_endpoint().is_some() => {
                retired_transactions.extend(
                    probe
                        .candidates
                        .into_iter()
                        .map(|candidate| candidate.tx_id),
                );
            }
            DirectProbeState::Active(probe) if now >= probe.expires_at => {
                retired_transactions.extend(
                    probe
                        .candidates
                        .into_iter()
                        .map(|candidate| candidate.tx_id),
                );
                peer.direct_probe = DirectProbeState::Exhausted;
            }
            DirectProbeState::Active(probe) => {
                actions.extend(probe.candidates.iter().map(|candidate| {
                    ping_action_with_transaction(
                        &shared.local_node_key,
                        peer.disco_key,
                        candidate.endpoint,
                        candidate.tx_id,
                    )
                }));
                peer.direct_probe = DirectProbeState::Active(probe);
            }
            DirectProbeState::Inactive => {}
            DirectProbeState::Exhausted => {
                peer.direct_probe = DirectProbeState::Exhausted;
            }
        }
    }

    for tx_id in retired_transactions {
        state.pending_tx.remove(&tx_id);
    }
    actions
}
