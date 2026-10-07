//! UDP peer-relay packet validation, negotiation, and retry transitions.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::conn::WgDatagram;
use crate::disco::{
    AllocateUDPRelayEndpointResponse, BindUDPRelayEndpoint, BindUDPRelayEndpointAnswer,
    BindUDPRelayEndpointCommon, CallMeMaybeVia, Message, Pong, UDPRelayEndpoint,
};
use crate::node::DiscoPublic;
use crate::udp_relay::{self, RelayPacket};

use super::state::{
    disco_message_kind, is_acceptable_peer_endpoint, is_usable_direct_endpoint,
    make_relay_ping_action, DiscoAction, DiscoTarget, PeerRelayRequest, PeerState,
    PendingPeerRelayRequest, RelayKey, RelayPeerEndpoint, Shared, State,
};

pub(super) enum RelayPacketOutcome {
    Unknown,
    Handled {
        response_packet: Option<Vec<u8>>,
        actions: Vec<DiscoAction>,
        datagram: Option<WgDatagram>,
    },
}

pub(super) fn handle_relay_packet(
    shared: &Shared,
    source: SocketAddr,
    packet: RelayPacket<'_>,
) -> RelayPacketOutcome {
    match packet {
        RelayPacket::Control { vni, payload } => {
            let response = handle_relay_control_packet(shared, source, vni, payload);
            match response {
                RelayControlOutcome::Unknown => RelayPacketOutcome::Unknown,
                RelayControlOutcome::Drop => RelayPacketOutcome::Handled {
                    response_packet: None,
                    actions: Vec::new(),
                    datagram: None,
                },
                RelayControlOutcome::Answer { packet, actions } => RelayPacketOutcome::Handled {
                    response_packet: Some(packet),
                    actions,
                    datagram: None,
                },
            }
        }
        RelayPacket::Disco { vni, payload } => {
            let Some(actions) = handle_relay_disco_packet(shared, source, vni, payload) else {
                return RelayPacketOutcome::Unknown;
            };
            RelayPacketOutcome::Handled {
                response_packet: None,
                actions,
                datagram: None,
            }
        }
        RelayPacket::Data { vni, payload } => {
            let mut state = shared.state.lock().unwrap();
            let Some(peer_key) = state.resolve_relay_peer(source, vni, Instant::now()) else {
                shared
                    .stats
                    .peer_relay_unmatched
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    relay_addr = %source,
                    relay_vni = vni,
                    "rust tailnet dropped UDP peer relay data from unmatched source"
                );
                return RelayPacketOutcome::Unknown;
            };
            let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
                state.peers_by_relay.remove(&RelayKey { addr: source, vni });
                return RelayPacketOutcome::Handled {
                    response_packet: None,
                    actions: Vec::new(),
                    datagram: None,
                };
            };
            let Some(relay) = peer.relay_endpoint.as_mut() else {
                state.peers_by_relay.remove(&RelayKey { addr: source, vni });
                return RelayPacketOutcome::Handled {
                    response_packet: None,
                    actions: Vec::new(),
                    datagram: None,
                };
            };
            let now = Instant::now();
            if !relay.is_bound() || !relay.is_fresh(now) {
                shared
                    .stats
                    .peer_relay_drops
                    .fetch_add(1, Ordering::Relaxed);
                return RelayPacketOutcome::Handled {
                    response_packet: None,
                    actions: Vec::new(),
                    datagram: None,
                };
            }
            relay.mark_verified(now);
            let peer = peer.derp_key.clone();
            let data = payload.to_vec();
            drop(state);
            shared
                .stats
                .peer_relay_wg_received
                .fetch_add(1, Ordering::Relaxed);
            RelayPacketOutcome::Handled {
                response_packet: None,
                actions: Vec::new(),
                datagram: Some(WgDatagram { peer, data }),
            }
        }
    }
}

pub(super) fn handle_relay_disco_packet(
    shared: &Shared,
    source: SocketAddr,
    vni: u32,
    payload: &[u8],
) -> Option<Vec<DiscoAction>> {
    let opened = match shared.local_disco.open(payload) {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(
                relay_addr = %source,
                relay_vni = vni,
                error = %err,
                "rust tailnet ignored undecodable UDP peer relay disco packet"
            );
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            return Some(Vec::new());
        }
    };
    let message_kind = disco_message_kind(&opened.message);
    tracing::debug!(
        relay_addr = %source,
        relay_vni = vni,
        message_kind,
        "rust tailnet UDP peer relay disco packet opened"
    );

    let mut state = shared.state.lock().unwrap();
    let peer_key = state.resolve_relay_peer(source, vni, Instant::now())?;
    let peer_disco = {
        let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
            state.peers_by_relay.remove(&RelayKey { addr: source, vni });
            return Some(Vec::new());
        };
        if peer.disco_key != opened.sender {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            return Some(Vec::new());
        }
        let Some(relay) = peer.relay_endpoint.as_mut() else {
            state.peers_by_relay.remove(&RelayKey { addr: source, vni });
            return Some(Vec::new());
        };
        let now = Instant::now();
        if !relay.is_bound() || !relay.is_fresh(now) {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            return Some(Vec::new());
        }
        relay.mark_verified(now);
        peer.disco_key
    };
    shared
        .stats
        .peer_relay_disco_received
        .fetch_add(1, Ordering::Relaxed);

    match opened.message {
        Message::Ping(ping) => Some(vec![DiscoAction {
            target: DiscoTarget::Relay { addr: source, vni },
            peer_disco,
            message: Message::Pong(Pong {
                tx_id: ping.tx_id,
                src: source,
            }),
        }]),
        Message::Pong(pong) => {
            let matched = state.pending_tx.remove(&pong.tx_id) == Some(peer_key);
            if matched {
                if let Some(peer) = state.peers_by_node.get_mut(&peer_key) {
                    if let Some(relay) = peer.relay_endpoint.as_mut() {
                        relay.mark_verified(Instant::now());
                    }
                }
            }
            Some(Vec::new())
        }
        _ => {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            Some(Vec::new())
        }
    }
}

pub(super) enum RelayControlOutcome {
    Unknown,
    Drop,
    Answer {
        packet: Vec<u8>,
        actions: Vec<DiscoAction>,
    },
}

pub(super) fn handle_relay_control_packet(
    shared: &Shared,
    source: SocketAddr,
    vni: u32,
    payload: &[u8],
) -> RelayControlOutcome {
    let opened = match shared.local_disco.open(payload) {
        Ok(opened) => opened,
        Err(err) => {
            tracing::debug!(
                relay_addr = %source,
                relay_vni = vni,
                error = %err,
                "rust tailnet ignored undecodable UDP peer relay control packet"
            );
            return RelayControlOutcome::Drop;
        }
    };

    let mut state = shared.state.lock().unwrap();
    let Some(peer_key) = state.resolve_relay_peer(source, vni, Instant::now()) else {
        return RelayControlOutcome::Unknown;
    };
    let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
        state.peers_by_relay.remove(&RelayKey { addr: source, vni });
        return RelayControlOutcome::Drop;
    };
    let Some(relay) = peer.relay_endpoint.as_mut() else {
        state.peers_by_relay.remove(&RelayKey { addr: source, vni });
        return RelayControlOutcome::Drop;
    };
    if relay.server_disco != opened.sender {
        shared
            .stats
            .peer_relay_drops
            .fetch_add(1, Ordering::Relaxed);
        return RelayControlOutcome::Drop;
    }

    match opened.message {
        Message::BindUDPRelayEndpointChallenge(challenge) => {
            let (
                peer_node_key,
                peer_disco,
                relay_server_disco,
                relay_addr,
                relay_vni,
                relay_generation,
                relay_remote_disco,
            ) = {
                if challenge.common.vni != relay.vni
                    || challenge.common.generation != relay.generation
                    || challenge.common.remote_key != relay.remote_disco
                {
                    shared
                        .stats
                        .peer_relay_drops
                        .fetch_add(1, Ordering::Relaxed);
                    return RelayControlOutcome::Drop;
                }
                relay.mark_bound(Instant::now());
                (
                    peer.node_key,
                    peer.disco_key,
                    relay.server_disco,
                    relay.addr,
                    relay.vni,
                    relay.generation,
                    relay.remote_disco,
                )
            };
            let answer = Message::BindUDPRelayEndpointAnswer(BindUDPRelayEndpointAnswer {
                common: BindUDPRelayEndpointCommon {
                    vni: relay_vni,
                    generation: relay_generation,
                    remote_key: relay_remote_disco,
                    challenge: challenge.common.challenge,
                },
            });
            let packet = match shared
                .local_disco
                .seal_to(&relay_server_disco, &answer, &mut OsRng)
            {
                Ok(sealed) => udp_relay::encode_control_packet(relay_vni, &sealed),
                Err(_) => return RelayControlOutcome::Drop,
            };
            let ping = make_relay_ping_action(
                &mut state,
                &shared.local_node_key,
                peer_node_key,
                peer_disco,
                relay_addr,
                relay_vni,
            );
            shared
                .stats
                .peer_relay_disco_received
                .fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                relay_addr = %relay_addr,
                relay_vni,
                "rust tailnet UDP peer relay bind answered"
            );
            RelayControlOutcome::Answer {
                packet,
                actions: vec![ping],
            }
        }
        _ => {
            shared
                .stats
                .peer_relay_drops
                .fetch_add(1, Ordering::Relaxed);
            RelayControlOutcome::Drop
        }
    }
}

pub(super) fn apply_call_me_maybe_via(
    state: &mut State,
    shared: &Shared,
    peer_key: [u8; 32],
    mut endpoint: UDPRelayEndpoint,
) -> Vec<DiscoAction> {
    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
        return Vec::new();
    };
    // The relay addresses come from the peer.
    let public_only = state.public_peer_endpoints_only;
    endpoint
        .addr_ports
        .retain(|addr| is_acceptable_peer_endpoint(*addr, public_only));
    let Some(relay) =
        relay_endpoint_from_descriptor(endpoint, shared.local_disco.public(), peer.disco_key)
    else {
        tracing::debug!("rust tailnet ignored unusable UDP peer relay endpoint descriptor");
        return Vec::new();
    };
    if let Some(existing) = peer.relay_endpoint.as_ref() {
        if existing.server_disco == relay.server_disco {
            if relay.lamport_id < existing.lamport_id {
                tracing::debug!(
                    relay_addr = %relay.addr,
                    relay_vni = relay.vni,
                    relay_lamport_id = relay.lamport_id,
                    current_lamport_id = existing.lamport_id,
                    "rust tailnet ignored stale UDP peer relay notification"
                );
                return Vec::new();
            }
            if relay.lamport_id == existing.lamport_id {
                tracing::debug!(
                    relay_addr = %existing.addr,
                    relay_vni = existing.vni,
                    relay_lamport_id = existing.lamport_id,
                    "rust tailnet reused duplicate UDP peer relay notification"
                );
                return (existing.verified_at.is_none() && existing.is_fresh(Instant::now()))
                    .then(|| relay_bind_action(&peer, existing))
                    .into_iter()
                    .collect();
            }
        }
    }

    let action = relay_bind_action(&peer, &relay);
    register_relay_endpoint(state, peer_key, relay);
    vec![action]
}

pub(super) fn relay_endpoint_from_descriptor(
    endpoint: UDPRelayEndpoint,
    local_disco: DiscoPublic,
    peer_disco: DiscoPublic,
) -> Option<RelayPeerEndpoint> {
    if endpoint.vni == 0
        || endpoint.server_disco.is_zero()
        || endpoint.bind_lifetime.is_zero()
        || endpoint.steady_state_lifetime.is_zero()
        || !endpoint.client_disco.contains(&local_disco)
        || !endpoint.client_disco.contains(&peer_disco)
    {
        return None;
    }
    let addr = endpoint
        .addr_ports
        .into_iter()
        .find(|addr| is_usable_direct_endpoint(*addr))?;
    let generation = nonzero_generation();
    Some(RelayPeerEndpoint {
        server_disco: endpoint.server_disco,
        remote_disco: peer_disco,
        addr,
        lamport_id: endpoint.lamport_id,
        vni: endpoint.vni,
        generation,
        bind_expires_at: Instant::now() + endpoint.bind_lifetime,
        steady_state_lifetime: endpoint.steady_state_lifetime,
        steady_expires_at: None,
        verified_at: None,
        retry_call_me_maybe_via: None,
    })
}

pub(super) fn apply_known_peer_relay_request(
    state: &mut State,
    shared: &Shared,
    peer_key: [u8; 32],
    bind_endpoint: UDPRelayEndpoint,
    advertise_endpoint: UDPRelayEndpoint,
    response_generation: Option<u32>,
) -> Vec<DiscoAction> {
    let local_disco = shared.local_disco.public();
    let Some(peer) = state.peers_by_node.get(&peer_key).cloned() else {
        tracing::debug!("rust tailnet ignored UDP peer relay request for unknown peer");
        return Vec::new();
    };
    let now = Instant::now();
    if let Some(relay) = peer
        .relay_endpoint
        .as_ref()
        .filter(|relay| relay.remote_disco == peer.disco_key && relay.is_fresh(now))
    {
        tracing::debug!(
            relay_addr = %relay.addr,
            relay_vni = relay.vni,
            "rust tailnet kept existing fresh UDP peer relay endpoint"
        );
        if let Some(generation) = response_generation {
            return vec![DiscoAction {
                target: DiscoTarget::Derp(peer.derp_key),
                peer_disco: peer.disco_key,
                message: Message::AllocateUDPRelayEndpointResponse(
                    AllocateUDPRelayEndpointResponse {
                        generation,
                        endpoint: advertise_endpoint,
                    },
                ),
            }];
        }
        return Vec::new();
    }
    let Some(mut relay) =
        relay_endpoint_from_descriptor(bind_endpoint, local_disco, peer.disco_key)
    else {
        tracing::debug!(
            "rust tailnet ignored unusable UDP peer relay endpoint descriptor from control path"
        );
        return Vec::new();
    };

    if response_generation.is_none() {
        relay.retry_call_me_maybe_via = Some(advertise_endpoint.clone());
    }
    let notify = if let Some(generation) = response_generation {
        Message::AllocateUDPRelayEndpointResponse(AllocateUDPRelayEndpointResponse {
            generation,
            endpoint: advertise_endpoint,
        })
    } else {
        Message::CallMeMaybeVia(CallMeMaybeVia {
            endpoint: advertise_endpoint,
        })
    };
    let bind = relay_bind_action(&peer, &relay);
    register_relay_endpoint(state, peer_key, relay);
    vec![
        bind,
        DiscoAction {
            target: DiscoTarget::Derp(peer.derp_key),
            peer_disco: peer.disco_key,
            message: notify,
        },
    ]
}

pub(super) fn nonzero_generation() -> u32 {
    loop {
        let generation = OsRng.next_u32();
        if generation != 0 {
            return generation;
        }
    }
}

pub(super) fn relay_bind_action(peer: &PeerState, relay: &RelayPeerEndpoint) -> DiscoAction {
    DiscoAction {
        target: DiscoTarget::Relay {
            addr: relay.addr,
            vni: relay.vni,
        },
        peer_disco: relay.server_disco,
        message: Message::BindUDPRelayEndpoint(BindUDPRelayEndpoint {
            common: BindUDPRelayEndpointCommon {
                vni: relay.vni,
                generation: relay.generation,
                remote_key: peer.disco_key,
                challenge: [0; 32],
            },
        }),
    }
}

pub(super) fn register_relay_endpoint(
    state: &mut State,
    peer_key: [u8; 32],
    relay: RelayPeerEndpoint,
) {
    state.remove_relay_keys_for_peer(&peer_key);
    let Some(peer) = state.peers_by_node.get_mut(&peer_key) else {
        return;
    };
    peer.relay_endpoint = Some(relay.clone());
    state.peers_by_relay.insert(relay.key(), peer_key);
    tracing::info!(
        relay_addr = %relay.addr,
        relay_vni = relay.vni,
        "rust tailnet UDP peer relay bind started"
    );
}

pub(super) fn apply_peer_relay_request(
    shared: &Shared,
    request: PeerRelayRequest,
) -> Vec<DiscoAction> {
    let peer_key = *request.peer.as_bytes();
    let mut state = shared.state.lock().unwrap();
    if !state.peers_by_node.contains_key(&peer_key) {
        if request.response_generation.is_none() {
            tracing::debug!(
                "rust tailnet discarded proactive UDP peer relay request for absent peer"
            );
            return Vec::new();
        }
        state.pending_peer_relays.insert(
            peer_key,
            PendingPeerRelayRequest {
                bind_endpoint: request.bind_endpoint,
                advertise_endpoint: request.advertise_endpoint,
                response_generation: request.response_generation,
            },
        );
        tracing::debug!("rust tailnet deferred UDP peer relay request for unknown peer");
        return Vec::new();
    };
    apply_known_peer_relay_request(
        &mut state,
        shared,
        peer_key,
        request.bind_endpoint,
        request.advertise_endpoint,
        request.response_generation,
    )
}

pub(super) fn retry_unverified_peer_relay_negotiation(
    shared: &Shared,
    now: Instant,
) -> Vec<DiscoAction> {
    let state = shared.state.lock().unwrap();
    let mut actions = Vec::new();
    for peer in state.peers_by_node.values() {
        let Some(relay) = peer.relay_endpoint.as_ref() else {
            continue;
        };
        if relay.verified_at.is_some() || now > relay.bind_expires_at {
            continue;
        }
        actions.push(relay_bind_action(peer, relay));
        if let Some(endpoint) = relay.retry_call_me_maybe_via.clone() {
            actions.push(DiscoAction {
                target: DiscoTarget::Derp(peer.derp_key.clone()),
                peer_disco: peer.disco_key,
                message: Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }),
            });
        }
    }
    actions
}
