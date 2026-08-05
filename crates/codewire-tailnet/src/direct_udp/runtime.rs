//! Socket/channel setup and the single transport orchestration loop.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::conn::{Transport, WgDatagram};
use crate::disco;
use crate::endpoint_tracker::EndpointTracker;
use crate::node::{AddrPort, Node};
use crate::stun;
use crate::udp_relay;

use super::disco_transport::{handle_disco_packet, send_disco_actions};
use super::discovery::{
    apply_discovered_endpoint, apply_peer_update, refresh_advertised_endpoints,
    retry_unverified_direct_candidates, send_stun_refresh, take_stun_response,
};
use super::peer_relay::{
    apply_peer_relay_request, handle_relay_packet, retry_unverified_peer_relay_negotiation,
    RelayPacketOutcome,
};
use super::state::{
    active_path_for_peer, derp_public_from_node, is_usable_direct_endpoint, path_for_peer,
    verified_peer_for_endpoint, ActivePeerPath, EndpointRefresh, PeerRelayRequest, PendingStun,
    Shared, TransportChannels,
};
use super::{
    Error, Handle, Options, PeerRelayAllocationEvent, PEER_RELAY_BIND_RETRY_INTERVAL,
    UDP_PACKET_LIMIT,
};

/// Wrap `fallback` with direct UDP discovery/path selection.
///
/// The returned [`Transport`] has the same Conn-facing shape as DERP-only. The
/// adapter decides where to send each encrypted WireGuard datagram.
pub async fn wrap_transport(
    fallback: Transport,
    mut options: Options,
) -> Result<(Transport, Handle), Error> {
    let socket = UdpSocket::bind(options.bind_addr)
        .await
        .map_err(|source| Error::Bind {
            addr: options.bind_addr,
            source,
        })?;
    let local_addr = socket.local_addr().map_err(Error::LocalAddr)?;
    let static_endpoints = options.advertise_endpoints.clone();
    tracing::info!(
        bind_addr = %options.bind_addr,
        local_addr = %local_addr,
        static_endpoint_count = static_endpoints.len(),
        stun_server_count = options.stun_servers.len(),
        "rust tailnet direct UDP socket bound"
    );

    let mut endpoint_tracker = EndpointTracker::default();
    let discovered_endpoints = if options.peer_direct_udp_enabled {
        stun::discover_mapped_addrs(&socket, &options.stun_servers, options.stun_timeout).await
    } else {
        options.advertise_endpoints.clear();
        Vec::new()
    };
    let discovered_endpoint_count = discovered_endpoints.len();
    for endpoint in discovered_endpoints {
        if is_usable_direct_endpoint(endpoint) && !options.advertise_endpoints.contains(&endpoint) {
            options.advertise_endpoints.push(endpoint);
        }
    }
    options.advertise_endpoints = endpoint_tracker.update(options.advertise_endpoints.clone());
    tracing::info!(
        discovered_endpoint_count,
        advertised_endpoint_count = options.advertise_endpoints.len(),
        "rust tailnet startup STUN discovery complete"
    );
    let socket = Arc::new(socket);

    let stun_servers = if options.peer_direct_udp_enabled {
        options.stun_servers.clone()
    } else {
        Vec::new()
    };
    let stun_timeout = options.stun_timeout;
    let stun_refresh_interval = options.stun_refresh_interval;
    let (to_transport, from_conn) = mpsc::unbounded_channel::<WgDatagram>();
    let (to_conn, from_transport) = mpsc::unbounded_channel::<WgDatagram>();
    let (peer_updates, peer_updates_rx) = mpsc::unbounded_channel::<Vec<Node>>();
    let (local_endpoint_updates, local_endpoint_updates_rx) =
        mpsc::unbounded_channel::<Vec<AddrPort>>();
    let (peer_relay_requests, peer_relay_requests_rx) =
        mpsc::unbounded_channel::<PeerRelayRequest>();
    let (peer_relay_allocation_events, peer_relay_allocation_events_rx) =
        mpsc::unbounded_channel::<PeerRelayAllocationEvent>();
    let shared = Arc::new(Shared::new(&options, peer_relay_allocation_events));

    tokio::spawn(run_direct_transport(
        shared.clone(),
        socket,
        fallback,
        TransportChannels {
            from_conn,
            to_conn,
            peer_updates_rx,
            peer_relay_requests_rx,
        },
        EndpointRefresh {
            static_endpoints,
            stun_servers,
            stun_timeout,
            stun_refresh_interval,
            endpoint_tracker,
            local_endpoint_updates,
        },
    ));

    Ok((
        Transport {
            to_transport,
            from_transport,
            peer_updates: Some(peer_updates),
            path_probe: Some(Arc::new({
                let shared = shared.clone();
                move |peer| path_for_peer(&shared, peer)
            })),
            local_endpoint_updates: Some(local_endpoint_updates_rx),
        },
        Handle {
            shared,
            local_addr,
            peer_relay_requests,
            peer_relay_allocation_events: Arc::new(Mutex::new(Some(
                peer_relay_allocation_events_rx,
            ))),
        },
    ))
}

async fn run_direct_transport(
    shared: Arc<Shared>,
    socket: Arc<UdpSocket>,
    fallback: Transport,
    channels: TransportChannels,
    mut endpoint_refresh: EndpointRefresh,
) {
    let TransportChannels {
        mut from_conn,
        to_conn,
        mut peer_updates_rx,
        mut peer_relay_requests_rx,
    } = channels;
    let fallback_tx = fallback.to_transport;
    let mut fallback_rx = fallback.from_transport;
    let mut udp_buf = vec![0u8; UDP_PACKET_LIMIT];
    let mut stun_refresh = tokio::time::interval(endpoint_refresh.stun_refresh_interval);
    stun_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut peer_relay_bind_retry = tokio::time::interval(PEER_RELAY_BIND_RETRY_INTERVAL);
    peer_relay_bind_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending_stun = Vec::<PendingStun>::new();
    let mut peer_relay_requests_closed = false;
    tracing::debug!(
        advertised_endpoint_count = shared.advertised_socket_addrs().len(),
        stun_server_count = endpoint_refresh.stun_servers.len(),
        "rust tailnet direct UDP transport loop started"
    );
    peer_relay_bind_retry.tick().await;

    loop {
        tokio::select! {
            _ = stun_refresh.tick(), if !endpoint_refresh.stun_servers.is_empty() => {
                refresh_advertised_endpoints(&shared, &mut endpoint_refresh, Vec::new());
                pending_stun = send_stun_refresh(&socket, &endpoint_refresh).await;
                tracing::debug!(
                    request_count = pending_stun.len(),
                    "rust tailnet STUN refresh sent"
                );
            }
            _ = peer_relay_bind_retry.tick() => {
                let now = Instant::now();
                let actions = retry_unverified_direct_candidates(&shared, now);
                if !actions.is_empty() {
                    tracing::debug!(
                        action_count = actions.len(),
                        "rust tailnet retrying unverified direct UDP candidates"
                    );
                }
                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;

                let actions = retry_unverified_peer_relay_negotiation(&shared, now);
                if !actions.is_empty() {
                    tracing::debug!(
                        action_count = actions.len(),
                        "rust tailnet retrying unverified UDP peer relay negotiation"
                    );
                }
                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
            }
            maybe = peer_updates_rx.recv() => {
                let Some(nodes) = maybe else { return; };
                let actions = apply_peer_update(&shared, nodes);
                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
            }
            maybe = peer_relay_requests_rx.recv(), if !peer_relay_requests_closed => {
                match maybe {
                    Some(request) => {
                        let actions = apply_peer_relay_request(&shared, request);
                        send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
                    }
                    None => peer_relay_requests_closed = true,
                }
            }
            maybe = from_conn.recv() => {
                let Some(dg) = maybe else { return; };
                send_wg_datagram(&shared, &socket, &fallback_tx, dg).await;
            }
            maybe = fallback_rx.recv() => {
                let Some(dg) = maybe else { return; };
                if disco::looks_like_wrapper(&dg.data) {
                    shared.stats.disco_derp_received.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        packet_len = dg.data.len(),
                        "rust tailnet DERP disco packet received"
                    );
                    handle_disco_packet(&shared, &socket, &fallback_tx, None, Some(dg.peer), &dg.data).await;
                } else {
                    let _ = to_conn.send(dg);
                }
            }
            recv = socket.recv_from(&mut udp_buf) => {
                let Ok((n, src)) = recv else { return; };
                let data = udp_buf[..n].to_vec();
                if let Some(mapped) = take_stun_response(&mut pending_stun, src, &data) {
                    tracing::debug!(
                        server = %src,
                        mapped_endpoint = %mapped,
                        "rust tailnet STUN refresh response"
                    );
                    apply_discovered_endpoint(&shared, &mut endpoint_refresh, mapped);
                } else {
                    if let Ok(packet) = udp_relay::decode_packet(&data) {
                        match handle_relay_packet(&shared, src, packet) {
                            RelayPacketOutcome::Unknown => {}
                            RelayPacketOutcome::Handled {
                                response_packet,
                                actions,
                                datagram,
                            } => {
                                if let Some(packet) = response_packet {
                                    if socket.send_to(&packet, src).await.is_ok() {
                                        shared
                                            .stats
                                            .peer_relay_disco_sent
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                send_disco_actions(&shared, &socket, &fallback_tx, actions).await;
                                if let Some(datagram) = datagram {
                                    let _ = to_conn.send(datagram);
                                }
                                continue;
                            }
                        }
                    }
                    if disco::looks_like_wrapper(&data) {
                        shared.stats.disco_udp_received.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            source = %src,
                            packet_len = n,
                            "rust tailnet UDP disco packet received"
                        );
                        handle_disco_packet(&shared, &socket, &fallback_tx, Some(src), None, &data).await;
                    } else if let Some(peer) = verified_peer_for_endpoint(&shared, src) {
                        shared.stats.direct_wg_received.fetch_add(1, Ordering::Relaxed);
                        let _ = to_conn.send(WgDatagram {
                            peer: derp_public_from_node(peer),
                            data,
                        });
                    }
                }
            }
        }
    }
}

async fn send_wg_datagram(
    shared: &Shared,
    socket: &UdpSocket,
    fallback_tx: &mpsc::UnboundedSender<WgDatagram>,
    dg: WgDatagram,
) {
    let sent = match active_path_for_peer(shared, dg.peer.as_bytes()) {
        Some(ActivePeerPath::Direct(endpoint)) => match socket.send_to(&dg.data, endpoint).await {
            Ok(_) => {
                shared.stats.direct_wg_sent.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    endpoint = %endpoint,
                    "rust tailnet sent WireGuard datagram over direct UDP"
                );
                true
            }
            Err(_) => false,
        },
        Some(ActivePeerPath::Relay { addr, vni }) => {
            let packet = udp_relay::encode_data_packet(vni, &dg.data);
            match socket.send_to(&packet, addr).await {
                Ok(_) => {
                    shared
                        .stats
                        .peer_relay_wg_sent
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::trace!(
                        relay_addr = %addr,
                        relay_vni = vni,
                        "rust tailnet sent WireGuard datagram over UDP peer relay"
                    );
                    true
                }
                Err(_) => false,
            }
        }
        None => false,
    };
    if sent {
        return;
    }

    shared
        .stats
        .fallback_wg_sent
        .fetch_add(1, Ordering::Relaxed);
    tracing::trace!("rust tailnet sent WireGuard datagram over fallback DERP");
    let _ = fallback_tx.send(dg);
}
