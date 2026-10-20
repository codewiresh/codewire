#[allow(clippy::wildcard_imports)]
use super::*;

#[test]
fn peer_relay_request_binds_internal_endpoint_and_advertises_public_endpoint() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
    }

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
    let endpoint = UDPRelayEndpoint {
        server_disco: DiscoPrivate::generate(&mut OsRng).public(),
        client_disco: [local_disco.public(), peer_disco],
        lamport_id: 7,
        vni: 9001,
        bind_lifetime: Duration::from_secs(5),
        steady_state_lifetime: Duration::from_secs(30),
        addr_ports: vec![bind_addr],
    };
    let mut advertised_endpoint = endpoint.clone();
    advertised_endpoint.addr_ports = vec![advertised_addr];

    let actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint,
            advertise_endpoint: advertised_endpoint.clone(),
            response_generation: None,
        },
    );

    assert_eq!(actions.len(), 2);
    match &actions[0].target {
        DiscoTarget::Relay { addr, vni } => {
            assert_eq!(*addr, bind_addr);
            assert_eq!(*vni, 9001);
        }
        _ => panic!("expected relay bind action"),
    }
    match &actions[1].message {
        Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
            assert_eq!(endpoint.addr_ports, vec![advertised_addr]);
            assert_eq!(endpoint.vni, 9001);
        }
        other => panic!("expected CallMeMaybeVia action, got {other:?}"),
    }
    {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        assert_eq!(peer.relay_endpoint.as_ref().unwrap().addr, bind_addr);
    }

    let retries = retry_unverified_peer_relay_negotiation(&shared, Instant::now());
    assert_eq!(retries.len(), 2);
    match &retries[0].target {
        DiscoTarget::Relay { addr, vni } => {
            assert_eq!(*addr, bind_addr);
            assert_eq!(*vni, 9001);
        }
        _ => panic!("expected retry to target internal relay bind address"),
    }
    match &retries[1].message {
        Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }) => {
            assert_eq!(endpoint.addr_ports, vec![advertised_addr]);
            assert_eq!(endpoint.vni, 9001);
        }
        other => panic!("expected retried CallMeMaybeVia action, got {other:?}"),
    }
}

#[test]
fn peer_relay_allocation_answer_uses_allocate_response_message() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
    }

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
    let endpoint = udp_relay_endpoint(
        DiscoPrivate::generate(&mut OsRng).public(),
        local_disco.public(),
        peer_disco,
        9001,
        bind_addr,
    );
    let mut advertised_endpoint = endpoint.clone();
    advertised_endpoint.addr_ports = vec![advertised_addr];

    let actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint,
            advertise_endpoint: advertised_endpoint.clone(),
            response_generation: Some(77),
        },
    );

    assert_eq!(actions.len(), 2);
    let Message::AllocateUDPRelayEndpointResponse(response) = &actions[1].message else {
        panic!("expected AllocateUDPRelayEndpointResponse");
    };
    assert_eq!(response.generation, 77);
    assert_eq!(response.endpoint, advertised_endpoint);
}

#[test]
fn peer_relay_request_keeps_fresh_existing_relay_endpoint() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
    }

    let server_disco = DiscoPrivate::generate(&mut OsRng).public();
    let first_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let second_bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41642);
    let first_advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
    let second_advertised_addr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41642);
    let first_endpoint = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        first_bind_addr,
    );
    let first_advertised = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        first_advertised_addr,
    );
    let second_endpoint = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9002,
        second_bind_addr,
    );
    let second_advertised = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9002,
        second_advertised_addr,
    );

    let first_actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: first_endpoint,
            advertise_endpoint: first_advertised,
            response_generation: None,
        },
    );
    assert_eq!(first_actions.len(), 2);

    let second_actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: second_endpoint,
            advertise_endpoint: second_advertised,
            response_generation: None,
        },
    );
    assert!(
        second_actions.is_empty(),
        "a repeated allocation must not churn a fresh relay path"
    );

    let state = shared.state.lock().unwrap();
    let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
    let relay = peer.relay_endpoint.as_ref().unwrap();
    assert_eq!(relay.addr, first_bind_addr);
    assert_eq!(relay.vni, 9001);
    assert!(state.peers_by_relay.contains_key(&RelayKey {
        addr: first_bind_addr,
        vni: 9001
    }));
    assert!(!state.peers_by_relay.contains_key(&RelayKey {
        addr: second_bind_addr,
        vni: 9002
    }));
}

#[test]
fn bound_peer_relay_requires_verification_before_selection() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
    }

    let server_disco = DiscoPrivate::generate(&mut OsRng).public();
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let endpoint = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        bind_addr,
    );
    let actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint.clone(),
            advertise_endpoint: endpoint,
            response_generation: None,
        },
    );
    assert_eq!(actions.len(), 2);

    {
        let mut state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
        peer.relay_endpoint
            .as_mut()
            .unwrap()
            .mark_bound(Instant::now());
    }

    let unverified = path_for_peer(&shared, peer_node);
    assert_eq!(unverified.transport, PeerTransport::DerpRelay);
    {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        let relay = peer.relay_endpoint.as_ref().unwrap();
        assert_eq!(relay.addr, bind_addr);
        assert_eq!(relay.vni, 9001);
        assert!(state.peers_by_relay.contains_key(&RelayKey {
            addr: bind_addr,
            vni: 9001
        }));
    }

    {
        let mut state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
        peer.relay_endpoint
            .as_mut()
            .unwrap()
            .mark_verified(Instant::now());
    }

    let verified = path_for_peer(&shared, peer_node);
    assert_eq!(verified.transport, PeerTransport::PeerRelay);
    assert_eq!(verified.endpoint, Some(bind_addr));
}

#[test]
fn unverified_peer_relay_retries_bind_and_notification() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    let peer_disco = shared
        .state
        .lock()
        .unwrap()
        .peers_by_node
        .get(peer_node.as_bytes())
        .unwrap()
        .disco_key;

    let retries = retry_unverified_peer_relay_negotiation(&shared, Instant::now());

    assert_eq!(retries.len(), 2);
    assert!(matches!(
        retries[0].message,
        Message::BindUDPRelayEndpoint(_)
    ));
    assert!(matches!(retries[1].message, Message::CallMeMaybeVia(_)));
    assert_eq!(
        peer_relay_endpoint_state(&shared, peer_node, peer_disco, Instant::now()),
        PeerRelayEndpointState::Negotiating
    );
}

#[test]
fn peer_relay_endpoint_state_reports_active_then_expired() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    let now = Instant::now();
    let peer_disco = {
        let mut state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
        let peer_disco = peer.disco_key;
        let relay = peer.relay_endpoint.as_mut().unwrap();
        relay.mark_bound(now);
        relay.mark_verified(now);
        peer_disco
    };
    assert_eq!(
        peer_relay_endpoint_state(&shared, peer_node, peer_disco, now),
        PeerRelayEndpointState::Active
    );

    {
        let mut state = shared.state.lock().unwrap();
        state
            .peers_by_node
            .get_mut(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_mut()
            .unwrap()
            .steady_expires_at = Some(now - Duration::from_millis(1));
    }
    assert_eq!(
        peer_relay_endpoint_state(&shared, peer_node, peer_disco, now),
        PeerRelayEndpointState::Missing
    );
}

#[test]
fn peer_disco_rotation_discards_old_relay_identity() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let old_peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let new_peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    let _ = apply_peer_update(
        &shared,
        vec![node_with_endpoints(
            peer_node,
            old_peer_disco,
            Vec::new(),
            B_IP,
        )],
    );

    let relay_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let endpoint = udp_relay_endpoint(
        DiscoPrivate::generate(&mut OsRng).public(),
        local_disco.public(),
        old_peer_disco,
        9001,
        relay_addr,
    );
    assert_eq!(
        apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer: peer_node,
                bind_endpoint: endpoint.clone(),
                advertise_endpoint: endpoint,
                response_generation: None,
            },
        )
        .len(),
        2
    );
    {
        let mut state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get_mut(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_mut()
            .unwrap();
        let now = Instant::now();
        relay.mark_bound(now);
        relay.mark_verified(now);
    }
    assert_eq!(
        peer_relay_endpoint_state(&shared, peer_node, old_peer_disco, Instant::now()),
        PeerRelayEndpointState::Active
    );

    let _ = apply_peer_update(
        &shared,
        vec![node_with_endpoints(
            peer_node,
            new_peer_disco,
            Vec::new(),
            B_IP,
        )],
    );

    assert_eq!(
        peer_relay_endpoint_state(&shared, peer_node, old_peer_disco, Instant::now()),
        PeerRelayEndpointState::Missing
    );
    assert_eq!(
        peer_relay_endpoint_state(&shared, peer_node, new_peer_disco, Instant::now()),
        PeerRelayEndpointState::Missing
    );
    let state = shared.state.lock().unwrap();
    let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
    assert_eq!(peer.disco_key, new_peer_disco);
    assert!(peer.relay_endpoint.is_none());
    assert!(state.peers_by_relay.is_empty());
}

#[test]
fn duplicate_call_me_maybe_via_reuses_relay_generation() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    let endpoint = retry_call_me_maybe_via_endpoint(&shared, &peer_node);
    let (generation, bind_expires_at) = {
        let state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_ref()
            .unwrap();
        (relay.generation, relay.bind_expires_at)
    };

    let duplicate_actions = {
        let mut state = shared.state.lock().unwrap();
        apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), endpoint.clone())
    };
    assert_eq!(duplicate_actions.len(), 1);
    assert!(matches!(
        duplicate_actions[0].message,
        Message::BindUDPRelayEndpoint(_)
    ));
    {
        let state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_ref()
            .unwrap();
        assert_eq!(relay.generation, generation);
        assert_eq!(relay.bind_expires_at, bind_expires_at);
    }

    {
        let mut state = shared.state.lock().unwrap();
        state
            .peers_by_node
            .get_mut(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_mut()
            .unwrap()
            .mark_verified(Instant::now());
        assert!(
            apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), endpoint,)
                .is_empty()
        );
    }
}

#[test]
fn newer_call_me_maybe_via_replaces_older_allocation() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    let mut newer = retry_call_me_maybe_via_endpoint(&shared, &peer_node);
    let old_key = RelayKey {
        addr: newer.addr_ports[0],
        vni: newer.vni,
    };
    newer.lamport_id += 1;
    newer.vni += 1;
    newer.addr_ports = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41642)];

    let actions = {
        let mut state = shared.state.lock().unwrap();
        apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), newer.clone())
    };
    assert_eq!(actions.len(), 1);

    let state = shared.state.lock().unwrap();
    let relay = state
        .peers_by_node
        .get(peer_node.as_bytes())
        .unwrap()
        .relay_endpoint
        .as_ref()
        .unwrap();
    assert_eq!(relay.server_disco, newer.server_disco);
    assert_eq!(relay.lamport_id, newer.lamport_id);
    assert_eq!(relay.vni, newer.vni);
    assert_eq!(relay.addr, newer.addr_ports[0]);
    assert!(!state.peers_by_relay.contains_key(&old_key));
    assert!(state.peers_by_relay.contains_key(&RelayKey {
        addr: newer.addr_ports[0],
        vni: newer.vni,
    }));
}

#[test]
fn stale_call_me_maybe_via_does_not_replace_newer_allocation() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    let older = retry_call_me_maybe_via_endpoint(&shared, &peer_node);
    let mut newer = older.clone();
    newer.lamport_id += 1;
    newer.vni += 1;
    newer.addr_ports = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41642)];
    {
        let mut state = shared.state.lock().unwrap();
        assert_eq!(
            apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), newer.clone(),)
                .len(),
            1
        );
    }
    let (generation, bind_expires_at) = {
        let state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_ref()
            .unwrap();
        (relay.generation, relay.bind_expires_at)
    };

    let stale_actions = {
        let mut state = shared.state.lock().unwrap();
        apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), older)
    };
    assert!(stale_actions.is_empty());

    let state = shared.state.lock().unwrap();
    let relay = state
        .peers_by_node
        .get(peer_node.as_bytes())
        .unwrap()
        .relay_endpoint
        .as_ref()
        .unwrap();
    assert_eq!(relay.lamport_id, newer.lamport_id);
    assert_eq!(relay.vni, newer.vni);
    assert_eq!(relay.addr, newer.addr_ports[0]);
    assert_eq!(relay.generation, generation);
    assert_eq!(relay.bind_expires_at, bind_expires_at);
}

#[test]
fn verified_peer_relay_stops_bind_retries() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    {
        let mut state = shared.state.lock().unwrap();
        let relay = state
            .peers_by_node
            .get_mut(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_mut()
            .unwrap();
        relay.mark_bound(Instant::now());
        relay.mark_verified(Instant::now());
    }

    assert!(retry_unverified_peer_relay_negotiation(&shared, Instant::now()).is_empty());
}

#[test]
fn expired_peer_relay_stops_bind_retries() {
    let (shared, peer_node) = peer_relay_retry_fixture();
    {
        let mut state = shared.state.lock().unwrap();
        state
            .peers_by_node
            .get_mut(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .as_mut()
            .unwrap()
            .bind_expires_at = Instant::now() - Duration::from_millis(1);
    }

    assert!(retry_unverified_peer_relay_negotiation(&shared, Instant::now()).is_empty());
}

#[tokio::test]
async fn peer_relay_data_accepts_observed_source_alias_after_bind() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
    }

    let server_disco = DiscoPrivate::generate(&mut OsRng).public();
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let source_alias = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 41641);
    let endpoint = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        bind_addr,
    );
    let actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint.clone(),
            advertise_endpoint: endpoint,
            response_generation: None,
        },
    );
    assert_eq!(actions.len(), 2);
    {
        let mut state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get_mut(peer_node.as_bytes()).unwrap();
        peer.relay_endpoint
            .as_mut()
            .unwrap()
            .mark_bound(Instant::now());
    }

    let payload = b"encrypted wireguard packet from relay source alias";
    let outcome = handle_relay_packet(
        &shared,
        source_alias,
        RelayPacket::Data { vni: 9001, payload },
    );

    let RelayPacketOutcome::Handled {
        response_packet: None,
        actions,
        datagram: Some(got),
    } = outcome
    else {
        panic!("expected handled relay datagram");
    };
    assert!(actions.is_empty());
    assert_eq!(got.peer.as_bytes(), peer_node.as_bytes());
    assert_eq!(got.data, payload);
    assert_eq!(shared.stats.snapshot().peer_relay_wg_received, 1);

    let state = shared.state.lock().unwrap();
    assert_eq!(
        state
            .peers_by_relay
            .get(&RelayKey {
                addr: source_alias,
                vni: 9001,
            })
            .copied(),
        Some(*peer_node.as_bytes())
    );
    let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
    let relay = peer.relay_endpoint.as_ref().unwrap();
    assert_eq!(
        relay.addr, bind_addr,
        "outbound relay address stays canonical"
    );
    assert_eq!(relay.active_addr(Instant::now()), Some(bind_addr));
}

#[test]
fn peer_relay_source_alias_is_not_learned_when_vni_is_ambiguous() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let first_secret = StaticSecret::random_from_rng(OsRng);
    let second_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let first_node = NodePublic::from_raw(PublicKey::from(&first_secret).to_bytes());
    let second_node = NodePublic::from_raw(PublicKey::from(&second_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let first_disco = DiscoPrivate::generate(&mut OsRng).public();
    let second_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *first_node.as_bytes(),
            peer_state(first_node, first_disco, reserve_local_endpoint()),
        );
        state.peers_by_node.insert(
            *second_node.as_bytes(),
            peer_state(second_node, second_disco, reserve_local_endpoint()),
        );
    }

    let server_disco = DiscoPrivate::generate(&mut OsRng).public();
    for (peer, disco, addr) in [
        (
            first_node,
            first_disco,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 41641),
        ),
        (
            second_node,
            second_disco,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)), 41641),
        ),
    ] {
        let endpoint = udp_relay_endpoint(server_disco, local_disco.public(), disco, 9001, addr);
        let actions = apply_peer_relay_request(
            &shared,
            PeerRelayRequest {
                peer,
                bind_endpoint: endpoint.clone(),
                advertise_endpoint: endpoint,
                response_generation: None,
            },
        );
        assert_eq!(actions.len(), 2);
        let mut state = shared.state.lock().unwrap();
        let peer_state = state.peers_by_node.get_mut(peer.as_bytes()).unwrap();
        peer_state
            .relay_endpoint
            .as_mut()
            .unwrap()
            .mark_bound(Instant::now());
    }

    let source_alias = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 12)), 41641);
    let mut state = shared.state.lock().unwrap();
    assert_eq!(
        state.resolve_relay_peer(source_alias, 9001, Instant::now()),
        None
    );
    assert!(!state.peers_by_relay.contains_key(&RelayKey {
        addr: source_alias,
        vni: 9001,
    }));
}

#[test]
fn peer_relay_allocation_request_answers_when_existing_relay_is_fresh() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco, reserve_local_endpoint()),
        );
    }

    let server_disco = DiscoPrivate::generate(&mut OsRng).public();
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
    let endpoint = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        bind_addr,
    );
    let advertised = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        advertised_addr,
    );

    let first_actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint.clone(),
            advertise_endpoint: advertised.clone(),
            response_generation: None,
        },
    );
    assert_eq!(first_actions.len(), 2);

    let response_actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint,
            advertise_endpoint: advertised.clone(),
            response_generation: Some(44),
        },
    );
    assert_eq!(
        response_actions.len(),
        1,
        "fresh proactive relay should still answer the peer allocation request"
    );
    let Message::AllocateUDPRelayEndpointResponse(response) = &response_actions[0].message else {
        panic!("expected AllocateUDPRelayEndpointResponse");
    };
    assert_eq!(response.generation, 44);
    assert_eq!(response.endpoint, advertised);
}

#[test]
fn peer_update_preserves_pending_pongs_for_existing_peer_only() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco,
    );
    let shared = shared_for_test(&options);
    let mut tx_id = [0u8; 12];
    OsRng.fill_bytes(&mut tx_id);
    {
        let mut state = shared.state.lock().unwrap();
        state.pending_tx.insert(tx_id, *peer_node.as_bytes());
    }

    let _ = apply_peer_update(
        &shared,
        vec![node_with_endpoints(peer_node, peer_disco, Vec::new(), B_IP)],
    );
    assert_eq!(
        shared.state.lock().unwrap().pending_tx.get(&tx_id),
        Some(peer_node.as_bytes()),
        "repeated peer updates must not invalidate in-flight disco pongs"
    );

    let _ = apply_peer_update(&shared, Vec::new());
    assert!(
        !shared.state.lock().unwrap().pending_tx.contains_key(&tx_id),
        "peer removal should drop stale pending pongs"
    );
}

#[test]
fn peer_relay_allocation_answer_waits_for_late_peer_update() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641);
    let advertised_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 41641);
    let endpoint = UDPRelayEndpoint {
        server_disco: DiscoPrivate::generate(&mut OsRng).public(),
        client_disco: [local_disco.public(), peer_disco],
        lamport_id: 7,
        vni: 9001,
        bind_lifetime: Duration::from_secs(5),
        steady_state_lifetime: Duration::from_secs(30),
        addr_ports: vec![bind_addr],
    };
    let mut advertised_endpoint = endpoint.clone();
    advertised_endpoint.addr_ports = vec![advertised_addr];

    let actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint,
            advertise_endpoint: advertised_endpoint.clone(),
            response_generation: Some(77),
        },
    );
    assert!(
        actions.is_empty(),
        "authenticated allocation answers should wait for the peer update"
    );

    let actions = apply_peer_update(
        &shared,
        vec![node_with_endpoints(peer_node, peer_disco, Vec::new(), B_IP)],
    );

    assert_eq!(actions.len(), 2);
    match &actions[0].target {
        DiscoTarget::Relay { addr, vni } => {
            assert_eq!(*addr, bind_addr);
            assert_eq!(*vni, 9001);
        }
        _ => panic!("expected relay bind action"),
    }
    match &actions[1].message {
        Message::AllocateUDPRelayEndpointResponse(response) => {
            assert_eq!(response.generation, 77);
            assert_eq!(response.endpoint.addr_ports, vec![advertised_addr]);
            assert_eq!(response.endpoint.vni, 9001);
        }
        other => panic!("expected AllocateUDPRelayEndpointResponse action, got {other:?}"),
    }
    let state = shared.state.lock().unwrap();
    assert!(state.pending_peer_relays.is_empty());
    let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
    assert_eq!(peer.relay_endpoint.as_ref().unwrap().addr, bind_addr);
}

#[test]
fn proactive_peer_relay_completion_while_absent_is_not_deferred() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_for_test(&options);
    let endpoint = udp_relay_endpoint(
        DiscoPrivate::generate(&mut OsRng).public(),
        local_disco.public(),
        peer_disco,
        9001,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641),
    );

    let actions = apply_peer_relay_request(
        &shared,
        PeerRelayRequest {
            peer: peer_node,
            bind_endpoint: endpoint.clone(),
            advertise_endpoint: endpoint,
            response_generation: None,
        },
    );
    assert!(actions.is_empty());
    assert!(
        shared.state.lock().unwrap().pending_peer_relays.is_empty(),
        "a proactive completion for an absent peer must not persist"
    );

    let actions = apply_peer_update(
        &shared,
        vec![node_with_endpoints(peer_node, peer_disco, Vec::new(), B_IP)],
    );
    assert!(actions.is_empty());
    let state = shared.state.lock().unwrap();
    assert!(state.pending_peer_relays.is_empty());
    assert!(
        state
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .relay_endpoint
            .is_none(),
        "a later peer update must not resurrect the stale completion"
    );
}

#[tokio::test]
async fn call_me_maybe_via_before_peer_update_is_counted() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng);
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let shared = shared_arc_for_test(&options);
    let endpoint = udp_relay_endpoint(
        DiscoPrivate::generate(&mut OsRng).public(),
        local_disco.public(),
        peer_disco.public(),
        41,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41641),
    );
    let packet = peer_disco
        .seal_to(
            &local_disco.public(),
            &Message::CallMeMaybeVia(CallMeMaybeVia { endpoint }),
            &mut OsRng,
        )
        .expect("seal CallMeMaybeVia");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (fallback_tx, _fallback_rx) = mpsc::unbounded_channel();

    handle_disco_packet(
        &shared,
        &socket,
        &fallback_tx,
        None,
        Some(derp_public_from_node(peer_node)),
        &packet,
    )
    .await;

    let stats = shared.stats.snapshot();
    assert_eq!(stats.peer_relay_notifications_opened, 1);
    assert_eq!(stats.peer_relay_notifications_unknown_peer, 1);
    assert_eq!(stats.peer_relay_notifications_received, 0);
    assert_eq!(stats.peer_relay_notification_actions, 0);
    assert_eq!(stats.peer_relay_notification_no_actions, 0);
}

#[tokio::test]
async fn allocate_udp_relay_endpoint_request_emits_event() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng);
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    );
    let (allocation_tx, mut allocation_rx) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared::new(&options, allocation_tx));
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco.public(), reserve_local_endpoint()),
        );
    }

    let message = Message::AllocateUDPRelayEndpointRequest(AllocateUDPRelayEndpointRequest {
        client_disco: [peer_disco.public(), local_disco.public()],
        generation: 88,
    });
    let packet = peer_disco
        .seal_to(&local_disco.public(), &message, &mut OsRng)
        .expect("seal allocation request");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (fallback_tx, _fallback_rx) = mpsc::unbounded_channel();

    handle_disco_packet(
        &shared,
        &socket,
        &fallback_tx,
        None,
        Some(derp_public_from_node(peer_node)),
        &packet,
    )
    .await;

    let event = allocation_rx.try_recv().expect("allocation event");
    assert_eq!(event.peer, peer_node);
    assert_eq!(event.peer_disco, peer_disco.public());
    assert_eq!(
        event.client_disco,
        [peer_disco.public(), local_disco.public()]
    );
    assert_eq!(event.generation, 88);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn call_me_maybe_via_binds_peer_relay_when_direct_udp_is_disabled() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

    let relay_key = DiscoPrivate::generate(&mut OsRng);
    let relay = udp_relay::SocketServer::bind(
        relay_key.clone(),
        udp_relay::SocketOptions::new("127.0.0.1:0".parse().unwrap())
            .with_expire_interval(Duration::from_millis(50)),
    )
    .await
    .unwrap();
    let relay_handle = relay.handle();
    let relay_endpoint = relay_handle
        .allocate_endpoint(a_disco.public(), b_disco.public())
        .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let relay_task = tokio::spawn(relay.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let (a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            a_node,
            a_disco.clone(),
        )
        .with_peer_direct_udp_enabled(false),
    )
    .await
    .unwrap();
    let (mut b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            b_node,
            b_disco.clone(),
        )
        .with_peer_direct_udp_enabled(false),
    )
    .await
    .unwrap();

    a_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node_with_endpoints(
            b_node,
            b_disco.public(),
            Vec::new(),
            B_IP,
        )])
        .unwrap();
    b_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node_with_endpoints(
            a_node,
            a_disco.public(),
            Vec::new(),
            A_IP,
        )])
        .unwrap();

    wait_peer_known(&a_handle, &b_node).await;
    wait_peer_known(&b_handle, &a_node).await;
    a_handle
        .request_peer_relay(b_node, relay_endpoint)
        .expect("request peer relay");

    wait_peer_relay(&a_handle, &b_node).await;
    wait_peer_relay(&b_handle, &a_node).await;
    assert_eq!(
        a_handle.path_for_peer(&b_node).transport,
        PeerTransport::PeerRelay
    );

    let payload = b"encrypted wireguard packet via shared UDP peer relay".to_vec();
    a_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(b_node),
            data: payload.clone(),
        })
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(got.peer.as_bytes(), a_node.as_bytes());
    assert_eq!(got.data, payload);
    assert_eq!(a_handle.stats().direct_wg_sent, 0);
    wait_stats(
        &a_handle,
        |stats| stats.peer_relay_wg_sent > 0,
        "a should send WireGuard over peer relay",
    )
    .await;
    wait_stats(
        &b_handle,
        |stats| stats.peer_relay_wg_received > 0,
        "b should receive WireGuard over peer relay",
    )
    .await;
    wait_stats(
        &a_handle,
        |stats| stats.disco_derp_sent > 0,
        "a should send fallback disco traffic",
    )
    .await;
    wait_stats(
        &b_handle,
        |stats| stats.disco_derp_received > 0,
        "b should receive fallback disco traffic",
    )
    .await;
    assert_eq!(a_handle.stats().fallback_wg_sent, 0);
    assert_eq!(b_handle.stats().fallback_wg_sent, 0);

    let _ = shutdown_tx.send(());
    relay_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_relay_notification_retry_recovers_call_me_maybe_via_loss() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let (a_fallback, b_fallback, dropped) =
        fallback_pair_drop_first_call_me_maybe_via(a_node, b_node, b_disco.clone());

    let relay_key = DiscoPrivate::generate(&mut OsRng);
    let relay = udp_relay::SocketServer::bind(
        relay_key,
        udp_relay::SocketOptions::new("127.0.0.1:0".parse().unwrap())
            .with_expire_interval(Duration::from_millis(50)),
    )
    .await
    .unwrap();
    let relay_handle = relay.handle();
    let relay_endpoint = relay_handle
        .allocate_endpoint(a_disco.public(), b_disco.public())
        .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let relay_task = tokio::spawn(relay.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let (mut a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            a_node,
            a_disco,
        )
        .with_peer_direct_udp_enabled(false),
    )
    .await
    .unwrap();
    let (mut b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            b_node,
            b_disco,
        )
        .with_peer_direct_udp_enabled(false),
    )
    .await
    .unwrap();

    a_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node_with_endpoints(
            b_node,
            b_handle.shared.local_disco.public(),
            Vec::new(),
            B_IP,
        )])
        .unwrap();
    b_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node_with_endpoints(
            a_node,
            a_handle.shared.local_disco.public(),
            Vec::new(),
            A_IP,
        )])
        .unwrap();
    wait_peer_known(&a_handle, &b_node).await;
    wait_peer_known(&b_handle, &a_node).await;

    a_handle
        .request_peer_relay(b_node, relay_endpoint)
        .expect("request peer relay");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if a_handle.path_for_peer(&b_node).transport == PeerTransport::PeerRelay
                && b_handle.path_for_peer(&a_node).transport == PeerTransport::PeerRelay
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "UDP peer relay did not recover the lost notification; a_stats={:?} b_stats={:?}",
            a_handle.stats(),
            b_handle.stats()
        )
    });

    assert_eq!(
        dropped.load(Ordering::Relaxed),
        1,
        "fallback must drop exactly the first CallMeMaybeVia"
    );
    wait_stats(
        &b_handle,
        |stats| {
            stats.peer_relay_notifications_opened > 0
                && stats.peer_relay_notifications_unknown_peer == 0
                && stats.peer_relay_notifications_received > 0
                && stats.peer_relay_notification_actions > 0
        },
        "b should count the accepted peer relay notification",
    )
    .await;
    assert_eq!(b_handle.stats().peer_relay_notification_no_actions, 0);

    let request = b"peer relay request after lossy notification".to_vec();
    a_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(b_node),
            data: request.clone(),
        })
        .unwrap();
    let got_request =
        tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(got_request.data, request);

    let response = b"peer relay response after lossy notification".to_vec();
    b_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(a_node),
            data: response.clone(),
        })
        .unwrap();
    let got_response =
        tokio::time::timeout(Duration::from_secs(2), a_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(got_response.data, response);
    assert_eq!(a_handle.stats().fallback_wg_sent, 0);
    assert_eq!(b_handle.stats().fallback_wg_sent, 0);

    let _ = shutdown_tx.send(());
    relay_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_relay_bind_retry_recovers_bind_answer_loss() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);
    let (relay_endpoint, dropped_sources, shutdown_tx, relay_task) =
        bind_answer_loss_relay(a_disco.public(), b_disco.public()).await;

    let (mut a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            a_node,
            a_disco,
        )
        .with_peer_direct_udp_enabled(false),
    )
    .await
    .unwrap();
    let (mut b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            b_node,
            b_disco,
        )
        .with_peer_direct_udp_enabled(false),
    )
    .await
    .unwrap();

    a_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node_with_endpoints(
            b_node,
            b_handle.shared.local_disco.public(),
            Vec::new(),
            B_IP,
        )])
        .unwrap();
    b_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node_with_endpoints(
            a_node,
            a_handle.shared.local_disco.public(),
            Vec::new(),
            A_IP,
        )])
        .unwrap();
    wait_peer_known(&a_handle, &b_node).await;
    wait_peer_known(&b_handle, &a_node).await;

    a_handle
        .request_peer_relay(b_node, relay_endpoint)
        .expect("request peer relay");
    wait_peer_relay(&a_handle, &b_node).await;
    wait_peer_relay(&b_handle, &a_node).await;

    assert_eq!(
        a_handle.path_for_peer(&b_node).transport,
        PeerTransport::PeerRelay
    );
    assert_eq!(
        b_handle.path_for_peer(&a_node).transport,
        PeerTransport::PeerRelay
    );
    assert_eq!(
        dropped_sources.lock().unwrap().len(),
        2,
        "relay must drop the first bind answer from each client source"
    );

    let request = b"peer relay request after lossy bind".to_vec();
    a_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(b_node),
            data: request.clone(),
        })
        .unwrap();
    let got_request =
        tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(got_request.data, request);

    let response = b"peer relay response after lossy bind".to_vec();
    b_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(a_node),
            data: response.clone(),
        })
        .unwrap();
    let got_response =
        tokio::time::timeout(Duration::from_secs(2), a_transport.from_transport.recv())
            .await
            .unwrap()
            .unwrap();
    assert_eq!(got_response.data, response);
    wait_stats(
        &a_handle,
        |stats| stats.peer_relay_wg_sent > 0,
        "a should publish the peer-relay send counter",
    )
    .await;
    wait_stats(
        &b_handle,
        |stats| stats.peer_relay_wg_sent > 0,
        "b should publish the peer-relay send counter",
    )
    .await;
    assert_eq!(a_handle.stats().fallback_wg_sent, 0);
    assert_eq!(b_handle.stats().fallback_wg_sent, 0);

    let _ = shutdown_tx.send(());
    relay_task.await.unwrap();
}

#[test]
fn public_only_ignores_call_me_maybe_via_relays_on_private_addresses() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng).public();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Vec::new(),
        local_node,
        local_disco.clone(),
    )
    .with_public_peer_endpoints_only(true);
    let shared = shared_for_test(&options);
    shared.state.lock().unwrap().peers_by_node.insert(
        *peer_node.as_bytes(),
        peer_state(peer_node, peer_disco, "203.0.113.7:41641".parse().unwrap()),
    );
    let server_disco = DiscoPrivate::generate(&mut OsRng).public();
    let private = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9001,
        "10.0.0.8:41641".parse().unwrap(),
    );
    let mut state = shared.state.lock().unwrap();
    let actions = apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), private);
    assert!(actions.is_empty(), "a private relay address is never bound");
    assert!(state
        .peers_by_node
        .get(peer_node.as_bytes())
        .unwrap()
        .relay_endpoint
        .is_none());

    let public = udp_relay_endpoint(
        server_disco,
        local_disco.public(),
        peer_disco,
        9002,
        "203.0.113.35:41641".parse().unwrap(),
    );
    let actions = apply_call_me_maybe_via(&mut state, &shared, *peer_node.as_bytes(), public);
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        actions[0].message,
        Message::BindUDPRelayEndpoint(_)
    ));
}
