#[allow(clippy::wildcard_imports)]
use super::*;

#[test]
fn direct_candidate_probe_expires_and_identical_updates_do_not_restart_it() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng);
    let first_endpoint = reserve_local_endpoint();
    let changed_endpoint = reserve_local_endpoint();
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        local_disco,
    );
    let shared = shared_for_test(&options);

    let initial = apply_peer_update(
        &shared,
        vec![node(peer_node, peer_disco.public(), first_endpoint, B_IP)],
    );
    assert_eq!(initial.len(), 1);
    let Message::Ping(initial_ping) = &initial[0].message else {
        panic!("new direct candidate should be pinged immediately");
    };
    let initial_tx_id = initial_ping.tx_id;
    let expires_at = {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        let DirectProbeState::Active(probe) = &peer.direct_probe else {
            panic!("new direct candidate should have an active probe window");
        };
        assert_eq!(state.pending_tx.len(), 1);
        probe.expires_at
    };

    let identical_while_active = apply_peer_update(
        &shared,
        vec![node(peer_node, peer_disco.public(), first_endpoint, B_IP)],
    );
    assert!(identical_while_active.is_empty());
    {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        let DirectProbeState::Active(probe) = &peer.direct_probe else {
            panic!("identical update should preserve the active probe window");
        };
        assert_eq!(probe.expires_at, expires_at);
        assert_eq!(state.pending_tx.len(), 1);
    }

    let retry = retry_unverified_direct_candidates(&shared, expires_at - Duration::from_millis(1));
    assert_eq!(retry.len(), 1);
    let Message::Ping(retry_ping) = &retry[0].message else {
        panic!("unverified direct candidate should be pinged again");
    };
    assert_eq!(retry_ping.tx_id, initial_tx_id);

    assert!(retry_unverified_direct_candidates(&shared, expires_at).is_empty());
    {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
        assert!(matches!(peer.direct_probe, DirectProbeState::Exhausted));
        assert!(state.pending_tx.is_empty());
    }

    let identical = apply_peer_update(
        &shared,
        vec![node(peer_node, peer_disco.public(), first_endpoint, B_IP)],
    );
    assert!(identical.is_empty());
    assert!(matches!(
        shared
            .state
            .lock()
            .unwrap()
            .peers_by_node
            .get(peer_node.as_bytes())
            .unwrap()
            .direct_probe,
        DirectProbeState::Exhausted
    ));

    let changed = apply_peer_update(
        &shared,
        vec![node(peer_node, peer_disco.public(), changed_endpoint, B_IP)],
    );
    assert_eq!(changed.len(), 1);
    let state = shared.state.lock().unwrap();
    let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
    assert!(matches!(peer.direct_probe, DirectProbeState::Active(_)));
    assert_eq!(state.pending_tx.len(), 1);
}

#[tokio::test]
async fn direct_udp_advertises_stun_discovered_endpoint() {
    let secret = StaticSecret::random_from_rng(OsRng);
    let node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
    let disco = DiscoPrivate::generate(&mut OsRng);
    let mapped = "203.0.113.10:45678".parse::<SocketAddr>().unwrap();
    let stun_server = fake_stun_server(mapped).await;
    let (fallback, _out_rx, _in_tx) = recording_fallback();

    let (_transport, handle) = wrap_transport(
        fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            node_key,
            disco,
        )
        .with_stun_servers(vec![stun_server])
        .with_stun_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap();

    assert_eq!(handle.advertised_endpoints(), vec![AddrPort(mapped)]);
}

#[tokio::test]
async fn direct_udp_refreshes_stun_discovered_endpoints() {
    let secret = StaticSecret::random_from_rng(OsRng);
    let node_key = NodePublic::from_raw(PublicKey::from(&secret).to_bytes());
    let disco = DiscoPrivate::generate(&mut OsRng);
    let mapped_a = "203.0.113.10:45678".parse::<SocketAddr>().unwrap();
    let mapped_b = "203.0.113.10:45679".parse::<SocketAddr>().unwrap();
    let stun_server = fake_stun_server_sequence(vec![mapped_a, mapped_b]).await;
    let (fallback, _out_rx, _in_tx) = recording_fallback();

    let (mut transport, handle) = wrap_transport(
        fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            node_key,
            disco,
        )
        .with_stun_servers(vec![stun_server])
        .with_stun_timeout(Duration::from_secs(1))
        .with_stun_refresh_interval(Duration::from_millis(20)),
    )
    .await
    .unwrap();

    assert_eq!(handle.advertised_endpoints(), vec![AddrPort(mapped_a)]);
    let mut updates = transport.local_endpoint_updates.take().unwrap();
    let update = tokio::time::timeout(Duration::from_secs(2), updates.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(update.contains(&AddrPort(mapped_a)));
    assert!(update.contains(&AddrPort(mapped_b)));
}

#[tokio::test]
async fn disabled_peer_direct_udp_ignores_authenticated_call_me_maybe() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let a_endpoint = reserve_local_endpoint();
    let b_endpoint = reserve_local_endpoint();
    let call_endpoint = reserve_local_endpoint();
    let options = Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone())
        .with_peer_direct_udp_enabled(false);
    let shared = shared_arc_for_test(&options);
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *b_node.as_bytes(),
            peer_state(b_node, b_disco.public(), b_endpoint),
        );
        state.peers_by_disco.insert(
            *b_disco.public().as_bytes(),
            DiscoPeerIndex::Unique(*b_node.as_bytes()),
        );
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listen = UdpSocket::bind(call_endpoint).await.unwrap();
    let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();
    let packet = b_disco
        .seal_to(
            &a_disco.public(),
            &Message::CallMeMaybe(CallMeMaybe {
                endpoints: vec![call_endpoint],
            }),
            &mut OsRng,
        )
        .unwrap();

    handle_disco_packet(
        &shared,
        &socket,
        &fallback.to_transport,
        None,
        Some(derp_public_from_node(b_node)),
        &packet,
    )
    .await;

    let mut got = [0u8; UDP_PACKET_LIMIT];
    assert!(
        tokio::time::timeout(Duration::from_millis(25), listen.recv_from(&mut got))
            .await
            .is_err(),
        "disabled direct peer UDP must not ping CallMeMaybe candidates"
    );
    assert!(
        shared.state.lock().unwrap().pending_tx.is_empty(),
        "disabled direct peer UDP must not retain direct probe transactions"
    );
    assert_eq!(shared.stats.snapshot().disco_udp_sent, 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), fallback_rx.recv())
            .await
            .is_err(),
        "ignored CallMeMaybe must not emit fallback traffic"
    );
}

#[test]
fn disabled_peer_direct_udp_drops_node_and_local_direct_candidates() {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let local_disco = DiscoPrivate::generate(&mut OsRng);
    let peer_disco = DiscoPrivate::generate(&mut OsRng);
    let local_endpoint = reserve_local_endpoint();
    let peer_endpoint = reserve_local_endpoint();
    let options = Options::new(
        local_endpoint,
        vec![local_endpoint],
        local_node,
        local_disco,
    )
    .with_peer_direct_udp_enabled(false);
    let shared = shared_for_test(&options);

    let actions = apply_peer_update(
        &shared,
        vec![node(peer_node, peer_disco.public(), peer_endpoint, B_IP)],
    );

    assert!(actions.is_empty());
    assert!(shared.advertised_socket_addrs().is_empty());
    let state = shared.state.lock().unwrap();
    let peer = state.peers_by_node.get(peer_node.as_bytes()).unwrap();
    assert!(peer.endpoints.is_empty());
    assert!(peer.verified_endpoint.is_none());
}

#[test]
fn call_me_maybe_endpoint_filter_matches_magicsock() {
    assert!(is_usable_direct_endpoint(
        "127.0.0.1:41641".parse().unwrap()
    ));
    assert!(is_usable_direct_endpoint(
        "[2001:db8::1]:41641".parse().unwrap()
    ));
    assert!(!is_usable_direct_endpoint("0.0.0.0:41641".parse().unwrap()));
    assert!(!is_usable_direct_endpoint("[::]:41641".parse().unwrap()));
    assert!(!is_usable_direct_endpoint(
        "[fe80::1]:41641".parse().unwrap()
    ));
}
