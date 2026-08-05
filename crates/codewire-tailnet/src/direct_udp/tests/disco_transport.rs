#[allow(clippy::wildcard_imports)]
use super::*;

#[tokio::test]
async fn derp_disco_ping_pong_uses_tailscale_magic_source() {
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
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            *peer_node.as_bytes(),
            peer_state(peer_node, peer_disco.public(), reserve_local_endpoint()),
        );
    }

    let tx_id = [7u8; 12];
    let message = Message::Ping(Ping {
        tx_id,
        node_key: Some(peer_node),
        padding: 0,
    });
    let packet = peer_disco
        .seal_to(&local_disco.public(), &message, &mut OsRng)
        .expect("seal DERP ping");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();

    handle_disco_packet(
        &shared,
        &socket,
        &fallback.to_transport,
        None,
        Some(derp_public_from_node(peer_node)),
        &packet,
    )
    .await;

    let got = tokio::time::timeout(Duration::from_secs(2), fallback_rx.recv())
        .await
        .unwrap()
        .expect("DERP Pong datagram");
    assert_eq!(got.peer.as_bytes(), peer_node.as_bytes());
    let opened = peer_disco.open(&got.data).expect("open DERP Pong");
    match opened.message {
        Message::Pong(pong) => {
            assert_eq!(pong.tx_id, tx_id);
            assert_eq!(pong.src, derp_magic_addr(1));
        }
        other => panic!("expected DERP Pong, got {other:?}"),
    }
}

#[test]
fn disco_peer_resolution_matches_magicsock_trust_rules() {
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let c_secret = StaticSecret::random_from_rng(OsRng);
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let c_node = NodePublic::from_raw(PublicKey::from(&c_secret).to_bytes());
    let shared_disco = DiscoPrivate::generate(&mut OsRng).public();
    let other_disco = DiscoPrivate::generate(&mut OsRng).public();
    let b_endpoint = reserve_local_endpoint();
    let c_endpoint = reserve_local_endpoint();
    let mut state = State::default();
    state.peers_by_node.insert(
        *b_node.as_bytes(),
        peer_state(b_node, shared_disco, b_endpoint),
    );
    state.peers_by_node.insert(
        *c_node.as_bytes(),
        peer_state(c_node, shared_disco, c_endpoint),
    );
    state
        .peers_by_disco
        .insert(*shared_disco.as_bytes(), DiscoPeerIndex::Ambiguous);

    let mut tx_id = [0u8; 12];
    OsRng.fill_bytes(&mut tx_id);
    let with_node_key = Message::Ping(Ping {
        tx_id,
        node_key: Some(b_node),
        padding: 0,
    });
    assert_eq!(
        peer_key_for_message(&state, shared_disco, &with_node_key, None),
        Some(*b_node.as_bytes()),
        "Ping NodeKey disambiguates only when the authenticated disco key matches"
    );
    assert_eq!(
        peer_key_for_message(&state, other_disco, &with_node_key, None),
        None,
        "Ping NodeKey alone is not trusted"
    );

    let without_node_key = Message::Ping(Ping {
        tx_id,
        node_key: None,
        padding: 0,
    });
    assert_eq!(
        peer_key_for_message(&state, shared_disco, &without_node_key, None),
        None,
        "ambiguous disco keys need DERP source, Ping NodeKey, or Pong TxID"
    );
    assert_eq!(
        peer_key_for_message(
            &state,
            shared_disco,
            &without_node_key,
            Some(&derp_public_from_node(c_node)),
        ),
        Some(*c_node.as_bytes()),
        "DERP source disambiguates when it matches the authenticated disco key"
    );

    state.pending_tx.insert(tx_id, *b_node.as_bytes());
    assert_eq!(
        peer_key_for_pong(&state, shared_disco, &tx_id),
        Some(*b_node.as_bytes()),
        "Pong TxID disambiguates shared disco keys"
    );
    assert_eq!(
        peer_key_for_pong(&state, other_disco, &tx_id),
        None,
        "Pong TxID does not let a different disco key claim a peer"
    );
}

#[tokio::test]
async fn direct_udp_rejects_ping_from_unowned_disco_key() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let attacker_disco = DiscoPrivate::generate(&mut OsRng);
    let a_endpoint = reserve_local_endpoint();
    let b_endpoint = reserve_local_endpoint();
    let (fallback, mut fallback_rx, _fallback_in_tx) = recording_fallback();

    let (a_transport, a_handle) = wrap_transport(
        fallback,
        Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
    )
    .await
    .unwrap();
    a_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node(b_node, b_disco.public(), b_endpoint, B_IP)])
        .unwrap();

    for _ in 0..100 {
        if a_handle.stats().disco_udp_sent > 0 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(
        a_handle.stats().disco_udp_sent > 0,
        "peer update should attempt disco before the spoof packet"
    );
    loop {
        match tokio::time::timeout(Duration::from_millis(10), fallback_rx.recv()).await {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("fallback transport closed during setup"),
            Err(_) => break,
        }
    }

    let attacker_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut tx_id = [0u8; 12];
    OsRng.fill_bytes(&mut tx_id);
    let spoofed = attacker_disco
        .seal_to(
            &a_disco.public(),
            &Message::Ping(Ping {
                tx_id,
                node_key: Some(b_node),
                padding: 0,
            }),
            &mut OsRng,
        )
        .unwrap();
    attacker_socket
        .send_to(&spoofed, a_handle.local_addr())
        .await
        .unwrap();
    sleep(Duration::from_millis(50)).await;

    assert!(
        !a_handle.has_verified_endpoint(&b_node),
        "unknown disco keys must not claim a peer's direct endpoint"
    );

    let payload = b"must stay on DERP fallback after spoofed ping".to_vec();
    a_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(b_node),
            data: payload.clone(),
        })
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), fallback_rx.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(got.peer.as_bytes(), b_node.as_bytes());
    assert_eq!(got.data, payload);
    assert_eq!(a_handle.stats().direct_wg_sent, 0);
    assert_eq!(a_handle.stats().fallback_wg_sent, 1);
}

#[tokio::test]
async fn call_me_maybe_matches_magicsock_derp_boundary() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let c_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let c_node = NodePublic::from_raw(PublicKey::from(&c_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let a_endpoint = reserve_local_endpoint();
    let b_endpoint = reserve_local_endpoint();
    let call_endpoint = reserve_local_endpoint();
    let options = Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone());
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
    let message = Message::CallMeMaybe(CallMeMaybe {
        endpoints: vec![call_endpoint],
    });
    let packet = b_disco
        .seal_to(&a_disco.public(), &message, &mut OsRng)
        .unwrap();

    handle_disco_packet(
        &shared,
        &socket,
        &fallback.to_transport,
        Some(b_endpoint),
        None,
        &packet,
    )
    .await;
    assert_eq!(
        shared.stats.snapshot().disco_udp_sent,
        0,
        "CallMeMaybe must be ignored when received over UDP"
    );

    handle_disco_packet(
        &shared,
        &socket,
        &fallback.to_transport,
        None,
        Some(derp_public_from_node(c_node)),
        &packet,
    )
    .await;
    assert_eq!(
        shared.stats.snapshot().disco_udp_sent,
        0,
        "CallMeMaybe must authenticate the DERP source node key"
    );

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
    let (n, _src) = tokio::time::timeout(Duration::from_secs(2), listen.recv_from(&mut got))
        .await
        .unwrap()
        .unwrap();
    let opened = b_disco.open(&got[..n]).unwrap();
    assert!(matches!(opened.message, Message::Ping(_)));
    assert_eq!(shared.stats.snapshot().disco_udp_sent, 1);

    assert!(
        tokio::time::timeout(Duration::from_millis(10), fallback_rx.recv())
            .await
            .is_err(),
        "CallMeMaybe handling should not emit DERP fallback datagrams"
    );
}
