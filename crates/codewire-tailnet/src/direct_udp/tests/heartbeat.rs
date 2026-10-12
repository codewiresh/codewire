//! Direct path upkeep: heartbeats renew a verified endpoint while WireGuard
//! flows, and a lapsed endpoint is probed again instead of leaving the peer
//! on DERP.
//!
//! The state tests drive the module's injected clock past the endpoint TTL;
//! the socket tests prove the same behavior over real UDP and disco.

#[allow(clippy::wildcard_imports)]
use super::*;

const TICK: Duration = PEER_RELAY_BIND_RETRY_INTERVAL;
const ADVERTISED: &str = "203.0.113.7:41641";

/// One known peer advertising [`ADVERTISED`], with `verified` verified at
/// `at`.
fn verified_peer(verified: SocketAddr, at: Instant) -> (Shared, [u8; 32]) {
    let local_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let local_node = NodePublic::from_raw(PublicKey::from(&local_secret).to_bytes());
    let peer_node = NodePublic::from_raw(PublicKey::from(&peer_secret).to_bytes());
    let options = Options::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Vec::new(),
        local_node,
        DiscoPrivate::generate(&mut OsRng),
    );
    let shared = shared_for_test(&options);
    let peer_key = *peer_node.as_bytes();
    {
        let mut state = shared.state.lock().unwrap();
        state.peers_by_node.insert(
            peer_key,
            peer_state(
                peer_node,
                DiscoPrivate::generate(&mut OsRng).public(),
                ADVERTISED.parse().unwrap(),
            ),
        );
        state.verify_endpoint(peer_key, verified, at);
    }
    (shared, peer_key)
}

/// The UDP targets of `actions`, which must all be disco pings.
fn pinged(actions: &[DiscoAction]) -> Vec<SocketAddr> {
    actions
        .iter()
        .map(|action| {
            assert!(matches!(action.message, Message::Ping(_)));
            match action.target {
                DiscoTarget::Udp(addr) => addr,
                _ => panic!("direct path upkeep pings over UDP"),
            }
        })
        .collect()
}

/// Answer each ping in `actions` from `from`, as the peer would, at `at`.
fn answer_from<'a>(
    shared: &Shared,
    peer_key: [u8; 32],
    actions: impl IntoIterator<Item = &'a DiscoAction>,
    from: SocketAddr,
    at: Instant,
) {
    let mut state = shared.state.lock().unwrap();
    for action in actions {
        let Message::Ping(ping) = &action.message else {
            panic!("direct path upkeep sends pings");
        };
        state.accept_pong(peer_key, &ping.tx_id, Some(from), at);
    }
}

fn sends_direct(shared: &Shared, peer_key: [u8; 32], at: Instant) -> Option<SocketAddr> {
    match active_path_for_peer(shared, &peer_key, at) {
        Some(ActivePeerPath::Direct(addr)) => Some(addr),
        _ => None,
    }
}

#[test]
fn heartbeats_keep_a_busy_direct_path_past_the_ttl() {
    let endpoint: SocketAddr = ADVERTISED.parse().unwrap();
    let t0 = Instant::now();
    let (shared, peer_key) = verified_peer(endpoint, t0);
    let busy_for = VERIFIED_ENDPOINT_TTL * 3;

    let mut heartbeats = Vec::new();
    let mut at = t0;
    while at <= t0 + busy_for {
        assert_eq!(
            sends_direct(&shared, peer_key, at),
            Some(endpoint),
            "WireGuard left the direct path {:?} after verification",
            at - t0
        );
        let actions = maintain_direct_paths(&shared, at);
        for target in pinged(&actions) {
            assert_eq!(target, endpoint, "a heartbeat pings the verified endpoint");
            heartbeats.push(at - t0);
        }
        answer_from(&shared, peer_key, &actions, endpoint, at);
        at += TICK;
    }

    let expected = (1..=9)
        .map(|n| DIRECT_HEARTBEAT_INTERVAL * n)
        .collect::<Vec<_>>();
    assert_eq!(heartbeats, expected, "one heartbeat per interval");
    assert!(
        shared.state.lock().unwrap().pending_tx.is_empty(),
        "answered heartbeats leave no transactions behind"
    );
}

#[test]
fn an_idle_peer_gets_no_heartbeat_and_no_probe_until_wireguard_resumes() {
    let endpoint: SocketAddr = ADVERTISED.parse().unwrap();
    let t0 = Instant::now();
    let (shared, peer_key) = verified_peer(endpoint, t0);
    assert_eq!(sends_direct(&shared, peer_key, t0), Some(endpoint));

    // One datagram, then silence: heartbeats stop once the peer is idle,
    // and the endpoint lapses without a probe.
    let mut heartbeats = 0;
    let mut at = t0;
    let quiet_until = t0 + DIRECT_SESSION_ACTIVE_TIMEOUT + VERIFIED_ENDPOINT_TTL * 2;
    while at <= quiet_until {
        let actions = maintain_direct_paths(&shared, at);
        heartbeats += pinged(&actions).len();
        answer_from(&shared, peer_key, &actions, endpoint, at);
        at += TICK;
    }
    assert_eq!(heartbeats, 4, "heartbeats only while the peer is in use");
    {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(&peer_key).unwrap();
        assert_eq!(peer.active_verified_endpoint(at), None);
        assert!(matches!(peer.direct_probe, DirectProbeState::Inactive));
        assert!(state.pending_tx.is_empty());
    }

    // WireGuard resumes: this datagram rides DERP, and upkeep probes again.
    assert!(active_path_for_peer(&shared, &peer_key, at).is_none());
    let probe = maintain_direct_paths(&shared, at);
    assert_eq!(pinged(&probe), [endpoint]);
    answer_from(&shared, peer_key, &probe, endpoint, at);
    assert_eq!(sends_direct(&shared, peer_key, at), Some(endpoint));
}

#[test]
fn a_lapsed_direct_path_probes_again_and_recovers_when_the_pong_returns() {
    // A NAT mapping learned from the peer's own ping, never advertised.
    let learned: SocketAddr = "198.51.100.9:62000".parse().unwrap();
    let advertised: SocketAddr = ADVERTISED.parse().unwrap();
    let t0 = Instant::now();
    let (shared, peer_key) = verified_peer(learned, t0);

    // WireGuard flows, but every heartbeat pong is lost.
    let mut lost = 0;
    let mut at = t0;
    while at <= t0 + VERIFIED_ENDPOINT_TTL {
        assert_eq!(sends_direct(&shared, peer_key, at), Some(learned));
        lost += pinged(&maintain_direct_paths(&shared, at)).len();
        at += TICK;
    }
    assert_eq!(lost, 3, "a heartbeat at 10, 20 and 30 s");

    // Lapsed: WireGuard falls back to DERP while upkeep probes the
    // advertised candidate and the lapsed address.
    assert!(active_path_for_peer(&shared, &peer_key, at).is_none());
    let probe = maintain_direct_paths(&shared, at);
    let mut targets = pinged(&probe);
    targets.sort_unstable();
    let mut expected = vec![advertised, learned];
    expected.sort_unstable();
    assert_eq!(targets, expected);
    {
        let state = shared.state.lock().unwrap();
        let peer = state.peers_by_node.get(&peer_key).unwrap();
        assert!(matches!(peer.direct_probe, DirectProbeState::Active(_)));
        assert!(peer.direct_heartbeat.is_none());
        assert_eq!(
            state.pending_tx.len(),
            2,
            "lost heartbeats are retired; only the probe is pending"
        );
    }

    // Still probing a tick later: DERP carries WireGuard, pings repeat.
    at += TICK;
    assert!(active_path_for_peer(&shared, &peer_key, at).is_none());
    assert_eq!(retry_unverified_direct_candidates(&shared, at).len(), 2);
    assert!(maintain_direct_paths(&shared, at).is_empty());

    // The lapsed address answers: direct again, and the probe is retired.
    let to_learned = probe
        .iter()
        .filter(|action| matches!(action.target, DiscoTarget::Udp(addr) if addr == learned));
    answer_from(&shared, peer_key, to_learned, learned, at);
    assert_eq!(sends_direct(&shared, peer_key, at), Some(learned));
    let state = shared.state.lock().unwrap();
    let peer = state.peers_by_node.get(&peer_key).unwrap();
    assert!(matches!(peer.direct_probe, DirectProbeState::Inactive));
    assert!(state.pending_tx.is_empty());
}

/// Two transports on loopback with direct UDP verified both ways.
struct VerifiedPair {
    a: Transport,
    a_handle: Handle,
    b: Transport,
    b_handle: Handle,
    a_node: NodePublic,
    b_node: NodePublic,
}

impl VerifiedPair {
    async fn new() -> Self {
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
        let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
        let a_disco = DiscoPrivate::generate(&mut OsRng);
        let b_disco = DiscoPrivate::generate(&mut OsRng);
        let a_endpoint = reserve_local_endpoint();
        let b_endpoint = reserve_local_endpoint();
        let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);
        let (a, a_handle) = wrap_transport(
            a_fallback,
            Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
        )
        .await
        .unwrap();
        let (b, b_handle) = wrap_transport(
            b_fallback,
            Options::new(b_endpoint, vec![b_endpoint], b_node, b_disco.clone()),
        )
        .await
        .unwrap();
        a.peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node(b_node, b_disco.public(), b_endpoint, B_IP)])
            .unwrap();
        b.peer_updates
            .as_ref()
            .unwrap()
            .send(vec![node(a_node, a_disco.public(), a_endpoint, A_IP)])
            .unwrap();
        wait_verified(&a_handle, &b_node).await;
        wait_verified(&b_handle, &a_node).await;
        Self {
            a,
            a_handle,
            b,
            b_handle,
            a_node,
            b_node,
        }
    }

    /// Send WireGuard from a to b and wait for it to arrive.
    async fn a_sends(&mut self, payload: &[u8]) {
        self.a
            .to_transport
            .send(WgDatagram {
                peer: derp_public_from_node(self.b_node),
                data: payload.to_vec(),
            })
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), self.b.from_transport.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.peer.as_bytes(), self.a_node.as_bytes());
        assert_eq!(got.data, payload);
    }
}

#[tokio::test]
async fn a_heartbeat_renews_a_busy_direct_path_over_udp() {
    let mut pair = VerifiedPair::new().await;
    pair.a_sends(b"wireguard keeps flowing").await;
    let before = pair.a_handle.stats();

    // Old enough for a heartbeat, well inside the TTL.
    pair.a_handle.age_verified_endpoint_for_test(
        &pair.b_node,
        DIRECT_HEARTBEAT_INTERVAL + Duration::from_secs(1),
    );
    let mut renewed = false;
    for _ in 0..500 {
        assert_eq!(
            pair.a_handle.path_for_peer(&pair.b_node).transport,
            PeerTransport::DirectUdp
        );
        let age = pair
            .a_handle
            .verified_endpoint_age_for_test(&pair.b_node)
            .unwrap();
        if age < DIRECT_HEARTBEAT_INTERVAL {
            renewed = true;
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(renewed, "no heartbeat pong renewed the endpoint");

    let after = pair.a_handle.stats();
    assert!(after.disco_udp_sent > before.disco_udp_sent, "{after:?}");
    assert!(
        after.disco_udp_received > before.disco_udp_received,
        "{after:?}"
    );
    pair.a_sends(b"still direct").await;
    let after = pair.a_handle.stats();
    assert_eq!(after.direct_wg_sent, before.direct_wg_sent + 1);
    assert_eq!(after.fallback_wg_sent, 0);
}

#[tokio::test]
async fn a_lapsed_direct_path_recovers_over_udp_without_a_peer_update() {
    let mut pair = VerifiedPair::new().await;
    pair.a_sends(b"direct before the lapse").await;
    let before = pair.a_handle.stats();
    assert_eq!(before.direct_wg_sent, 1);

    pair.a_handle
        .expire_verified_endpoint_for_test(&pair.b_node);
    assert_eq!(
        pair.a_handle.path_for_peer(&pair.b_node).transport,
        PeerTransport::DerpRelay
    );
    // b is idle and sends nothing; only a's new probe can restore direct.
    wait_verified(&pair.a_handle, &pair.b_node).await;
    let recovered = pair.a_handle.stats();
    assert!(
        recovered.disco_udp_sent > before.disco_udp_sent,
        "{recovered:?}"
    );
    assert_eq!(pair.b_handle.stats().direct_wg_sent, 0);

    pair.a_sends(b"direct after the probe").await;
    let after = pair.a_handle.stats();
    assert_eq!(after.direct_wg_sent, recovered.direct_wg_sent + 1);
    assert_eq!(after.fallback_wg_sent, recovered.fallback_wg_sent);
}
