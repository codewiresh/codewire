use codewire_tailnet::disco::DiscoPrivate;
use rand::rngs::OsRng;

use super::*;

#[tokio::test]
async fn relay_bind_endpoint_overrides_advertised_addr_ports() {
    let advertised = UDPRelayEndpoint {
        server_disco: DiscoPrivate::generate(&mut OsRng).public(),
        client_disco: [
            DiscoPrivate::generate(&mut OsRng).public(),
            DiscoPrivate::generate(&mut OsRng).public(),
        ],
        lamport_id: 1,
        vni: 42,
        bind_lifetime: Duration::from_secs(10),
        steady_state_lifetime: Duration::from_secs(60),
        addr_ports: vec!["203.0.113.35:41641".parse().unwrap()],
    };

    let bind = relay_bind_endpoint(&advertised, &["127.0.0.1:41641".into()])
        .await
        .unwrap();

    assert_eq!(bind.addr_ports, vec!["127.0.0.1:41641".parse().unwrap()]);
    assert_eq!(bind.vni, advertised.vni);
    assert_eq!(
        advertised.addr_ports,
        vec!["203.0.113.35:41641".parse().unwrap()]
    );
}

#[test]
fn peer_relay_allocation_tracker_recovers_without_a_peer_update() {
    let key = PeerRelayKey {
        peer: NodePublic::from_raw([0x11; 32]),
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![key],
        "the first observed peer starts one allocation"
    );
    assert!(
        tracker
            .begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing)
            .is_empty()
    );

    let failure = tracker.finish_failure(key);
    assert_eq!(failure.attempts, 1);
    assert_eq!(failure.failures, 1);
    assert!(
        tracker
            .begin_pending(
                now + PEER_RELAY_ALLOCATION_RETRY_DELAY - Duration::from_millis(1),
                |_| direct_udp::PeerRelayEndpointState::Missing
            )
            .is_empty(),
        "the retry cadence still suppresses rapid duplicates"
    );
    assert_eq!(
        tracker.begin_pending(
            now + PEER_RELAY_ALLOCATION_RETRY_DELAY + Duration::from_millis(1),
            |_| direct_udp::PeerRelayEndpointState::Missing,
        ),
        vec![key],
        "the failed first attempt retries without another peer snapshot"
    );
}

#[test]
fn peer_relay_allocation_tracker_preserves_unverified_relay_notification_retry() {
    let key = PeerRelayKey {
        peer: NodePublic::from_raw([0x11; 32]),
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![key]
    );
    let success = tracker.finish_success(key, now);
    assert_eq!(success.queued_count, 1);
    assert!(
        tracker
            .begin_pending(now + PEER_RELAY_ALLOCATION_RETRY_DELAY * 4, |_| {
                direct_udp::PeerRelayEndpointState::Negotiating
            })
            .is_empty(),
        "a fresh negotiating relay leaves bind and CallMeMaybe retry ownership to codewire-tailnet"
    );
}

#[test]
fn peer_relay_allocation_tracker_reallocates_after_endpoint_expiry() {
    let key = PeerRelayKey {
        peer: NodePublic::from_raw([0x11; 32]),
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![key]
    );
    tracker.finish_success(key, now);
    assert!(
        tracker
            .begin_pending(now + Duration::from_millis(100), |_| {
                direct_udp::PeerRelayEndpointState::Negotiating
            })
            .is_empty()
    );
    assert!(
        tracker
            .begin_pending(now + Duration::from_millis(200), |_| {
                direct_udp::PeerRelayEndpointState::Active
            })
            .is_empty()
    );
    assert_eq!(
        tracker.begin_pending(now + Duration::from_secs(2), |_| {
            direct_udp::PeerRelayEndpointState::Missing
        }),
        vec![key],
        "an observed relay that expires is reallocated without another peer snapshot"
    );
}

#[test]
fn peer_relay_allocation_tracker_retries_when_tailnet_never_registers_success() {
    let key = PeerRelayKey {
        peer: NodePublic::from_raw([0x11; 32]),
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![key]
    );
    tracker.finish_success(key, now);
    assert!(
        tracker
            .begin_pending(
                now + PEER_RELAY_REGISTRATION_GRACE - Duration::from_millis(1),
                |_| direct_udp::PeerRelayEndpointState::Missing
            )
            .is_empty()
    );
    assert_eq!(
        tracker.begin_pending(
            now + PEER_RELAY_REGISTRATION_GRACE + Duration::from_millis(1),
            |_| direct_udp::PeerRelayEndpointState::Missing,
        ),
        vec![key],
        "a successful HTTP response cannot leave an unregistered relay permanently queued"
    );
}

#[test]
fn peer_relay_allocation_tracker_preserves_in_flight_across_remove_readd() {
    let key = PeerRelayKey {
        peer: NodePublic::from_raw([0x11; 32]),
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![key]
    );
    tracker.replace_peers([]);
    assert_eq!(tracker.state().in_flight_count, 1);
    tracker.replace_peers([key]);
    assert!(
        tracker
            .begin_pending(now + Duration::from_secs(1), |_| {
                direct_udp::PeerRelayEndpointState::Missing
            })
            .is_empty(),
        "re-adding the same peer cannot duplicate its active allocation"
    );

    tracker.replace_peers([]);
    let success = tracker.finish_success(key, now + Duration::from_secs(1));
    assert_eq!(success.in_flight_count, 0);
    assert_eq!(
        success.queued_count, 0,
        "a completion for a peer that remains absent cannot resurrect queued state"
    );
}

#[test]
fn peer_relay_allocation_tracker_starts_fresh_allocation_after_disco_rotation() {
    let peer = NodePublic::from_raw([0x11; 32]);
    let old_key = PeerRelayKey {
        peer,
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let new_key = PeerRelayKey {
        peer,
        peer_disco: DiscoPublic::from_raw([0x33; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([old_key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![old_key]
    );
    tracker.finish_success(old_key, now);
    assert!(
        tracker
            .begin_pending(now + Duration::from_millis(100), |_| {
                direct_udp::PeerRelayEndpointState::Active
            })
            .is_empty()
    );

    tracker.replace_peers([new_key]);
    assert_eq!(
        tracker.begin_pending(now + Duration::from_millis(200), |key| {
            assert_eq!(key, new_key);
            direct_udp::PeerRelayEndpointState::Missing
        }),
        vec![new_key],
        "a new disco identity for the same node must start a new relay allocation"
    );
}

#[tokio::test]
async fn peer_relay_allocation_attempt_timeout_allows_tracker_retry() {
    let key = PeerRelayKey {
        peer: NodePublic::from_raw([0x11; 32]),
        peer_disco: DiscoPublic::from_raw([0x22; 32]),
    };
    let mut tracker = PeerRelayAllocationTracker::default();
    let now = Instant::now();

    tracker.replace_peers([key]);
    assert_eq!(
        tracker.begin_pending(now, |_| direct_udp::PeerRelayEndpointState::Missing),
        vec![key]
    );
    let error = bounded_peer_relay_allocation_attempt(
        Duration::from_millis(10),
        std::future::pending::<Result<()>>(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    tracker.finish_failure(key);
    assert_eq!(
        tracker.begin_pending(
            now + PEER_RELAY_ALLOCATION_RETRY_DELAY + Duration::from_millis(1),
            |_| direct_udp::PeerRelayEndpointState::Missing,
        ),
        vec![key],
        "the timed-out in-flight reservation is released for a bounded retry"
    );
}
