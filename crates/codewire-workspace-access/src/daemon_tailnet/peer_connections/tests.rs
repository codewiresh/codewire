use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use codewire_tailnet::node::DiscoPublic;
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::*;

const A6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x0a));
const A4: IpAddr = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10));
const B6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x0b));
const DAEMON6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x0d));

fn own() -> [Prefix; 1] {
    [Prefix::new(DAEMON6, 128)]
}

fn key(byte: u8) -> NodePublic {
    NodePublic::from_raw([byte; 32])
}

/// A peer as the coordinator announces it, under a fresh session id.
fn node(key: NodePublic, addresses: &[IpAddr]) -> Node {
    Node {
        id: Uuid::new_v4(),
        as_of: "2026-07-11T12:00:00Z".parse().unwrap(),
        key,
        disco_key: DiscoPublic::default(),
        preferred_derp: 1,
        derp_latency: None,
        endpoints: Vec::new(),
        addresses: addresses
            .iter()
            .map(|addr| Prefix::new(*addr, if addr.is_ipv4() { 32 } else { 128 }))
            .collect(),
    }
}

/// A connection from `peer` that stays open until it is closed, once it is
/// recorded.
async fn held(connections: &Arc<PeerConnections>, peer: IpAddr) -> JoinHandle<()> {
    let open = connections.len();
    let task = {
        let connections = connections.clone();
        tokio::spawn(async move {
            connections.serve(peer, std::future::pending()).await;
        })
    };
    while connections.len() == open && !task.is_finished() {
        tokio::task::yield_now().await;
    }
    task
}

/// Lets every connection task see the last applied set.
async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_removed_client_loses_its_connections_on_both_families_after_the_grace_and_only_it() {
    let connections = Arc::new(PeerConnections::default());
    connections.apply(
        &[node(key(0x0a), &[A6, A4]), node(key(0x0b), &[B6])],
        &own(),
    );
    let a6 = held(&connections, A6).await;
    let a4 = held(&connections, A4).await;
    let b6 = held(&connections, B6).await;

    connections.apply(&[node(key(0x0b), &[B6])], &own());
    tokio::time::sleep(ABSENT_GRACE - Duration::from_secs(1)).await;
    settle().await;
    assert!(!a6.is_finished() && !a4.is_finished(), "inside the grace");

    tokio::time::sleep(Duration::from_secs(2)).await;
    settle().await;
    assert!(a6.is_finished() && a4.is_finished(), "past the grace");
    assert!(!b6.is_finished(), "B is still a peer");
    assert_eq!(connections.len(), 1);
    b6.abort();
}

#[tokio::test(start_paused = true)]
async fn a_reconnect_whose_removal_comes_first_keeps_the_connection() {
    let connections = Arc::new(PeerConnections::default());
    connections.apply(&[node(key(0x0a), &[A6])], &own());
    let from_a = held(&connections, A6).await;

    // The old node's removal, then the same key under a new session.
    connections.apply(&[], &own());
    tokio::time::sleep(Duration::from_secs(5)).await;
    connections.apply(&[node(key(0x0a), &[A6])], &own());
    tokio::time::sleep(ABSENT_GRACE * 2).await;
    settle().await;

    assert!(!from_a.is_finished());
    from_a.abort();
}

#[tokio::test(start_paused = true)]
async fn a_peer_set_that_starts_empty_and_fills_keeps_every_connection_whose_peer_returns() {
    let connections = Arc::new(PeerConnections::default());
    connections.apply(&[node(key(0x0a), &[A6]), node(key(0x0b), &[B6])], &own());
    let from_a = held(&connections, A6).await;
    let from_b = held(&connections, B6).await;

    // The daemon's coordinator session starts again and replays its peers.
    connections.apply(&[], &own());
    tokio::time::sleep(Duration::from_secs(3)).await;
    connections.apply(&[node(key(0x0a), &[A6])], &own());
    tokio::time::sleep(Duration::from_secs(3)).await;
    connections.apply(&[node(key(0x0a), &[A6]), node(key(0x0b), &[B6])], &own());
    tokio::time::sleep(ABSENT_GRACE * 2).await;
    settle().await;

    assert!(!from_a.is_finished() && !from_b.is_finished());
    from_a.abort();
    from_b.abort();
}

#[tokio::test(start_paused = true)]
async fn an_address_another_key_holds_closes_the_connection_at_once() {
    let connections = Arc::new(PeerConnections::default());
    connections.apply(&[node(key(0x0a), &[A6])], &own());
    let from_a = held(&connections, A6).await;

    connections.apply(&[node(key(0x0c), &[A6])], &own());
    settle().await;

    assert!(from_a.is_finished());
    assert_eq!(connections.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_second_client_announcing_the_address_leaves_it_held_by_neither() {
    let connections = Arc::new(PeerConnections::default());
    connections.apply(&[node(key(0x0a), &[A6])], &own());
    let from_a = held(&connections, A6).await;

    connections.apply(&[node(key(0x0a), &[A6]), node(key(0x0c), &[A6])], &own());
    tokio::time::sleep(ABSENT_GRACE + Duration::from_secs(1)).await;
    settle().await;

    assert!(from_a.is_finished());
}

#[tokio::test]
async fn nothing_is_served_from_an_address_no_single_peer_holds() {
    let connections = PeerConnections::default();
    let mut served = false;
    connections.serve(A6, async { served = true }).await;
    assert!(!served, "no peer set applied yet");

    connections.apply(&[node(key(0x0a), &[A6]), node(key(0x0c), &[A6])], &own());
    connections.serve(A6, async { served = true }).await;
    assert!(!served, "two keys claim the address");
    assert_eq!(connections.len(), 0);
}

#[tokio::test]
async fn only_a_peers_own_host_address_is_held() {
    let connections = PeerConnections::default();
    let mut wide = node(key(0x0a), &[]);
    wide.addresses = vec![Prefix::new(A6, 120), Prefix::new(DAEMON6, 128)];
    connections.apply(&[wide], &own());
    let mut served = false;
    connections.serve(B6, async { served = true }).await;
    assert!(!served, "a broader prefix holds no address");
    connections.serve(DAEMON6, async { served = true }).await;
    assert!(!served, "the daemon's own address is no peer's");
}

#[tokio::test]
async fn a_connection_that_ends_by_itself_leaves_nothing_behind() {
    let connections = PeerConnections::default();
    connections.apply(&[node(key(0x0a), &[A6])], &own());
    let mut served = false;
    connections.serve(A6, async { served = true }).await;
    assert!(served);
    assert_eq!(connections.len(), 0);
}
