#[allow(clippy::wildcard_imports)]
use super::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::conn::{Conn, Options as ConnOptions, PeerTransport, Transport, WgDatagram};
use crate::disco::{
    AllocateUDPRelayEndpointRequest, CallMeMaybe, CallMeMaybeVia, Message, Ping, UDPRelayEndpoint,
};
use crate::node::{DiscoPublic, Node, NodePublic, Prefix};
use crate::udp_relay::{self, RelayPacket};

#[allow(clippy::wildcard_imports)]
use super::disco_transport::*;
#[allow(clippy::wildcard_imports)]
use super::discovery::*;
#[allow(clippy::wildcard_imports)]
use super::peer_relay::*;
#[allow(clippy::wildcard_imports)]
use super::state::*;

#[path = "tests/disco_transport.rs"]
mod disco_transport;
#[path = "tests/discovery.rs"]
mod discovery;
#[path = "tests/peer_relay.rs"]
mod peer_relay;

#[test]
fn direct_udp_module_dependencies_are_explicit_and_acyclic() {
    let facade = include_str!("mod.rs");
    let state = include_str!("state.rs");
    let discovery = include_str!("discovery.rs");
    let disco_transport = include_str!("disco_transport.rs");
    let peer_relay = include_str!("peer_relay.rs");
    let runtime = include_str!("runtime.rs");

    for (name, source) in [
        ("state", state),
        ("discovery", discovery),
        ("disco_transport", disco_transport),
        ("peer_relay", peer_relay),
        ("runtime", runtime),
    ] {
        assert!(
            !source.contains("use super::*;"),
            "{name} must declare its dependencies explicitly"
        );
    }

    for child in [
        "state",
        "discovery",
        "disco_transport",
        "peer_relay",
        "runtime",
    ] {
        assert!(
            !facade.contains(&format!("use {child}::*;")),
            "the facade must not hide {child} dependencies behind a glob"
        );
    }

    for forbidden in ["discovery", "disco_transport", "peer_relay", "runtime"] {
        assert!(!state.contains(&format!("super::{forbidden}")));
    }
    for forbidden in ["disco_transport", "runtime"] {
        assert!(!discovery.contains(&format!("super::{forbidden}")));
    }
    for forbidden in ["discovery", "runtime"] {
        assert!(!disco_transport.contains(&format!("super::{forbidden}")));
    }
    for forbidden in ["discovery", "disco_transport", "runtime"] {
        assert!(!peer_relay.contains(&format!("super::{forbidden}")));
    }
}

const A_IP: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000a);
const B_IP: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000b);

fn reserve_local_endpoint() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn fallback_pair(a_node: NodePublic, b_node: NodePublic) -> (Transport, Transport) {
    fallback_pair_filtering_a_to_b(a_node, b_node, |_| true)
}

fn fallback_pair_filtering_a_to_b(
    a_node: NodePublic,
    b_node: NodePublic,
    mut should_forward: impl FnMut(&WgDatagram) -> bool + Send + 'static,
) -> (Transport, Transport) {
    let (a_out_tx, mut a_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (b_out_tx, mut b_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<WgDatagram>();

    tokio::spawn(async move {
        while let Some(dg) = a_out_rx.recv().await {
            if !should_forward(&dg) {
                continue;
            }
            let _ = b_in_tx.send(WgDatagram {
                peer: derp_public_from_node(a_node),
                data: dg.data,
            });
        }
    });
    tokio::spawn(async move {
        while let Some(dg) = b_out_rx.recv().await {
            let _ = a_in_tx.send(WgDatagram {
                peer: derp_public_from_node(b_node),
                data: dg.data,
            });
        }
    });

    (
        Transport {
            to_transport: a_out_tx,
            from_transport: a_in_rx,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: None,
        },
        Transport {
            to_transport: b_out_tx,
            from_transport: b_in_rx,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: None,
        },
    )
}

fn fallback_pair_drop_first_call_me_maybe_via(
    a_node: NodePublic,
    b_node: NodePublic,
    b_disco: DiscoPrivate,
) -> (Transport, Transport, Arc<AtomicU64>) {
    let dropped = Arc::new(AtomicU64::new(0));
    let task_dropped = dropped.clone();
    let pair = fallback_pair_filtering_a_to_b(a_node, b_node, move |dg| {
        let is_call_me_maybe_via = b_disco
            .open(&dg.data)
            .map(|opened| matches!(opened.message, Message::CallMeMaybeVia(_)))
            .unwrap_or(false);
        !is_call_me_maybe_via
            || task_dropped
                .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
    });
    (pair.0, pair.1, dropped)
}

fn shared_for_test(options: &Options) -> Shared {
    let (allocation_tx, _allocation_rx) = mpsc::unbounded_channel();
    Shared::new(options, allocation_tx)
}

fn shared_arc_for_test(options: &Options) -> Arc<Shared> {
    Arc::new(shared_for_test(options))
}

fn recording_fallback() -> (
    Transport,
    mpsc::UnboundedReceiver<WgDatagram>,
    mpsc::UnboundedSender<WgDatagram>,
) {
    let (out_tx, out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    (
        Transport {
            to_transport: out_tx,
            from_transport: in_rx,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: None,
        },
        out_rx,
        in_tx,
    )
}

async fn fake_stun_server(mapped: SocketAddr) -> SocketAddr {
    fake_stun_server_sequence(vec![mapped]).await
}

async fn fake_stun_server_sequence(mapped: Vec<SocketAddr>) -> SocketAddr {
    const BINDING_SUCCESS: u16 = 0x0101;
    const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
    const MAGIC_COOKIE: u32 = 0x2112_A442;
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let mut mapped = mapped.into_iter();
        let mut last = None;
        let mut buf = [0u8; 1500];
        loop {
            let Ok((_, peer)) = server.recv_from(&mut buf).await else {
                return;
            };
            let endpoint = match mapped.next() {
                Some(endpoint) => {
                    last = Some(endpoint);
                    endpoint
                }
                None => match last {
                    Some(endpoint) => endpoint,
                    None => return,
                },
            };
            let mut tx_id = [0u8; 12];
            tx_id.copy_from_slice(&buf[8..20]);

            let mut attr = Vec::new();
            attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            match endpoint {
                SocketAddr::V4(addr) => {
                    attr.extend_from_slice(&(8u16).to_be_bytes());
                    attr.push(0);
                    attr.push(0x01);
                    attr.extend_from_slice(
                        &(addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes(),
                    );
                    let cookie = MAGIC_COOKIE.to_be_bytes();
                    let ip = addr.ip().octets();
                    attr.extend(ip.iter().zip(cookie).map(|(a, b)| a ^ b));
                }
                SocketAddr::V6(_) => unreachable!("test uses IPv4 mapped address"),
            }

            let mut packet = Vec::new();
            packet.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
            packet.extend_from_slice(&(attr.len() as u16).to_be_bytes());
            packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            packet.extend_from_slice(&tx_id);
            packet.extend_from_slice(&attr);
            server.send_to(&packet, peer).await.unwrap();
        }
    });
    server_addr
}

async fn bind_answer_loss_relay(
    disco_a: DiscoPublic,
    disco_b: DiscoPublic,
) -> (
    UDPRelayEndpoint,
    Arc<Mutex<HashSet<SocketAddr>>>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = socket.local_addr().unwrap();
    let relay_disco = DiscoPrivate::generate(&mut OsRng);
    let relay = Arc::new(Mutex::new(udp_relay::Server::new(
        relay_disco.clone(),
        vec![relay_addr],
    )));
    let endpoint = relay
        .lock()
        .unwrap()
        .allocate_endpoint(disco_a, disco_b)
        .unwrap();
    let dropped_sources = Arc::new(Mutex::new(HashSet::new()));
    let task_dropped_sources = dropped_sources.clone();
    let task_relay = relay.clone();
    let mut control_counts = HashMap::<SocketAddr, usize>::new();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_PACKET_LIMIT];
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => return,
                received = socket.recv_from(&mut buf) => {
                    let Ok((n, source)) = received else { return; };
                    if let Ok(RelayPacket::Control { payload, .. }) =
                        udp_relay::decode_packet(&buf[..n])
                    {
                        let count = control_counts.entry(source).or_default();
                        *count += 1;
                        if *count == 2 {
                            let opened = relay_disco.open(payload).unwrap();
                            assert!(matches!(
                                opened.message,
                                Message::BindUDPRelayEndpointAnswer(_)
                            ));
                            task_dropped_sources.lock().unwrap().insert(source);
                            continue;
                        }
                    }
                    let output = task_relay
                        .lock()
                        .unwrap()
                        .handle_packet(source, &buf[..n])
                        .unwrap();
                    if let Some(output) = output {
                        socket.send_to(&output.packet, output.to).await.unwrap();
                    }
                }
            }
        }
    });
    (endpoint, dropped_sources, shutdown_tx, task)
}

fn node(
    node_key: NodePublic,
    disco_key: DiscoPublic,
    endpoint: SocketAddr,
    ip: std::net::Ipv6Addr,
) -> Node {
    node_with_endpoints(node_key, disco_key, vec![endpoint], ip)
}

fn node_with_endpoints(
    node_key: NodePublic,
    disco_key: DiscoPublic,
    endpoints: Vec<SocketAddr>,
    ip: std::net::Ipv6Addr,
) -> Node {
    Node {
        id: Uuid::new_v4(),
        as_of: chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        key: node_key,
        disco_key,
        preferred_derp: 1,
        derp_latency: None,
        endpoints: endpoints.into_iter().map(AddrPort).collect(),
        addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
    }
}

fn peer_state(node_key: NodePublic, disco_key: DiscoPublic, endpoint: SocketAddr) -> PeerState {
    PeerState {
        node_key,
        derp_key: derp_public_from_node(node_key),
        disco_key,
        endpoints: vec![endpoint],
        verified_endpoint: None,
        direct_probe: DirectProbeState::Inactive,
        relay_endpoint: None,
        preferred_derp: 1,
    }
}

fn udp_relay_endpoint(
    server_disco: DiscoPublic,
    local_disco: DiscoPublic,
    peer_disco: DiscoPublic,
    vni: u32,
    addr: SocketAddr,
) -> UDPRelayEndpoint {
    UDPRelayEndpoint {
        server_disco,
        client_disco: [local_disco, peer_disco],
        lamport_id: vni as u64,
        vni,
        bind_lifetime: Duration::from_secs(5),
        steady_state_lifetime: Duration::from_secs(30),
        addr_ports: vec![addr],
    }
}

fn peer_relay_retry_fixture() -> (Shared, NodePublic) {
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
    shared.state.lock().unwrap().peers_by_node.insert(
        *peer_node.as_bytes(),
        peer_state(peer_node, peer_disco, reserve_local_endpoint()),
    );
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
    assert_eq!(actions.len(), 2);
    (shared, peer_node)
}

fn retry_call_me_maybe_via_endpoint(shared: &Shared, peer_node: &NodePublic) -> UDPRelayEndpoint {
    shared
        .state
        .lock()
        .unwrap()
        .peers_by_node
        .get(peer_node.as_bytes())
        .unwrap()
        .relay_endpoint
        .as_ref()
        .unwrap()
        .retry_call_me_maybe_via
        .clone()
        .unwrap()
}

fn conn_options(
    secret: &StaticSecret,
    disco: DiscoPrivate,
    ip: std::net::Ipv6Addr,
    endpoints: Vec<AddrPort>,
) -> ConnOptions {
    ConnOptions {
        id: Uuid::new_v4(),
        addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
        endpoints,
        private_key: Some(secret.clone()),
        disco_private: Some(disco),
    }
}

async fn wait_verified(handle: &Handle, peer: &NodePublic) {
    for _ in 0..500 {
        if handle.has_verified_endpoint(peer) {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("direct UDP endpoint was not verified for peer");
}

async fn wait_peer_known(handle: &Handle, peer: &NodePublic) {
    for _ in 0..500 {
        if handle.path_for_peer(peer).transport != PeerTransport::Unknown {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("peer metadata was not applied before relay request");
}

async fn wait_peer_relay(handle: &Handle, peer: &NodePublic) {
    for _ in 0..500 {
        if handle.path_for_peer(peer).transport == PeerTransport::PeerRelay {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("UDP peer relay endpoint was not bound for peer");
}

async fn wait_stats(handle: &Handle, predicate: impl Fn(&Stats) -> bool, message: &str) {
    for _ in 0..500 {
        let stats = handle.stats();
        if predicate(&stats) {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("{message}; final stats: {:?}", handle.stats());
}

#[tokio::test]
async fn direct_udp_recovers_when_first_ping_precedes_receiver_peer_state() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

    let (a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            a_node,
            a_disco.clone(),
        ),
    )
    .await
    .unwrap();
    let (b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            b_node,
            b_disco.clone(),
        ),
    )
    .await
    .unwrap();

    a_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node(
            b_node,
            b_disco.public(),
            b_handle.local_addr(),
            B_IP,
        )])
        .unwrap();

    wait_stats(
        &b_handle,
        |stats| stats.disco_udp_received > 0,
        "b should receive the first ping before it knows a",
    )
    .await;
    assert!(!b_handle.has_verified_endpoint(&a_node));
    let received_before_peer_state = b_handle.stats().disco_udp_received;

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

    wait_verified(&a_handle, &b_node).await;
    wait_verified(&b_handle, &a_node).await;
    assert!(
        b_handle.stats().disco_udp_received > received_before_peer_state,
        "a scheduled retry should reach b after b applies peer state"
    );
    assert!(a_handle.stats().disco_udp_sent >= 2);
}

#[tokio::test]
async fn direct_udp_verifies_endpoint_before_sending_wg() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let a_endpoint = reserve_local_endpoint();
    let b_endpoint = reserve_local_endpoint();
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

    let (a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
    )
    .await
    .unwrap();
    let (mut b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(b_endpoint, vec![b_endpoint], b_node, b_disco.clone()),
    )
    .await
    .unwrap();

    a_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node(b_node, b_disco.public(), b_endpoint, B_IP)])
        .unwrap();
    b_transport
        .peer_updates
        .as_ref()
        .unwrap()
        .send(vec![node(a_node, a_disco.public(), a_endpoint, A_IP)])
        .unwrap();

    for _ in 0..100 {
        if a_handle.has_verified_endpoint(&b_node) && b_handle.has_verified_endpoint(&a_node) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(a_handle.has_verified_endpoint(&b_node));
    assert!(b_handle.has_verified_endpoint(&a_node));

    let payload = b"encrypted wireguard packet".to_vec();
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
    assert!(a_handle.stats().direct_wg_sent > 0);
    assert!(b_handle.stats().direct_wg_received > 0);
    assert_eq!(a_handle.stats().fallback_wg_sent, 0);

    a_handle.expire_verified_endpoint_for_test(&b_node);
    let fallback_payload = b"fallback after endpoint expiry".to_vec();
    a_transport
        .to_transport
        .send(WgDatagram {
            peer: derp_public_from_node(b_node),
            data: fallback_payload.clone(),
        })
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), b_transport.from_transport.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.peer.as_bytes(), a_node.as_bytes());
    assert_eq!(got.data, fallback_payload);
    assert_eq!(a_handle.stats().fallback_wg_sent, 1);
}

#[tokio::test]
async fn conn_tunnel_uses_verified_direct_udp_path() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let a_endpoint = reserve_local_endpoint();
    let b_endpoint = reserve_local_endpoint();
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

    let (a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(a_endpoint, vec![a_endpoint], a_node, a_disco.clone()),
    )
    .await
    .unwrap();
    let (b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(b_endpoint, vec![b_endpoint], b_node, b_disco.clone()),
    )
    .await
    .unwrap();

    let a = Conn::new(
        conn_options(
            &a_secret,
            a_disco.clone(),
            A_IP,
            a_handle.advertised_endpoints(),
        ),
        a_transport,
    )
    .unwrap();
    let b = Conn::new(
        conn_options(
            &b_secret,
            b_disco.clone(),
            B_IP,
            b_handle.advertised_endpoints(),
        ),
        b_transport,
    )
    .unwrap();

    let b_peer = node(b_node, b_disco.public(), b_endpoint, B_IP);
    let a_peer = node(a_node, a_disco.public(), a_endpoint, A_IP);
    a.update_peers(std::slice::from_ref(&b_peer)).unwrap();
    b.update_peers(std::slice::from_ref(&a_peer)).unwrap();
    wait_verified(&a_handle, &b_node).await;
    wait_verified(&b_handle, &a_node).await;
    assert_eq!(
        a.probe_peer_path(&b_peer).unwrap().transport,
        PeerTransport::DirectUdp
    );

    let mut listener = a.listen("tcp", ":9022").await.unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let dst = SocketAddr::new(IpAddr::V6(A_IP), 9022);
    let mut b_stream = tokio::time::timeout(Duration::from_secs(10), b.dial_context_tcp(dst))
        .await
        .unwrap()
        .unwrap();

    let req = b"go-style TestTunnelTCP over Rust direct UDP";
    b_stream.write_all(req).await.unwrap();
    b_stream.flush().await.unwrap();

    let mut a_stream = tokio::time::timeout(Duration::from_secs(10), accept)
        .await
        .unwrap()
        .unwrap();
    let mut got = vec![0; req.len()];
    tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, req);

    assert!(a_handle.stats().direct_wg_received > 0 || a_handle.stats().direct_wg_sent > 0);
    assert!(b_handle.stats().direct_wg_received > 0 || b_handle.stats().direct_wg_sent > 0);

    a_handle.expire_verified_endpoint_for_test(&b_node);
    assert_eq!(
        a.probe_peer_path(&b_peer).unwrap().transport,
        PeerTransport::DerpRelay
    );
}

#[tokio::test]
async fn conn_tunnel_uses_stun_discovered_direct_udp_path_without_static_endpoints() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let a_endpoint = reserve_local_endpoint();
    let b_endpoint = reserve_local_endpoint();
    let a_stun = fake_stun_server(a_endpoint).await;
    let b_stun = fake_stun_server(b_endpoint).await;
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

    let (a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(a_endpoint, Vec::new(), a_node, a_disco.clone())
            .with_stun_servers(vec![a_stun])
            .with_stun_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap();
    let (b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(b_endpoint, Vec::new(), b_node, b_disco.clone())
            .with_stun_servers(vec![b_stun])
            .with_stun_timeout(Duration::from_secs(1)),
    )
    .await
    .unwrap();

    let a_endpoints = a_handle.advertised_endpoints();
    let b_endpoints = b_handle.advertised_endpoints();
    assert_eq!(a_endpoints, vec![AddrPort(a_endpoint)]);
    assert_eq!(b_endpoints, vec![AddrPort(b_endpoint)]);

    let a = Conn::new(
        conn_options(&a_secret, a_disco.clone(), A_IP, a_endpoints),
        a_transport,
    )
    .unwrap();
    let b = Conn::new(
        conn_options(&b_secret, b_disco.clone(), B_IP, b_endpoints),
        b_transport,
    )
    .unwrap();

    let b_peer = node_with_endpoints(b_node, b_disco.public(), vec![b_endpoint], B_IP);
    let a_peer = node_with_endpoints(a_node, a_disco.public(), vec![a_endpoint], A_IP);
    a.update_peers(std::slice::from_ref(&b_peer)).unwrap();
    b.update_peers(std::slice::from_ref(&a_peer)).unwrap();
    wait_verified(&a_handle, &b_node).await;
    wait_verified(&b_handle, &a_node).await;
    assert_eq!(
        a.probe_peer_path(&b_peer).unwrap().transport,
        PeerTransport::DirectUdp
    );
    assert_eq!(
        b.probe_peer_path(&a_peer).unwrap().transport,
        PeerTransport::DirectUdp
    );

    let mut listener = a.listen("tcp", ":9022").await.unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let dst = SocketAddr::new(IpAddr::V6(A_IP), 9022);
    let mut b_stream = tokio::time::timeout(Duration::from_secs(10), b.dial_context_tcp(dst))
        .await
        .unwrap()
        .unwrap();

    let req = b"go-style TestTunnelTCP over Rust STUN-discovered direct UDP";
    b_stream.write_all(req).await.unwrap();
    b_stream.flush().await.unwrap();

    let mut a_stream = tokio::time::timeout(Duration::from_secs(10), accept)
        .await
        .unwrap()
        .unwrap();
    let mut got = vec![0; req.len()];
    tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, req);

    assert!(a_handle.stats().direct_wg_received > 0 || a_handle.stats().direct_wg_sent > 0);
    assert!(b_handle.stats().direct_wg_received > 0 || b_handle.stats().direct_wg_sent > 0);
    assert_eq!(a_handle.stats().fallback_wg_sent, 0);
    assert_eq!(b_handle.stats().fallback_wg_sent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conn_tunnel_uses_verified_peer_relay_path() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_node = NodePublic::from_raw(PublicKey::from(&a_secret).to_bytes());
    let b_node = NodePublic::from_raw(PublicKey::from(&b_secret).to_bytes());
    let a_disco = DiscoPrivate::generate(&mut OsRng);
    let b_disco = DiscoPrivate::generate(&mut OsRng);
    let (a_fallback, b_fallback) = fallback_pair(a_node, b_node);

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

    let (a_transport, a_handle) = wrap_transport(
        a_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            a_node,
            a_disco.clone(),
        ),
    )
    .await
    .unwrap();
    let (b_transport, b_handle) = wrap_transport(
        b_fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            b_node,
            b_disco.clone(),
        ),
    )
    .await
    .unwrap();

    let a = Conn::new(
        conn_options(&a_secret, a_disco.clone(), A_IP, Vec::new()),
        a_transport,
    )
    .unwrap();
    let b = Conn::new(
        conn_options(&b_secret, b_disco.clone(), B_IP, Vec::new()),
        b_transport,
    )
    .unwrap();

    let b_peer = node_with_endpoints(b_node, b_disco.public(), Vec::new(), B_IP);
    let a_peer = node_with_endpoints(a_node, a_disco.public(), Vec::new(), A_IP);
    a.update_peers(std::slice::from_ref(&b_peer)).unwrap();
    b.update_peers(std::slice::from_ref(&a_peer)).unwrap();

    wait_peer_known(&a_handle, &b_node).await;
    wait_peer_known(&b_handle, &a_node).await;
    a_handle
        .request_peer_relay(b_node, relay_endpoint)
        .expect("request peer relay");
    wait_peer_relay(&a_handle, &b_node).await;
    wait_peer_relay(&b_handle, &a_node).await;
    assert_eq!(
        a.probe_peer_path(&b_peer).unwrap().transport,
        PeerTransport::PeerRelay
    );
    assert_eq!(
        b.probe_peer_path(&a_peer).unwrap().transport,
        PeerTransport::PeerRelay
    );

    let mut listener = a.listen("tcp", ":9022").await.unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
    let dst = SocketAddr::new(IpAddr::V6(A_IP), 9022);
    let mut b_stream = tokio::time::timeout(Duration::from_secs(10), b.dial_context_tcp(dst))
        .await
        .unwrap()
        .unwrap();

    let req: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    b_stream.write_all(&req).await.unwrap();
    b_stream.flush().await.unwrap();

    let mut a_stream = tokio::time::timeout(Duration::from_secs(10), accept)
        .await
        .unwrap()
        .unwrap();
    let mut got = vec![0; req.len()];
    tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, req);

    let resp: Vec<u8> = (0..4096).map(|i| (255 - (i % 251)) as u8).collect();
    a_stream.write_all(&resp).await.unwrap();
    a_stream.flush().await.unwrap();

    let mut got_back = vec![0; resp.len()];
    tokio::time::timeout(Duration::from_secs(10), b_stream.read_exact(&mut got_back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got_back, resp);

    wait_stats(
        &a_handle,
        |stats| stats.peer_relay_wg_received > 0,
        "a should receive WireGuard over peer relay",
    )
    .await;
    wait_stats(
        &b_handle,
        |stats| stats.peer_relay_wg_sent > 0,
        "b should send WireGuard over peer relay",
    )
    .await;
    assert_eq!(a_handle.stats().fallback_wg_sent, 0);
    assert_eq!(b_handle.stats().fallback_wg_sent, 0);
    let relay_stats = relay_handle.stats();
    assert!(
        relay_stats.packets_forwarded > 4,
        "large TCP stream should forward multiple peer-relay data packets"
    );
    let max_forwarded = relay_stats.max_packet_bytes_forwarded as usize;
    assert!(
        max_forwarded >= crate::netstack::TUNNEL_MTU,
        "large TCP stream did not exercise MTU-sized peer-relay packets, max={max_forwarded}"
    );
    assert!(
        max_forwarded <= crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET,
        "peer relay forwarded {max_forwarded}-byte UDP payload, exceeding cross-node budget {}",
        crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET
    );

    let _ = shutdown_tx.send(());
    relay_task.await.unwrap().unwrap();
}
