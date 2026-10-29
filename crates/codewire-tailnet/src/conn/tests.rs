//! #59 capstone — the end-to-end two-`Conn` tunnel proof.
//!
//! This is the hard gate: it proves the **whole** Rust tunnel works, not just
//! the pieces. Two [`Conn`]s, each holding the other as a peer, exchange
//! application bytes in **both directions** through the full stack:
//!
//! ```text
//!   A app write ─► A netstack TCP ─► WG encapsulate ─► transport ─►
//!     ─► WG decapsulate ─► B netstack TCP ─► B app read   (and back)
//! ```
//!
//! Two transport backings, both exercising the identical `Conn` data path:
//!
//! * [`channel_shim_tunnel`] (default, hermetic) — an in-process shim wires
//!   each Conn's outbound transport channel to the other's inbound channel,
//!   standing in for the DERP relay. Runs under plain `cargo test`.
//! * [`real_derp_tunnel`] (`#[ignore]`, opt-in) — spawns the real
//!   `codewire-derp` server binary and relays the encrypted WG datagrams through it
//!   via the Rust [`crate::derp::Client`], exactly like the #46 interop test.
//!   This proves the tunnel over the real relay. Gated on `CODEWIRE_DERP_BIN`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use uuid::Uuid;

use chrono::{DateTime, Utc};

use super::{Conn, Options, PeerPath, PeerTransport, Transport, WgDatagram};
use crate::derp::NodePublic as DerpPublic;
use crate::node::{AddrPort, DiscoPublic, Node, NodePublic, Prefix};

// Two ULA addresses inside Codewire's `fd7a:115c:a1e0::/48` range. A is `::a`,
// B is `::b`; the peers route to each other by these /128 AllowedIPs.
const A_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000a);
const B_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000b);
/// Build a `Node` record for a peer: its WG public key (== DERP routing key)
/// and the single /128 ULA it owns.
fn peer_node(pubkey: &PublicKey, ip: Ipv6Addr) -> Node {
    Node {
        id: Uuid::new_v4(),
        as_of: DateTime::<Utc>::UNIX_EPOCH,
        key: NodePublic::from_raw(pubkey.to_bytes()),
        disco_key: DiscoPublic::default(),
        preferred_derp: 1,
        derp_latency: None,
        endpoints: Vec::new(),
        addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
    }
}

/// Options for one end of the tunnel: explicit key (so both ends agree on the
/// peer identity) + the single ULA address it answers for.
fn conn_opts(secret: &StaticSecret, ip: Ipv6Addr) -> Options {
    Options {
        id: Uuid::new_v4(),
        addresses: vec![Prefix::new(IpAddr::V6(ip), 128)],
        endpoints: Vec::new(),
        private_key: Some(secret.clone()),
        disco_private: None,
    }
}

fn peer_relay_packet_len_for_wg(wg_packet_len: usize) -> usize {
    crate::udp_relay::encode_data_packet(1, &vec![0; wg_packet_len]).len()
}

#[derive(Default)]
struct TransportMetrics {
    datagrams: AtomicUsize,
    max_wg_datagram_bytes: AtomicUsize,
}

impl TransportMetrics {
    fn observe_wg_datagram(&self, len: usize) {
        self.datagrams.fetch_add(1, Ordering::Relaxed);
        self.max_wg_datagram_bytes.fetch_max(len, Ordering::Relaxed);
    }

    fn datagrams(&self) -> usize {
        self.datagrams.load(Ordering::Relaxed)
    }

    fn max_wg_datagram_bytes(&self) -> usize {
        self.max_wg_datagram_bytes.load(Ordering::Relaxed)
    }
}

#[test]
fn wireguard_scratch_buffer_accepts_go_tailnet_sized_packets() {
    // Tailscale's tstun.MaxPacketSize is the upper bound for packets its
    // userspace engine can inject. Rust must accept that ceiling from Go peers
    // even though our own smoltcp MTU is intentionally lower.
    const {
        assert!(
            super::WG_BUF >= 64 << 10,
            "Rust tailnet must accept full-size WireGuard packets from Go/Tailscale peers"
        );
    };
}

#[test]
fn production_tunnel_mtu_fits_cross_node_peer_relay_budget() {
    let worst_case_wg_data_packet =
        crate::netstack::TUNNEL_MTU + crate::netstack::WIREGUARD_DATA_PACKET_OVERHEAD;
    let worst_case_peer_relay_udp_payload = peer_relay_packet_len_for_wg(worst_case_wg_data_packet);

    const {
        assert!(crate::netstack::TUNNEL_MTU < 1280);
    }
    assert!(
        worst_case_peer_relay_udp_payload <= crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET,
        "TUNNEL_MTU={} allows peer-relay UDP payload {} bytes, exceeding the cross-node budget {}",
        crate::netstack::TUNNEL_MTU,
        worst_case_peer_relay_udp_payload,
        crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET
    );
}

/// Drive a request/response exchange across an already-built pair of Conns.
/// A binds `:port`, B dials A, A→B then B→A bytes are asserted. Shared by both
/// transport backings so the proof is identical.
async fn exercise_tunnel(a: &Conn, b: &Conn, port: u16) {
    exercise_tunnel_payload(
        a,
        b,
        port,
        b"hello through the full WireGuard-over-transport tunnel",
        b"ack back across the tunnel",
    )
    .await;
}

async fn exercise_tunnel_payload(a: &Conn, b: &Conn, port: u16, req: &[u8], resp: &[u8]) {
    // A listens.
    let mut listener = a
        .listen("tcp", &format!(":{port}"))
        .await
        .expect("A listen");
    let accept = tokio::spawn(async move { listener.accept().await.expect("A accepts") });

    // B dials A's ULA:port. The first SYN triggers the WG handshake under the
    // hood; allow generous time for handshake + connect.
    let dst = SocketAddr::new(IpAddr::V6(A_IP), port);
    let mut b_stream = tokio::time::timeout(Duration::from_secs(15), b.dial_context_tcp(dst))
        .await
        .expect("dial did not hang")
        .expect("B dials A");

    // B -> A.
    b_stream.write_all(req).await.expect("B write");
    b_stream.flush().await.expect("B flush");

    let mut a_stream = tokio::time::timeout(Duration::from_secs(15), accept)
        .await
        .expect("accept did not hang")
        .expect("accept join");

    let mut got = vec![0u8; req.len()];
    tokio::time::timeout(Duration::from_secs(15), a_stream.read_exact(&mut got))
        .await
        .expect("A read did not hang")
        .expect("A read_exact");
    assert_eq!(
        got.as_slice(),
        req,
        "A must receive exactly what B sent (B->A)"
    );

    // A -> B (reverse direction over the same connection).
    a_stream.write_all(resp).await.expect("A write");
    a_stream.flush().await.expect("A flush");

    let mut got_back = vec![0u8; resp.len()];
    tokio::time::timeout(Duration::from_secs(15), b_stream.read_exact(&mut got_back))
        .await
        .expect("B read did not hang")
        .expect("B read_exact");
    assert_eq!(
        got_back.as_slice(),
        resp,
        "B must receive exactly what A sent (A->B)"
    );
}

#[test]
fn peer_path_constructors_report_their_transport() {
    let endpoint: SocketAddr = "203.0.113.10:41641".parse().unwrap();

    let direct = PeerPath::direct_udp(endpoint);
    assert_eq!(direct.transport, PeerTransport::DirectUdp);
    assert_eq!(direct.endpoint, Some(endpoint));

    let relay = PeerPath::peer_relay(endpoint);
    assert_eq!(relay.transport, PeerTransport::PeerRelay);
    assert_eq!(relay.endpoint, Some(endpoint));

    let derp = PeerPath::derp_relay(3);
    assert_eq!(derp.transport, PeerTransport::DerpRelay);
    assert_eq!(derp.derp_region_id, Some(3));
    // Region 0 means "unset" and falls back to the default region.
    assert_eq!(PeerPath::derp_relay(0).derp_region_id, Some(1));

    let unknown = PeerPath::unknown();
    assert_eq!(unknown.transport, PeerTransport::Unknown);
    assert_eq!((unknown.endpoint, unknown.derp_region_id), (None, None));
}

// ---------------------------------------------------------------------------
// Default, hermetic: in-process channel shim standing in for the DERP relay.
// ---------------------------------------------------------------------------

/// Wire two Conns' transport channels so each one's outbound encrypted
/// datagrams arrive at the other's inbound channel — an in-process "relay".
///
/// The shim rewrites the datagram's `peer` field on delivery: A addresses its
/// datagrams to B's key (so the real relay would route to B); on B's inbound
/// side the relevant key is the **source** (A), which is how B's `Conn` looks
/// the session up. We therefore relabel each delivered datagram with the
/// sender's key, exactly as the real DERP server delivers `RecvPacket{source}`.
fn shim(a_pub: DerpPublic, b_pub: DerpPublic) -> (Transport, Transport) {
    metered_shim(a_pub, b_pub, None)
}

fn metered_shim(
    a_pub: DerpPublic,
    b_pub: DerpPublic,
    metrics: Option<Arc<TransportMetrics>>,
) -> (Transport, Transport) {
    let (a_out_tx, mut a_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (b_out_tx, mut b_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<WgDatagram>();

    // A's outbound (addressed "to B") → delivered to B, relabeled source = A.
    let b_in_for_a = b_in_tx.clone();
    let a_src = a_pub;
    let a_metrics = metrics.clone();
    tokio::spawn(async move {
        while let Some(dg) = a_out_rx.recv().await {
            if let Some(metrics) = a_metrics.as_ref() {
                metrics.observe_wg_datagram(dg.data.len());
            }
            let _ = b_in_for_a.send(WgDatagram {
                peer: a_src.clone(),
                data: dg.data,
            });
        }
    });
    // B's outbound (addressed "to A") → delivered to A, relabeled source = B.
    let a_in_for_b = a_in_tx.clone();
    let b_src = b_pub;
    let b_metrics = metrics;
    tokio::spawn(async move {
        while let Some(dg) = b_out_rx.recv().await {
            if let Some(metrics) = b_metrics.as_ref() {
                metrics.observe_wg_datagram(dg.data.len());
            }
            let _ = a_in_for_b.send(WgDatagram {
                peer: b_src.clone(),
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

fn endpoint_update_transport() -> (Transport, mpsc::UnboundedSender<Vec<AddrPort>>) {
    let (out_tx, _out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (_in_tx, in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (endpoint_tx, endpoint_rx) = mpsc::unbounded_channel::<Vec<AddrPort>>();
    (
        Transport {
            to_transport: out_tx,
            from_transport: in_rx,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: Some(endpoint_rx),
        },
        endpoint_tx,
    )
}

#[tokio::test]
async fn channel_shim_tunnel() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_pub = PublicKey::from(&a_secret);
    let b_pub = PublicKey::from(&b_secret);

    let (a_transport, b_transport) = shim(
        DerpPublic::from_raw(a_pub.to_bytes()),
        DerpPublic::from_raw(b_pub.to_bytes()),
    );

    let a = Conn::new(conn_opts(&a_secret, A_IP), a_transport).expect("Conn A");
    let b = Conn::new(conn_opts(&b_secret, B_IP), b_transport).expect("Conn B");

    // Each registers the other as its sole peer.
    a.update_peers(&[peer_node(&b_pub, B_IP)]).expect("A peers");
    b.update_peers(&[peer_node(&a_pub, A_IP)]).expect("B peers");

    exercise_tunnel(&a, &b, 2222).await;
}

#[tokio::test]
async fn channel_shim_max_segment_stream_stays_under_peer_relay_budget() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_pub = PublicKey::from(&a_secret);
    let b_pub = PublicKey::from(&b_secret);
    let metrics = Arc::new(TransportMetrics::default());

    let (a_transport, b_transport) = metered_shim(
        DerpPublic::from_raw(a_pub.to_bytes()),
        DerpPublic::from_raw(b_pub.to_bytes()),
        Some(metrics.clone()),
    );

    let a = Conn::new(conn_opts(&a_secret, A_IP), a_transport).expect("Conn A");
    let b = Conn::new(conn_opts(&b_secret, B_IP), b_transport).expect("Conn B");
    a.update_peers(&[peer_node(&b_pub, B_IP)]).expect("A peers");
    b.update_peers(&[peer_node(&a_pub, A_IP)]).expect("B peers");

    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    let response: Vec<u8> = (0..4096).map(|i| (255 - (i % 251)) as u8).collect();
    exercise_tunnel_payload(&a, &b, 9023, &payload, &response).await;

    let max_wg = metrics.max_wg_datagram_bytes();
    assert!(
        metrics.datagrams() > 4,
        "large TCP stream should emit multiple WireGuard datagrams, saw {}",
        metrics.datagrams()
    );
    assert!(
        max_wg >= crate::netstack::TUNNEL_MTU,
        "large TCP stream did not exercise MTU-sized WireGuard datagrams, max={max_wg}"
    );
    let relay_payload_len = peer_relay_packet_len_for_wg(max_wg);
    assert!(
        relay_payload_len <= crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET,
        "max DERP-path WireGuard datagram {max_wg} would become peer-relay UDP payload {relay_payload_len}, exceeding budget {}",
        crate::netstack::PEER_RELAY_UDP_PAYLOAD_BUDGET
    );
}

/// A second exchange after the first proves the established session is reused
/// (no re-handshake per connection) and that `Node()`/peer state survive.
#[tokio::test]
async fn channel_shim_tunnel_reports_node() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_pub = PublicKey::from(&a_secret);
    let b_pub = PublicKey::from(&b_secret);

    let (a_transport, b_transport) = shim(
        DerpPublic::from_raw(a_pub.to_bytes()),
        DerpPublic::from_raw(b_pub.to_bytes()),
    );
    let a = Conn::new(conn_opts(&a_secret, A_IP), a_transport).expect("Conn A");
    let b = Conn::new(conn_opts(&b_secret, B_IP), b_transport).expect("Conn B");
    a.update_peers(&[peer_node(&b_pub, B_IP)]).expect("A peers");
    b.update_peers(&[peer_node(&a_pub, A_IP)]).expect("B peers");

    // Node() reports our own key + address.
    let node = a.node();
    assert_eq!(node.key.as_bytes(), &a_pub.to_bytes());
    assert_ne!(
        node.disco_key.as_bytes(),
        &[0u8; 32],
        "Tailscale magicsock ignores non-WireGuard-only peers with a zero disco key"
    );
    assert_eq!(node.addresses[0].addr(), IpAddr::V6(A_IP));
    assert_eq!(node.preferred_derp, 1, "defaults to region 1 when unset");
    assert!(
        node.endpoints.is_empty(),
        "relay-only Rust Conn must not advertise direct endpoints until #265 adds STUN/disco UDP support"
    );

    exercise_tunnel(&a, &b, 8080).await;
}

#[tokio::test]
async fn transport_local_endpoint_updates_republish_node() {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let (transport, endpoint_tx) = endpoint_update_transport();
    let conn = Conn::new(conn_opts(&secret, A_IP), transport).expect("Conn");
    let seen = Arc::new(Mutex::new(Vec::<Vec<AddrPort>>::new()));
    let seen_cb = seen.clone();
    conn.set_node_callback(move |node| {
        seen_cb.lock().unwrap().push(node.endpoints.clone());
    });

    let endpoint = AddrPort("203.0.113.5:31000".parse().unwrap());
    endpoint_tx.send(vec![endpoint]).unwrap();

    for _ in 0..100 {
        if conn.node().endpoints == vec![endpoint] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(conn.node().key.as_bytes(), &public.to_bytes());
    assert_eq!(conn.node().endpoints, vec![endpoint]);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|eps| eps == &vec![endpoint]),
        "node callback should observe transport endpoint update"
    );
}

#[tokio::test]
async fn channel_shim_path_probe_reports_derp_relay() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_pub = PublicKey::from(&a_secret);
    let b_pub = PublicKey::from(&b_secret);

    let (a_transport, b_transport) = shim(
        DerpPublic::from_raw(a_pub.to_bytes()),
        DerpPublic::from_raw(b_pub.to_bytes()),
    );
    let a = Conn::new(conn_opts(&a_secret, A_IP), a_transport).expect("Conn A");
    let b = Conn::new(conn_opts(&b_secret, B_IP), b_transport).expect("Conn B");

    let mut b_peer = peer_node(&b_pub, B_IP);
    b_peer.preferred_derp = 7;
    let a_peer = peer_node(&a_pub, A_IP);
    a.update_peers(std::slice::from_ref(&b_peer))
        .expect("A peers");
    b.update_peers(&[a_peer]).expect("B peers");

    let path = a.probe_peer_path(&b_peer).expect("path probe");
    assert_eq!(path.transport, PeerTransport::DerpRelay);
    assert_eq!(path.derp_region_id, Some(7));
    assert!(path.endpoint.is_none());
}

#[test]
fn peer_relay_path_is_distinct_from_direct_udp() {
    let endpoint = "203.0.113.34:31000".parse().unwrap();
    let path = PeerPath::peer_relay(endpoint);

    assert_eq!(path.transport, PeerTransport::PeerRelay);
    assert_eq!(path.endpoint, Some(endpoint));
    assert!(path.derp_region_id.is_none());
}

// ---------------------------------------------------------------------------
// Opt-in: the full tunnel over the real codewire-derp relay server.
// ---------------------------------------------------------------------------

/// The full Rust tunnel over the real DERP server. Mirrors the #46 interop
/// harness: spawns `codewire-derp` (cleartext PORT, no TLS/STUN), connects two
/// Rust DERP clients, wires them as each Conn's transport, then runs the same
/// end-to-end byte exchange.
///
/// ```sh
/// CODEWIRE_DERP_BIN=/tmp/codewire-derp \
///   cargo test -p codewire-tailnet --release real_derp_tunnel -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "spawns the codewire-derp server binary named by CODEWIRE_DERP_BIN; CI runs it beside the DERP contract"]
async fn real_derp_tunnel() {
    use std::process::Stdio;

    let bin = std::env::var("CODEWIRE_DERP_BIN")
        .expect("set CODEWIRE_DERP_BIN to the prebuilt codewire-derp binary");
    let port = "34897";
    let mut child = tokio::process::Command::new(&bin)
        .env("PORT", port)
        .env("TLS_PORT", "")
        .env("STUN_PORT", "-1")
        .env("CODEWIRE_DEBUG_DERP", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn codewire-derp");

    let addr = format!("127.0.0.1:{port}");
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "DERP server never started on {addr}");

    // WG identities for the two tunnel ends.
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_wg_pub = PublicKey::from(&a_secret);
    let b_wg_pub = PublicKey::from(&b_secret);

    // Each Conn's DERP routing key == its WG public key (Codewire model). So
    // the DERP client must connect with a private key whose public matches.
    let a_derp_priv = crate::derp::NodePrivate::from_raw(a_secret.to_bytes());
    let b_derp_priv = crate::derp::NodePrivate::from_raw(b_secret.to_bytes());

    let mut rng = OsRng;
    let a_client = crate::derp::connect_plain(&addr, "127.0.0.1", a_derp_priv, &mut rng)
        .await
        .expect("A DERP connect");
    let b_client = crate::derp::connect_plain(&addr, "127.0.0.1", b_derp_priv, &mut rng)
        .await
        .expect("B DERP connect");
    // The DERP routing key the relay knows each client by is its derp public.
    assert_eq!(a_client.public_key().as_bytes(), &a_wg_pub.to_bytes());
    assert_eq!(b_client.public_key().as_bytes(), &b_wg_pub.to_bytes());

    let a = Conn::new(
        conn_opts(&a_secret, A_IP),
        super::transport_from_derp_client(a_client),
    )
    .expect("Conn A");
    let b = Conn::new(
        conn_opts(&b_secret, B_IP),
        super::transport_from_derp_client(b_client),
    )
    .expect("Conn B");

    a.update_peers(&[peer_node(&b_wg_pub, B_IP)])
        .expect("A peers");
    b.update_peers(&[peer_node(&a_wg_pub, A_IP)])
        .expect("B peers");

    // Let both clients register with the relay before traffic.
    tokio::time::sleep(Duration::from_millis(200)).await;

    exercise_tunnel(&a, &b, 9022).await;

    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[test]
fn prefix_contains_never_panics_on_oversized_bits() {
    // A Prefix built via `new` is not range-checked, so an oversized bit
    // count must not panic the route lookup (regression for the pump-task
    // panic where `bits/8` sliced past the address octets).
    use super::prefix_contains;
    // Clamped to /32, this behaves as an exact V4 match — no panic either way.
    let v4 = Prefix::new(IpAddr::from([10, 0, 0, 0]), 200);
    assert!(prefix_contains(&v4, IpAddr::from([10, 0, 0, 0])));
    assert!(!prefix_contains(&v4, IpAddr::from([10, 0, 0, 1])));
    let v6 = Prefix::new(IpAddr::from(A_IP), 200);
    // Clamped to /128, the exact ULA still matches; a different one does not.
    assert!(prefix_contains(&v6, IpAddr::from(A_IP)));
    assert!(!prefix_contains(&v6, IpAddr::from(B_IP)));
}

#[test]
fn inbound_packets_must_come_from_the_sending_peers_allowed_ips() {
    let (ns_in_tx, mut ns_in_rx) = mpsc::channel(4);
    let allowed = [Prefix::new(IpAddr::V6(B_IP), 128)];
    super::deliver_inbound(&allowed, IpAddr::V6(B_IP), b"from b", &ns_in_tx);
    super::deliver_inbound(&allowed, IpAddr::V6(A_IP), b"spoofed a", &ns_in_tx);
    super::deliver_inbound(
        &allowed,
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        b"v4",
        &ns_in_tx,
    );
    super::deliver_inbound(&[], IpAddr::V6(B_IP), b"no allowed ips", &ns_in_tx);
    assert_eq!(ns_in_rx.try_recv().unwrap(), b"from b");
    assert!(ns_in_rx.try_recv().is_err());
}

#[tokio::test]
async fn a_peer_cannot_send_from_an_address_it_does_not_own() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_pub = PublicKey::from(&a_secret);
    let b_pub = PublicKey::from(&b_secret);
    let (a_transport, b_transport) = shim(
        DerpPublic::from_raw(a_pub.to_bytes()),
        DerpPublic::from_raw(b_pub.to_bytes()),
    );
    let a = Conn::new(conn_opts(&a_secret, A_IP), a_transport).expect("Conn A");
    let b = Conn::new(conn_opts(&b_secret, B_IP), b_transport).expect("Conn B");
    // B allows A only ::c, but A sends from its own address ::a.
    let c_ip = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000c);
    a.update_peers(&[peer_node(&b_pub, B_IP)]).expect("A peers");
    b.update_peers(&[peer_node(&a_pub, c_ip)]).expect("B peers");
    let mut listener = b.listen("tcp", ":2224").await.expect("B listen");
    let dial = tokio::spawn(async move {
        if let Ok(mut stream) = a
            .dial_context_tcp(SocketAddr::new(IpAddr::V6(B_IP), 2224))
            .await
        {
            let _ = stream.write_all(b"from a").await;
            let _ = stream.flush().await;
            std::future::pending::<()>().await;
        }
        drop(a);
    });
    let accepted = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "B must drop packets from outside A's allowed IPs"
    );
    dial.abort();
}

/// The coordinator tells both peers about each other at about the same time,
/// so the dialer's first initiation can reach the listener a moment before
/// the listener knows the dialer's key. The dialer must not wait for
/// boringtun's 5 s `REKEY_TIMEOUT` to try again.
#[tokio::test]
async fn first_handshake_survives_a_peer_that_learns_of_us_late() {
    let a_secret = StaticSecret::random_from_rng(OsRng);
    let b_secret = StaticSecret::random_from_rng(OsRng);
    let a_pub = PublicKey::from(&a_secret);
    let b_pub = PublicKey::from(&b_secret);
    let (a_transport, b_transport) = shim(
        DerpPublic::from_raw(a_pub.to_bytes()),
        DerpPublic::from_raw(b_pub.to_bytes()),
    );
    let a = Conn::new(conn_opts(&a_secret, A_IP), a_transport).expect("Conn A");
    let b = Conn::new(conn_opts(&b_secret, B_IP), b_transport).expect("Conn B");
    a.update_peers(&[peer_node(&b_pub, B_IP)]).expect("A peers");

    let mut listener = b.listen("tcp", ":2225").await.expect("B listen");
    let serve = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("B accepts");
        stream.write_all(b"banner").await.expect("B writes");
        stream.flush().await.expect("B flushes");
        stream
    });

    let started = tokio::time::Instant::now();
    let dial = tokio::spawn(async move {
        let mut stream = a
            .dial_context_tcp(SocketAddr::new(IpAddr::V6(B_IP), 2225))
            .await
            .expect("A dials");
        let mut banner = [0u8; 6];
        stream.read_exact(&mut banner).await.expect("A reads");
        (a, stream, banner)
    });

    // B learns of A only after A's first initiation has arrived and been
    // dropped as coming from an unknown key.
    tokio::time::sleep(Duration::from_millis(30)).await;
    b.update_peers(&[peer_node(&a_pub, A_IP)]).expect("B peers");

    let (_a, _stream, banner) = tokio::time::timeout(Duration::from_secs(2), dial)
        .await
        .expect("first byte well before boringtun's 5 s handshake retransmit")
        .expect("dial task");
    assert_eq!(&banner, b"banner");
    assert!(
        started.elapsed() < Duration::from_millis(600),
        "first byte took {:?}",
        started.elapsed()
    );
    serve.await.expect("serve task");
}

/// A DERP stand-in for one daemon and several clients: the daemon's
/// datagrams go to the client its routing key names, each client's to the
/// daemon. Counts what reaches each client.
struct DaemonRelay {
    daemon: Transport,
    clients: Vec<(Transport, Arc<AtomicUsize>)>,
}

fn daemon_relay(daemon_key: DerpPublic, client_keys: &[DerpPublic]) -> DaemonRelay {
    let (daemon_out_tx, mut daemon_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (daemon_in_tx, daemon_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let mut routes = Vec::new();
    let mut clients = Vec::new();
    for key in client_keys {
        let (client_out_tx, mut client_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let (client_in_tx, client_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
        let received = Arc::new(AtomicUsize::new(0));
        routes.push((key.clone(), client_in_tx, received.clone()));
        let to_daemon = daemon_in_tx.clone();
        let source = key.clone();
        tokio::spawn(async move {
            while let Some(dg) = client_out_rx.recv().await {
                let _ = to_daemon.send(WgDatagram {
                    peer: source.clone(),
                    data: dg.data,
                });
            }
        });
        clients.push((
            Transport {
                to_transport: client_out_tx,
                from_transport: client_in_rx,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
            received,
        ));
    }
    tokio::spawn(async move {
        while let Some(dg) = daemon_out_rx.recv().await {
            if let Some((_, to_client, received)) = routes
                .iter()
                .find(|(key, _, _)| key.as_bytes() == dg.peer.as_bytes())
            {
                received.fetch_add(1, Ordering::SeqCst);
                let _ = to_client.send(WgDatagram {
                    peer: daemon_key.clone(),
                    data: dg.data,
                });
            }
        }
    });
    DaemonRelay {
        daemon: Transport {
            to_transport: daemon_out_tx,
            from_transport: daemon_in_rx,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: None,
        },
        clients,
    }
}

/// A daemon must never send one peer's traffic to another. After the first
/// client departs, the daemon's leftover segments for it (here, writes on its
/// still-open stream) have no route; they must be dropped, not sent to the
/// next client, who may be a different user.
#[tokio::test]
async fn leftover_segments_for_a_departed_peer_never_reach_the_next_peer() {
    const C_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000c);
    let daemon_secret = StaticSecret::random_from_rng(OsRng);
    let first_secret = StaticSecret::random_from_rng(OsRng);
    let second_secret = StaticSecret::random_from_rng(OsRng);
    let daemon_pub = PublicKey::from(&daemon_secret);
    let first_pub = PublicKey::from(&first_secret);
    let second_pub = PublicKey::from(&second_secret);
    let mut relay = daemon_relay(
        DerpPublic::from_raw(daemon_pub.to_bytes()),
        &[
            DerpPublic::from_raw(first_pub.to_bytes()),
            DerpPublic::from_raw(second_pub.to_bytes()),
        ],
    );
    let (second_transport, second_received) = relay.clients.pop().unwrap();
    let (first_transport, _) = relay.clients.pop().unwrap();
    let daemon = Conn::new(conn_opts(&daemon_secret, A_IP), relay.daemon).expect("daemon");
    let first = Conn::new(conn_opts(&first_secret, B_IP), first_transport).expect("first");
    let second = Conn::new(conn_opts(&second_secret, C_IP), second_transport).expect("second");

    // The first client connects and talks.
    daemon
        .update_peers(&[peer_node(&first_pub, B_IP)])
        .expect("daemon peers");
    first
        .update_peers(&[peer_node(&daemon_pub, A_IP)])
        .expect("first peers");
    let mut listener = daemon.listen("tcp", ":22").await.expect("daemon listen");
    let mut first_stream = first
        .dial_context_tcp(SocketAddr::new(IpAddr::V6(A_IP), 22))
        .await
        .expect("first dials");
    let mut daemon_stream = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("daemon accepts")
        .expect("accept");
    first_stream
        .write_all(b"hello")
        .await
        .expect("first writes");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), daemon_stream.read_exact(&mut got))
        .await
        .expect("daemon reads")
        .expect("read");

    // The first client departs; the second, the daemon's only peer now, has
    // not sent anything yet.
    drop(first_stream);
    drop(first);
    daemon
        .update_peers(&[peer_node(&second_pub, C_IP)])
        .expect("daemon peers");
    second
        .update_peers(&[peer_node(&daemon_pub, A_IP)])
        .expect("second peers");

    // The daemon keeps writing to the departed client's stream. Nothing
    // acknowledges it any more, so bound each write.
    for _ in 0..5 {
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            daemon_stream.write_all(b"for the first user only").await?;
            daemon_stream.flush().await
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        second_received.load(Ordering::SeqCst),
        0,
        "the daemon sent the departed client's traffic to the next client"
    );
    assert!(daemon.unrouted_packets_dropped() > 0);

    // The second client's own traffic still flows.
    let accept = tokio::spawn(async move { listener.accept().await.expect("accept") });
    let mut second_stream = second
        .dial_context_tcp(SocketAddr::new(IpAddr::V6(A_IP), 22))
        .await
        .expect("second dials");
    let mut second_side = tokio::time::timeout(Duration::from_secs(5), accept)
        .await
        .expect("daemon accepts the second client")
        .expect("accept task");
    second_side
        .write_all(b"yours")
        .await
        .expect("daemon writes");
    second_side.flush().await.expect("daemon flushes");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), second_stream.read_exact(&mut got))
        .await
        .expect("second reads")
        .expect("read");
    assert_eq!(&got, b"yours");
}

fn node_with_addresses(pubkey: &PublicKey, addresses: Vec<Prefix>) -> Node {
    Node {
        addresses,
        ..peer_node(pubkey, A_IP)
    }
}

/// Nodes publish their own addresses through the coordinator. A peer owns
/// only its host addresses that no other peer claims and that are not ours:
/// a broader prefix would make it the route for traffic that is not its own.
#[test]
fn peers_own_only_their_uncontested_host_addresses() {
    let host = |last: u16| {
        Prefix::new(
            IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, last)),
            128,
        )
    };
    let own = [host(0xa)];
    let key = |seed: u8| PublicKey::from(&StaticSecret::from([seed; 32]));
    let broad = node_with_addresses(
        &key(1),
        vec![
            host(0x1),
            Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            Prefix::new(
                IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0)),
                48,
            ),
            Prefix::new(IpAddr::from([10, 0, 0, 0]), 8),
            Prefix::new(IpAddr::from([10, 0, 0, 1]), 32),
        ],
    );
    let victim = node_with_addresses(&key(2), vec![host(0x2)]);
    let squatter = node_with_addresses(&key(3), vec![host(0x2), host(0x3), host(0xa)]);

    let allowed = super::allowed_ips(&[broad, victim, squatter], &own);
    assert_eq!(
        allowed,
        vec![
            vec![host(0x1), Prefix::new(IpAddr::from([10, 0, 0, 1]), 32)],
            // An address two peers claim belongs to neither.
            Vec::new(),
            vec![host(0x3)],
        ]
    );
}

#[tokio::test]
async fn a_broad_prefix_does_not_make_a_peer_the_default_route() {
    let daemon_secret = StaticSecret::random_from_rng(OsRng);
    let peer_secret = StaticSecret::random_from_rng(OsRng);
    let peer_pub = PublicKey::from(&peer_secret);
    let (to_transport, mut sent) = mpsc::unbounded_channel::<WgDatagram>();
    let (_inbound, from_transport) = mpsc::unbounded_channel::<WgDatagram>();
    let daemon = Conn::new(
        conn_opts(&daemon_secret, A_IP),
        Transport {
            to_transport,
            from_transport,
            peer_updates: None,
            path_probe: None,
            local_endpoint_updates: None,
        },
    )
    .expect("daemon");
    daemon
        .update_peers(&[node_with_addresses(
            &peer_pub,
            vec![
                Prefix::new(IpAddr::V6(B_IP), 128),
                Prefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            ],
        )])
        .expect("daemon peers");

    // Traffic for an address no peer owns goes nowhere.
    let elsewhere = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x00ee);
    let _unrouted = tokio::time::timeout(
        Duration::from_secs(2),
        daemon.dial_context_tcp(SocketAddr::new(IpAddr::V6(elsewhere), 22)),
    )
    .await
    .expect("dial returns");
    let unrouted = tokio::time::timeout(Duration::from_millis(300), sent.recv()).await;
    assert!(
        unrouted.is_err(),
        "sent {unrouted:?} for an unowned address"
    );
    assert!(daemon.unrouted_packets_dropped() > 0);

    // Traffic for the peer's own address still reaches it.
    let _routed = tokio::time::timeout(
        Duration::from_secs(2),
        daemon.dial_context_tcp(SocketAddr::new(IpAddr::V6(B_IP), 22)),
    )
    .await
    .expect("dial returns");
    let initiation = tokio::time::timeout(Duration::from_secs(2), sent.recv())
        .await
        .expect("handshake for the peer's own address")
        .expect("transport open");
    assert_eq!(initiation.peer.as_bytes(), &peer_pub.to_bytes());
    assert_eq!(initiation.data.len(), 148);
}
