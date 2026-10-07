//! DERP first: a connection must not wait for direct UDP.
//!
//! A client dials a daemon over a DERP stand-in with real one-way latency.
//! The daemon advertises a direct endpoint that swallows every datagram, so
//! WireGuard has to ride DERP until disco proves a UDP path, and the first
//! byte must arrive as fast as it does for a client that never tries direct
//! UDP. Once the endpoint starts answering, the open stream moves to direct
//! UDP without a reconnect.

#[allow(clippy::wildcard_imports)]
use super::*;

const ONE_WAY: Duration = Duration::from_millis(20);
const BANNER: &[u8] = b"SSH-2.0-codewire-test\r\n";

/// A DERP stand-in that delivers each datagram after `one_way`, in order.
fn delayed_fallback_pair(
    a_node: NodePublic,
    b_node: NodePublic,
    one_way: Duration,
) -> (Transport, Transport) {
    fn pipe(
        mut from: mpsc::UnboundedReceiver<WgDatagram>,
        to: mpsc::UnboundedSender<WgDatagram>,
        source: NodePublic,
        one_way: Duration,
    ) {
        let (due_tx, mut due_rx) = mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
        tokio::spawn(async move {
            while let Some(dg) = from.recv().await {
                if due_tx
                    .send((tokio::time::Instant::now() + one_way, dg.data))
                    .is_err()
                {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            while let Some((due, data)) = due_rx.recv().await {
                tokio::time::sleep_until(due).await;
                let _ = to.send(WgDatagram {
                    peer: derp_public_from_node(source),
                    data,
                });
            }
        });
    }

    let (a_out_tx, a_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (b_out_tx, b_out_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<WgDatagram>();
    pipe(a_out_rx, b_in_tx, a_node, one_way);
    pipe(b_out_rx, a_in_tx, b_node, one_way);
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

/// The daemon's advertised direct endpoint: a UDP forwarder that swallows
/// every datagram until it is opened, then relays both ways between the
/// client and the daemon's real socket, as a NAT or load balancer would.
struct DirectGate {
    advertised: SocketAddr,
    open: Arc<std::sync::atomic::AtomicBool>,
}

impl DirectGate {
    async fn closed_in_front_of(daemon: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let advertised = front.local_addr().unwrap();
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_open = open.clone();
        tokio::spawn(async move {
            let mut client = None;
            let mut front_buf = vec![0u8; 65_536];
            let mut back_buf = vec![0u8; 65_536];
            loop {
                tokio::select! {
                    received = front.recv_from(&mut front_buf) => {
                        let Ok((n, from)) = received else { return; };
                        if task_open.load(Ordering::SeqCst) {
                            client = Some(from);
                            let _ = back.send_to(&front_buf[..n], daemon).await;
                        }
                    }
                    received = back.recv_from(&mut back_buf) => {
                        let Ok((n, from)) = received else { return; };
                        if let (true, Some(client)) = (task_open.load(Ordering::SeqCst), client) {
                            if from == daemon {
                                let _ = front.send_to(&back_buf[..n], client).await;
                            }
                        }
                    }
                }
            }
        });
        Self { advertised, open }
    }

    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
    }
}

/// How the client reaches the daemon in one measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientMode {
    /// DERP only: the client never binds a UDP socket (`CW_DERP_ONLY`).
    DerpOnly,
    /// The default client: direct UDP discovery wrapped around DERP.
    DirectCapable,
}

/// A connected client and daemon over the delayed DERP stand-in.
struct Pair {
    client: Conn,
    daemon: Conn,
    client_handle: Option<Handle>,
    daemon_handle: Handle,
    daemon_peer: Node,
    client_peer: Node,
    gate: DirectGate,
}

async fn pair(mode: ClientMode) -> Pair {
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let daemon_secret = StaticSecret::random_from_rng(OsRng);
    let client_node = NodePublic::from_raw(PublicKey::from(&client_secret).to_bytes());
    let daemon_node = NodePublic::from_raw(PublicKey::from(&daemon_secret).to_bytes());
    let client_disco = DiscoPrivate::generate(&mut OsRng);
    let daemon_disco = DiscoPrivate::generate(&mut OsRng);
    let (client_fallback, daemon_fallback) =
        delayed_fallback_pair(client_node, daemon_node, ONE_WAY);

    let daemon_bind = reserve_local_endpoint();
    let gate = DirectGate::closed_in_front_of(daemon_bind).await;
    let (daemon_transport, daemon_handle) = wrap_transport(
        daemon_fallback,
        Options::new(
            daemon_bind,
            vec![gate.advertised],
            daemon_node,
            daemon_disco.clone(),
        ),
    )
    .await
    .unwrap();
    let (client_transport, client_handle) = match mode {
        ClientMode::DerpOnly => (client_fallback, None),
        ClientMode::DirectCapable => {
            let (transport, handle) = wrap_transport(
                client_fallback,
                Options::new(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                    Vec::new(),
                    client_node,
                    client_disco.clone(),
                ),
            )
            .await
            .unwrap();
            (transport, Some(handle))
        }
    };

    let daemon = Conn::new(
        conn_options(
            &daemon_secret,
            daemon_disco.clone(),
            B_IP,
            daemon_handle.advertised_endpoints(),
        ),
        daemon_transport,
    )
    .unwrap();
    let client = Conn::new(
        conn_options(&client_secret, client_disco.clone(), A_IP, Vec::new()),
        client_transport,
    )
    .unwrap();
    Pair {
        client,
        daemon,
        client_handle,
        daemon_handle,
        daemon_peer: node(daemon_node, daemon_disco.public(), gate.advertised, B_IP),
        client_peer: node_with_endpoints(client_node, client_disco.public(), Vec::new(), A_IP),
        gate,
    }
}

/// Serve an SSH-style banner on the daemon's port 22 and return the
/// accepted stream.
async fn serve_banner(daemon: &Conn) -> tokio::task::JoinHandle<crate::netstack::TcpStream> {
    let mut listener = daemon.listen("tcp", ":22").await.unwrap();
    tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        stream.write_all(BANNER).await.unwrap();
        stream.flush().await.unwrap();
        stream
    })
}

/// Dial port 22 and time the first banner byte. When
/// `daemon_learns_client_after` is set, the daemon gets the client's node
/// that long after the dial starts, as when the coordinator's update to the
/// daemon trails the client's first handshake initiation.
async fn first_byte_latency(
    mode: ClientMode,
    daemon_learns_client_after: Option<Duration>,
) -> (Duration, Pair) {
    let pair = pair(mode).await;
    pair.client
        .update_peers(std::slice::from_ref(&pair.daemon_peer))
        .unwrap();
    if daemon_learns_client_after.is_none() {
        pair.daemon
            .update_peers(std::slice::from_ref(&pair.client_peer))
            .unwrap();
    }
    let served = serve_banner(&pair.daemon).await;

    let started = Instant::now();
    let dial = pair
        .client
        .dial_context_tcp(SocketAddr::new(IpAddr::V6(B_IP), 22));
    let late_update = async {
        if let Some(delay) = daemon_learns_client_after {
            sleep(delay).await;
            pair.daemon
                .update_peers(std::slice::from_ref(&pair.client_peer))
                .unwrap();
        }
    };
    let (dialed, ()) = tokio::join!(dial, late_update);
    let mut stream = dialed.unwrap();
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut first))
        .await
        .expect("first byte arrived")
        .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(first[0], BANNER[0]);
    served.abort();
    (elapsed, pair)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_tcp_byte_with_unreachable_direct_endpoint_matches_derp_only() {
    let (derp_only, _) = first_byte_latency(ClientMode::DerpOnly, None).await;
    let (direct_capable, pair) = first_byte_latency(ClientMode::DirectCapable, None).await;
    let client_stats = pair.client_handle.as_ref().unwrap().stats();
    eprintln!("first byte: derp_only={derp_only:?} direct_capable={direct_capable:?}");

    assert!(
        direct_capable <= derp_only + Duration::from_millis(100),
        "direct-capable first byte {direct_capable:?} vs DERP-only {derp_only:?}"
    );
    assert_eq!(client_stats.direct_wg_sent, 0, "{client_stats:?}");
    assert!(client_stats.fallback_wg_sent > 0, "{client_stats:?}");
    assert!(
        client_stats.disco_udp_sent > 0,
        "the client probed the unreachable endpoint meanwhile: {client_stats:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_tcp_byte_survives_a_daemon_that_learns_of_the_client_late() {
    for mode in [ClientMode::DerpOnly, ClientMode::DirectCapable] {
        let (elapsed, _) = first_byte_latency(mode, Some(Duration::from_millis(30))).await;
        eprintln!("first byte with a late daemon update: {mode:?}={elapsed:?}");
        assert!(
            elapsed < Duration::from_secs(1),
            "{mode:?} first byte took {elapsed:?}; boringtun alone retries after 5 s"
        );
    }
}

#[tokio::test]
async fn client_start_does_not_wait_for_stun() {
    let node_key = NodePublic::from_raw([7; 32]);
    let silent_stun = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = |wait: bool| {
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            node_key,
            DiscoPrivate::generate(&mut OsRng),
        )
        .with_stun_servers(vec![silent_stun.local_addr().unwrap()])
        .with_stun_timeout(Duration::from_millis(400))
        .with_stun_before_start(wait)
    };

    let started = Instant::now();
    let (_waited, _) = wrap_transport(recording_fallback().0, options(true))
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(400));

    let started = Instant::now();
    let (_started, _) = wrap_transport(recording_fallback().0, options(false))
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "start took {:?}",
        started.elapsed()
    );

    // An answering STUN server still yields the mapped endpoint, published
    // after start.
    let mapped: SocketAddr = "203.0.113.7:41641".parse().unwrap();
    let stun = fake_stun_server(mapped).await;
    // Keep the fallback's halves alive: a closed DERP stand-in ends the loop.
    let (fallback, _fallback_out, _fallback_in) = recording_fallback();
    let (mut transport, handle) = wrap_transport(
        fallback,
        Options::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Vec::new(),
            node_key,
            DiscoPrivate::generate(&mut OsRng),
        )
        .with_stun_servers(vec![stun])
        .with_stun_before_start(false),
    )
    .await
    .unwrap();
    assert!(handle.advertised_endpoints().is_empty());
    let published = tokio::time::timeout(
        Duration::from_secs(2),
        transport.local_endpoint_updates.as_mut().unwrap().recv(),
    )
    .await
    .expect("endpoint published after STUN answered")
    .unwrap();
    assert_eq!(published, vec![AddrPort(mapped)]);
    assert_eq!(handle.advertised_endpoints(), vec![AddrPort(mapped)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_stream_moves_from_derp_to_direct_udp_once_disco_proves_it() {
    let pair = pair(ClientMode::DirectCapable).await;
    let client_handle = pair.client_handle.clone().unwrap();
    pair.client
        .update_peers(std::slice::from_ref(&pair.daemon_peer))
        .unwrap();
    pair.daemon
        .update_peers(std::slice::from_ref(&pair.client_peer))
        .unwrap();
    let served = serve_banner(&pair.daemon).await;

    let mut client_stream = pair
        .client
        .dial_context_tcp(SocketAddr::new(IpAddr::V6(B_IP), 22))
        .await
        .unwrap();
    let mut banner = vec![0u8; BANNER.len()];
    tokio::time::timeout(
        Duration::from_secs(5),
        client_stream.read_exact(&mut banner),
    )
    .await
    .expect("banner over DERP")
    .unwrap();
    assert_eq!(banner, BANNER);
    let mut daemon_stream = served.await.unwrap();
    assert_eq!(
        pair.client
            .probe_peer_path(&pair.daemon_peer)
            .unwrap()
            .transport,
        PeerTransport::DerpRelay
    );
    assert_eq!(client_handle.stats().direct_wg_sent, 0);

    // The endpoint starts answering while the stream is open.
    pair.gate.open();
    wait_verified(&client_handle, &pair.daemon_peer.key).await;
    assert_eq!(
        pair.client
            .probe_peer_path(&pair.daemon_peer)
            .unwrap()
            .transport,
        PeerTransport::DirectUdp
    );
    let derp_before = client_handle.stats().fallback_wg_sent;

    // Same stream, both directions, now over direct UDP.
    for round in 0..3u8 {
        let request = [b'q', round];
        client_stream.write_all(&request).await.unwrap();
        client_stream.flush().await.unwrap();
        let mut got = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), daemon_stream.read_exact(&mut got))
            .await
            .expect("request after upgrade")
            .unwrap();
        assert_eq!(got, request);
        let reply = [b'r', round];
        daemon_stream.write_all(&reply).await.unwrap();
        daemon_stream.flush().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), client_stream.read_exact(&mut got))
            .await
            .expect("reply after upgrade")
            .unwrap();
        assert_eq!(got, reply);
    }

    let client_stats = client_handle.stats();
    let daemon_stats = pair.daemon_handle.stats();
    assert!(client_stats.direct_wg_sent > 0, "{client_stats:?}");
    assert!(client_stats.direct_wg_received > 0, "{client_stats:?}");
    assert!(daemon_stats.direct_wg_received > 0, "{daemon_stats:?}");
    assert_eq!(
        client_stats.fallback_wg_sent, derp_before,
        "no client WireGuard over DERP after the upgrade: {client_stats:?}"
    );
}
