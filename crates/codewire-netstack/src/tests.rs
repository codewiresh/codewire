//! #59 netstack spike — in-process loopback proof.
//!
//! This is the hard gate: it proves a real userspace TCP handshake + data
//! transfer happens over the bare-IP-packet abstraction, with no kernel TUN,
//! no encrypted transport and no real sockets involved. We stand up two [`Netstack`]
//! instances and cross-wire their packet channels:
//!
//! ```text
//!   A.outbound ──────────────► B.inbound
//!   B.outbound ──────────────► A.inbound
//! ```
//!
//! Then B binds a port, A connects to B's interface IP:port, and we exchange
//! bytes in **both directions** over the resulting TCP streams. If the
//! payloads round-trip, smoltcp drove a SYN/SYN-ACK/ACK handshake and
//! segmented data purely through our `phy::Device` channel seam.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{
    parse_initial_ipv4_tcp_syn, InitialTcpSynError, Netstack, NetstackConfig, NetstackLimits,
};

/// Documentation-only ULA addresses for the in-process endpoints.
const A_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000a);
const B_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000b);
const PREFIX: u8 = 48;
const PACKET_QUEUE: usize = 64;

/// Build two netstacks with their packet channels cross-wired so each one's
/// outbound IP packets become the other's inbound packets — an in-process
/// "wire" standing in for an arbitrary packet transport.
fn wired_pair() -> (Netstack, Netstack) {
    // A.out -> B.in
    let (a_out_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    // B.out -> A.in
    let (b_out_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);

    let a = Netstack::new(IpAddr::V6(A_IP), PREFIX, a_in_rx, a_out_tx);
    let b = Netstack::new(IpAddr::V6(B_IP), PREFIX, b_in_rx, b_out_tx);
    (a, b)
}

fn wired_pair_with_limits(
    a_limits: NetstackLimits,
    b_limits: NetstackLimits,
) -> (Netstack, Netstack) {
    let packet_capacity = a_limits.max_queued_packets.min(b_limits.max_queued_packets);
    let (a_out_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(packet_capacity);
    let (b_out_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(packet_capacity);
    let config = |local_ip| NetstackConfig {
        local_ip,
        prefix_len: PREFIX,
        mtu: 1_500,
        verify_rx_checksums: true,
        accept_any_ip: false,
        default_gateway: None,
    };
    let a = Netstack::with_config_and_limits(config(IpAddr::V6(A_IP)), a_limits, a_in_rx, a_out_tx)
        .expect("A bounded netstack");
    let b = Netstack::with_config_and_limits(config(IpAddr::V6(B_IP)), b_limits, b_in_rx, b_out_tx)
        .expect("B bounded netstack");
    (a, b)
}

fn tight_limits() -> NetstackLimits {
    NetstackLimits {
        max_listeners: 4,
        max_connections: 4,
        socket_buffer_bytes: 1024,
        command_queue: 4,
        accept_queue: 1,
        stream_send_queue: 1,
        stream_receive_queue: 1,
        stream_chunk_bytes: 128,
        max_queued_packets: 16,
        max_packets_per_wake: 4,
        tcp_idle_timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn loopback_tcp_handshake_and_bidirectional_transfer() {
    let (a, b) = wired_pair();

    let port = 2222; // arbitrary; mirrors `Listen("tcp", ":22")`-style usage.

    // B binds and waits to accept.
    let mut listener = b.bind(port).await.expect("bind");
    let accept_task = tokio::spawn(async move {
        let stream = listener
            .accept()
            .await
            .expect("listener accepts an inbound stream");
        stream
    });

    // A connects to B's interface IP:port.
    let dst = SocketAddr::new(IpAddr::V6(B_IP), port);
    let mut a_stream = tokio::time::timeout(Duration::from_secs(5), a.connect(dst))
        .await
        .expect("connect did not hang")
        .expect("connect");

    // A -> B: send a request.
    let request = b"hello over userspace TCP";
    a_stream.write_all(request).await.expect("client write");
    a_stream.flush().await.expect("client flush");

    // B accepts and reads the request.
    let mut b_stream = tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .expect("accept did not hang")
        .expect("accept task");

    let mut got = vec![0u8; request.len()];
    tokio::time::timeout(Duration::from_secs(5), b_stream.read_exact(&mut got))
        .await
        .expect("server read did not hang")
        .expect("server read_exact");
    assert_eq!(&got, request, "B must receive exactly what A sent");

    // B -> A: send a response back over the same connection.
    let response = b"ack from the listener side";
    b_stream.write_all(response).await.expect("server write");
    b_stream.flush().await.expect("server flush");

    let mut got_back = vec![0u8; response.len()];
    tokio::time::timeout(Duration::from_secs(5), a_stream.read_exact(&mut got_back))
        .await
        .expect("client read did not hang")
        .expect("client read_exact");
    assert_eq!(&got_back, response, "A must receive exactly what B sent");
}

#[tokio::test]
async fn any_ip_destination_bridges_only_through_an_injected_stream() {
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const WORKER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const ORIGINAL_DESTINATION: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 19)), 443);

    let (guest_out, mut guest_packets) = mpsc::channel(PACKET_QUEUE);
    let (to_worker, worker_in) = mpsc::channel(PACKET_QUEUE);
    let (worker_out, mut worker_packets) = mpsc::channel(PACKET_QUEUE);
    let (to_guest, guest_in) = mpsc::channel(PACKET_QUEUE);
    let guest = Netstack::with_config(
        NetstackConfig {
            local_ip: IpAddr::V4(GUEST_IP),
            prefix_len: 30,
            mtu: 1_500,
            verify_rx_checksums: true,
            accept_any_ip: false,
            default_gateway: Some(IpAddr::V4(WORKER_IP)),
        },
        guest_in,
        guest_out,
    )
    .expect("guest netstack config");
    let worker = Netstack::with_config(
        NetstackConfig {
            local_ip: IpAddr::V4(WORKER_IP),
            prefix_len: 30,
            mtu: 1_500,
            verify_rx_checksums: true,
            accept_any_ip: true,
            default_gateway: None,
        },
        worker_in,
        worker_out,
    )
    .expect("worker netstack config");

    let connect = tokio::spawn(async move {
        guest
            .connect(ORIGINAL_DESTINATION)
            .await
            .expect("guest connect")
    });
    let initial_packet = tokio::time::timeout(Duration::from_secs(5), guest_packets.recv())
        .await
        .expect("guest did not emit an initial packet")
        .expect("guest packet channel closed");
    let initial = parse_initial_ipv4_tcp_syn(&initial_packet).expect("strict initial SYN");
    assert_eq!(initial.source.ip(), IpAddr::V4(GUEST_IP));
    assert_eq!(initial.destination, ORIGINAL_DESTINATION);

    assert_eq!(
        parse_initial_ipv4_tcp_syn(&initial_packet[..10]),
        Err(InitialTcpSynError::InvalidIpv4)
    );
    let mut trailing = initial_packet.clone();
    trailing.push(0);
    assert_eq!(
        parse_initial_ipv4_tcp_syn(&trailing),
        Err(InitialTcpSynError::NonCanonicalIpv4Length)
    );
    let mut corrupt_checksum = initial_packet.clone();
    corrupt_checksum[8] ^= 1;
    assert_eq!(
        parse_initial_ipv4_tcp_syn(&corrupt_checksum),
        Err(InitialTcpSynError::InvalidIpv4Checksum)
    );
    let mut fragmented = initial_packet.clone();
    {
        let mut ipv4 = Ipv4Packet::new_unchecked(fragmented.as_mut_slice());
        ipv4.set_more_frags(true);
        ipv4.fill_checksum();
    }
    assert_eq!(
        parse_initial_ipv4_tcp_syn(&fragmented),
        Err(InitialTcpSynError::FragmentedIpv4)
    );

    // Admission is dynamic: only after the caller validates the surfaced
    // original destination does it bind that exact AnyIP endpoint and feed
    // the SYN to the stack.
    let mut listener = worker
        .bind_endpoint(ORIGINAL_DESTINATION)
        .await
        .expect("bind exact external destination");
    assert_eq!(listener.local_endpoint(), Some(ORIGINAL_DESTINATION));
    to_worker
        .send(initial_packet)
        .await
        .expect("forward admitted initial SYN");

    let guest_wire = tokio::spawn(async move {
        while let Some(packet) = guest_packets.recv().await {
            if to_worker.send(packet).await.is_err() {
                break;
            }
        }
    });
    let worker_wire = tokio::spawn(async move {
        while let Some(packet) = worker_packets.recv().await {
            if to_guest.send(packet).await.is_err() {
                break;
            }
        }
    });

    let accepted = tokio::spawn(async move {
        listener
            .accept()
            .await
            .expect("worker accepts guest connection")
    });
    let mut guest_stream = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .expect("guest connect did not hang")
        .expect("guest connect task");
    let mut worker_stream = tokio::time::timeout(Duration::from_secs(5), accepted)
        .await
        .expect("worker accept did not hang")
        .expect("worker accept task");
    assert_eq!(worker_stream.local_addr(), ORIGINAL_DESTINATION);
    assert_eq!(worker_stream.peer_addr(), initial.source);

    // The duplex pair models a connected stream injected by the egress
    // broker. Neither userspace netstack owns or creates a host socket.
    let (mut worker_connector, mut synthetic_upstream) = tokio::io::duplex(4096);
    let bridge = tokio::spawn(async move {
        tokio::io::copy_bidirectional(&mut worker_stream, &mut worker_connector).await
    });

    let request = b"synthetic request through broker connector";
    guest_stream.write_all(request).await.expect("guest write");
    let mut received = vec![0; request.len()];
    tokio::time::timeout(
        Duration::from_secs(5),
        synthetic_upstream.read_exact(&mut received),
    )
    .await
    .expect("injected connector read did not hang")
    .expect("injected connector read");
    assert_eq!(received, request);

    let response = b"synthetic response from broker connector";
    synthetic_upstream
        .write_all(response)
        .await
        .expect("injected connector write");
    let mut returned = vec![0; response.len()];
    tokio::time::timeout(
        Duration::from_secs(5),
        guest_stream.read_exact(&mut returned),
    )
    .await
    .expect("guest response did not hang")
    .expect("guest response read");
    assert_eq!(returned, response);

    guest_stream.shutdown().await.expect("guest shutdown");
    drop(guest_stream);
    drop(synthetic_upstream);
    tokio::time::timeout(Duration::from_secs(5), bridge)
        .await
        .expect("bridge shutdown did not hang")
        .expect("bridge task")
        .expect("bridge copy");
    guest_wire.abort();
    worker_wire.abort();
}

#[tokio::test]
async fn listener_and_packet_queue_limits_are_hard_and_recoverable() {
    let mut limits = tight_limits();
    limits.max_listeners = 1;
    limits.max_queued_packets = 4;
    limits.max_packets_per_wake = 2;

    let (oversized_out, _oversized_packets) = mpsc::channel(5);
    let (_oversized_in, oversized_rx) = mpsc::channel(4);
    let invalid = Netstack::with_config_and_limits(
        NetstackConfig {
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix_len: 30,
            mtu: 1_500,
            verify_rx_checksums: true,
            accept_any_ip: true,
            default_gateway: None,
        },
        limits,
        oversized_rx,
        oversized_out,
    );
    assert!(invalid.is_err(), "oversized packet queues must be rejected");

    let (outbound, _packets) = mpsc::channel(4);
    let (keep_inbound_open, inbound) = mpsc::channel(4);
    let stack = Netstack::with_config_and_limits(
        NetstackConfig {
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix_len: 30,
            mtu: 1_500,
            verify_rx_checksums: true,
            accept_any_ip: true,
            default_gateway: None,
        },
        limits,
        inbound,
        outbound,
    )
    .expect("bounded stack");
    let first_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 443);
    let second_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 443);
    let first = stack
        .bind_endpoint(first_endpoint)
        .await
        .expect("first bind");
    match stack.bind_endpoint(first_endpoint).await {
        Ok(_) => panic!("duplicate endpoint must not bind"),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse),
    }
    assert!(
        stack.bind_endpoint(second_endpoint).await.is_err(),
        "a second live listener must exceed the configured limit"
    );
    drop(first);
    let replacement = stack
        .bind_endpoint(second_endpoint)
        .await
        .expect("dropping a listener must release its slot");
    assert_eq!(replacement.local_endpoint(), Some(second_endpoint));
    drop(keep_inbound_open);
}

#[tokio::test]
async fn connection_limit_rejects_excess_and_recovers_after_drop() {
    let guest_limits = tight_limits();
    let mut worker_limits = tight_limits();
    worker_limits.max_connections = 1;
    let (guest, worker) = wired_pair_with_limits(guest_limits, worker_limits);
    let mut first_listener = worker.bind(7101).await.expect("first listener");
    let mut second_listener = worker.bind(7102).await.expect("second listener");

    let first_client = guest
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7101))
        .await
        .expect("first client");
    let first_server = tokio::time::timeout(Duration::from_secs(2), first_listener.accept())
        .await
        .expect("first accept timed out")
        .expect("first accepted stream");

    let excess_client = guest
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7102))
        .await
        .expect("excess client starts locally");
    assert!(
        tokio::time::timeout(Duration::from_millis(150), second_listener.accept())
            .await
            .is_err(),
        "worker must not surface a connection beyond its cap"
    );

    drop(excess_client);
    drop(first_server);
    drop(first_client);
    tokio::time::sleep(Duration::from_millis(20)).await;

    let replacement_client = guest
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7102))
        .await
        .expect("replacement client");
    let replacement_server = tokio::time::timeout(Duration::from_secs(2), second_listener.accept())
        .await
        .expect("replacement accept timed out")
        .expect("replacement accepted stream");
    drop(replacement_server);
    drop(replacement_client);
}

#[tokio::test]
async fn bounded_stream_queues_apply_backpressure() {
    let limits = tight_limits();
    let (client_stack, server_stack) = wired_pair_with_limits(limits, limits);
    let mut listener = server_stack.bind(7200).await.expect("listener");
    let mut client = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7200))
        .await
        .expect("client");
    let _server = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accepted stream");

    let payload = vec![0x5a; 1024 * 1024];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), client.write_all(&payload))
            .await
            .is_err(),
        "a non-reading peer must backpressure a bounded writer"
    );
}

#[tokio::test]
async fn half_close_keeps_the_reverse_direction_open() {
    let (client_stack, server_stack) = wired_pair();
    let mut listener = server_stack.bind(7300).await.expect("listener");
    let mut client = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7300))
        .await
        .expect("client");
    let mut server = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accepted stream");

    client.write_all(b"request").await.expect("client request");
    client.shutdown().await.expect("client half-close");
    let mut request = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut request))
        .await
        .expect("server did not observe client FIN")
        .expect("server read through FIN");
    assert_eq!(request, b"request");

    server
        .write_all(b"response")
        .await
        .expect("server response");
    let mut response = [0; 8];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .expect("client did not receive reverse-direction response")
        .expect("client response read");
    assert_eq!(&response, b"response");
    server.shutdown().await.expect("server half-close");
    let mut eof = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut eof))
        .await
        .expect("client did not observe server FIN")
        .expect("client read through FIN");
    assert!(eof.is_empty());
}

#[tokio::test]
async fn dropped_peer_surfaces_a_prompt_connection_abort() {
    let (client_stack, server_stack) = wired_pair();
    let mut listener = server_stack.bind(7400).await.expect("listener");
    let mut client = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7400))
        .await
        .expect("client");
    let server = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accepted stream");
    drop(server);

    let mut byte = [0; 1];
    let error = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("peer reset did not terminate the connection")
        .expect_err("peer reset must not look like a clean EOF");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn packet_transport_loss_closes_listeners_and_rejects_commands() {
    let (outbound, _packets) = mpsc::channel(PACKET_QUEUE);
    let (inbound, inbound_rx) = mpsc::channel(PACKET_QUEUE);
    let stack = Netstack::new(IpAddr::V6(A_IP), PREFIX, inbound_rx, outbound);
    let mut listener = stack.bind(7500).await.expect("listener");

    drop(inbound);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("listener did not close after packet transport loss")
            .is_none(),
        "packet transport loss must close the accept side"
    );
    assert!(
        stack.bind(7501).await.is_err(),
        "driver commands must fail after packet transport loss"
    );
}

#[tokio::test]
async fn idle_timeout_reclaims_a_silent_connection() {
    let mut limits = tight_limits();
    limits.tcp_idle_timeout = Duration::from_secs(1);
    let (client_stack, server_stack) = wired_pair_with_limits(limits, limits);
    let mut listener = server_stack.bind(7600).await.expect("listener");
    let mut client = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7600))
        .await
        .expect("client");
    let _server = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accepted stream");

    let mut byte = [0; 1];
    let error = tokio::time::timeout(Duration::from_secs(3), client.read(&mut byte))
        .await
        .expect("idle timeout did not reclaim the connection")
        .expect_err("idle timeout must not look like a clean EOF");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
}

/// Audit one wire packet like a checksum-verifying peer: every TCP segment
/// leaving the stack must carry a fully computed checksum.
fn audit_tunnel_packet(pkt: &[u8], failures: &Mutex<Vec<String>>, tcp_segments: &AtomicUsize) {
    let ip = match Ipv6Packet::new_checked(pkt) {
        Ok(ip) => ip,
        Err(e) => {
            failures
                .lock()
                .unwrap()
                .push(format!("packet does not parse as IPv6: {e}"));
            return;
        }
    };
    if ip.next_header() != IpProtocol::Tcp {
        return;
    }
    let src = IpAddress::Ipv6(ip.src_addr());
    let dst = IpAddress::Ipv6(ip.dst_addr());
    match TcpPacket::new_checked(ip.payload()) {
        Ok(tcp) => {
            if !tcp.verify_checksum(&src, &dst) {
                failures.lock().unwrap().push(format!(
                    "TCP segment {src} -> {dst} has an invalid checksum"
                ));
            }
            tcp_segments.fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => {
            failures
                .lock()
                .unwrap()
                .push(format!("TCP segment does not parse: {e}"));
        }
    }
}

fn spawn_auditing_wire(
    mut from: mpsc::Receiver<Vec<u8>>,
    to: mpsc::Sender<Vec<u8>>,
    failures: Arc<Mutex<Vec<String>>>,
    tcp_segments: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        while let Some(pkt) = from.recv().await {
            audit_tunnel_packet(&pkt, &failures, &tcp_segments);
            if to.send(pkt).await.is_err() {
                break;
            }
        }
    });
}

/// Checksum contract. A same-engine loopback passes even with
/// checksums disabled on both ends (neither side verifies), which is exactly
/// how a broken-TX-checksum stack can look green locally while a strict peer
/// drops every packet on ingress. Here the wire itself plays that peer and
/// fails the test if any segment would not survive `gro.RXChecksumOffload`.
#[tokio::test]
async fn loopback_packets_carry_verifiable_checksums() {
    let failures = Arc::new(Mutex::new(Vec::new()));
    let tcp_segments = Arc::new(AtomicUsize::new(0));

    let (a_out_tx, a_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_in_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_out_tx, b_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (a_in_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);

    let a = Netstack::new(IpAddr::V6(A_IP), PREFIX, a_in_rx, a_out_tx);
    let b = Netstack::new(IpAddr::V6(B_IP), PREFIX, b_in_rx, b_out_tx);

    spawn_auditing_wire(a_out_rx, b_in_tx, failures.clone(), tcp_segments.clone());
    spawn_auditing_wire(b_out_rx, a_in_tx, failures.clone(), tcp_segments.clone());

    let port = 4222;
    let mut listener = b.bind(port).await.expect("bind");
    let accept_task = tokio::spawn(async move { listener.accept().await.expect("accept") });

    let dst = SocketAddr::new(IpAddr::V6(B_IP), port);
    let mut a_stream = tokio::time::timeout(Duration::from_secs(5), a.connect(dst))
        .await
        .expect("connect did not hang")
        .expect("connect");

    let request = b"checksum audit request";
    a_stream.write_all(request).await.expect("client write");
    a_stream.flush().await.expect("client flush");

    let mut b_stream = tokio::time::timeout(Duration::from_secs(5), accept_task)
        .await
        .expect("accept did not hang")
        .expect("accept task");
    let mut got = vec![0u8; request.len()];
    tokio::time::timeout(Duration::from_secs(5), b_stream.read_exact(&mut got))
        .await
        .expect("server read did not hang")
        .expect("server read_exact");
    assert_eq!(&got, request);

    let response = b"checksum audit response";
    b_stream.write_all(response).await.expect("server write");
    b_stream.flush().await.expect("server flush");
    let mut got_back = vec![0u8; response.len()];
    tokio::time::timeout(Duration::from_secs(5), a_stream.read_exact(&mut got_back))
        .await
        .expect("client read did not hang")
        .expect("client read_exact");
    assert_eq!(&got_back, response);

    let failures = failures.lock().unwrap();
    assert!(
        failures.is_empty(),
        "wire packets a checksum-verifying peer would drop: {failures:?}"
    );
    assert!(
        tcp_segments.load(Ordering::Relaxed) >= 3,
        "expected at least the handshake segments to cross the wire"
    );
}

/// A larger, multi-segment transfer to prove smoltcp is actually segmenting,
/// ACKing, and reassembling across configured-MTU packets (not just fitting one
/// payload in a single packet).
#[tokio::test]
async fn loopback_multi_segment_stream() {
    let (a, b) = wired_pair();
    let port = 9000;

    let mut listener = b.bind(port).await.expect("bind");
    let echo_task = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept");
        // Echo everything back until EOF.
        let mut buf = vec![0u8; 4096];
        let mut total = Vec::new();
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    total.extend_from_slice(&buf[..n]);
                    stream.write_all(&buf[..n]).await.expect("echo write");
                }
                Err(e) => panic!("echo read error: {e}"),
            }
        }
        stream.flush().await.ok();
        total
    });

    let dst = SocketAddr::new(IpAddr::V6(B_IP), port);
    let mut a_stream = tokio::time::timeout(Duration::from_secs(5), a.connect(dst))
        .await
        .expect("connect did not hang")
        .expect("connect");

    // 16 KiB spans many MTU-sized tunnel packets.
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
    a_stream.write_all(&payload).await.expect("write payload");
    a_stream.flush().await.expect("flush");

    // Read the echo back fully.
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), a_stream.read_exact(&mut echoed))
        .await
        .expect("echo read did not hang")
        .expect("read echo");
    assert_eq!(echoed, payload, "echoed bytes must match the sent payload");

    // Close write side so the echo task sees EOF and finishes.
    a_stream.shutdown().await.ok();
    drop(a_stream);

    let server_total = tokio::time::timeout(Duration::from_secs(5), echo_task)
        .await
        .expect("echo task did not hang")
        .expect("echo task");
    assert_eq!(
        server_total, payload,
        "server must have received the whole payload across segments"
    );
}
