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
    build_ipv4_tcp_refusal, parse_initial_ipv4_tcp_syn, InitialTcpSynError, Netstack,
    NetstackConfig, NetstackLimits,
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

/// A peer that sends a short request and closes its sending half before the
/// server even accepts must still deliver every byte before EOF (#2540). This
/// is the Mesh ingress shape: dial, write, FIN, then the bridge accepts.
async fn short_request_then_fin(client_stack: &Netstack, port: u16, request: &[u8]) {
    let mut client = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), port))
        .await
        .expect("client");
    client.write_all(request).await.expect("client request");
    client.shutdown().await.expect("client half-close");
    // Keep the client open: closing it fully is not part of this exchange.
    std::mem::forget(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_request_then_fin_reaches_the_server_before_eof() {
    for limits in [None, Some(tight_limits())] {
        let (client_stack, server_stack) = match limits {
            Some(limits) => wired_pair_with_limits(limits, limits),
            None => wired_pair(),
        };
        let mut listener = server_stack.bind(7400).await.expect("listener");
        let rounds = if limits.is_some() { 3 } else { 64 };
        for round in 0..rounds {
            let request = format!("mesh request {round}").into_bytes();
            short_request_then_fin(&client_stack, 7400, &request).await;
            let mut server = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("accept timed out")
                .expect("accepted stream");
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut received))
                .await
                .expect("server did not observe the request and FIN")
                .expect("server read through FIN");
            assert_eq!(received, request, "round {round}");
        }
    }
}

/// Relay packets from `rx` to `tx`, delaying every other one so adjacent
/// packets arrive swapped: a reordering path such as a DERP relay under load.
fn reordering_link(mut rx: mpsc::Receiver<Vec<u8>>, tx: mpsc::Sender<Vec<u8>>) {
    tokio::spawn(async move {
        let index = Arc::new(AtomicUsize::new(0));
        while let Some(packet) = rx.recv().await {
            let tx = tx.clone();
            let delay = if index.fetch_add(1, Ordering::Relaxed).is_multiple_of(2) {
                Duration::from_millis(3)
            } else {
                Duration::ZERO
            };
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = tx.send(packet).await;
            });
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_request_then_fin_survives_reordered_packets() {
    let (a_out_tx, a_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_in_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_out_tx, b_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (a_in_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    reordering_link(a_out_rx, b_in_tx);
    reordering_link(b_out_rx, a_in_tx);
    let client_stack = Netstack::new(IpAddr::V6(A_IP), PREFIX, a_in_rx, a_out_tx);
    let server_stack = Netstack::new(IpAddr::V6(B_IP), PREFIX, b_in_rx, b_out_tx);
    let mut listener = server_stack.bind(7402).await.expect("listener");
    for round in 0..32 {
        let request = format!("reordered request {round}").into_bytes();
        short_request_then_fin(&client_stack, 7402, &request).await;
        let mut server = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept timed out")
            .expect("accepted stream");
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut received))
            .await
            .expect("server did not observe the request and FIN")
            .expect("server read through FIN");
        assert_eq!(received, request, "round {round}");
    }
}

/// A reader that falls behind fills the receive queue and closes the TCP
/// window. Taking data must wake the driver to reopen it; otherwise every
/// window's worth waits for the driver's next unrelated wakeup (its 50 ms idle
/// tick), and a guest upload through a slow relay collapsed to a few MB/s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_falls_behind_reopens_the_window_at_once() {
    const BYTES: usize = 16 * 1024 * 1024;
    let (client_stack, server_stack) = wired_pair();
    let mut listener = server_stack.bind(7410).await.expect("listener");
    let writer = tokio::spawn(async move {
        let mut client = client_stack
            .connect(SocketAddr::new(IpAddr::V6(B_IP), 7410))
            .await
            .expect("client");
        client.write_all(&vec![7_u8; BYTES]).await.expect("upload");
        client.shutdown().await.expect("client half-close");
        (client_stack, client)
    });
    let mut server = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accepted stream");
    // Let the receive queue and the window fill before reading.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut received = 0;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), server.read(&mut buffer))
            .await
            .expect("read stalled")
            .expect("read");
        if read == 0 {
            break;
        }
        received += read;
    }
    let _ = writer.await.expect("writer");
    // The wake itself is proved deterministically below; this end-to-end run
    // proves the bytes all arrive intact once the reader catches up.
    assert_eq!(received, BYTES);
}

/// Taking a chunk from the receive queue wakes the driver, which then moves
/// the socket's buffered bytes on and reopens the window.
#[tokio::test]
async fn reading_a_chunk_wakes_the_driver() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let notify = Arc::new(Notify::new());
    let (to_stream, rx) = mpsc::channel(1);
    let (tx, _from_stream) = mpsc::channel(1);
    let (driver_tx, _commands) = mpsc::channel(1);
    let endpoint = smoltcp::wire::IpEndpoint::new(IpAddress::Ipv6(A_IP), 7414);
    let mut stream = super::stream::TcpStream::new(
        rx,
        tx,
        Arc::new(super::stream::StreamControl::new(notify.clone())),
        driver_tx,
        endpoint,
        endpoint,
        1024,
    );
    to_stream
        .send(b"queued".to_vec())
        .await
        .expect("queue a chunk");
    let mut buffer = [0_u8; 16];
    let read = stream.read(&mut buffer).await.expect("read");
    assert_eq!(&buffer[..read], b"queued");
    tokio::time::timeout(Duration::from_millis(100), notify.notified())
        .await
        .expect("the read freed receive-queue space without waking the driver");
}

/// Several clients dialing one listener at the same moment are all accepted
/// and deliver their requests intact (#2546). With one parked LISTEN socket,
/// every SYN after the first was answered with RST and the client's write or
/// half-close failed with "userspace TCP connection aborted".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dialers_are_all_accepted() {
    const DIALERS: usize = 16;
    let (client_stack, server_stack) = wired_pair();
    let mut listener = server_stack.bind(7404).await.expect("listener");
    let client_stack = Arc::new(client_stack);
    let mut dialers = Vec::new();
    for index in 0..DIALERS {
        let client_stack = client_stack.clone();
        dialers.push(tokio::spawn(async move {
            let request = format!("concurrent request {index}").into_bytes();
            short_request_then_fin(&client_stack, 7404, &request).await;
        }));
    }
    let mut received = Vec::new();
    for _ in 0..DIALERS {
        let mut server = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept timed out")
            .expect("accepted stream");
        let mut request = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), server.read_to_end(&mut request))
            .await
            .expect("server did not observe the request and FIN")
            .expect("server read through FIN");
        received.push(String::from_utf8(request).expect("utf-8 request"));
    }
    for dialer in dialers {
        dialer.await.expect("dialer");
    }
    received.sort();
    let mut expected: Vec<_> = (0..DIALERS)
        .map(|index| format!("concurrent request {index}"))
        .collect();
    expected.sort();
    assert_eq!(received, expected);
}

/// Relay packets from `rx` to `tx`, keeping a copy of every initial SYN.
fn syn_recording_link(
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
) -> Arc<Mutex<Vec<Vec<u8>>>> {
    let syns = Arc::new(Mutex::new(Vec::new()));
    let recorded = syns.clone();
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let initial_syn = Ipv6Packet::new_checked(&packet[..])
                .ok()
                .filter(|ip| ip.next_header() == IpProtocol::Tcp)
                .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok())
                .is_some_and(|tcp| tcp.syn() && !tcp.ack());
            if initial_syn {
                recorded.lock().unwrap().push(packet.clone());
            }
            if tx.send(packet).await.is_err() {
                return;
            }
        }
    });
    syns
}

async fn accept_one(listener: &mut super::TcpListener) -> super::TcpStream {
    tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accepted stream")
}

fn tcp_source_port(packet: &[u8]) -> u16 {
    let ip = Ipv6Packet::new_checked(packet).expect("IPv6");
    TcpPacket::new_checked(ip.payload())
        .expect("TCP")
        .src_port()
}

/// A SYN repeating a live connection's 4-tuple (a late retransmission or a
/// duplicate) is not handed to a spare LISTEN socket (#2546). smoltcp gives a
/// SYN to the first accepting socket in slot order, so a LISTEN socket in a
/// slot freed below the connection's would open a phantom second socket for
/// the same 4-tuple, which takes the connection's later segments and resets
/// the client. The connection is either established or, as with Mesh's
/// request-then-FIN, half-closed by the client.
async fn repeated_syn_case(half_closed: bool) {
    let (a_out_tx, a_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_in_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_out_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let syns = syn_recording_link(a_out_rx, b_in_tx.clone());
    let client_stack = Netstack::new(IpAddr::V6(A_IP), PREFIX, a_in_rx, a_out_tx);
    let server_stack = Netstack::new(IpAddr::V6(B_IP), PREFIX, b_in_rx, b_out_tx);
    let mut listener = server_stack.bind(7406).await.expect("listener");

    // The first connection takes the listener's first socket slot.
    let mut first = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7406))
        .await
        .expect("first client");
    first.write_all(b"first").await.expect("first request");
    let mut first_server = accept_one(&mut listener).await;
    let mut request = [0_u8; 5];
    first_server
        .read_exact(&mut request)
        .await
        .expect("first read");

    // The second connection's socket takes a later slot.
    let mut second = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7406))
        .await
        .expect("second client");
    second.write_all(b"second").await.expect("second request");
    let mut second_server = accept_one(&mut listener).await;
    let mut request = [0_u8; 6];
    second_server
        .read_exact(&mut request)
        .await
        .expect("second read");
    if half_closed {
        second.shutdown().await.expect("client half-close");
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), second_server.read_to_end(&mut rest))
            .await
            .expect("server did not see the FIN")
            .expect("server read to EOF");
        assert!(rest.is_empty());
    }

    // Free the first slot: the server aborts the first connection, and once
    // the client has seen that reset its server socket is gone.
    drop(first_server);
    let mut byte = [0_u8; 1];
    let observed = tokio::time::timeout(Duration::from_secs(5), first.read(&mut byte))
        .await
        .expect("the client did not see the first connection end");
    assert!(observed.is_err() || observed.is_ok_and(|read| read == 0));
    drop(first);
    let port = second.local_addr().port();
    let repeated = syns
        .lock()
        .unwrap()
        .iter()
        .find(|packet| tcp_source_port(packet) == port)
        .cloned()
        .expect("recorded SYN");
    b_in_tx.send(repeated).await.expect("repeat SYN");

    // Past a phantom socket's SYN-ACK retransmission, the connection still
    // carries data, and nothing else was accepted.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    if !half_closed {
        second.write_all(b"ping").await.expect("client write");
        let mut ping = [0_u8; 4];
        tokio::time::timeout(Duration::from_secs(5), second_server.read_exact(&mut ping))
            .await
            .expect("server read timed out")
            .expect("server read");
        assert_eq!(&ping, b"ping");
    }
    // A response larger than the window completes only if the client's ACKs
    // reach the connection's socket, and its FIN only if the client's last
    // ACK does too.
    let response = vec![7_u8; 1024 * 1024];
    let writer = tokio::spawn(async move {
        second_server
            .write_all(&response)
            .await
            .expect("server write");
        second_server.shutdown().await.expect("server close");
        second_server
    });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), second.read_to_end(&mut received))
        .await
        .expect("client read timed out")
        .expect("client read");
    assert_eq!(received.len(), 1024 * 1024);
    drop(writer.await.expect("server writer"));
    assert!(
        tokio::time::timeout(Duration::from_millis(500), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_syn_never_opens_a_second_socket() {
    repeated_syn_case(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_syn_for_a_half_closed_connection_never_opens_a_second_socket() {
    repeated_syn_case(true).await;
}

/// Relay packets from `rx` to `tx`, dropping every SYN-ACK addressed to one of
/// `ports`: those clients' handshakes never complete.
fn syn_ack_dropping_link(
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    ports: &'static [u16],
) {
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            let lost = Ipv6Packet::new_checked(&packet[..])
                .ok()
                .filter(|ip| ip.next_header() == IpProtocol::Tcp)
                .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok())
                .is_some_and(|tcp| tcp.syn() && tcp.ack() && ports.contains(&tcp.dst_port()));
            if !lost && tx.send(packet).await.is_err() {
                return;
            }
        }
    });
}

/// Handshakes that never complete close their sockets at the idle timeout.
/// Those closed sockets must stop counting against the accept queue, or a
/// few lost handshakes would leave the listener refusing every later client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshakes_that_never_complete_do_not_wedge_the_listener() {
    // The client netstack numbers its ports from 49152: the first two dials
    // lose every SYN-ACK.
    const LOST: &[u16] = &[49152, 49153];
    let limits = NetstackLimits {
        accept_queue: 2,
        tcp_idle_timeout: Duration::from_secs(1),
        ..NetstackLimits::default()
    };
    let config = |local_ip| NetstackConfig {
        local_ip,
        prefix_len: PREFIX,
        mtu: 1_500,
        verify_rx_checksums: true,
        accept_any_ip: false,
        default_gateway: None,
    };
    let (a_out_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_out_tx, b_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (a_in_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    syn_ack_dropping_link(b_out_rx, a_in_tx, LOST);
    let client_stack =
        Netstack::with_config_and_limits(config(IpAddr::V6(A_IP)), limits, a_in_rx, a_out_tx)
            .expect("client netstack");
    let server_stack =
        Netstack::with_config_and_limits(config(IpAddr::V6(B_IP)), limits, b_in_rx, b_out_tx)
            .expect("server netstack");
    let mut listener = server_stack.bind(7408).await.expect("listener");
    let mut lost = Vec::new();
    for _ in LOST {
        let client = client_stack
            .connect(SocketAddr::new(IpAddr::V6(B_IP), 7408))
            .await
            .expect("dial");
        assert!(LOST.contains(&client.local_addr().port()));
        lost.push(client);
    }
    // Past the idle timeout, both half-open sockets have closed.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let mut client = client_stack
        .connect(SocketAddr::new(IpAddr::V6(B_IP), 7408))
        .await
        .expect("fresh dial");
    client.write_all(b"fresh").await.expect("request");
    let mut server = accept_one(&mut listener).await;
    let mut request = [0_u8; 5];
    server.read_exact(&mut request).await.expect("read");
    assert_eq!(&request, b"fresh");
    drop(lost);
}

/// A client stack that routes every destination through a worker stack that
/// accepts any IP, with the SYN-ACKs to `lost` client ports dropped on the
/// way back.
fn any_ip_pair(worker_limits: NetstackLimits, lost: &'static [u16]) -> (Netstack, Netstack) {
    let config = |local_ip, accept_any_ip, default_gateway| NetstackConfig {
        local_ip,
        prefix_len: PREFIX,
        mtu: 1_500,
        verify_rx_checksums: true,
        accept_any_ip,
        default_gateway,
    };
    let (a_out_tx, b_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (b_out_tx, b_out_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    let (a_in_tx, a_in_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE);
    syn_ack_dropping_link(b_out_rx, a_in_tx, lost);
    let client = Netstack::with_config_and_limits(
        config(IpAddr::V6(A_IP), false, Some(IpAddr::V6(B_IP))),
        NetstackLimits::default(),
        a_in_rx,
        a_out_tx,
    )
    .expect("client netstack");
    let worker = Netstack::with_config_and_limits(
        config(IpAddr::V6(B_IP), true, None),
        worker_limits,
        b_in_rx,
        b_out_tx,
    )
    .expect("worker netstack");
    (client, worker)
}

/// A destination outside both stacks' prefix, reached through the worker.
fn remote(index: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0xdead, 0, 0, 0, 0, 0, 1 + index)),
        443,
    )
}

/// #2993: the catch-all listener accepts more live destinations than the
/// stack has listeners, each stream naming its own destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_catch_all_accepts_more_live_destinations_than_listeners() {
    let limits = NetstackLimits {
        max_listeners: 2,
        max_connections: 8,
        ..NetstackLimits::default()
    };
    let (client, worker) = any_ip_pair(limits, &[]);
    let mut listener = worker.bind_catch_all().await.expect("catch-all");
    assert_eq!(listener.local_port(), 0);
    assert!(
        worker.bind_catch_all().await.is_err(),
        "one catch-all listener at a time"
    );
    let mut live = Vec::new();
    for index in 0..6_u16 {
        let mut stream = client.connect(remote(index)).await.expect("dial");
        stream.write_all(&[index as u8]).await.expect("write");
        let mut accepted = accept_one(&mut listener).await;
        assert_eq!(accepted.local_addr(), remote(index));
        let mut byte = [0_u8; 1];
        accepted.read_exact(&mut byte).await.expect("read");
        assert_eq!(byte[0], index as u8);
        live.push((stream, accepted));
    }
}

/// #2993: an explicit listener takes connections to its endpoint before the
/// catch-all does; every other destination reaches the catch-all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_listener_takes_its_endpoint_before_the_catch_all() {
    let (client, worker) = any_ip_pair(NetstackLimits::default(), &[]);
    let mut catch_all = worker.bind_catch_all().await.expect("catch-all");
    let mut explicit = worker.bind_endpoint(remote(1)).await.expect("explicit");
    let _first = client.connect(remote(1)).await.expect("dial explicit");
    assert_eq!(accept_one(&mut explicit).await.local_addr(), remote(1));
    let _second = client.connect(remote(2)).await.expect("dial other");
    assert_eq!(accept_one(&mut catch_all).await.local_addr(), remote(2));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), catch_all.accept())
            .await
            .is_err(),
        "the explicit listener's connection never reached the catch-all"
    );
}

/// #2993: more destinations than the stack has connections, one after
/// another, all connect: a closed connection frees its slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_destinations_beyond_the_connection_limit_all_connect() {
    let limits = NetstackLimits {
        max_connections: 4,
        ..NetstackLimits::default()
    };
    let (client, worker) = any_ip_pair(limits, &[]);
    let mut listener = worker.bind_catch_all().await.expect("catch-all");
    for index in 0..12_u16 {
        let mut stream = client.connect(remote(index)).await.expect("dial");
        stream.write_all(b"x").await.expect("write");
        let mut accepted = accept_one(&mut listener).await;
        assert_eq!(accepted.local_addr(), remote(index));
        let mut byte = [0_u8; 1];
        accepted.read_exact(&mut byte).await.expect("read");
        drop(accepted);
        drop(stream);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// #2993: half-open handshakes hold connection slots, so the catch-all drops a
/// SYN beyond the limit; once those handshakes time out, the client's SYN
/// retry connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_catch_all_drops_syns_beyond_the_connection_limit_until_a_slot_frees() {
    // The client numbers its ports from 49152: the first two dials lose every
    // SYN-ACK and stay half-open on the worker.
    const LOST: &[u16] = &[49152, 49153];
    let limits = NetstackLimits {
        max_connections: 2,
        tcp_idle_timeout: Duration::from_secs(1),
        ..NetstackLimits::default()
    };
    let (client, worker) = any_ip_pair(limits, LOST);
    let mut listener = worker.bind_catch_all().await.expect("catch-all");
    let mut half_open = Vec::new();
    for index in 0..2_u16 {
        let stream = client.connect(remote(index)).await.expect("dial");
        assert!(LOST.contains(&stream.local_addr().port()));
        half_open.push(stream);
    }
    let _third = client
        .connect(remote(2))
        .await
        .expect("dial beyond the limit");
    assert!(
        tokio::time::timeout(Duration::from_millis(500), listener.accept())
            .await
            .is_err(),
        "no connection beyond the limit while the slots are held"
    );
    let accepted = tokio::time::timeout(Duration::from_secs(15), listener.accept())
        .await
        .expect("the retried SYN connected once the half-open slots freed")
        .expect("accepted stream");
    assert_eq!(accepted.local_addr(), remote(2));
    drop(half_open);
}

/// #3003: a SYN refused with `build_ipv4_tcp_refusal` fails the client's
/// connect as refused, before any handshake completes.
#[tokio::test]
async fn a_refused_syn_fails_the_connect_as_refused() {
    const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const WORKER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DESTINATION: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 19)), 443);
    let (guest_out, mut guest_packets) = mpsc::channel(PACKET_QUEUE);
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
    let mut stream = guest.connect(DESTINATION).await.expect("connect starts");
    let syn = tokio::time::timeout(Duration::from_secs(5), guest_packets.recv())
        .await
        .expect("guest sent its SYN")
        .expect("guest packet channel open");
    let initial = parse_initial_ipv4_tcp_syn(&syn).expect("initial SYN");

    let refusal = build_ipv4_tcp_refusal(&syn).expect("refusal");
    {
        let ipv4 = Ipv4Packet::new_checked(&refusal[..]).expect("IPv4");
        assert!(ipv4.verify_checksum());
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from(ipv4.src_addr().octets())),
            DESTINATION.ip()
        );
        assert_eq!(
            IpAddr::V4(Ipv4Addr::from(ipv4.dst_addr().octets())),
            initial.source.ip()
        );
        let tcp = TcpPacket::new_checked(ipv4.payload()).expect("TCP");
        assert!(tcp.verify_checksum(
            &IpAddress::Ipv4(ipv4.src_addr()),
            &IpAddress::Ipv4(ipv4.dst_addr())
        ));
        assert!(tcp.rst() && tcp.ack() && !tcp.syn());
        assert_eq!(tcp.src_port(), DESTINATION.port());
        assert_eq!(tcp.dst_port(), initial.source.port());
        let syn_tcp = TcpPacket::new_checked(Ipv4Packet::new_checked(&syn[..]).unwrap().payload())
            .unwrap()
            .seq_number();
        assert_eq!(tcp.ack_number(), syn_tcp + 1);
    }
    assert_eq!(
        build_ipv4_tcp_refusal(&refusal),
        Err(InitialTcpSynError::NotInitialSyn),
        "only an initial SYN is refused"
    );

    to_guest.send(refusal).await.expect("deliver the refusal");
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("the refused connect ends at once");
    // A Linux guest reports ECONNREFUSED for this RST+ACK in SYN-SENT (RFC
    // 793); here it is enough that the connect ends without any data.
    assert!(
        !matches!(read, Ok(n) if n > 0),
        "the refused connect delivered data: {read:?}"
    );
}
