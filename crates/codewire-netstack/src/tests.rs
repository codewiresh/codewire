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

use smoltcp::wire::{IpAddress, IpProtocol, Ipv6Packet, TcpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::{Netstack, NetstackConfig};

/// Documentation-only ULA addresses for the in-process endpoints.
const A_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000a);
const B_IP: Ipv6Addr = Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x000b);
const PREFIX: u8 = 48;

/// Build two netstacks with their packet channels cross-wired so each one's
/// outbound IP packets become the other's inbound packets — an in-process
/// "wire" standing in for an arbitrary packet transport.
fn wired_pair() -> (Netstack, Netstack) {
    // A.out -> B.in
    let (a_out_tx, b_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // B.out -> A.in
    let (b_out_tx, a_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let a = Netstack::new(IpAddr::V6(A_IP), PREFIX, a_in_rx, a_out_tx);
    let b = Netstack::new(IpAddr::V6(B_IP), PREFIX, b_in_rx, b_out_tx);
    (a, b)
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

    let (guest_out, worker_in) = mpsc::unbounded_channel();
    let (worker_out, guest_in) = mpsc::unbounded_channel();
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

    let mut listener = worker
        .bind_endpoint(ORIGINAL_DESTINATION)
        .await
        .expect("bind exact external destination");
    assert_eq!(listener.local_endpoint(), Some(ORIGINAL_DESTINATION));

    let accepted = tokio::spawn(async move {
        listener
            .accept()
            .await
            .expect("worker accepts guest connection")
    });
    let mut guest_stream =
        tokio::time::timeout(Duration::from_secs(5), guest.connect(ORIGINAL_DESTINATION))
            .await
            .expect("guest connect did not hang")
            .expect("guest connect");
    let mut worker_stream = tokio::time::timeout(Duration::from_secs(5), accepted)
        .await
        .expect("worker accept did not hang")
        .expect("worker accept task");

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
    mut from: mpsc::UnboundedReceiver<Vec<u8>>,
    to: mpsc::UnboundedSender<Vec<u8>>,
    failures: Arc<Mutex<Vec<String>>>,
    tcp_segments: Arc<AtomicUsize>,
) {
    tokio::spawn(async move {
        while let Some(pkt) = from.recv().await {
            audit_tunnel_packet(&pkt, &failures, &tcp_segments);
            if to.send(pkt).is_err() {
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

    let (a_out_tx, a_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (b_in_tx, b_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (b_out_tx, b_out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (a_in_tx, a_in_rx) = mpsc::unbounded_channel::<Vec<u8>>();

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
