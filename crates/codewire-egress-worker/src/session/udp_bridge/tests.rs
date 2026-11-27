use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use codewire_netstack::parse_canonical_ipv4_udp_datagram;
use tokio::sync::mpsc;

use super::*;

const GUEST_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 6);
const PEER_A: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 35), 41_641);
const PEER_B: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 40), 41_641);
const OTHER_IP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 41_641);
const OTHER_PORT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 35), 41_642);

fn build_raw_ipv4_udp(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    zero_udp_checksum: bool,
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).unwrap();
    let total_len = u16::try_from(28 + payload.len()).unwrap();
    let mut packet = vec![0_u8; usize::from(total_len)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());
    let ip_ck = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_ck.to_be_bytes());
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    if !zero_udp_checksum {
        let udp_ck = udp_ipv4_checksum(src_ip, dst_ip, &packet[20..]);
        packet[26..28].copy_from_slice(&udp_ck.to_be_bytes());
    }
    packet
}

#[test]
fn outbound_allows_exact_guest_31000_to_allowlisted_peer_with_valid_or_zero_checksum() {
    let allowed = [PEER_A, PEER_B];
    let with_ck = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"disco-ping",
        false,
    );
    assert_eq!(
        parse_outbound_udp(
            &with_ck,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        Some((PEER_A, b"disco-ping".as_slice()))
    );

    // IPv4 zero UDP checksum means "none" per RFC 768 and is accepted.
    let zero_ck = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_B.ip(),
        PEER_B.port(),
        b"wg-data",
        true,
    );
    assert_eq!(
        parse_outbound_udp(
            &zero_ck,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        Some((PEER_B, b"wg-data".as_slice()))
    );
}

#[test]
fn outbound_rejects_wrong_sport_spoofed_src_non_allowlisted_dst_fragments_checksum_and_oversized() {
    let allowed = [PEER_A];

    // Wrong source port (sport != 31000)
    let wrong_sport = build_raw_ipv4_udp(
        GUEST_IP,
        31_001,
        *PEER_A.ip(),
        PEER_A.port(),
        b"nope",
        false,
    );
    assert_eq!(
        parse_outbound_udp(
            &wrong_sport,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Spoofed source IP
    let spoofed_src = build_raw_ipv4_udp(
        Ipv4Addr::new(192, 0, 2, 2),
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"spoof",
        false,
    );
    assert_eq!(
        parse_outbound_udp(
            &spoofed_src,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Non-allowlisted IP and non-allowlisted port
    let bad_ip = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *OTHER_IP.ip(),
        OTHER_IP.port(),
        b"ip",
        false,
    );
    let bad_port = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *OTHER_PORT.ip(),
        OTHER_PORT.port(),
        b"port",
        false,
    );
    assert_eq!(
        parse_outbound_udp(
            &bad_ip,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );
    assert_eq!(
        parse_outbound_udp(
            &bad_port,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Fragmented IPv4 (MF=1)
    let mut mf = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"frag",
        false,
    );
    mf[6] = 0x20;
    mf[7] = 0x00;
    mf[10..12].fill(0);
    let ck = internet_checksum(&mf[..20]);
    mf[10..12].copy_from_slice(&ck.to_be_bytes());
    assert_eq!(
        parse_outbound_udp(
            &mf,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Fragmented IPv4 (frag_offset > 0)
    let mut offset = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"frag",
        false,
    );
    offset[6] = 0x00;
    offset[7] = 0x01;
    offset[10..12].fill(0);
    let ck = internet_checksum(&offset[..20]);
    offset[10..12].copy_from_slice(&ck.to_be_bytes());
    assert_eq!(
        parse_outbound_udp(
            &offset,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Bad non-zero UDP checksum
    let mut bad_udp_ck = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"corrupt",
        false,
    );
    bad_udp_ck[26] ^= 0x01;
    assert_eq!(
        parse_outbound_udp(
            &bad_udp_ck,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Bad IPv4 header checksum
    let mut bad_ip_ck = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"corrupt",
        false,
    );
    bad_ip_ck[10] ^= 0x01;
    assert_eq!(
        parse_outbound_udp(
            &bad_ip_ck,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );

    // Oversized payload (> MTU - 28)
    let oversized_payload = vec![0xab; MAX_UDP_BRIDGE_PAYLOAD + 1];
    let oversized = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        &oversized_payload,
        false,
    );
    assert_eq!(
        parse_outbound_udp(
            &oversized,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );
}

#[test]
fn inbound_builds_valid_canonical_ipv4_udp_and_rejects_unlisted_or_oversized() {
    let allowed = [PEER_A];
    let frame = build_inbound_udp(
        PEER_A,
        GUEST_IP,
        TAILNET_UDP_PORT,
        b"relay-reply",
        &allowed,
        MAX_UDP_BRIDGE_PAYLOAD,
    )
    .expect("allowlisted peer within MTU builds valid frame");

    let parsed = parse_canonical_ipv4_udp_datagram(&frame).expect("valid canonical frame");
    assert_eq!(is_ipv4_udp_peer(parsed.source), Some(PEER_A));
    assert_eq!(
        is_ipv4_udp_peer(parsed.destination),
        Some(SocketAddrV4::new(GUEST_IP, TAILNET_UDP_PORT))
    );
    assert_eq!(&frame[IPV4_UDP_HEADER_LEN..], b"relay-reply");

    // Non-allowlisted sender or oversized payload refused.
    assert_eq!(
        build_inbound_udp(
            OTHER_IP,
            GUEST_IP,
            TAILNET_UDP_PORT,
            b"drop",
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );
    assert_eq!(
        build_inbound_udp(
            OTHER_PORT,
            GUEST_IP,
            TAILNET_UDP_PORT,
            b"drop",
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD
        ),
        None
    );
    assert_eq!(
        build_inbound_udp(
            PEER_A,
            GUEST_IP,
            TAILNET_UDP_PORT,
            &vec![0x11; MAX_UDP_BRIDGE_PAYLOAD + 1],
            &allowed,
            MAX_UDP_BRIDGE_PAYLOAD,
        ),
        None
    );
}

#[tokio::test]
async fn bridge_handle_forwards_bidirectionally_and_drops_on_full_without_blocking() {
    let (mut host_end, worker_end) = tokio::io::duplex(64 * 1024);
    let (to_guest_tx, mut to_guest_rx) = mpsc::channel(2);
    let handle = UdpBridgeHandle::spawn(
        UdpBridgeAttachment {
            stream: Box::pin(worker_end),
            allowed_peers: vec![PEER_A],
        },
        GUEST_IP,
        NETWORK_MTU,
        to_guest_tx,
    )
    .expect("non-empty peers start bridge");

    // Outbound: valid packet forwards; non-allowlisted returns false.
    let valid_out = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *PEER_A.ip(),
        PEER_A.port(),
        b"hello-relay",
        false,
    );
    let bad_out = build_raw_ipv4_udp(
        GUEST_IP,
        TAILNET_UDP_PORT,
        *OTHER_IP.ip(),
        OTHER_IP.port(),
        b"drop",
        false,
    );
    assert!(handle.try_forward_from_guest(&valid_out));
    assert!(!handle.try_forward_from_guest(&bad_out));

    let mut recv_buf = vec![0_u8; MAX_UDP_BRIDGE_PAYLOAD];
    let (dst, len) = tokio::time::timeout(
        Duration::from_secs(2),
        read_udp_bridge_frame(&mut host_end, &mut recv_buf),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(dst, PEER_A);
    assert_eq!(&recv_buf[..len], b"hello-relay");

    // Inbound: non-allowlisted sender silently dropped; allowlisted arrives;
    // flooding beyond channel capacity (2) drops cleanly without blocking!
    write_udp_bridge_frame(&mut host_end, OTHER_IP, b"untrusted")
        .await
        .unwrap();
    for seq in 0_u8..10 {
        write_udp_bridge_frame(&mut host_end, PEER_A, &[seq; 16])
            .await
            .unwrap();
    }
    let first = tokio::time::timeout(Duration::from_secs(2), to_guest_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let parsed = parse_canonical_ipv4_udp_datagram(&first).unwrap();
    assert_eq!(is_ipv4_udp_peer(parsed.source), Some(PEER_A));
    assert_eq!(&first[IPV4_UDP_HEADER_LEN..], &[0_u8; 16]);

    // Because the reader used try_send while the queue held 2 items, writing
    // 10 frames never blocked even though we had not drained yet.
    drop(handle);
}

#[tokio::test]
async fn session_dispatches_allowlisted_udp_to_bridge_and_non_matching_to_udp_refusals() {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use codewire_network_session::{
        NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck, NetworkHostHello,
        NetworkHostReady, NetworkKey, NetworkRole, NetworkSession, SessionLimits,
        encoded_network_frame_len,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use uuid::Uuid;

    use crate::session::{
        BoxedBrokerStream, BrokerDnsAnswer, EgressBroker, SessionAddresses, TcpFlow,
        run_network_session_with_channels,
    };

    struct RecordingBroker {
        refused_udp: Mutex<Vec<SocketAddr>>,
    }

    #[async_trait]
    impl EgressBroker for RecordingBroker {
        async fn authorize_tcp(&self, _flow: TcpFlow) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        }
        async fn connect_tcp(&self, _flow: TcpFlow) -> io::Result<BoxedBrokerStream> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        }
        async fn resolve_dns(
            &self,
            _question: &codewire_netstack::DnsQuestion,
        ) -> io::Result<BrokerDnsAnswer> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
        }
        async fn refuse_udp(&self, destination: SocketAddr) -> io::Result<()> {
            self.refused_udp.lock().unwrap().push(destination);
            Ok(())
        }
    }

    let vm_id = Uuid::from_u128(0x6637_0000_0000_4000_8000_0000_0000_0001);
    let generation = 1;
    let host_key = NetworkKey::derive(
        "udp-bridge-session-test-token-0123456789",
        vm_id,
        generation,
    )
    .unwrap();
    let key = NetworkKey::derive(
        "udp-bridge-session-test-token-0123456789",
        vm_id,
        generation,
    )
    .unwrap();
    let limits = SessionLimits::LOCAL;
    let addresses = SessionAddresses::STANDARD;
    let (host_stream, mut guest_stream) = tokio::io::duplex(64 * 1024);
    let (mut runner_udp, worker_udp) = tokio::io::duplex(64 * 1024);
    let broker = Arc::new(RecordingBroker {
        refused_udp: Mutex::new(Vec::new()),
    });
    let broker_for_session = Arc::clone(&broker);
    let session_task = tokio::spawn(async move {
        run_network_session_with_channels(
            host_stream,
            host_key,
            (vm_id, generation),
            (limits, addresses),
            broker_for_session,
            None,
            Some(UdpBridgeAttachment {
                stream: Box::pin(worker_udp),
                allowed_peers: vec![PEER_A],
            }),
            || Ok(()),
        )
        .await
    });

    // Complete authenticated guest handshake.
    let mut hello_bytes = [0_u8; NETWORK_HOST_HELLO_LEN];
    guest_stream.read_exact(&mut hello_bytes).await.unwrap();
    let hello = NetworkHostHello::decode(&hello_bytes, &key, vm_id, generation).unwrap();
    let ack = NetworkGuestAck::new(hello.nonce, hello.packet_bound)
        .unwrap()
        .encode(&key);
    guest_stream.write_all(&ack).await.unwrap();
    guest_stream.flush().await.unwrap();
    let mut ready_bytes = [0_u8; NETWORK_HOST_READY_LEN];
    guest_stream.read_exact(&mut ready_bytes).await.unwrap();
    NetworkHostReady::decode(&ready_bytes, &key, &hello.nonce).unwrap();
    let mut guest_session =
        NetworkSession::new(&key, &hello.nonce, NetworkRole::Guest, hello.packet_bound).unwrap();
    // Drain initial EgressTrust frame.
    let mut hdr = [0_u8; codewire_network_session::NETWORK_FRAME_HEADER_LEN];
    guest_stream.read_exact(&mut hdr).await.unwrap();
    let trust_len = encoded_network_frame_len(&hdr, hello.packet_bound).unwrap();
    let mut trust_frame = vec![0_u8; trust_len];
    trust_frame[..hdr.len()].copy_from_slice(&hdr);
    guest_stream
        .read_exact(&mut trust_frame[hdr.len()..])
        .await
        .unwrap();
    let _ = guest_session.decode_frame(&trust_frame).unwrap();

    // 1. Send allowlisted UDP (guest, 31000) -> PEER_A; 2. wrong sport; 3. unlisted IP.
    for pkt in [
        build_raw_ipv4_udp(
            addresses.guest,
            TAILNET_UDP_PORT,
            *PEER_A.ip(),
            PEER_A.port(),
            b"tailnet-ping",
            false,
        ),
        build_raw_ipv4_udp(
            addresses.guest,
            31_001,
            *PEER_A.ip(),
            PEER_A.port(),
            b"wrong-sport",
            false,
        ),
        build_raw_ipv4_udp(
            addresses.guest,
            TAILNET_UDP_PORT,
            *OTHER_IP.ip(),
            OTHER_IP.port(),
            b"wrong-dst",
            false,
        ),
    ] {
        let frame = guest_session.encode_packet(&pkt).unwrap();
        guest_stream.write_all(&frame).await.unwrap();
    }
    guest_stream.flush().await.unwrap();

    // Verify allowlisted packet reached runner_udp.
    let mut buf = vec![0_u8; MAX_UDP_BRIDGE_PAYLOAD];
    let (dst, len) = tokio::time::timeout(
        Duration::from_secs(2),
        read_udp_bridge_frame(&mut runner_udp, &mut buf),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(dst, PEER_A);
    assert_eq!(&buf[..len], b"tailnet-ping");

    // Verify inbound reply from PEER_A reaches guest_stream (while OTHER_IP is dropped).
    write_udp_bridge_frame(&mut runner_udp, OTHER_IP, b"drop-me")
        .await
        .unwrap();
    write_udp_bridge_frame(&mut runner_udp, PEER_A, b"tailnet-pong")
        .await
        .unwrap();
    guest_stream.read_exact(&mut hdr).await.unwrap();
    let reply_len = encoded_network_frame_len(&hdr, hello.packet_bound).unwrap();
    let mut reply_frame = vec![0_u8; reply_len];
    reply_frame[..hdr.len()].copy_from_slice(&hdr);
    guest_stream
        .read_exact(&mut reply_frame[hdr.len()..])
        .await
        .unwrap();
    let reply_pkt = guest_session.decode_packet(&reply_frame).unwrap();
    let parsed_reply = parse_canonical_ipv4_udp_datagram(&reply_pkt).unwrap();
    assert_eq!(is_ipv4_udp_peer(parsed_reply.source), Some(PEER_A));
    assert_eq!(
        is_ipv4_udp_peer(parsed_reply.destination),
        Some(SocketAddrV4::new(addresses.guest, TAILNET_UDP_PORT))
    );
    assert_eq!(&reply_pkt[IPV4_UDP_HEADER_LEN..], b"tailnet-pong");

    // Wait briefly for the two rejected packets' refuse_udp calls.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if broker.refused_udp.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let refused = broker.refused_udp.lock().unwrap().clone();
    assert!(refused.contains(&SocketAddr::V4(PEER_A))); // from sport 31001
    assert!(refused.contains(&SocketAddr::V4(OTHER_IP))); // from unlisted IP
    assert_eq!(refused.len(), 2);

    drop(guest_stream);
    let _ = session_task.await;
}
