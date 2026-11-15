use std::os::unix::net::UnixDatagram;

use tokio::io::DuplexStream;
use uuid::Uuid;

use super::*;
use crate::{NETWORK_GUEST_ACK_LEN, NetworkGuestAck};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const MTU: usize = 1_500;

fn identity() -> (Uuid, u64) {
    (
        Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0),
        7,
    )
}

fn key() -> NetworkKey {
    let (vm_id, generation) = identity();
    NetworkKey::derive(TOKEN, vm_id, generation).unwrap()
}

/// The host's side of the handshake, as the egress worker runs it.
async fn host_handshake(stream: &mut DuplexStream, key: &NetworkKey) -> NetworkSession {
    let (vm_id, generation) = identity();
    let nonce = [9_u8; 32];
    let hello = NetworkHostHello::new(vm_id, generation, nonce).unwrap();
    stream.write_all(&hello.encode(key)).await.unwrap();
    let mut ack = [0_u8; NETWORK_GUEST_ACK_LEN];
    stream.read_exact(&mut ack).await.unwrap();
    NetworkGuestAck::decode(&ack, key, &nonce).unwrap();
    stream
        .write_all(&NetworkHostReady::new(nonce).unwrap().encode(key))
        .await
        .unwrap();
    NetworkSession::new(key, &nonce, NetworkRole::Host).unwrap()
}

/// A minimal canonical IPv4 packet of `len` bytes.
fn ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
    packet
}

/// A datagram socket pair stands in for the TUN device: each read or write
/// is one whole packet, as on a TUN.
fn tun_pair() -> (Arc<AsyncFd<OwnedFd>>, UnixDatagram) {
    let (guest, peer) = UnixDatagram::pair().unwrap();
    guest.set_nonblocking(true).unwrap();
    #[allow(deprecated)]
    // RUSTSEC-2026-0386: an owned `OwnedFd` is outside `AsyncFd::new`'s unsound case, as for the guest's TUN.
    let registered = AsyncFd::new(OwnedFd::from(guest)).unwrap();
    (Arc::new(registered), peer)
}

#[tokio::test]
async fn the_guest_authenticates_the_host_and_refuses_another_key() {
    let (vm_id, generation) = identity();
    let (guest, mut host) = tokio::io::duplex(4096);
    let host_task = tokio::spawn(async move { host_handshake(&mut host, &key()).await });
    authenticate_guest(guest, &key(), vm_id, generation)
        .await
        .unwrap();
    host_task.await.unwrap();

    // The host end stays alive in this scope, so the guest fails on
    // authentication rather than on a closed stream.
    let (guest, mut host) = tokio::io::duplex(4096);
    let other = NetworkKey::derive("fedcba9876543210fedcba9876543210", vm_id, generation).unwrap();
    let hello = NetworkHostHello::new(vm_id, generation, [9; 32]).unwrap();
    host.write_all(&hello.encode(&other)).await.unwrap();
    assert!(matches!(
        authenticate_guest(guest, &key(), vm_id, generation).await,
        Err(GuestHandshakeError::AuthenticateHello)
    ));
}

#[tokio::test]
async fn packets_cross_the_bridge_both_ways_and_non_canonical_ones_do_not() {
    let (vm_id, generation) = identity();
    let (guest, mut host) = tokio::io::duplex(1 << 16);
    let host_task = tokio::spawn(async move {
        let session = host_handshake(&mut host, &key()).await;
        (host, session)
    });
    let (guest, guest_session) = authenticate_guest(guest, &key(), vm_id, generation)
        .await
        .unwrap();
    let (mut host, mut host_session) = host_task.await.unwrap();
    let (tun, peer) = tun_pair();
    let bridge = tokio::spawn(bridge_guest(guest, guest_session, tun, MTU));

    // Guest to host: a non-canonical packet is dropped, a canonical one framed.
    peer.send(&[0x60; 40]).unwrap();
    let outbound = ipv4_packet(60);
    peer.send(&outbound).unwrap();
    let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
    host.read_exact(&mut header).await.unwrap();
    let mut frame = vec![0_u8; encoded_network_frame_len(&header).unwrap()];
    frame[..NETWORK_FRAME_HEADER_LEN].copy_from_slice(&header);
    host.read_exact(&mut frame[NETWORK_FRAME_HEADER_LEN..])
        .await
        .unwrap();
    assert_eq!(host_session.decode_packet(&frame).unwrap(), outbound);

    // Host to guest: the packet reaches the TUN whole.
    let inbound = ipv4_packet(80);
    host.write_all(&host_session.encode_packet(&inbound).unwrap())
        .await
        .unwrap();
    let mut received = vec![0_u8; 2048];
    let length = tokio::task::spawn_blocking(move || {
        // A hang guard: a bridge that never writes fails the test.
        peer.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        let length = peer.recv(&mut received).unwrap();
        received.truncate(length);
        received
    })
    .await
    .unwrap();
    assert_eq!(length, inbound);

    // A host that sends a packet over the session's bound ends the session.
    host.write_all(&host_session.encode_packet(&ipv4_packet(MTU + 1)).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        bridge.await.unwrap(),
        Err(GuestBridgeError::NonCanonicalPacket)
    ));
}
