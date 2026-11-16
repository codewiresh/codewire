use serde_json::Value;

use super::*;

const TOKEN: &str = "guest-network-test-token-0123456789abcdef";

fn bound() -> PacketBound {
    crate::SessionLimits::LOCAL.packet_bound()
}

fn identity() -> (Uuid, u64, [u8; NONCE_LEN]) {
    (
        Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
        7,
        std::array::from_fn(|index| index as u8),
    )
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

/// The fixture is written by `testdata/local-vm-network/protocol-v2.py`, an
/// independent codec.
#[test]
fn rust_codec_matches_the_cross_language_v2_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../testdata/local-vm-network/protocol-v2.json"
    ))
    .unwrap();
    let (vm_id, generation, nonce) = identity();
    assert_eq!(fixture["token"], TOKEN);
    assert_eq!(fixture["vm_id"], vm_id.to_string());
    assert_eq!(fixture["generation"], generation);
    assert_eq!(decode_hex(fixture["nonce_hex"].as_str().unwrap()), nonce);
    assert_eq!(fixture["packet_bound"], bound().bytes());

    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    key.with_bytes(|bytes| {
        assert_eq!(
            bytes.as_slice(),
            decode_hex(fixture["synthetic_hmac_fixture_hex"].as_str().unwrap())
        )
    });
    let hello = NetworkHostHello::new(vm_id, generation, nonce, bound()).unwrap();
    assert_eq!(
        hello.encode(&key).as_slice(),
        decode_hex(fixture["host_hello_hex"].as_str().unwrap())
    );
    assert_eq!(
        NetworkHostHello::decode(&hello.encode(&key), &key, vm_id, generation).unwrap(),
        hello
    );
    let ack = NetworkGuestAck::new(nonce, bound()).unwrap();
    assert_eq!(
        ack.encode(&key).as_slice(),
        decode_hex(fixture["guest_ack_hex"].as_str().unwrap())
    );
    let ready = NetworkHostReady::new(nonce).unwrap();
    assert_eq!(
        ready.encode(&key).as_slice(),
        decode_hex(fixture["host_ready_hex"].as_str().unwrap())
    );
    assert_eq!(
        NetworkGuestAck::decode(&ack.encode(&key), &key, &nonce, bound()).unwrap(),
        ack
    );
    let ready = NetworkHostReady::new(nonce).unwrap();
    assert_eq!(
        NetworkHostReady::decode(&ready.encode(&key), &key, &nonce).unwrap(),
        ready
    );

    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound()).unwrap();
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host, bound()).unwrap();
    let guest_packet = guest.encode_packet(b"synthetic-guest-packet").unwrap();
    assert_eq!(
        guest_packet,
        decode_hex(fixture["guest_packet_hex"].as_str().unwrap())
    );
    assert_eq!(
        host.decode_packet(&guest_packet).unwrap(),
        b"synthetic-guest-packet"
    );
    // The host's frame 1 is always its egress trust; a local VM's says none.
    let host_trust = host.encode_egress_trust(&EgressTrust::None).unwrap();
    assert_eq!(
        host_trust,
        decode_hex(fixture["host_egress_trust_hex"].as_str().unwrap())
    );
    assert_eq!(
        guest.decode_frame(&host_trust).unwrap(),
        NetworkFrame::EgressTrust(EgressTrust::None)
    );
    let host_packet = host.encode_packet(b"synthetic-host-packet").unwrap();
    assert_eq!(
        host_packet,
        decode_hex(fixture["host_packet_hex"].as_str().unwrap())
    );
    assert_eq!(
        guest.decode_packet(&host_packet).unwrap(),
        b"synthetic-host-packet"
    );
}

#[test]
fn wrong_identity_key_nonce_direction_sequence_and_tag_fail_closed() {
    let (vm_id, generation, nonce) = identity();
    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    let hello = NetworkHostHello::new(vm_id, generation, nonce, bound())
        .unwrap()
        .encode(&key);
    let wrong_key = NetworkKey::derive(
        "wrong-network-test-token-0123456789abcdef",
        vm_id,
        generation,
    )
    .unwrap();
    assert_eq!(
        NetworkHostHello::decode(&hello, &wrong_key, vm_id, generation),
        Err(NetworkError::AuthenticationFailed)
    );
    assert_eq!(
        NetworkHostHello::decode(&hello, &key, vm_id, generation + 1),
        Err(NetworkError::InvalidIdentity)
    );
    assert_eq!(
        NetworkGuestAck::decode(
            &NetworkGuestAck::new(nonce, bound()).unwrap().encode(&key),
            &key,
            &[0xa5; NONCE_LEN],
            bound(),
        ),
        Err(NetworkError::InvalidIdentity)
    );
    assert_eq!(
        NetworkHostReady::decode(
            &NetworkHostReady::new(nonce).unwrap().encode(&key),
            &key,
            &[0xa5; NONCE_LEN],
        ),
        Err(NetworkError::InvalidIdentity)
    );

    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound()).unwrap();
    let mut other_guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound()).unwrap();
    let frame = guest.encode_packet(b"packet").unwrap();
    assert_eq!(
        other_guest.decode_packet(&frame),
        Err(NetworkError::AuthenticationFailed)
    );
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host, bound()).unwrap();
    assert_eq!(host.decode_packet(&frame).unwrap(), b"packet");
    assert_eq!(
        host.decode_packet(&frame),
        Err(NetworkError::InvalidSequence)
    );

    let mut damaged = guest.encode_packet(b"second").unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        host.decode_packet(&damaged),
        Err(NetworkError::AuthenticationFailed)
    );
}

#[test]
fn malformed_and_oversized_frames_fail_before_allocation() {
    let (vm_id, generation, nonce) = identity();
    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound()).unwrap();
    assert_eq!(
        guest.encode_packet(&[]),
        Err(NetworkError::InvalidPacketLength)
    );
    assert_eq!(
        guest.encode_packet(&vec![0; bound().bytes() + 1]),
        Err(NetworkError::InvalidPacketLength)
    );

    let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
    header[..8].copy_from_slice(FRAME_MAGIC);
    header[16..18].copy_from_slice(&u16::try_from(bound().bytes() + 1).unwrap().to_le_bytes());
    assert_eq!(
        encoded_network_frame_len(&header, bound()),
        Err(NetworkError::InvalidPacketLength)
    );
    header[16..18].copy_from_slice(&1_u16.to_le_bytes());
    // Byte 18 is the frame kind, packet or control; another is refused,
    // as is anything in byte 19.
    header[18] = 2;
    assert_eq!(
        encoded_network_frame_len(&header, bound()),
        Err(NetworkError::InvalidFraming)
    );
    header[18] = 0;
    header[19] = 1;
    assert_eq!(
        encoded_network_frame_len(&header, bound()),
        Err(NetworkError::InvalidFraming)
    );
}

#[test]
fn inherited_worker_key_rejects_only_the_invalid_zero_value() {
    assert!(NetworkKey::from_derived_bytes([0; NETWORK_KEY_LEN]).is_err());
    let key = NetworkKey::from_derived_bytes([0xa5; NETWORK_KEY_LEN]).unwrap();
    key.with_bytes(|bytes| assert_eq!(bytes, &[0xa5; NETWORK_KEY_LEN]));
}

#[test]
fn the_host_fixes_the_bound_and_the_guest_must_accept_exactly_it() {
    let (vm_id, generation, nonce) = identity();
    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    let hosted = crate::SessionLimits::HOSTED.packet_bound();
    let hello = NetworkHostHello::new(vm_id, generation, nonce, hosted).unwrap();
    let decoded = NetworkHostHello::decode(&hello.encode(&key), &key, vm_id, generation).unwrap();
    assert_eq!(decoded.packet_bound, hosted);

    // An acknowledgement of another bound fails the handshake.
    let local_ack = NetworkGuestAck::new(nonce, bound()).unwrap().encode(&key);
    assert_eq!(
        NetworkGuestAck::decode(&local_ack, &key, &nonce, hosted),
        Err(NetworkError::InvalidPacketBound)
    );

    // A bound outside the accepted range is refused even when authentic.
    let mut tampered = hello.encode(&key);
    tampered[64..66].copy_from_slice(&1_024_u16.to_le_bytes());
    let tag = authentication_tag(&key, HOST_HELLO_DOMAIN, &[&tampered[..66]]);
    tampered[66..].copy_from_slice(&tag);
    assert_eq!(
        NetworkHostHello::decode(&tampered, &key, vm_id, generation),
        Err(NetworkError::InvalidPacketBound)
    );
    // And an unauthenticated change to it fails authentication.
    let mut changed = hello.encode(&key);
    changed[64..66].copy_from_slice(&4_096_u16.to_le_bytes());
    assert_eq!(
        NetworkHostHello::decode(&changed, &key, vm_id, generation),
        Err(NetworkError::AuthenticationFailed)
    );
}

#[test]
fn a_session_frames_packets_up_to_its_own_bound() {
    let (vm_id, generation, nonce) = identity();
    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    let hosted = crate::SessionLimits::HOSTED.packet_bound();
    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, hosted).unwrap();
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host, hosted).unwrap();
    let jumbo = vec![7_u8; hosted.bytes()];
    let frame = guest.encode_packet(&jumbo).unwrap();
    assert_eq!(host.decode_packet(&frame).unwrap(), jumbo);
    // A local session refuses the same frame's length.
    assert_eq!(
        encoded_network_frame_len(&frame[..NETWORK_FRAME_HEADER_LEN], bound()),
        Err(NetworkError::InvalidPacketLength)
    );
}

#[test]
fn the_self_check_crosses_under_the_session_mac_and_only_as_control() {
    let (vm_id, generation, nonce) = identity();
    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound()).unwrap();
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host, bound()).unwrap();
    for result in [
        SelfCheck::Passed,
        SelfCheck::Failed(SelfCheckFailure::DirectDial),
        SelfCheck::Failed(SelfCheckFailure::Dns),
    ] {
        let frame = guest.encode_self_check(result).unwrap();
        assert_eq!(
            host.decode_frame(&frame).unwrap(),
            NetworkFrame::SelfCheck(result)
        );
    }
    // A packet reader refuses a control frame rather than taking it as a packet.
    let control = guest.encode_self_check(SelfCheck::Passed).unwrap();
    assert_eq!(
        host.decode_packet(&control),
        Err(NetworkError::InvalidControl)
    );
    // The kind byte is authenticated: turning a packet into control fails.
    let mut packet = guest.encode_packet(&[0x45; 20]).unwrap();
    packet[18] = 1;
    assert_eq!(
        host.decode_frame(&packet),
        Err(NetworkError::AuthenticationFailed)
    );
}

#[test]
fn a_malformed_self_check_is_a_protocol_error() {
    for body in [&[][..], &[0, 0], &[1], &[1, 0], &[1, 3], &[2], &[0, 1, 2]] {
        assert_eq!(
            SelfCheck::decode(body),
            Err(NetworkError::InvalidControl),
            "{body:?}"
        );
    }
}

fn session_pair(bound: PacketBound) -> (NetworkSession, NetworkSession) {
    let (vm_id, generation, nonce) = identity();
    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    (
        NetworkSession::new(&key, &nonce, NetworkRole::Guest, bound).unwrap(),
        NetworkSession::new(&key, &nonce, NetworkRole::Host, bound).unwrap(),
    )
}

#[test]
fn the_hosts_first_frame_carries_its_egress_trust_and_nothing_else_does() {
    let hosted = crate::SessionLimits::HOSTED.packet_bound();
    for trust in [
        EgressTrust::None,
        EgressTrust::Ca(vec![0x30; MAX_EGRESS_TRUST_BYTES]),
    ] {
        let (mut guest, mut host) = session_pair(hosted);
        let frame = host.encode_egress_trust(&trust).unwrap();
        assert_eq!(
            guest.decode_frame(&frame).unwrap(),
            NetworkFrame::EgressTrust(trust)
        );
        // Once only: the host's later frames are packets.
        assert_eq!(
            host.encode_egress_trust(&EgressTrust::None),
            Err(NetworkError::InvalidControl)
        );
        let packet = host.encode_packet(&[0x45; 20]).unwrap();
        assert_eq!(guest.decode_packet(&packet).unwrap(), vec![0x45; 20]);
    }

    // The host's encoder puts no packet at frame 1, and the guest refuses one
    // a host built anyway, and a trust frame anywhere else.
    let (mut guest, mut host) = session_pair(bound());
    assert_eq!(
        host.encode_packet(&[0x45; 20]),
        Err(NetworkError::InvalidControl)
    );
    let packet_first = host.encode_frame(FRAME_KIND_PACKET, &[0x45; 20]).unwrap();
    assert_eq!(
        guest.decode_frame(&packet_first),
        Err(NetworkError::InvalidControl)
    );
    let (mut guest, mut host) = session_pair(bound());
    guest
        .decode_frame(&host.encode_egress_trust(&EgressTrust::None).unwrap())
        .unwrap();
    let second = host
        .encode_frame(FRAME_KIND_CONTROL, &[CONTROL_EGRESS_TRUST])
        .unwrap();
    assert_eq!(
        guest.decode_frame(&second),
        Err(NetworkError::InvalidControl)
    );
}

#[test]
fn each_control_message_travels_one_way_only() {
    let (mut guest, mut host) = session_pair(bound());
    assert_eq!(
        guest.encode_egress_trust(&EgressTrust::None),
        Err(NetworkError::InvalidControl)
    );
    assert_eq!(
        host.encode_self_check(SelfCheck::Passed),
        Err(NetworkError::InvalidControl)
    );
    // A self-check a host built anyway, after its trust, is refused.
    guest
        .decode_frame(&host.encode_egress_trust(&EgressTrust::None).unwrap())
        .unwrap();
    let from_host = host
        .encode_frame(FRAME_KIND_CONTROL, &[CONTROL_SELF_CHECK, SELF_CHECK_PASSED])
        .unwrap();
    assert_eq!(
        guest.decode_frame(&from_host),
        Err(NetworkError::InvalidControl)
    );
    // An unnamed control message is refused either way.
    let unknown = guest.encode_frame(FRAME_KIND_CONTROL, &[9]).unwrap();
    assert_eq!(
        host.decode_frame(&unknown),
        Err(NetworkError::InvalidControl)
    );
}

#[test]
fn a_control_frame_fits_its_session_bound_too() {
    // The largest CA fits a hosted session but not a local one, whose reader
    // would refuse the frame's length before reading it.
    let largest = EgressTrust::Ca(vec![0x30; MAX_EGRESS_TRUST_BYTES]);
    let (_, mut local) = session_pair(bound());
    assert_eq!(
        local.encode_egress_trust(&largest),
        Err(NetworkError::InvalidPacketLength)
    );
    let (_, mut hosted) = session_pair(crate::SessionLimits::HOSTED.packet_bound());
    let frame = hosted.encode_egress_trust(&largest).unwrap();
    assert!(encoded_network_frame_len(&frame[..NETWORK_FRAME_HEADER_LEN], bound()).is_err());
}

#[test]
fn an_egress_ca_is_never_empty_or_over_its_bound() {
    let (_, mut host) = session_pair(crate::SessionLimits::HOSTED.packet_bound());
    for der in [Vec::new(), vec![0x30; MAX_EGRESS_TRUST_BYTES + 1]] {
        assert_eq!(
            host.encode_egress_trust(&EgressTrust::Ca(der)),
            Err(NetworkError::InvalidControl)
        );
    }
    assert_eq!(
        EgressTrust::decode(&vec![0x30; MAX_EGRESS_TRUST_BYTES + 1]),
        Err(NetworkError::InvalidControl)
    );
}
