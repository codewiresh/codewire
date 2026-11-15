use serde_json::Value;

use super::*;

const TOKEN: &str = "guest-network-test-token-0123456789abcdef";

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

#[test]
fn rust_codec_matches_the_cross_language_v1_fixture() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../testdata/local-vm-network/protocol-v1.json"
    ))
    .unwrap();
    let (vm_id, generation, nonce) = identity();
    assert_eq!(fixture["token"], TOKEN);
    assert_eq!(fixture["vm_id"], vm_id.to_string());
    assert_eq!(fixture["generation"], generation);
    assert_eq!(decode_hex(fixture["nonce_hex"].as_str().unwrap()), nonce);

    let key = NetworkKey::derive(TOKEN, vm_id, generation).unwrap();
    key.with_bytes(|bytes| {
        assert_eq!(
            bytes.as_slice(),
            decode_hex(fixture["synthetic_hmac_fixture_hex"].as_str().unwrap())
        )
    });
    let hello = NetworkHostHello::new(vm_id, generation, nonce).unwrap();
    assert_eq!(
        hello.encode(&key).as_slice(),
        decode_hex(fixture["host_hello_hex"].as_str().unwrap())
    );
    assert_eq!(
        NetworkHostHello::decode(&hello.encode(&key), &key, vm_id, generation).unwrap(),
        hello
    );
    let ack = NetworkGuestAck::new(nonce).unwrap();
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
        NetworkGuestAck::decode(&ack.encode(&key), &key, &nonce).unwrap(),
        ack
    );
    let ready = NetworkHostReady::new(nonce).unwrap();
    assert_eq!(
        NetworkHostReady::decode(&ready.encode(&key), &key, &nonce).unwrap(),
        ready
    );

    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest).unwrap();
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host).unwrap();
    let guest_packet = guest.encode_packet(b"synthetic-guest-packet").unwrap();
    assert_eq!(
        guest_packet,
        decode_hex(fixture["guest_packet_hex"].as_str().unwrap())
    );
    assert_eq!(
        host.decode_packet(&guest_packet).unwrap(),
        b"synthetic-guest-packet"
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
    let hello = NetworkHostHello::new(vm_id, generation, nonce)
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
            &NetworkGuestAck::new(nonce).unwrap().encode(&key),
            &key,
            &[0xa5; NONCE_LEN],
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

    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest).unwrap();
    let mut other_guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest).unwrap();
    let frame = guest.encode_packet(b"packet").unwrap();
    assert_eq!(
        other_guest.decode_packet(&frame),
        Err(NetworkError::AuthenticationFailed)
    );
    let mut host = NetworkSession::new(&key, &nonce, NetworkRole::Host).unwrap();
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
    let mut guest = NetworkSession::new(&key, &nonce, NetworkRole::Guest).unwrap();
    assert_eq!(
        guest.encode_packet(&[]),
        Err(NetworkError::InvalidPacketLength)
    );
    assert_eq!(
        guest.encode_packet(&vec![0; NETWORK_MAX_PACKET_BYTES + 1]),
        Err(NetworkError::InvalidPacketLength)
    );

    let mut header = [0_u8; NETWORK_FRAME_HEADER_LEN];
    header[..8].copy_from_slice(FRAME_MAGIC);
    header[16..18].copy_from_slice(&((NETWORK_MAX_PACKET_BYTES + 1) as u16).to_le_bytes());
    assert_eq!(
        encoded_network_frame_len(&header),
        Err(NetworkError::InvalidPacketLength)
    );
    header[16..18].copy_from_slice(&1_u16.to_le_bytes());
    header[18] = 1;
    assert_eq!(
        encoded_network_frame_len(&header),
        Err(NetworkError::InvalidFraming)
    );
}

#[test]
fn inherited_worker_key_rejects_only_the_invalid_zero_value() {
    assert!(NetworkKey::from_derived_bytes([0; NETWORK_KEY_LEN]).is_err());
    let key = NetworkKey::from_derived_bytes([0xa5; NETWORK_KEY_LEN]).unwrap();
    key.with_bytes(|bytes| assert_eq!(bytes, &[0xa5; NETWORK_KEY_LEN]));
}
