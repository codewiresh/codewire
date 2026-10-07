use v1::credential_ssh_request::Operation;
use v1::credential_ssh_response::Result as SshResult;

use super::*;

fn identities() -> Operation {
    Operation::Identities(v1::CredentialSshIdentitiesRequest {})
}

fn sign(key: &[u8], data: &[u8], flags: u32) -> Operation {
    Operation::Sign(v1::CredentialSshSignRequest {
        public_key_blob: key.to_vec(),
        data: data.to_vec(),
        flags,
    })
}

fn identity(key: &[u8]) -> SshResult {
    SshResult::Identity(v1::CredentialSshIdentity {
        public_key_blob: key.to_vec(),
    })
}

fn signature(bytes: &[u8]) -> SshResult {
    SshResult::Signature(v1::CredentialSshSignature {
        signature_blob: bytes.to_vec(),
    })
}

// Independent fixture construction keeps literal wire expectations separate
// from the production encoder and its private string helper.
fn string(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    output.extend_from_slice(bytes);
}

fn sign_payload(key: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut bytes = vec![13];
    string(&mut bytes, key);
    string(&mut bytes, data);
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes
}

fn identity_payload(count: u32, key: &[u8], comment: &[u8]) -> Vec<u8> {
    let mut bytes = vec![12];
    bytes.extend_from_slice(&count.to_be_bytes());
    string(&mut bytes, key);
    string(&mut bytes, comment);
    bytes
}

fn signature_payload(value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![14];
    string(&mut bytes, value);
    bytes
}

#[test]
fn request_payloads_match_exact_wire_and_roundtrip() {
    assert_eq!(encode_request(&identities()).unwrap(), [11]);
    assert_eq!(decode_request(&[11]).unwrap(), identities());
    for flags in [0, 2, 4] {
        let operation = sign(b"public", b"synthetic-authentication-data", flags);
        let payload = sign_payload(b"public", b"synthetic-authentication-data", flags);
        assert_eq!(encode_request(&operation).unwrap(), payload);
        assert_eq!(decode_request(&payload).unwrap(), operation);
    }
    let largest = sign(
        &vec![1; MAX_PUBLIC_KEY_BYTES],
        &vec![2; MAX_SIGNING_DATA_BYTES],
        4,
    );
    let payload = encode_request(&largest).unwrap();
    assert_eq!(
        payload.len(),
        13 + MAX_PUBLIC_KEY_BYTES + MAX_SIGNING_DATA_BYTES
    );
    assert!(payload.len() <= MAX_PAYLOAD_BYTES);
    assert_eq!(decode_request(&payload).unwrap(), largest);
}

#[test]
fn response_payloads_match_exact_wire_and_discard_imported_comment() {
    let result = identity(b"public");
    let expected = identity_payload(1, b"public", b"codewire-selected-key");
    assert_eq!(
        encode_response(&result, SshOperation::Identities).unwrap(),
        expected
    );
    for comment in [
        vec![],
        b"arbitrary imported comment".to_vec(),
        vec![0xff; MAX_PUBLIC_KEY_BYTES],
    ] {
        let decoded = decode_response(
            &identity_payload(1, b"public", &comment),
            SshOperation::Identities,
        )
        .unwrap();
        assert_eq!(decoded, result);
        assert_eq!(
            encode_response(&decoded, SshOperation::Identities).unwrap(),
            expected
        );
    }
    for (operation, result, expected) in [
        (
            SshOperation::Identities,
            identity(&vec![1; MAX_PUBLIC_KEY_BYTES]),
            identity_payload(1, &vec![1; MAX_PUBLIC_KEY_BYTES], b"codewire-selected-key"),
        ),
        (
            SshOperation::Sign,
            signature(&vec![3; MAX_SIGNATURE_BYTES]),
            signature_payload(&vec![3; MAX_SIGNATURE_BYTES]),
        ),
    ] {
        let encoded = encode_response(&result, operation).unwrap();
        assert_eq!(encoded, expected);
        assert!(encoded.len() <= MAX_PAYLOAD_BYTES);
        assert_eq!(decode_response(&encoded, operation).unwrap(), result);
    }
}

#[test]
fn every_truncation_and_trailing_byte_is_rejected() {
    for payload in [vec![11], sign_payload(b"public", b"synthetic-data", 4)] {
        for length in 0..payload.len() {
            assert!(
                decode_request(&payload[..length]).is_err(),
                "request prefix {length}"
            );
        }
        for suffix in [0, 5, 11, 255] {
            let mut trailing = payload.clone();
            trailing.push(suffix);
            assert!(decode_request(&trailing).is_err());
        }
    }
    for (operation, payload) in [
        (
            SshOperation::Identities,
            identity_payload(1, b"public", b"comment"),
        ),
        (SshOperation::Sign, signature_payload(b"signature")),
        (SshOperation::Identities, vec![5]),
        (SshOperation::Sign, vec![5]),
    ] {
        for length in 0..payload.len() {
            assert!(
                decode_response(&payload[..length], operation).is_err(),
                "response prefix {length}"
            );
        }
        let mut trailing = payload;
        trailing.push(0);
        assert!(decode_response(&trailing, operation).is_err());
    }
}

#[test]
fn all_unsupported_opcodes_and_wrong_operation_results_fail_closed() {
    for opcode in 0..=u8::MAX {
        if !matches!(opcode, 11 | 13) {
            assert!(
                decode_request(&[opcode]).is_err(),
                "request opcode {opcode}"
            );
            let mut candidate = sign_payload(b"public", b"data", 0);
            candidate[0] = opcode;
            assert!(
                decode_request(&candidate).is_err(),
                "request opcode {opcode}"
            );
        }
        if !matches!(opcode, 5 | 12 | 14) {
            for operation in [SshOperation::Identities, SshOperation::Sign] {
                assert!(
                    decode_response(&[opcode], operation).is_err(),
                    "response opcode {opcode}"
                );
            }
        }
    }
    assert!(decode_response(&identity_payload(1, b"key", b""), SshOperation::Sign).is_err());
    assert!(decode_response(&signature_payload(b"signature"), SshOperation::Identities).is_err());
    assert!(encode_response(&identity(b"key"), SshOperation::Sign).is_err());
    assert!(encode_response(&signature(b"signature"), SshOperation::Identities).is_err());
}

#[test]
fn identity_count_and_closed_failure_are_not_generalized() {
    for count in [0, 2, u32::MAX] {
        assert!(
            decode_response(
                &identity_payload(count, b"key", b"comment"),
                SshOperation::Identities
            )
            .is_err()
        );
    }
    for operation in [SshOperation::Identities, SshOperation::Sign] {
        for reason in [1, 2, 3, 4] {
            assert_eq!(
                encode_response(&SshResult::Failure(reason), operation).unwrap(),
                [5]
            );
        }
        for reason in [0, 5, -1, i32::MAX] {
            assert!(encode_response(&SshResult::Failure(reason), operation).is_err());
        }
        assert_eq!(
            decode_response(&[5], operation).unwrap(),
            SshResult::Failure(v1::CredentialBridgeFailureReason::Denied as i32)
        );
    }
}

#[test]
fn request_bounds_and_flags_match_typed_validation() {
    for (key, data) in [
        (vec![], vec![1]),
        (vec![1; MAX_PUBLIC_KEY_BYTES + 1], vec![2]),
        (vec![1], vec![]),
        (vec![1], vec![2; MAX_SIGNING_DATA_BYTES + 1]),
    ] {
        assert!(encode_request(&sign(&key, &data, 0)).is_err());
        assert!(decode_request(&sign_payload(&key, &data, 0)).is_err());
    }
    for flags in [1, 3, 5, 6, u32::MAX] {
        assert!(encode_request(&sign(b"key", b"data", flags)).is_err());
        assert!(decode_request(&sign_payload(b"key", b"data", flags)).is_err());
    }
    // No algorithm inference here: RSA flags=0 and a wrong selected key must
    // still be rejected by the unchanged authority, not by a second policy.
    assert!(decode_request(&sign_payload(b"opaque-key", b"data", 0)).is_ok());
}

#[test]
fn response_bounds_and_untrusted_length_prefixes_fail_closed() {
    for key in [vec![], vec![1; MAX_PUBLIC_KEY_BYTES + 1]] {
        assert!(encode_response(&identity(&key), SshOperation::Identities).is_err());
        assert!(
            decode_response(&identity_payload(1, &key, b""), SshOperation::Identities).is_err()
        );
    }
    assert!(
        decode_response(
            &identity_payload(1, b"key", &vec![1; MAX_PUBLIC_KEY_BYTES + 1]),
            SshOperation::Identities
        )
        .is_err()
    );
    for bytes in [vec![], vec![1; MAX_SIGNATURE_BYTES + 1]] {
        assert!(encode_response(&signature(&bytes), SshOperation::Sign).is_err());
        assert!(decode_response(&signature_payload(&bytes), SshOperation::Sign).is_err());
    }
    for opcode in [13, 14] {
        let mut payload = vec![opcode];
        payload.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_request(&payload).is_err());
        assert!(decode_response(&payload, SshOperation::Sign).is_err());
    }
    for offset in [1, 8] {
        let mut payload = sign_payload(b"key", b"data", 0);
        payload[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_request(&payload).is_err());
    }
    for offset in [1, 5, 12] {
        let mut payload = identity_payload(1, b"key", b"comment");
        payload[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_response(&payload, SshOperation::Identities).is_err());
    }
    let oversized = vec![11; MAX_PAYLOAD_BYTES + 1];
    assert!(decode_request(&oversized).is_err());
    for operation in [SshOperation::Identities, SshOperation::Sign] {
        assert!(decode_response(&oversized, operation).is_err());
    }
}

#[test]
fn errors_are_value_blind_and_payload_does_not_include_outer_prefix() {
    let first = decode_request(&sign_payload(b"public", b"first synthetic input", 1)).unwrap_err();
    let second = decode_request(&sign_payload(b"public", b"other synthetic input", 1)).unwrap_err();
    assert_eq!(first.code(), tonic::Code::InvalidArgument);
    assert_eq!(first.message(), second.message());
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
    assert!(decode_request(&[0, 0, 0, 1, 11]).is_err());
    assert!(decode_response(&[0, 0, 0, 1, 5], SshOperation::Sign).is_err());
}
