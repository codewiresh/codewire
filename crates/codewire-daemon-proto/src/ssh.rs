//! Bounded SSH framing, not key selection or signing authorization.
//!
//! Every authority must additionally enforce the admitted environment/profile,
//! exact selected public key and supported algorithm. These checks neither read
//! provider material nor authorize an arbitrary SSH agent command.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::Status;

use crate::codewire::bridge::v1;

/// Finite OpenSSH agent payload framing, without sockets or authorization.
pub mod agent;

pub const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;
pub const MAX_SIGNING_DATA_BYTES: usize = 64 * 1024;
pub const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
pub const MAX_DEADLINE: Duration = Duration::from_secs(30);
/// The lifetime a guest requests. The host checks the deadline against its own
/// clock, and a guest clock may run up to two seconds ahead of it (a macOS
/// guest follows its RTC only once it is two seconds off), so the guest stays
/// that far below the maximum.
pub const REQUEST_LIFETIME: Duration = Duration::from_secs(28);

/// Fixed operation inferred from the closed request, never a caller route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshOperation {
    Identities,
    Sign,
}

/// Canonical non-nil UUID spelling shared with the other bridge operations.
pub fn valid_request_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        && value != "00000000-0000-0000-0000-000000000000"
}

/// Remaining original deadline. Relays may shorten it, never reset it.
pub fn remaining_deadline(deadline_unix_ms: u64) -> Result<Duration, Status> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Status::unavailable("SSH deadline clock is unavailable"))?;
    remaining_at(deadline_unix_ms, now)
}

fn remaining_at(deadline_unix_ms: u64, now: Duration) -> Result<Duration, Status> {
    let remaining = Duration::from_millis(deadline_unix_ms)
        .checked_sub(now)
        .filter(|remaining| !remaining.is_zero() && *remaining <= MAX_DEADLINE)
        .ok_or_else(|| Status::invalid_argument("SSH deadline is invalid"))?;
    Ok(remaining)
}

pub fn validate_request(request: &v1::CredentialSshRequest) -> Result<SshOperation, Status> {
    remaining_deadline(request.deadline_unix_ms)?;
    validate_request_shape(request)
}

/// The request's closed shape without its deadline: a transport checks this
/// on receipt, and the request's handler checks the deadline, so a request
/// whose deadline is out of range (a skewed or older guest clock) is refused
/// alone instead of ending the bridge epoch that carries every request.
pub fn validate_request_shape(request: &v1::CredentialSshRequest) -> Result<SshOperation, Status> {
    if !valid_request_id(&request.request_id) {
        return Err(invalid());
    }
    validate_operation(request.operation.as_ref().ok_or_else(invalid)?)
}

fn validate_operation(
    operation: &v1::credential_ssh_request::Operation,
) -> Result<SshOperation, Status> {
    use v1::credential_ssh_request::Operation;
    match operation {
        Operation::Identities(_) => Ok(SshOperation::Identities),
        Operation::Sign(sign)
            if bounded(&sign.public_key_blob, MAX_PUBLIC_KEY_BYTES)
                && bounded(&sign.data, MAX_SIGNING_DATA_BYTES)
                && matches!(sign.flags, 0 | 2 | 4) =>
        {
            Ok(SshOperation::Sign)
        }
        _ => Err(invalid()),
    }
}

pub fn validate_response(
    response: &v1::CredentialSshResponse,
    operation: SshOperation,
) -> Result<(), Status> {
    if !valid_request_id(&response.request_id) {
        return Err(invalid());
    }
    validate_result(response.result.as_ref().ok_or_else(invalid)?, operation)
}

fn validate_result(
    result: &v1::credential_ssh_response::Result,
    operation: SshOperation,
) -> Result<(), Status> {
    use v1::credential_ssh_response::Result;
    match (result, operation) {
        (Result::Identity(identity), SshOperation::Identities)
            if bounded(&identity.public_key_blob, MAX_PUBLIC_KEY_BYTES) =>
        {
            Ok(())
        }
        (Result::Signature(signature), SshOperation::Sign)
            if bounded(&signature.signature_blob, MAX_SIGNATURE_BYTES) =>
        {
            Ok(())
        }
        (Result::Failure(reason), _)
            if matches!(
                v1::CredentialBridgeFailureReason::try_from(*reason),
                Ok(v1::CredentialBridgeFailureReason::Denied
                    | v1::CredentialBridgeFailureReason::Unavailable
                    | v1::CredentialBridgeFailureReason::UpstreamFailed
                    | v1::CredentialBridgeFailureReason::ResponseTooLarge)
            ) =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

fn bounded(bytes: &[u8], maximum: usize) -> bool {
    !bytes.is_empty() && bytes.len() <= maximum
}

fn invalid() -> Status {
    Status::invalid_argument("SSH bridge frame is invalid")
}

impl fmt::Debug for v1::CredentialSshSignRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialSshSignRequest")
            .field("public_key_blob", &self.public_key_blob)
            .field("data", &"[REDACTED]")
            .field("flags", &self.flags)
            .finish()
    }
}

impl fmt::Debug for v1::CredentialSshSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialSshSignature")
            .field("signature_blob", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    const ID: &str = "10000000-0000-0000-0000-000000000001";

    #[test]
    fn typed_frames_roundtrip_through_generated_bridge_envelopes() {
        let guest = v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(sign())),
        };
        assert_eq!(
            v1::CredentialBridgeGuestMessage::decode(guest.encode_to_vec().as_slice()).unwrap(),
            guest
        );
        let host = v1::CredentialBridgeHostMessage {
            payload: Some(v1::credential_bridge_host_message::Payload::Ssh(
                v1::CredentialSshResponse {
                    request_id: ID.to_owned(),
                    result: Some(v1::credential_ssh_response::Result::Signature(
                        v1::CredentialSshSignature {
                            signature_blob: vec![7; 64],
                        },
                    )),
                },
            )),
        };
        assert_eq!(
            v1::CredentialBridgeHostMessage::decode(host.encode_to_vec().as_slice()).unwrap(),
            host
        );
    }

    fn sign() -> v1::CredentialSshRequest {
        v1::CredentialSshRequest {
            request_id: ID.to_owned(),
            deadline_unix_ms: 1,
            operation: Some(v1::credential_ssh_request::Operation::Sign(
                v1::CredentialSshSignRequest {
                    public_key_blob: vec![1; MAX_PUBLIC_KEY_BYTES],
                    data: vec![2; MAX_SIGNING_DATA_BYTES],
                    flags: 0,
                },
            )),
        }
    }

    #[test]
    fn request_ids_are_canonical_and_nonzero() {
        assert!(valid_request_id(ID));
        for bad in [
            "",
            "10000000-0000-0000-0000-00000000000A",
            "00000000-0000-0000-0000-000000000000",
            "10000000_0000-0000-0000-000000000001",
        ] {
            assert!(!valid_request_id(bad));
        }
    }

    #[test]
    fn original_deadline_is_finite_and_not_rounded_up() {
        let now = Duration::from_millis(1_000);
        assert_eq!(remaining_at(31_000, now).unwrap(), MAX_DEADLINE);
        for bad in [0, 999, 1_000, 31_001, u64::MAX] {
            assert!(remaining_at(bad, now).is_err());
        }
        assert!(remaining_at(1_000, Duration::from_micros(1_000_001)).is_err());
    }

    #[test]
    fn closed_request_operations_and_bounds() {
        let request = sign();
        assert_eq!(
            validate_request_shape(&request).unwrap(),
            SshOperation::Sign
        );
        for flags in [0, 2, 4, 1, 3, 6, u32::MAX] {
            let mut candidate = request.clone();
            let Some(v1::credential_ssh_request::Operation::Sign(value)) =
                candidate.operation.as_mut()
            else {
                unreachable!()
            };
            value.flags = flags;
            assert_eq!(
                validate_request_shape(&candidate).is_ok(),
                matches!(flags, 0 | 2 | 4)
            );
        }
        for (key, data) in [
            (0, 1),
            (MAX_PUBLIC_KEY_BYTES + 1, 1),
            (1, 0),
            (1, MAX_SIGNING_DATA_BYTES + 1),
        ] {
            let mut candidate = request.clone();
            let Some(v1::credential_ssh_request::Operation::Sign(value)) =
                candidate.operation.as_mut()
            else {
                unreachable!()
            };
            value.public_key_blob = vec![1; key];
            value.data = vec![2; data];
            assert!(validate_request_shape(&candidate).is_err());
        }
        let mut candidate = request;
        candidate.operation = None;
        assert!(validate_request_shape(&candidate).is_err());
        candidate.operation = Some(v1::credential_ssh_request::Operation::Identities(
            v1::CredentialSshIdentitiesRequest {},
        ));
        assert_eq!(
            validate_request_shape(&candidate).unwrap(),
            SshOperation::Identities
        );
    }

    #[test]
    fn response_matches_operation_and_closed_failure() {
        use v1::credential_ssh_response::Result;
        let mut response = v1::CredentialSshResponse {
            request_id: ID.to_owned(),
            result: Some(Result::Identity(v1::CredentialSshIdentity {
                public_key_blob: vec![1],
            })),
        };
        assert!(validate_response(&response, SshOperation::Identities).is_ok());
        assert!(validate_response(&response, SshOperation::Sign).is_err());
        response.result = Some(Result::Signature(v1::CredentialSshSignature {
            signature_blob: vec![1; MAX_SIGNATURE_BYTES],
        }));
        assert!(validate_response(&response, SshOperation::Sign).is_ok());
        assert!(validate_response(&response, SshOperation::Identities).is_err());
        for reason in [0, 1, 2, 3, 4, 5, -1] {
            response.result = Some(Result::Failure(reason));
            assert_eq!(
                validate_response(&response, SshOperation::Sign).is_ok(),
                (1..=4).contains(&reason)
            );
        }
        for bytes in [vec![], vec![1; MAX_SIGNATURE_BYTES + 1]] {
            response.result = Some(Result::Signature(v1::CredentialSshSignature {
                signature_blob: bytes,
            }));
            assert!(validate_response(&response, SshOperation::Sign).is_err());
        }
        response.result = None;
        assert!(validate_response(&response, SshOperation::Sign).is_err());
    }

    #[test]
    fn debug_is_independent_of_signing_payload_and_signature() {
        let mut first = sign();
        let printed = format!("{first:?}");
        let Some(v1::credential_ssh_request::Operation::Sign(value)) = first.operation.as_mut()
        else {
            unreachable!()
        };
        value.data = b"different authentication payload".to_vec();
        assert_eq!(printed, format!("{first:?}"));
        assert!(printed.contains("[REDACTED]"));
        assert_eq!(
            format!(
                "{:?}",
                v1::CredentialSshSignature {
                    signature_blob: vec![1]
                }
            ),
            format!(
                "{:?}",
                v1::CredentialSshSignature {
                    signature_blob: vec![2; 100]
                }
            )
        );
    }
}
