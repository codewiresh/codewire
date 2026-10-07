use std::time::{SystemTime, UNIX_EPOCH};

use codewire_daemon_proto::codewire::bridge::v1;
use codewire_daemon_proto::ssh::{self, SshOperation};

use super::*;

const REQUEST_ID: &str = "10000000-0000-0000-0000-000000000001";

fn future_deadline() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 5_000
}

fn identities_request() -> v1::CredentialSshRequest {
    v1::CredentialSshRequest {
        request_id: REQUEST_ID.into(),
        deadline_unix_ms: future_deadline(),
        operation: Some(v1::credential_ssh_request::Operation::Identities(
            v1::CredentialSshIdentitiesRequest {},
        )),
    }
}

fn sign_request() -> v1::CredentialSshRequest {
    v1::CredentialSshRequest {
        request_id: REQUEST_ID.into(),
        deadline_unix_ms: future_deadline(),
        operation: Some(v1::credential_ssh_request::Operation::Sign(
            v1::CredentialSshSignRequest {
                public_key_blob: vec![1],
                data: vec![2],
                flags: 0,
            },
        )),
    }
}

#[test]
fn ssh_guest_validation_preserves_exact_request_and_rejects_deadline_and_bounds() {
    for request in [identities_request(), sign_request()] {
        let message = v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(request)),
        };
        let exact = message.clone();
        validate_credential_bridge_guest_message(&message).unwrap();
        assert_eq!(message, exact);
    }

    let mut expired = sign_request();
    expired.deadline_unix_ms = 1;
    let expired = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(expired)),
    };
    assert!(matches!(
        validate_credential_bridge_guest_message(&expired),
        Err(SessionClientError::Status(status)) if status.code() == tonic::Code::InvalidArgument
    ));

    let mut oversized = sign_request();
    let Some(v1::credential_ssh_request::Operation::Sign(sign)) = oversized.operation.as_mut()
    else {
        unreachable!()
    };
    sign.data = vec![3; ssh::MAX_SIGNING_DATA_BYTES + 1];
    let oversized = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ssh(oversized)),
    };
    assert!(matches!(
        validate_credential_bridge_guest_message(&oversized),
        Err(SessionClientError::Status(status)) if status.code() == tonic::Code::InvalidArgument
    ));
}

#[test]
fn correlated_ssh_response_validation_rejects_mismatched_result_kind() {
    use v1::credential_ssh_response::Result;

    let identity = v1::CredentialSshResponse {
        request_id: REQUEST_ID.into(),
        result: Some(Result::Identity(v1::CredentialSshIdentity {
            public_key_blob: vec![1],
        })),
    };
    assert!(ssh::validate_response(&identity, SshOperation::Identities).is_ok());
    assert!(ssh::validate_response(&identity, SshOperation::Sign).is_err());

    let signature = v1::CredentialSshResponse {
        request_id: REQUEST_ID.into(),
        result: Some(Result::Signature(v1::CredentialSshSignature {
            signature_blob: vec![2],
        })),
    };
    assert!(ssh::validate_response(&signature, SshOperation::Sign).is_ok());
    assert!(ssh::validate_response(&signature, SshOperation::Identities).is_err());
}

#[tokio::test]
async fn ssh_response_uses_existing_bounded_sender_and_preserves_exact_frame() {
    use v1::credential_ssh_response::Result;

    let (input, mut output) = mpsc::channel(1);
    let sender = CredentialBridgeResponseSender {
        input,
        _hosted_lifetime: None,
    };
    let invalid = sender
        .send_ssh(v1::CredentialSshResponse {
            request_id: REQUEST_ID.into(),
            result: Some(Result::Signature(v1::CredentialSshSignature {
                signature_blob: Vec::new(),
            })),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        invalid,
        SessionClientError::Status(status) if status.code() == tonic::Code::InvalidArgument
    ));
    assert!(matches!(
        output.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let response = v1::CredentialSshResponse {
        request_id: REQUEST_ID.into(),
        result: Some(Result::Signature(v1::CredentialSshSignature {
            signature_blob: vec![3, 4],
        })),
    };
    sender.send_ssh(response.clone()).await.unwrap();
    let queued_sender = sender.clone();
    let queued = tokio::spawn(async move {
        queued_sender
            .send_response_end(v1::CredentialBridgeResponseEnd {
                request_id: REQUEST_ID.into(),
            })
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !queued.is_finished(),
        "SSH and HTTP did not share one budget"
    );
    assert_eq!(
        output.recv().await.unwrap().payload,
        Some(v1::credential_bridge_host_message::Payload::Ssh(response))
    );
    queued.await.unwrap().unwrap();
    assert!(matches!(
        output.recv().await.unwrap().payload,
        Some(v1::credential_bridge_host_message::Payload::ResponseEnd(_))
    ));
    drop(output);
    let error = sender
        .send_ssh(v1::CredentialSshResponse {
            request_id: REQUEST_ID.into(),
            result: Some(Result::Failure(
                v1::CredentialBridgeFailureReason::Unavailable as i32,
            )),
        })
        .await
        .unwrap_err();
    assert!(matches!(error, SessionClientError::RequestClosed));
}

#[test]
fn non_ssh_guest_frames_keep_the_existing_cancel_path() {
    let cancel = v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Cancel(
            v1::CredentialBridgeCancel {
                request_id: REQUEST_ID.into(),
            },
        )),
    };
    assert!(validate_credential_bridge_guest_message(&cancel).is_ok());
}
