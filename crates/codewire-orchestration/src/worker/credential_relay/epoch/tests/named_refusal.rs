//! The broker's named refusal of an admission, as the relay reads it for the
//! daemon (#6406).

use codewire_access::Refusal;
use codewire_daemon_proto::CREDENTIAL_BRIDGE_REFUSAL_HEADER;
use codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeRefusal;

use super::*;

fn refused(code: tonic::Code, value: &str) -> Status {
    let mut status = Status::new(
        code,
        "platform credential bridge authority denied the session",
    );
    status
        .metadata_mut()
        .insert(CREDENTIAL_BRIDGE_REFUSAL_HEADER, value.parse().unwrap());
    status
}

#[test]
fn only_a_named_permission_denied_carries_a_refusal() {
    let departed = (CredentialBridgeRefusal::CredentialOwnerDeparted as i32).to_string();
    assert_eq!(
        named_refusal(&refused(tonic::Code::PermissionDenied, &departed)),
        Some(Refusal::CredentialOwnerDeparted)
    );
    // A bare denial, or another code, sends no refusal: the daemon's epoch
    // just isn't admitted, as before.
    assert_eq!(named_refusal(&Status::permission_denied("denied")), None);
    assert_eq!(
        named_refusal(&refused(tonic::Code::Unavailable, &departed)),
        None
    );
}

#[test]
fn an_unknown_or_malformed_refusal_is_a_plain_denial_or_none() {
    for value in ["1000", "0", "-1"] {
        assert_eq!(
            named_refusal(&refused(tonic::Code::PermissionDenied, value)),
            Some(Refusal::Denied),
            "{value}"
        );
    }
    for value in ["", "18x", "123456"] {
        assert_eq!(
            named_refusal(&refused(tonic::Code::PermissionDenied, value)),
            None,
            "{value}"
        );
    }
}
