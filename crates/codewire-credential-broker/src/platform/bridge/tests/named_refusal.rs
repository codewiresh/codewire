//! An admission refused for a named reason carries it to the relay; any
//! other denial carries nothing (#6406).

use codewire_access::Refusal;
use codewire_daemon_proto::CREDENTIAL_BRIDGE_REFUSAL_HEADER;
use codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeRefusal;

use super::*;

fn refusal_of(status: &Status) -> Option<String> {
    status
        .metadata()
        .get(CREDENTIAL_BRIDGE_REFUSAL_HEADER)
        .map(|value| value.to_str().unwrap().to_owned())
}

#[test]
fn a_departed_or_disabled_creator_is_a_named_permission_denied() {
    for (error, refusal, wire) in [
        (
            PlatformRuntimeError::CreatorDeparted,
            Refusal::CredentialOwnerDeparted,
            CredentialBridgeRefusal::CredentialOwnerDeparted,
        ),
        (
            PlatformRuntimeError::CreatorDisabled,
            Refusal::CredentialOwnerDisabled,
            CredentialBridgeRefusal::CredentialOwnerDisabled,
        ),
    ] {
        for status in [
            runtime_status(error),
            PlatformBridgeAuthenticationError::Refused(refusal).status(),
        ] {
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
            assert_eq!(refusal_of(&status), Some((wire as i32).to_string()));
            // The message names no reason; only the closed value does.
            assert_eq!(
                status.message(),
                "platform credential bridge authority denied the session"
            );
        }
    }
    let denied = runtime_status(PlatformRuntimeError::Denied);
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    assert_eq!(refusal_of(&denied), None);
}
