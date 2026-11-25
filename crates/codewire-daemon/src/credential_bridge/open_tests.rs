//! A host's first frame: an Open, or a hosted relay's refusal of the epoch
//! (#6406).

use codewire_access::Refusal;
use codewire_daemon_proto::codewire::bridge::v1::credential_bridge_host_message::Payload;

use super::*;

fn identity() -> BridgeIdentity {
    BridgeIdentity {
        environment_id: uuid::Uuid::new_v4(),
        environment_generation: 7,
    }
}

fn refused(identity: BridgeIdentity, refusal: i32) -> v1::CredentialBridgeHostMessage {
    v1::CredentialBridgeHostMessage {
        payload: Some(Payload::EpochRefused(v1::CredentialBridgeEpochRefused {
            protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
            environment_id: identity.environment_id.to_string(),
            environment_generation: identity.environment_generation,
            refusal,
        })),
    }
}

async fn first(
    identity: BridgeIdentity,
    message: v1::CredentialBridgeHostMessage,
    hosted: bool,
) -> Result<Opening, Status> {
    let mut input = tokio_stream::iter([Ok(message)]);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    read_open(&mut input, identity, deadline, false, hosted).await
}

#[tokio::test]
async fn a_hosted_daemon_takes_its_epochs_refusal_in_place_of_open() {
    let identity = identity();
    let departed = v1::CredentialBridgeRefusal::CredentialOwnerDeparted as i32;
    assert!(matches!(
        first(identity, refused(identity, departed), true).await,
        Ok(Opening::Refused(Refusal::CredentialOwnerDeparted))
    ));
    // A value this daemon doesn't know is a plain denial.
    assert!(matches!(
        first(identity, refused(identity, 1_000), true).await,
        Ok(Opening::Refused(Refusal::Denied))
    ));
}

#[tokio::test]
async fn a_refusal_for_another_identity_or_to_a_local_daemon_is_refused() {
    let identity = identity();
    let departed = v1::CredentialBridgeRefusal::CredentialOwnerDeparted as i32;
    let other = BridgeIdentity {
        environment_generation: 8,
        ..identity
    };
    let wrong = first(identity, refused(other, departed), true)
        .await
        .err()
        .unwrap();
    assert_eq!(wrong.code(), tonic::Code::FailedPrecondition);
    let local = first(identity, refused(identity, departed), false)
        .await
        .err()
        .unwrap();
    assert_eq!(local.code(), tonic::Code::InvalidArgument);
}
