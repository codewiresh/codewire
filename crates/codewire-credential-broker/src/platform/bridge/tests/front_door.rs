//! Front-door streams joining an admitted epoch (codewire#4001): the
//! handle, the order of the checks, and one stream per epoch.

use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITIES_HEADER, CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES,
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
};
use prost::Message as _;
use tonic::metadata::BinaryMetadataValue;

use super::*;

/// The handle an admitted epoch's response carries.
fn handle_of(response: &Response<Streaming<v1::CredentialBridgeHostMessage>>) -> Vec<u8> {
    let values: Vec<_> = response
        .metadata()
        .get_all_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER)
        .iter()
        .map(|value| value.to_bytes().unwrap().to_vec())
        .collect();
    assert_eq!(values.len(), 1, "exactly one handle");
    values.into_iter().next().unwrap()
}

impl Fixture {
    /// A front-door stream presenting `identity` and `handle`, its first
    /// message a Ready for the fixture's binding.
    pub(super) async fn join(
        &self,
        identity: Option<&str>,
        handle: Option<&[u8]>,
    ) -> (
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Result<Response<Streaming<v1::CredentialBridgeHostMessage>>, Status>,
    ) {
        let (input, receiver) = mpsc::channel(4);
        input.send(self.ready()).await.unwrap();
        let mut request = rpc_request(receiver, identity);
        if let Some(handle) = handle {
            request.metadata_mut().insert_bin(
                CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
                BinaryMetadataValue::from_bytes(handle),
            );
        }
        let result = self.client().await.front_door_bridge(request).await;
        (input, result)
    }
}

#[tokio::test]
async fn an_admitted_epoch_carries_one_handle_that_never_appears_in_its_frames() {
    let fixture = Fixture::new().await;
    let (input, response) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut response = response.unwrap();
    let handle = handle_of(&response);
    assert_eq!(handle.len(), CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES);
    // A request's whole answer, encoded: the handle is in none of it.
    input.send(leased_request()).await.unwrap();
    drop(input);
    let mut frames = Vec::new();
    while let Ok(Some(frame)) = tokio::time::timeout(TEST_TIMEOUT, response.get_mut().message())
        .await
        .unwrap()
    {
        frames.extend(frame.encode_to_vec());
    }
    assert!(
        !frames
            .windows(handle.len())
            .any(|window| window == handle.as_slice()),
        "the handle never travels in a frame"
    );
    fixture.slots_released().await;
    fixture.finish().await;
}

#[tokio::test]
async fn a_front_door_stream_with_the_epochs_handle_joins_and_lists_its_operations() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let handle = handle_of(&epoch.unwrap());
    let (_input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    let joined = joined.unwrap();
    let capabilities: Vec<_> = joined
        .metadata()
        .get_all(CREDENTIAL_BRIDGE_CAPABILITIES_HEADER)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        capabilities,
        [
            codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_FRONT_DOOR,
            codewire_daemon_proto::CREDENTIAL_BRIDGE_CAPABILITY_REQUEST_BODY_STREAM,
        ]
    );
    assert_eq!(
        fixture.service.streams_in_use(),
        2,
        "the joined stream holds a slot"
    );
}

#[tokio::test]
async fn the_relay_identity_is_checked_before_the_handle_is_read() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let handle = handle_of(&epoch.unwrap());
    let calls = fixture.authenticator.authority.calls.load(Ordering::SeqCst);
    // Without a handle too: the caller learns nothing about handles until
    // its identity is accepted.
    for handle in [Some(&handle[..]), None] {
        let (_input, joined) = fixture.join(None, handle).await;
        assert_eq!(joined.unwrap_err().code(), Code::Unauthenticated);
    }
    let (_input, joined) = fixture.join(Some("synthetic-deny"), Some(&handle)).await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(
        fixture.authenticator.authority.calls.load(Ordering::SeqCst),
        calls,
        "no binding is read for an unauthenticated caller"
    );
}

#[tokio::test]
async fn a_missing_malformed_or_unknown_handle_is_denied() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let mut wrong = handle_of(&epoch.unwrap());
    wrong[0] ^= 1;
    for handle in [None, Some(&wrong[..16]), Some(&wrong[..])] {
        let (_input, joined) = fixture.join(Some("synthetic-allow"), handle).await;
        assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);
    }
}

#[tokio::test]
async fn an_ended_epochs_handle_is_denied() {
    let fixture = Fixture::new().await;
    let (epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let epoch = epoch.unwrap();
    let handle = handle_of(&epoch);
    drop((epoch_input, epoch));
    fixture.slots_released().await;
    let (_input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);
}

#[tokio::test]
async fn another_bindings_handle_is_denied() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let handle = handle_of(&epoch.unwrap());
    // The same relay identity, now naming another generation of the binding.
    fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .context
        .environment_generation += 1;
    let (_input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);
}

#[tokio::test]
async fn an_epoch_serves_one_front_door_stream_and_takes_the_next_once_it_ends() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let handle = handle_of(&epoch.unwrap());
    let (first_input, first) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    let first = first.unwrap();
    let (_second_input, second) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
    // cw-egress restarts: its old stream ends, and its new one joins at once.
    drop((first_input, first));
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            let (_input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
            match joined {
                Ok(_) => break,
                Err(status) if status.code() == Code::AlreadyExists => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(status) => panic!("unexpected {status:?}"),
            }
        }
    })
    .await
    .expect("the next front-door stream joins once the first has ended");
}
