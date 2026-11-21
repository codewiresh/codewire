//! Front-door streams joining an admitted epoch (codewire#4001): the
//! handle, the order of the checks, and one stream per epoch.

use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_CAPABILITIES_HEADER, CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES,
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER, CREDENTIAL_BRIDGE_PLACEHOLDERS_HEADER,
};
use prost::Message as _;
use tonic::metadata::BinaryMetadataValue;

use super::*;

/// The handle an admitted epoch's response carries.
pub(super) fn handle_of(
    response: &Response<Streaming<v1::CredentialBridgeHostMessage>>,
) -> Vec<u8> {
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
    let (input, response) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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
    let (epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
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

#[tokio::test]
async fn an_idle_joined_stream_ends_and_returns_its_slot() {
    let idle = Duration::from_millis(300);
    let fixture = Fixture::idling_after(idle).await;
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
    let handle = handle_of(&epoch.unwrap());
    let before = fixture.service.streams_in_use();
    let (_input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    let mut joined = joined.unwrap();
    assert_eq!(fixture.service.streams_in_use(), before + 1);
    // Nothing in flight and nothing sent: it ends on its own, cleanly.
    let ended = tokio::time::timeout(TEST_TIMEOUT, joined.get_mut().message())
        .await
        .expect("the idle stream ended");
    assert!(matches!(ended, Ok(None)), "{ended:?}");
    tokio::time::timeout(TEST_TIMEOUT, async {
        while fixture.service.streams_in_use() != before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("its slot is returned");
    // And the epoch takes the next stream at once.
    let (_next_input, next) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    assert!(next.is_ok());
}

/// #5555: a hosted epoch's broker sends nothing that lacks the Sandbox's own
/// placeholder. The user's own token on the front door is refused with the
/// hosted refusal, before any lease, and no upstream is called.
#[tokio::test]
async fn a_hosted_front_door_request_without_the_placeholder_is_refused_and_never_sent() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
    let handle = handle_of(&epoch.unwrap());
    let (input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    let mut joined = joined.unwrap();
    let request_id = Uuid::new_v4().to_string();
    input
        .send(v1::CredentialBridgeGuestMessage {
            payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                v1::CredentialBridgeRequest {
                    capability_slot: "github".into(),
                    route: "github-api".into(),
                    request_id: request_id.clone(),
                    method: "GET".into(),
                    path: "/user".into(),
                    query: String::new(),
                    headers: vec![v1::CredentialHttpHeader {
                        name: "authorization".into(),
                        value: b"token ghp_usersOwnToken0123456789".to_vec(),
                    }],
                    body: vec![],
                    intercepted_host: "api.github.com".into(),
                    streamed_body: false,
                    intercept_decision: Vec::new(),
                    destination_ip: String::new(),
                },
            )),
        })
        .await
        .unwrap();
    let failure = loop {
        let frame = tokio::time::timeout(TEST_TIMEOUT, joined.get_mut().message())
            .await
            .unwrap()
            .unwrap()
            .expect("an answer before the stream ends");
        if let Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure)) =
            frame.payload
        {
            break failure;
        }
    };
    assert_eq!(failure.request_id, request_id);
    assert_eq!(
        failure.refusal,
        v1::CredentialBridgeRefusal::SelectedCredentialOnly as i32
    );
    assert_eq!(fixture.upstream.calls.load(Ordering::SeqCst), 0);
}

/// Only an epoch the relay says is intercepted can be joined (#4001): one it
/// says isn't carries no handle, so no front door is ever served beside its
/// real logins.
#[tokio::test]
async fn an_epoch_the_relay_says_is_not_intercepted_carries_no_handle() {
    let fixture = Fixture::new().await;
    let (_epoch_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    let epoch = epoch.unwrap();
    assert_eq!(
        epoch
            .metadata()
            .get_all_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER)
            .iter()
            .count(),
        0
    );
}

/// The placeholders an admitted epoch's response carries, one per value.
fn placeholder_values(
    response: &Response<Streaming<v1::CredentialBridgeHostMessage>>,
) -> Vec<String> {
    response
        .metadata()
        .get_all(CREDENTIAL_BRIDGE_PLACEHOLDERS_HEADER)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

/// An intercepted epoch's response carries its projected placeholders in
/// exactly one value, for the relay alone (#4001); one that isn't carries
/// none. This fixture's service derives none, so the value is empty.
#[tokio::test]
async fn an_intercepted_epoch_carries_one_placeholders_value_and_another_none() {
    let fixture = Fixture::new().await;
    let (_intercepted_input, intercepted) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
    assert_eq!(placeholder_values(&intercepted.unwrap()), [""]);
    let (_input, epoch) = fixture.open(Some("synthetic-allow"), fixture.ready()).await;
    assert!(placeholder_values(&epoch.unwrap()).is_empty());
}

/// The placeholders value is inserted sensitive, so HTTP/2 never indexes it
/// and a metadata `Debug` never prints it.
#[test]
fn the_placeholders_value_is_sensitive() {
    let placeholder =
        codewire_access::CredentialPlaceholder::parse(codewire_access::known_answer::PLACEHOLDER)
            .unwrap();
    let mut metadata = MetadataMap::new();
    super::super::insert_placeholders(
        &mut metadata,
        &codewire_access::ProjectedPlaceholders::default().with_anthropic(placeholder),
    )
    .unwrap();
    let value = metadata.get(CREDENTIAL_BRIDGE_PLACEHOLDERS_HEADER).unwrap();
    assert!(value.is_sensitive());
    assert!(!format!("{metadata:?}").contains(codewire_access::known_answer::PLACEHOLDER));
}

/// With hosted placeholders on, an intercepted epoch whose grants can't be
/// evaluated is refused rather than admitted with part of a set or none; an
/// epoch that isn't intercepted derives nothing and is admitted.
#[tokio::test]
async fn an_intercepted_epoch_whose_placeholders_cant_be_derived_is_refused() {
    let fixture = Fixture::with_hosted_placeholders().await;
    let (_input, intercepted) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
    assert_eq!(intercepted.unwrap_err().code(), Code::Unavailable);
    let (_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["false"])
        .await;
    assert!(placeholder_values(&epoch.unwrap()).is_empty());
}

/// A relay states an epoch's interception at most once, and exactly `true`
/// or `false`; anything else refuses the epoch, never defaulting to real
/// logins. The relay's identity is checked first.
#[tokio::test]
async fn a_repeated_or_other_interception_header_refuses_the_epoch() {
    let fixture = Fixture::new().await;
    for intercepted in [
        &["yes"][..],
        &["TRUE"],
        &[""],
        &["false", "false"],
        &["true", "false"],
    ] {
        let (_input, epoch) = fixture
            .open_as(Some("synthetic-allow"), fixture.ready(), intercepted)
            .await;
        assert_eq!(
            epoch.unwrap_err().code(),
            Code::PermissionDenied,
            "{intercepted:?}"
        );
        let (_input, epoch) = fixture.open_as(None, fixture.ready(), intercepted).await;
        assert_eq!(epoch.unwrap_err().code(), Code::Unauthenticated);
    }
    assert_eq!(fixture.service.streams_in_use(), 0);
}

/// A relay older than the header sends none (#4001). While hosted
/// placeholders are off, the service could serve no intercepted epoch
/// anyway, so the epoch is admitted as not intercepted, with no handle: a
/// deploy that rolls the credential service first changes nothing. With
/// them on, a missing header refuses the epoch.
#[tokio::test]
async fn a_missing_interception_header_is_not_intercepted_only_while_placeholders_are_off() {
    let fixture = Fixture::new().await;
    let (_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &[])
        .await;
    let epoch = epoch.unwrap();
    assert_eq!(
        epoch
            .metadata()
            .get_all_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER)
            .iter()
            .count(),
        0
    );

    let fixture = Fixture::with_hosted_placeholders().await;
    let (_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &[])
        .await;
    assert_eq!(epoch.unwrap_err().code(), Code::PermissionDenied);
    let (_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["false"])
        .await;
    assert!(epoch.is_ok());
}
