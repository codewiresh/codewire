//! A local front door joining its owner's delegation epoch (codewire#4909):
//! the handle in the admission answer, the owner scope, and one stream per
//! epoch, through the same registry as a hosted join.

use codewire_daemon_proto::{
    CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES, CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
};
use tonic::metadata::BinaryMetadataValue;

use super::*;

const OWNER: &str = "synthetic-owner-a";
const OTHER_OWNER: &str = "synthetic-owner-b";

type Output = ReceiverStream<Result<v1::CredentialBridgeHostMessage, Status>>;

/// The request headers a join carries, with `handle` when given.
fn presenting(handle: Option<&[u8]>) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    if let Some(handle) = handle {
        metadata.insert_bin(
            CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
            BinaryMetadataValue::from_bytes(handle),
        );
    }
    metadata
}

impl Fixture {
    /// A delegation epoch admitted for `owner`, its first message a Ready
    /// for the fixture's environment; returns its input, output and handle.
    async fn delegate(
        &self,
        owner: &str,
    ) -> (
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Output,
        Vec<u8>,
    ) {
        self.delegate_declaring(owner, true).await
    }

    /// A delegation epoch admitted for `owner`, whose Open declared a front
    /// door or not.
    async fn delegate_declaring(
        &self,
        owner: &str,
        front_door: bool,
    ) -> (
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Output,
        Vec<u8>,
    ) {
        let (input, receiver) = mpsc::channel(4);
        input.send(self.ready()).await.unwrap();
        let authority = Arc::clone(&self.authenticator.authority);
        let (output, _expires_at_unix, handle) = self
            .service
            .serve_authenticated_delegation(owner.to_owned(), async move {
                Ok((authority, ReceiverStream::new(receiver).map(Ok), front_door))
            })
            .await
            .unwrap();
        (input, output, handle)
    }

    /// A front-door stream joining as `owner` with `handle`, its first
    /// message a Ready for the fixture's environment.
    async fn join_delegated(
        &self,
        owner: &str,
        handle: Option<&[u8]>,
    ) -> (
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Result<Output, Status>,
    ) {
        let (input, receiver) = mpsc::channel(4);
        input.send(self.ready()).await.unwrap();
        let joined = self
            .service
            .join_delegated_front_door(
                owner.to_owned(),
                &presenting(handle),
                ReceiverStream::new(receiver).map(Ok).boxed(),
            )
            .await;
        (input, joined)
    }
}

#[tokio::test]
async fn a_delegation_returns_one_handle_its_owner_joins_with() {
    let fixture = Fixture::new().await;
    let (_epoch_input, _epoch, handle) = fixture.delegate(OWNER).await;
    assert_eq!(handle.len(), CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES);
    let (_input, joined) = fixture.join_delegated(OWNER, Some(&handle)).await;
    joined.unwrap();
    assert_eq!(
        fixture.service.streams_in_use(),
        2,
        "the joined stream holds a slot"
    );
}

/// An unknown handle, another owner's valid one, one of another length and
/// none at all are one refusal, with one message (#4909, cw-security).
#[tokio::test]
async fn another_owners_handle_is_refused_exactly_as_an_unknown_one() {
    let fixture = Fixture::new().await;
    let (_epoch_input, _epoch, handle) = fixture.delegate(OWNER).await;
    let mut unknown = handle.clone();
    unknown[0] ^= 1;
    let mut refusals = Vec::new();
    for (owner, presented) in [
        (OTHER_OWNER, Some(handle.as_slice())),
        (OWNER, Some(unknown.as_slice())),
        (
            OWNER,
            Some(&handle[..CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES - 1]),
        ),
        (OWNER, None),
    ] {
        let (_input, joined) = fixture.join_delegated(owner, presented).await;
        let status = joined.unwrap_err();
        refusals.push((status.code(), status.message().to_owned()));
    }
    assert!(
        refusals
            .iter()
            .all(|refusal| *refusal == (Code::PermissionDenied, "credential bridge denied".into())),
        "{refusals:?}"
    );
    // The owner's own handle still joins: the refusals claimed nothing.
    let (_input, joined) = fixture.join_delegated(OWNER, Some(&handle)).await;
    joined.unwrap();
}

#[tokio::test]
async fn an_ended_delegations_handle_is_refused() {
    let fixture = Fixture::new().await;
    let (epoch_input, epoch, handle) = fixture.delegate(OWNER).await;
    drop((epoch_input, epoch));
    fixture.slots_released().await;
    let (_input, joined) = fixture.join_delegated(OWNER, Some(&handle)).await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);
}

#[tokio::test]
async fn a_delegation_serves_one_front_door_stream_at_a_time() {
    let fixture = Fixture::new().await;
    let (_epoch_input, _epoch, handle) = fixture.delegate(OWNER).await;
    let (_first_input, first) = fixture.join_delegated(OWNER, Some(&handle)).await;
    let _first = first.unwrap();
    let (_second_input, second) = fixture.join_delegated(OWNER, Some(&handle)).await;
    assert_eq!(second.unwrap_err().code(), Code::AlreadyExists);
}

/// A hosted epoch's handle never joins as a delegation, and a delegation's
/// never joins as a hosted binding: each claim searches its own scope.
#[tokio::test]
async fn hosted_and_delegated_handles_never_cross_scopes() {
    let fixture = Fixture::new().await;
    let (_hosted_input, hosted) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
    let hosted = hosted
        .unwrap()
        .metadata()
        .get_bin(CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER)
        .unwrap()
        .to_bytes()
        .unwrap()
        .to_vec();
    let (_input, joined) = fixture.join_delegated(OWNER, Some(&hosted)).await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);

    let (_epoch_input, _epoch, delegated) = fixture.delegate(OWNER).await;
    let (_input, joined) = fixture
        .join(Some("synthetic-allow"), Some(&delegated))
        .await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);
}

/// A delegation that didn't declare a front door gets no handle, and keeps
/// its logins as before; one that did gets a handle and seals placeholders
/// (#4909, cw-security).
#[tokio::test]
async fn only_a_delegation_that_declared_a_front_door_can_be_joined() {
    let fixture = Fixture::new().await;
    let (_input, _epoch, handle) = fixture.delegate_declaring(OWNER, false).await;
    assert!(handle.is_empty(), "an undeclared delegation has no handle");
    let (_input, joined) = fixture
        .join_delegated(OWNER, Some(&[0_u8; CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES]))
        .await;
    assert_eq!(joined.unwrap_err().code(), Code::PermissionDenied);

    let (_input, _epoch, handle) = fixture.delegate_declaring(OWNER, true).await;
    assert_eq!(handle.len(), CREDENTIAL_BRIDGE_EPOCH_HANDLE_BYTES);
    let (_input, joined) = fixture.join_delegated(OWNER, Some(&handle)).await;
    joined.unwrap();
}

/// Every joinable epoch seals its logins with placeholders: a declared
/// delegation (#4909) and an intercepted hosted epoch (#4001). An epoch no
/// front door can join keeps its logins.
#[test]
fn every_joinable_scope_seals_placeholders() {
    assert!(super::super::seals_placeholders(Some(
        &FrontDoorScope::Owner(OWNER.into())
    )));
    assert!(super::super::seals_placeholders(Some(
        &FrontDoorScope::Binding {
            environment_id: Uuid::new_v4(),
            generation: 1,
        }
    )));
    assert!(!super::super::seals_placeholders(None));
}

/// A delegation epoch whose Open declared a front door is paired, so it
/// seals only placeholder logins; its leases must carry placeholders, or
/// every login is refused `no_placeholder_beside_front_door` (#4909, Dev
/// 2026-11-22). Hosted epochs keep following the hosted switch, and an
/// undeclared delegation carries none.
#[test]
fn a_delegation_that_declared_a_front_door_leases_placeholders() {
    use super::super::lease_placeholders;
    for hosted_switch in [false, true] {
        assert!(lease_placeholders(false, hosted_switch, true));
        assert!(!lease_placeholders(false, hosted_switch, false));
        assert_eq!(
            lease_placeholders(true, hosted_switch, false),
            hosted_switch
        );
    }
}
