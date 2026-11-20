//! The interception CA's methods on the bridge service (codewire#4001): which
//! authentication each takes, and what a leaf request needs of its epoch.

use codewire_daemon_proto::CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER;
use codewire_daemon_proto::broker::v1::{
    EnsureInterceptionCaRequest, SignInterceptionLeavesRequest,
};
use tonic::metadata::BinaryMetadataValue;

use super::front_door::handle_of;
use super::*;

/// Counts what the service asked of the CAs.
#[derive(Default)]
pub(super) struct RecordingCas {
    ensured: AtomicUsize,
    signed: AtomicUsize,
}

#[async_trait]
impl InterceptionCas for RecordingCas {
    async fn ensure(
        &self,
        _pod_uid: &str,
        _pod_name: &str,
    ) -> Result<Vec<u8>, InterceptionCaError> {
        self.ensured.fetch_add(1, Ordering::SeqCst);
        Ok(b"ca-certificate".to_vec())
    }

    async fn sign(&self, _request: LeafRequest<'_>) -> Result<SignedLeaf, InterceptionCaError> {
        self.signed.fetch_add(1, Ordering::SeqCst);
        Err(InterceptionCaError::Unavailable)
    }
}

const POD: &str = "2f6b1c9e-5d4a-4c3b-9a8e-1f2d3c4b5a69";

fn relay_only<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert("x-synthetic-relay", "relay-allow".parse().unwrap());
    request
}

fn ensure_request() -> EnsureInterceptionCaRequest {
    EnsureInterceptionCaRequest {
        pod_uid: POD.to_owned(),
        pod_name: "sandbox-0".to_owned(),
    }
}

fn leaves_request(
    identity: Option<&str>,
    handle: Option<&[u8]>,
) -> Request<SignInterceptionLeavesRequest> {
    let mut request = Request::new(SignInterceptionLeavesRequest {
        leaf_public_key: b"synthetic-key".to_vec(),
    });
    if let Some(identity) = identity {
        request
            .metadata_mut()
            .insert("x-synthetic-identity", identity.parse().unwrap());
    }
    if let Some(handle) = handle {
        request.metadata_mut().insert_bin(
            CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
            BinaryMetadataValue::from_bytes(handle),
        );
    }
    request
}

#[tokio::test]
async fn the_relay_token_alone_ensures_a_ca_and_opens_nothing_else() {
    let fixture = Fixture::new().await;
    let mut client = fixture.client().await;
    let response = client
        .ensure_interception_ca(relay_only(ensure_request()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.ca_certificate_der, b"ca-certificate");
    // Every other method demands the whole chain.
    let leaves = client
        .sign_interception_leaves(relay_only(SignInterceptionLeavesRequest {
            leaf_public_key: b"synthetic-key".to_vec(),
        }))
        .await
        .unwrap_err();
    assert_eq!(leaves.code(), Code::Unauthenticated);
    for front_door in [false, true] {
        let (input, receiver) = mpsc::channel(4);
        input.send(fixture.ready()).await.unwrap();
        let mut request = Request::new(ReceiverStream::new(receiver));
        request
            .metadata_mut()
            .insert("x-synthetic-relay", "relay-allow".parse().unwrap());
        let error = if front_door {
            client.front_door_bridge(request).await.unwrap_err()
        } else {
            client.credential_bridge(request).await.unwrap_err()
        };
        assert_eq!(
            error.code(),
            Code::Unauthenticated,
            "front door: {front_door}"
        );
    }
    assert_eq!(fixture.cas.signed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_workspace_session_cannot_ensure_a_ca() {
    let fixture = Fixture::new().await;
    let mut request = Request::new(ensure_request());
    request
        .metadata_mut()
        .insert("x-synthetic-identity", "synthetic-allow".parse().unwrap());
    let error = fixture
        .client()
        .await
        .ensure_interception_ca(request)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated);
    assert_eq!(fixture.cas.ensured.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_authenticator_that_serves_no_relay_only_call_refuses_it() {
    struct WorkspaceOnly;
    #[async_trait]
    impl PlatformBridgeAuthenticator for WorkspaceOnly {
        type Authority = Authority;
        async fn authenticate(
            &self,
            _metadata: &MetadataMap,
        ) -> Result<Arc<Authority>, PlatformBridgeAuthenticationError> {
            Err(PlatformBridgeAuthenticationError::Denied)
        }
    }
    let mut metadata = MetadataMap::new();
    metadata.insert("x-synthetic-relay", "relay-allow".parse().unwrap());
    assert!(matches!(
        WorkspaceOnly.authenticate_relay(&metadata).await,
        Err(PlatformBridgeAuthenticationError::Unauthenticated)
    ));
}

#[tokio::test]
async fn a_leaf_request_before_its_binding_has_an_epoch_is_unavailable_to_retry() {
    let fixture = Fixture::new().await;
    // Authenticated, with a well-formed handle, but no epoch admitted yet.
    let error = fixture
        .client()
        .await
        .sign_interception_leaves(leaves_request(Some("synthetic-allow"), Some(&[7; 32])))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(fixture.cas.signed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_leaf_request_needs_its_bindings_live_epoch_handle_and_takes_no_stream() {
    let fixture = Fixture::new().await;
    // Only an intercepted epoch has a handle (#4001).
    let (_epoch_input, epoch) = fixture
        .open_as(Some("synthetic-allow"), fixture.ready(), &["true"])
        .await;
    let handle = handle_of(&epoch.unwrap());
    let mut client = fixture.client().await;
    for (request, expected) in [
        (leaves_request(None, Some(&handle)), Code::Unauthenticated),
        (
            leaves_request(Some("synthetic-allow"), None),
            Code::PermissionDenied,
        ),
        // An admitted binding, and a handle that is none of its epochs'.
        (
            leaves_request(Some("synthetic-allow"), Some(&[7; 32])),
            Code::PermissionDenied,
        ),
    ] {
        let error = client.sign_interception_leaves(request).await.unwrap_err();
        assert_eq!(error.code(), expected);
    }
    // The right handle reaches the session's grants, which this fixture's
    // closed database can't answer: it fails closed, signing nothing.
    let error = client
        .sign_interception_leaves(leaves_request(Some("synthetic-allow"), Some(&handle)))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(fixture.cas.signed.load(Ordering::SeqCst), 0);
    // Reading the epoch's bounds took neither its front-door place nor a
    // stream permit.
    let (_input, joined) = fixture.join(Some("synthetic-allow"), Some(&handle)).await;
    assert!(joined.is_ok());
}

#[tokio::test]
async fn a_leaf_request_speaks_for_the_workspace_pod_never_the_relay() {
    let fixture = Fixture::new().await;
    let session = fixture
        .authenticator
        .authority
        .session
        .lock()
        .unwrap()
        .clone();
    let RuntimeIdentity::Hosted { relay, workspace } = &session.identity else {
        panic!("the fixture's session is hosted");
    };
    let speaks_for = crate::platform::bridge::interception::workspace_pod_uid(&session);
    assert_eq!(speaks_for, Some(workspace.uid));
    assert_ne!(speaks_for, Some(relay.uid));
}
