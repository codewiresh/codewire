//! `IssueIdentityToken` through the binding listener's own authentication,
//! the production verifier and kube client (as in `tests.rs`), with minting
//! over a fake store and signer.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use codewire_server_core::bounded_http1::PeerAddr;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::service::{BindError, IdentityCallError, WorkspaceBindingState};
use super::tests::{
    ENVIRONMENT_ID, FakeCluster, FakeStore, Fixture, OTHER_PEER, PEER, fixture_with, valid_bearer,
};
use super::{app, workspace_binding_router};
use crate::identity::MintingSwitch;
use crate::identity::mint::tests::{self as mint, AUDIENCE, FakeSigner, ORG, claims};
use crate::identity::mint::{IdentityMinting, MintLimits, MintRefusal};
use crate::worker::environment_auth::WorkspaceCredentialScope;

const CALL_TIMEOUT: Duration = Duration::from_secs(10);

struct Minting {
    fixture: Fixture,
    signer: Arc<FakeSigner>,
    mints: Arc<mint::FakeStore>,
}

fn minting_with(limits: Option<MintLimits>) -> Minting {
    let signer = FakeSigner::new();
    let mints = mint::FakeStore::for_environment(ENVIRONMENT_ID);
    let mut minter = mint::minting(signer.clone(), mints.clone(), MintingSwitch::On);
    if let Some(limits) = limits {
        minter = minter.with_limits(limits);
    }
    let minter = Some(Arc::new(minter));
    let fixture = fixture_with(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
        |state| state.with_identity(minter),
    );
    Minting {
        fixture,
        signer,
        mints,
    }
}

fn minting() -> Minting {
    minting_with(None)
}

async fn issue(
    state: &WorkspaceBindingState,
    peer: std::net::IpAddr,
    resource: &str,
) -> Result<String, IdentityCallError> {
    tokio::time::timeout(
        CALL_TIMEOUT,
        state.issue_identity_token(&valid_bearer(), Some(peer), resource),
    )
    .await
    .expect("the call answers within its bound")
    .map(|response| response.token)
}

fn refused(refusal: MintRefusal) -> Result<String, IdentityCallError> {
    Err(IdentityCallError::Refused(refusal))
}

#[tokio::test]
async fn a_bound_pod_gets_a_token_for_its_own_sandbox_and_a_registered_audience() {
    let minting = minting();
    let token = issue(&minting.fixture.state, PEER, "HTTPS://K8S.WALK.EXAMPLE:443")
        .await
        .unwrap();
    let claims = claims(&token);
    assert_eq!(claims["aud"], json!(AUDIENCE));
    assert_eq!(claims["codewire.sh"]["sandbox_id"], json!(ENVIRONMENT_ID));
    assert_eq!(claims["groups"][0], json!(format!("{ORG}:all")));
    assert_eq!(minting.fixture.reviews(), 1);
    assert_eq!(minting.mints.records().len(), 1);
}

#[tokio::test]
async fn identity_off_answers_identity_unavailable_before_any_review() {
    let fixture = fixture_with(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
        |state| state,
    );
    assert_eq!(
        issue(&fixture.state, PEER, AUDIENCE).await,
        refused(MintRefusal::IdentityUnavailable)
    );
    assert_eq!(fixture.reviews(), 0);
}

#[tokio::test]
async fn a_malformed_and_an_unregistered_resource_get_the_same_answer() {
    let minting = minting();
    for malformed in [
        "http://k8s.walk.example",
        "https://k8s.walk.example/?a=1",
        "k8s",
    ] {
        assert_eq!(
            issue(&minting.fixture.state, PEER, malformed).await,
            refused(MintRefusal::InvalidTarget),
            "{malformed}"
        );
    }
    assert_eq!(
        minting.fixture.reviews(),
        0,
        "malformed input costs no review"
    );
    assert_eq!(
        issue(&minting.fixture.state, PEER, "https://unregistered.example").await,
        refused(MintRefusal::InvalidTarget)
    );
    // The path is kept as written: a trailing slash is another audience.
    assert_eq!(
        issue(&minting.fixture.state, PEER, "https://k8s.walk.example/").await,
        refused(MintRefusal::InvalidTarget)
    );
    assert_eq!(minting.signer.signs(), 0);
}

#[tokio::test]
async fn a_caller_is_authenticated_exactly_as_a_bound_method_is() {
    let minting = minting();
    // Another workload holding the same projected token.
    assert_eq!(
        issue(&minting.fixture.state, OTHER_PEER, AUDIENCE).await,
        Err(IdentityCallError::Binding(BindError::PermissionDenied))
    );
    assert_eq!(minting.signer.signs(), 0);
}

#[tokio::test]
async fn a_stopped_sandbox_gets_no_cached_token_from_the_rpc() {
    let minting = minting();
    issue(&minting.fixture.state, PEER, AUDIENCE).await.unwrap();
    minting.mints.change(|sandbox| sandbox.stopped = true);
    assert_eq!(
        issue(&minting.fixture.state, PEER, AUDIENCE).await,
        refused(MintRefusal::IdentityStopped)
    );
    minting.mints.change(|sandbox| sandbox.stopped = false);
    issue(&minting.fixture.state, PEER, AUDIENCE).await.unwrap();
    // The repeat cost a review and no signature.
    assert_eq!((minting.fixture.reviews(), minting.signer.signs()), (3, 1));
}

#[tokio::test]
async fn a_sandbox_past_its_burst_is_refused_before_review_and_its_binding_still_works() {
    let minting = minting();
    for call in 0..10 {
        assert!(
            issue(&minting.fixture.state, PEER, AUDIENCE).await.is_ok(),
            "call {call}"
        );
    }
    for _ in 0..5 {
        assert_eq!(
            issue(&minting.fixture.state, PEER, AUDIENCE).await,
            refused(MintRefusal::ResourceExhausted)
        );
    }
    assert_eq!(minting.fixture.reviews(), 10);
    // The binding's own limits are untouched: its renewal still succeeds.
    tokio::time::timeout(
        CALL_TIMEOUT,
        minting
            .fixture
            .state
            .refresh_access(&valid_bearer(), Some(PEER)),
    )
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn the_replicas_limit_is_refused_before_review() {
    let minting = minting_with(Some(MintLimits::with(
        (1.0, 10.0),
        (1.0, 10.0),
        (0.0, 1.0),
        16,
    )));
    issue(&minting.fixture.state, PEER, AUDIENCE).await.unwrap();
    assert_eq!(
        issue(&minting.fixture.state, OTHER_PEER, AUDIENCE).await,
        refused(MintRefusal::ResourceExhausted)
    );
    assert_eq!(minting.fixture.reviews(), 1);
}

#[tokio::test]
async fn no_free_review_slot_is_resource_exhausted() {
    let minting = minting_with(Some(MintLimits::with(
        (1.0, 10.0),
        (1.0, 10.0),
        (1.0, 10.0),
        0,
    )));
    assert_eq!(
        issue(&minting.fixture.state, PEER, AUDIENCE).await,
        refused(MintRefusal::ResourceExhausted)
    );
    assert_eq!(minting.fixture.reviews(), 0);
}

#[tokio::test]
async fn the_organizations_limit_applies_once_its_sandbox_is_known() {
    let minting = minting_with(Some(MintLimits::with(
        (1.0, 10.0),
        (0.0, 1.0),
        (1.0, 10.0),
        16,
    )));
    issue(&minting.fixture.state, PEER, AUDIENCE).await.unwrap();
    assert_eq!(
        issue(&minting.fixture.state, PEER, AUDIENCE).await,
        refused(MintRefusal::ResourceExhausted)
    );
    assert_eq!(minting.fixture.reviews(), 2, "the review comes first");
}

/// One call through the listener's router, as JSON: (HTTP status, body).
async fn call_over_http(state: Arc<WorkspaceBindingState>, resource: &str) -> (StatusCode, Value) {
    let token = super::tests::token_expiring_at(super::tests::unix_now() + 600);
    let mut request =
        Request::post("/codewire.internal.v1.WorkspaceBindingService/IssueIdentityToken")
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(json!({ "resource": resource }).to_string()))
            .unwrap();
    request
        .extensions_mut()
        .insert(PeerAddr(std::net::SocketAddr::new(PEER, 40_000)));
    let response = tokio::time::timeout(
        CALL_TIMEOUT,
        app(workspace_binding_router(state)).oneshot(request),
    )
    .await
    .unwrap()
    .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn the_wire_answer_is_the_token_or_the_refusals_name() {
    let minting = minting();
    let state = minting.fixture.state.clone();
    let (status, body) = call_over_http(state.clone(), AUDIENCE).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        claims(body["token"].as_str().unwrap())["aud"],
        json!(AUDIENCE)
    );
    assert!(body["expiresAt"].is_string() || body["expiresAt"].is_number());

    let (status, body) = call_over_http(state.clone(), "https://unregistered.example").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({"code": "invalid_argument", "message": "invalid_target"})
    );

    minting.mints.change(|sandbox| sandbox.stopped = true);
    let (status, body) = call_over_http(state, AUDIENCE).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({"code": "permission_denied", "message": "identity_stopped"})
    );
    assert_eq!((minting.fixture.reviews(), minting.signer.signs()), (3, 1));
}

#[tokio::test]
async fn the_minting_switch_off_answers_identity_unavailable() {
    let signer = FakeSigner::new();
    let mints = mint::FakeStore::for_environment(ENVIRONMENT_ID);
    let minter: IdentityMinting = mint::minting(signer.clone(), mints.clone(), MintingSwitch::Off);
    let fixture = fixture_with(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
        |state| state.with_identity(Some(Arc::new(minter))),
    );
    assert_eq!(
        issue(&fixture.state, PEER, AUDIENCE).await,
        refused(MintRefusal::IdentityUnavailable)
    );
    assert_eq!(signer.signs(), 0);
    assert_eq!(signer.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.reviews(), 1, "authenticated first, then refused");
}
