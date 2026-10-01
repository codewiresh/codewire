//! `BindWorkspace` decisions through the production verifier and kube client.
//! Kubernetes is an in-process HTTP service (TokenReview, Pod and Sandbox
//! reads), not a replacement authenticator, and the binding store is a fake
//! with the same contract as the SQL lookup.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header::AUTHORIZATION};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_gateway_proto::{
    GATEWAY_BINDING_SERVICE_ACCOUNT, GATEWAY_BINDING_TOKEN_AUDIENCE,
    WORKSPACE_BINDING_TOKEN_AUDIENCE,
};
use codewire_server_core::bounded_http1::PeerAddr;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use k8s_openapi::api::core::v1::{Pod, PodSpec, PodStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
use serde_json::{Value, json};
use tower::{ServiceExt, service_fn};

use super::limits::RequestLimits;
use super::service::{BindError, WorkspaceBindingState};
use super::store::{BindingNotifications, BindingStore, BindingStoreUnavailable, LiveBinding};
use super::{app, workspace_binding_router};
use crate::sandbox::{LABEL_ENV_ID, LABEL_TYPE};
use crate::worker::gatewayauth::{
    SCOPE_DAEMON, WorkspaceCredentialScope, issue_token, issue_workspace_daemon_credential,
};

const NAMESPACE: &str = "sandboxes";
const POD_NAME: &str = "sandbox-workspace-1";
const POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const OTHER_POD_UID: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const SANDBOX_NAME: &str = "sandbox-workspace-1";
const SANDBOX_UID: &str = "5a4db0c5-6d1e-4b0f-9b3c-2f0e7c1d9a11";
const CLAIM_UID: &str = "c0ffee00-1d2e-4f3a-8b4c-5d6e7f8a9b0c";
const ENVIRONMENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const SECRET: &str = "synthetic-session-secret";
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 0, 9));

// ---------------------------------------------------------------- fixtures

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn token_expiring_at(exp: u64) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#)),
        URL_SAFE_NO_PAD.encode(b"synthetic-signature")
    )
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

fn valid_bearer() -> HeaderMap {
    bearer(&token_expiring_at(unix_now() + 600))
}

fn review(namespace: &str, service_account: &str, audience: &str) -> TokenReviewStatus {
    TokenReviewStatus {
        authenticated: Some(true),
        audiences: Some(vec![audience.into()]),
        user: Some(UserInfo {
            username: Some(format!(
                "system:serviceaccount:{namespace}:{service_account}"
            )),
            extra: Some(BTreeMap::from([
                (
                    "authentication.kubernetes.io/pod-name".into(),
                    vec![POD_NAME.into()],
                ),
                (
                    "authentication.kubernetes.io/pod-uid".into(),
                    vec![POD_UID.into()],
                ),
            ])),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn valid_review() -> TokenReviewStatus {
    review(
        NAMESPACE,
        GATEWAY_BINDING_SERVICE_ACCOUNT,
        WORKSPACE_BINDING_TOKEN_AUDIENCE,
    )
}

fn controller(api_version: &str, kind: &str, name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: api_version.into(),
        kind: kind.into(),
        name: name.into(),
        uid: uid.into(),
        controller: Some(true),
        ..Default::default()
    }
}

fn workspace_pod() -> Pod {
    Pod {
        metadata: ObjectMeta {
            name: Some(POD_NAME.into()),
            namespace: Some(NAMESPACE.into()),
            uid: Some(POD_UID.into()),
            labels: Some(BTreeMap::from([
                (LABEL_TYPE.into(), "workspace".into()),
                (LABEL_ENV_ID.into(), ENVIRONMENT_ID.into()),
            ])),
            owner_references: Some(vec![controller(
                "agents.x-k8s.io/v1beta1",
                "Sandbox",
                SANDBOX_NAME,
                SANDBOX_UID,
            )]),
            ..Default::default()
        },
        spec: Some(PodSpec {
            service_account_name: Some(GATEWAY_BINDING_SERVICE_ACCOUNT.into()),
            containers: Vec::new(),
            ..Default::default()
        }),
        status: Some(PodStatus {
            phase: Some("Running".into()),
            ..Default::default()
        }),
    }
}

fn sandbox() -> Value {
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": {
            "name": SANDBOX_NAME,
            "namespace": NAMESPACE,
            "uid": SANDBOX_UID,
            "ownerReferences": [{
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                "kind": "SandboxClaim",
                "name": "sandbox-claim",
                "uid": CLAIM_UID,
                "controller": true,
            }],
        },
    })
}

fn binding(scope: WorkspaceCredentialScope) -> LiveBinding {
    LiveBinding {
        environment_id: ENVIRONMENT_ID.into(),
        pod_uid: POD_UID.into(),
        namespace: NAMESPACE.into(),
        pod_name: POD_NAME.into(),
        claim_uid: CLAIM_UID.into(),
        sandbox_uid: SANDBOX_UID.into(),
        operation_generation: 7,
        projection_selection_sha256: Some("ab".repeat(32)),
        managed_credential_clients: "github".into(),
        credential_scope: scope,
    }
}

// ------------------------------------------------------- fake Kubernetes

/// Sticky sequences: each read pops the next value and keeps the last.
struct Sequence<T>(Mutex<VecDeque<T>>);

impl<T: Clone> Sequence<T> {
    fn of(values: impl IntoIterator<Item = T>) -> Self {
        Self(Mutex::new(values.into_iter().collect()))
    }

    fn next(&self) -> T {
        let mut values = self.0.lock().unwrap();
        if values.len() > 1 {
            values.pop_front().unwrap()
        } else {
            values.front().cloned().expect("sequence has a value")
        }
    }
}

struct FakeCluster {
    review: TokenReviewStatus,
    reviews: AtomicUsize,
    pods: Sequence<Option<Pod>>,
    sandboxes: Sequence<Option<Value>>,
}

impl FakeCluster {
    fn new(
        review: TokenReviewStatus,
        pods: Vec<Option<Pod>>,
        sandboxes: Vec<Option<Value>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            review,
            reviews: AtomicUsize::new(0),
            pods: Sequence::of(pods),
            sandboxes: Sequence::of(sandboxes),
        })
    }

    fn valid() -> Arc<Self> {
        Self::new(
            valid_review(),
            vec![Some(workspace_pod())],
            vec![Some(sandbox())],
        )
    }

    fn client(self: &Arc<Self>) -> kube::Client {
        let cluster = self.clone();
        let service = service_fn(move |request: Request<kube::client::Body>| {
            let cluster = cluster.clone();
            async move {
                let path = request.uri().path().to_owned();
                let method = request.method().clone();
                let response = if method == "POST"
                    && path == "/apis/authentication.k8s.io/v1/tokenreviews"
                {
                    cluster.reviews.fetch_add(1, Ordering::SeqCst);
                    json_response(
                        StatusCode::CREATED,
                        serde_json::to_value(TokenReview {
                            status: Some(cluster.review.clone()),
                            ..Default::default()
                        })
                        .unwrap(),
                    )
                } else if method == "GET"
                    && path == format!("/api/v1/namespaces/{NAMESPACE}/pods/{POD_NAME}")
                {
                    match cluster.pods.next() {
                        Some(pod) => {
                            json_response(StatusCode::OK, serde_json::to_value(pod).unwrap())
                        }
                        None => not_found(),
                    }
                } else if method == "GET"
                    && path
                        == format!(
                            "/apis/agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxes/{SANDBOX_NAME}"
                        )
                {
                    match cluster.sandboxes.next() {
                        Some(sandbox) => json_response(StatusCode::OK, sandbox),
                        None => not_found(),
                    }
                } else {
                    panic!("unexpected Kubernetes request {method} {path}");
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        kube::Client::new(service, NAMESPACE)
    }
}

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn not_found() -> Response<Body> {
    json_response(
        StatusCode::NOT_FOUND,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure","message":"not found","reason":"NotFound","code":404}),
    )
}

// ------------------------------------------------------------ fake store

struct FakeStore {
    results: Sequence<Result<Option<LiveBinding>, BindingStoreUnavailable>>,
    available_after: Option<tokio::time::Instant>,
    queries: AtomicUsize,
}

impl FakeStore {
    fn returning(results: Vec<Result<Option<LiveBinding>, BindingStoreUnavailable>>) -> Arc<Self> {
        Arc::new(Self {
            results: Sequence::of(results),
            available_after: None,
            queries: AtomicUsize::new(0),
        })
    }

    fn bound(scope: WorkspaceCredentialScope) -> Arc<Self> {
        Self::returning(vec![Ok(Some(binding(scope)))])
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl BindingStore for FakeStore {
    async fn live_binding(
        &self,
        pod_uid: &str,
        namespace: &str,
        pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        assert_eq!(
            (pod_uid, namespace, pod_name),
            (POD_UID, NAMESPACE, POD_NAME)
        );
        self.queries.fetch_add(1, Ordering::SeqCst);
        if self
            .available_after
            .is_some_and(|after| tokio::time::Instant::now() < after)
        {
            return Ok(None);
        }
        self.results.next()
    }
}

struct Fixture {
    cluster: Arc<FakeCluster>,
    store: Arc<FakeStore>,
    notifications: Arc<BindingNotifications>,
    state: Arc<WorkspaceBindingState>,
}

fn fixture(cluster: Arc<FakeCluster>, store: Arc<FakeStore>) -> Fixture {
    fixture_with(cluster, store, |state| state)
}

fn fixture_with(
    cluster: Arc<FakeCluster>,
    store: Arc<FakeStore>,
    configure: impl FnOnce(WorkspaceBindingState) -> WorkspaceBindingState,
) -> Fixture {
    let notifications = Arc::new(BindingNotifications::default());
    let state = Arc::new(configure(
        WorkspaceBindingState::new(
            Some(cluster.client()),
            store.clone(),
            notifications.clone(),
            NAMESPACE,
            SECRET,
        )
        .with_timing(Duration::from_millis(300), Duration::from_millis(50)),
    ));
    Fixture {
        cluster,
        store,
        notifications,
        state,
    }
}

impl Fixture {
    async fn bind(
        &self,
        wait_seconds: u32,
    ) -> Result<codewire_proto::codewire::internal::v1::BindWorkspaceResponse, BindError> {
        self.state
            .bind(&valid_bearer(), Some(PEER), wait_seconds)
            .await
    }

    fn reviews(&self) -> usize {
        self.cluster.reviews.load(Ordering::SeqCst)
    }
}

// ----------------------------------------------------------------- tests

#[tokio::test]
async fn a_bound_pod_gets_its_binding_and_a_pod_scoped_credential() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let response = fixture.bind(20).await.unwrap();
    assert_eq!(response.environment_id, ENVIRONMENT_ID);
    assert_eq!(response.pod_uid, POD_UID);
    assert_eq!(response.operation_generation, 7);
    assert_eq!(response.projection_selection_sha256, "ab".repeat(32));
    assert_eq!(response.managed_credential_clients, "github");
    assert_eq!(
        response.daemon_credential,
        issue_workspace_daemon_credential(SECRET, ENVIRONMENT_ID, POD_UID).unwrap()
    );
    // Never the environment-wide daemon token.
    assert_ne!(
        response.daemon_credential,
        issue_token(SECRET, ENVIRONMENT_ID, SCOPE_DAEMON).unwrap()
    );
    let debug = format!("{response:?}");
    assert!(!debug.contains(&response.daemon_credential));
    assert_eq!(fixture.reviews(), 1);
    // The lookup, then the re-check after the live re-reads.
    assert_eq!(fixture.store.queries(), 2);
}

#[tokio::test]
async fn garbage_and_expired_bearers_never_reach_token_review() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    for headers in [
        HeaderMap::new(),
        bearer("opaque-codewire-oauth-bearer"),
        bearer(&issue_token(SECRET, ENVIRONMENT_ID, SCOPE_DAEMON).unwrap()),
        bearer(&token_expiring_at(unix_now().saturating_sub(1))),
    ] {
        // Each attempt spends a peer token; stay inside the burst.
        assert_eq!(
            fixture.state.bind(&headers, Some(PEER), 0).await,
            Err(BindError::Unauthenticated)
        );
    }
    assert_eq!(fixture.reviews(), 0);
    assert_eq!(fixture.store.queries(), 0);
}

#[tokio::test]
async fn a_peer_flood_is_refused_before_any_review() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    for _ in 0..5 {
        assert_eq!(
            fixture.state.bind(&HeaderMap::new(), Some(PEER), 0).await,
            Err(BindError::Unauthenticated)
        );
    }
    assert_eq!(fixture.bind(0).await, Err(BindError::ResourceExhausted));
    assert_eq!(fixture.reviews(), 0);
    // Another peer is unaffected.
    assert!(
        fixture
            .state
            .bind(
                &valid_bearer(),
                Some(IpAddr::V4(Ipv4Addr::new(10, 244, 0, 10))),
                0
            )
            .await
            .is_ok()
    );
    // No peer address means the listener could not attribute the request.
    assert_eq!(
        fixture.state.bind(&valid_bearer(), None, 0).await,
        Err(BindError::Unavailable)
    );
}

#[tokio::test]
async fn only_the_exact_workspace_binding_audience_authenticates() {
    for audience in [
        GATEWAY_BINDING_TOKEN_AUDIENCE,
        codewire_gateway_proto::CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
        codewire_gateway_proto::CREDENTIAL_GATEWAY_TOKEN_AUDIENCE,
        "https://kubernetes.default.svc",
    ] {
        let fixture = fixture(
            FakeCluster::new(
                review(NAMESPACE, GATEWAY_BINDING_SERVICE_ACCOUNT, audience),
                vec![Some(workspace_pod())],
                vec![Some(sandbox())],
            ),
            FakeStore::bound(WorkspaceCredentialScope::Pod),
        );
        assert_eq!(fixture.bind(0).await, Err(BindError::Unauthenticated));
        assert_eq!(fixture.reviews(), 1);
        assert_eq!(fixture.store.queries(), 0);
    }
}

#[tokio::test]
async fn reviewed_namespace_and_service_account_are_enforced() {
    for (namespace, service_account) in [
        ("other-sandboxes", GATEWAY_BINDING_SERVICE_ACCOUNT),
        (NAMESPACE, "default"),
    ] {
        let fixture = fixture(
            FakeCluster::new(
                review(namespace, service_account, WORKSPACE_BINDING_TOKEN_AUDIENCE),
                vec![Some(workspace_pod())],
                vec![Some(sandbox())],
            ),
            FakeStore::bound(WorkspaceCredentialScope::Pod),
        );
        assert_eq!(fixture.bind(0).await, Err(BindError::PermissionDenied));
        assert_eq!(fixture.store.queries(), 0);
    }
}

#[tokio::test]
async fn the_live_pod_must_be_the_reviewed_running_sandbox_workspace() {
    type PodMutation = (&'static str, fn(&mut Pod));
    let mutations: Vec<PodMutation> = vec![
        ("replaced UID", |pod| {
            pod.metadata.uid = Some(OTHER_POD_UID.into())
        }),
        ("terminating", |pod| {
            pod.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()))
        }),
        ("service account", |pod| {
            pod.spec.as_mut().unwrap().service_account_name = Some("default".into())
        }),
        ("gateway role", |pod| {
            pod.metadata
                .labels
                .as_mut()
                .unwrap()
                .insert(LABEL_TYPE.into(), "gateway".into());
        }),
        ("no role", |pod| {
            pod.metadata.labels.as_mut().unwrap().remove(LABEL_TYPE);
        }),
        ("no controller", |pod| pod.metadata.owner_references = None),
        ("two controllers", |pod| {
            pod.metadata
                .owner_references
                .as_mut()
                .unwrap()
                .push(controller("apps/v1", "ReplicaSet", "rs", OTHER_POD_UID))
        }),
        ("ReplicaSet controller", |pod| {
            pod.metadata.owner_references =
                Some(vec![controller("apps/v1", "ReplicaSet", "rs", SANDBOX_UID)])
        }),
        ("pending", |pod| {
            pod.status.as_mut().unwrap().phase = Some("Pending".into())
        }),
    ];
    for (label, mutate) in mutations {
        let mut pod = workspace_pod();
        mutate(&mut pod);
        let fixture = fixture(
            FakeCluster::new(valid_review(), vec![Some(pod)], vec![Some(sandbox())]),
            FakeStore::bound(WorkspaceCredentialScope::Pod),
        );
        assert_eq!(
            fixture.bind(0).await,
            Err(BindError::PermissionDenied),
            "{label}"
        );
        assert_eq!(fixture.store.queries(), 0, "{label}");
    }

    let missing = fixture(
        FakeCluster::new(valid_review(), vec![None], vec![Some(sandbox())]),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    assert_eq!(missing.bind(0).await, Err(BindError::NotFound));
}

#[tokio::test]
async fn an_unbound_pod_waits_then_gets_not_found() {
    let fixture = fixture(FakeCluster::valid(), FakeStore::returning(vec![Ok(None)]));
    let started = tokio::time::Instant::now();
    assert_eq!(fixture.bind(20).await, Err(BindError::NotFound));
    // The fixture caps the wait at 300ms and re-queries every 50ms.
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(fixture.store.queries() >= 3);
    assert_eq!(fixture.reviews(), 1, "one review covers the whole wait");
    assert_eq!(fixture.notifications.waiting(), 0);

    // wait_seconds = 0 looks once and answers at once.
    let once = self::fixture(FakeCluster::valid(), FakeStore::returning(vec![Ok(None)]));
    assert_eq!(once.bind(0).await, Err(BindError::NotFound));
    assert_eq!(once.store.queries(), 1);
}

#[tokio::test]
async fn a_recorded_binding_wakes_the_waiter_before_the_requery() {
    let fixture = fixture_with(
        FakeCluster::valid(),
        FakeStore::returning(vec![
            Ok(None),
            Ok(Some(binding(WorkspaceCredentialScope::Pod))),
        ]),
        |state| state.with_timing(Duration::from_secs(10), Duration::from_secs(10)),
    );
    let notifications = fixture.notifications.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        notifications.notify(POD_UID);
    });
    let started = tokio::time::Instant::now();
    assert!(fixture.bind(20).await.is_ok());
    assert!(started.elapsed() < Duration::from_secs(5));
    // None, then the binding, then the re-check after the live re-reads.
    assert_eq!(fixture.store.queries(), 3);
}

#[tokio::test]
async fn a_binding_released_or_moved_during_the_re_reads_is_not_served() {
    let mut moved = binding(WorkspaceCredentialScope::Pod);
    moved.operation_generation += 1;
    for (after, expected) in [
        (Ok(None), BindError::NotFound),
        (Ok(Some(moved)), BindError::PermissionDenied),
        (Err(BindingStoreUnavailable), BindError::Unavailable),
    ] {
        let fixture = fixture(
            FakeCluster::valid(),
            FakeStore::returning(vec![
                Ok(Some(binding(WorkspaceCredentialScope::Pod))),
                after,
            ]),
        );
        assert_eq!(fixture.bind(0).await, Err(expected));
        assert_eq!(fixture.store.queries(), 2);
    }
}

#[tokio::test]
async fn a_pod_replaced_or_relabelled_during_the_wait_is_denied() {
    let mut replaced = workspace_pod();
    replaced.metadata.uid = Some(OTHER_POD_UID.into());
    let mut relabelled = workspace_pod();
    relabelled.metadata.labels.as_mut().unwrap().insert(
        LABEL_ENV_ID.into(),
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into(),
    );
    let mut reowned = workspace_pod();
    reowned.metadata.owner_references = Some(vec![controller(
        "agents.x-k8s.io/v1beta1",
        "Sandbox",
        SANDBOX_NAME,
        OTHER_POD_UID,
    )]);
    let mut terminating = workspace_pod();
    terminating.metadata.deletion_timestamp = Some(Time(k8s_openapi::jiff::Timestamp::now()));
    for after in [replaced, relabelled, reowned, terminating] {
        let fixture = fixture(
            FakeCluster::new(
                valid_review(),
                vec![Some(workspace_pod()), Some(after)],
                vec![Some(sandbox())],
            ),
            FakeStore::bound(WorkspaceCredentialScope::Pod),
        );
        assert_eq!(fixture.bind(0).await, Err(BindError::PermissionDenied));
    }
    let deleted = fixture(
        FakeCluster::new(
            valid_review(),
            vec![Some(workspace_pod()), None],
            vec![Some(sandbox())],
        ),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    assert_eq!(deleted.bind(0).await, Err(BindError::NotFound));
}

#[tokio::test]
async fn a_sandbox_reowned_or_replaced_during_the_wait_is_denied() {
    let mut other_claim = sandbox();
    other_claim["metadata"]["ownerReferences"][0]["uid"] = json!(OTHER_POD_UID);
    let mut other_uid = sandbox();
    other_uid["metadata"]["uid"] = json!(OTHER_POD_UID);
    let mut terminating = sandbox();
    terminating["metadata"]["deletionTimestamp"] = json!("2026-10-01T00:00:00Z");
    let mut not_a_claim = sandbox();
    not_a_claim["metadata"]["ownerReferences"][0]["kind"] = json!("SandboxWarmPool");
    let mut two_controllers = sandbox();
    two_controllers["metadata"]["ownerReferences"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
            "kind": "SandboxClaim",
            "name": "another",
            "uid": OTHER_POD_UID,
            "controller": true,
        }));
    for sandbox in [
        Some(other_claim),
        Some(other_uid),
        Some(terminating),
        Some(not_a_claim),
        Some(two_controllers),
        None,
    ] {
        let fixture = fixture(
            FakeCluster::new(valid_review(), vec![Some(workspace_pod())], vec![sandbox]),
            FakeStore::bound(WorkspaceCredentialScope::Pod),
        );
        assert_eq!(fixture.bind(0).await, Err(BindError::PermissionDenied));
    }
}

#[tokio::test]
async fn a_binding_that_does_not_match_the_live_chain_is_denied() {
    let mut other_sandbox = binding(WorkspaceCredentialScope::Pod);
    other_sandbox.sandbox_uid = OTHER_POD_UID.into();
    let mut other_claim = binding(WorkspaceCredentialScope::Pod);
    other_claim.claim_uid = OTHER_POD_UID.into();
    let mut other_environment = binding(WorkspaceCredentialScope::Pod);
    other_environment.environment_id = "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into();
    for recorded in [
        other_sandbox,
        other_claim,
        other_environment,
        binding(WorkspaceCredentialScope::Environment),
    ] {
        let fixture = fixture(
            FakeCluster::valid(),
            FakeStore::returning(vec![Ok(Some(recorded))]),
        );
        assert_eq!(fixture.bind(0).await, Err(BindError::PermissionDenied));
    }
}

#[tokio::test]
async fn dependencies_that_fail_close_as_unavailable() {
    let store = fixture(
        FakeCluster::valid(),
        FakeStore::returning(vec![Err(BindingStoreUnavailable)]),
    );
    assert_eq!(store.bind(0).await, Err(BindError::Unavailable));

    let notifications = Arc::new(BindingNotifications::default());
    let no_cluster = WorkspaceBindingState::new(
        None,
        FakeStore::bound(WorkspaceCredentialScope::Pod),
        notifications,
        NAMESPACE,
        SECRET,
    );
    assert_eq!(
        no_cluster.bind(&valid_bearer(), Some(PEER), 0).await,
        Err(BindError::Unavailable)
    );

    let full = fixture_with(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
        |state| state.with_limits(RequestLimits::with_review_slots(0)),
    );
    assert_eq!(full.bind(0).await, Err(BindError::Unavailable));
    assert_eq!(full.reviews(), 0);
}

#[tokio::test]
async fn one_request_in_flight_per_reviewed_pod() {
    let fixture = fixture_with(
        FakeCluster::valid(),
        FakeStore::returning(vec![Ok(None)]),
        |state| state.with_timing(Duration::from_secs(1), Duration::from_millis(50)),
    );
    let state = fixture.state.clone();
    let waiting = tokio::spawn(async move { state.bind(&valid_bearer(), Some(PEER), 20).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        fixture
            .state
            .bind(
                &valid_bearer(),
                Some(IpAddr::V4(Ipv4Addr::new(10, 244, 0, 11))),
                0
            )
            .await,
        Err(BindError::ResourceExhausted)
    );
    assert_eq!(waiting.await.unwrap(), Err(BindError::NotFound));
}

#[tokio::test]
async fn a_token_that_expires_during_the_wait_gets_no_binding() {
    let store = Arc::new(FakeStore {
        results: Sequence::of(vec![Ok(Some(binding(WorkspaceCredentialScope::Pod)))]),
        available_after: Some(tokio::time::Instant::now() + Duration::from_millis(2_200)),
        queries: AtomicUsize::new(0),
    });
    let fixture = fixture_with(FakeCluster::valid(), store, |state| {
        state.with_timing(Duration::from_secs(5), Duration::from_millis(100))
    });
    let headers = bearer(&token_expiring_at(unix_now() + 2));
    assert_eq!(
        fixture.state.bind(&headers, Some(PEER), 20).await,
        Err(BindError::Unauthenticated)
    );
}

#[tokio::test]
async fn the_listener_app_serves_only_bind_workspace() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let app = app(workspace_binding_router(fixture.state.clone()));
    let token = token_expiring_at(unix_now() + 600);
    let request = |path: &str| {
        let mut request = Request::post(path)
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(r#"{"waitSeconds":0}"#))
            .unwrap();
        request
            .extensions_mut()
            .insert(PeerAddr(std::net::SocketAddr::new(PEER, 40_000)));
        request
    };

    let response = app
        .clone()
        .oneshot(request(
            "/codewire.internal.v1.WorkspaceBindingService/BindWorkspace",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["environmentId"], ENVIRONMENT_ID);
    assert_eq!(body["podUid"], POD_UID);

    for path in [
        "/codewire.internal.v1.GatewayBindingService/IssueGatewayBinding",
        "/codewire.internal.v1.GatewayBindingService/IssueGatewayDaemonCredential",
        "/codewire.internal.v1.MeshAuthorizationService/ResolveMeshAuthorization",
        "/codewire.v1.EnvironmentService/ListEnvironments",
        "/metrics",
        "/healthz",
        "/readyz",
    ] {
        let response = app.clone().oneshot(request(path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[test]
fn error_codes_are_value_blind() {
    for (error, code) in [
        (
            BindError::Unauthenticated,
            connectrpc::ErrorCode::Unauthenticated,
        ),
        (
            BindError::PermissionDenied,
            connectrpc::ErrorCode::PermissionDenied,
        ),
        (BindError::NotFound, connectrpc::ErrorCode::NotFound),
        (
            BindError::ResourceExhausted,
            connectrpc::ErrorCode::ResourceExhausted,
        ),
        (BindError::Unavailable, connectrpc::ErrorCode::Unavailable),
    ] {
        let rendered = error.connect();
        assert_eq!(rendered.code, code);
        let message = rendered.message.unwrap_or_default();
        for value in [POD_UID, POD_NAME, ENVIRONMENT_ID, NAMESPACE, SECRET] {
            assert!(!message.contains(value));
        }
    }
}
