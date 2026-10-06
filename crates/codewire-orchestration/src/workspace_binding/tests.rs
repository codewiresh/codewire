//! `WorkspaceBindingService` decisions through the production verifier and
//! kube client. Kubernetes is an in-process HTTP service (TokenReview, Pod,
//! Sandbox, Service and Node reads), not a replacement authenticator, and the
//! binding store is a fake with the same contract as the SQL lookup.

use std::collections::{BTreeMap, HashMap, VecDeque};
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

use super::access::{
    AccessSettings, RelayAllocation, RelayAllocationRequest, RelayAllocator, RelayEndpoint,
    RelayError,
};
use super::limits::RequestLimits;
use super::service::{BindError, WorkspaceBindingState};
use super::store::{
    BindingNotifications, BindingStore, BindingStoreUnavailable, HostKeyRecord, LiveBinding,
};
use super::{app, workspace_binding_router};
use crate::runtime_transport::{PeerRelayTransport, RuntimeTransportZone, TRANSPORT_ZONE_LABEL};
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
/// Another tenant workload holding the same projected token.
const OTHER_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 0, 10));
const ENVIRONMENT_GENERATION: i64 = 9;
const NODE_NAME: &str = "runtime-node-1";
const ZONE: &str = "dev-hel1";
const COORDINATOR_URL: &str = "https://dev.codewire.sh";
const ALLOCATOR_URL: &str =
    "http://codewire-udp-relay.dev.svc.cluster.local:8095/internal/udp-relay/allocations";
const HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const OTHER_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoVDsBGpvXjHq1Mc3BJ6ANWjUtpnGxFp1yfCaeHRu3T";

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
            pod_ip: Some(PEER.to_string()),
            ..Default::default()
        }),
    }
}

fn scheduled_pod() -> Pod {
    let mut pod = workspace_pod();
    pod.spec.as_mut().unwrap().node_name = Some(NODE_NAME.into());
    pod
}

fn direct_udp_service() -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": crate::sandbox::template::gateway_direct_udp_service_name(ENVIRONMENT_ID),
            "namespace": NAMESPACE,
        },
        "spec": {"type": "LoadBalancer", "ports": [{"port": 41700, "protocol": "UDP"}]},
        "status": {"loadBalancer": {"ingress": [{"ip": "203.0.113.7"}]}},
    })
}

fn zoned_node() -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {"name": NODE_NAME, "labels": {TRANSPORT_ZONE_LABEL: ZONE}},
    })
}

fn zone() -> RuntimeTransportZone {
    RuntimeTransportZone {
        name: ZONE.into(),
        runtime_region: "hel1".into(),
        peer_relay: Some(PeerRelayTransport {
            public_endpoints: vec!["198.51.100.4:41641".into()],
            dns: None,
            allocator_url: ALLOCATOR_URL.into(),
            bind_addrs: vec!["10.0.0.4:41641".into()],
        }),
        enabled: true,
        ..Default::default()
    }
}

fn disco(byte: u8) -> String {
    format!("discokey:{}", format!("{byte:02x}").repeat(32))
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
        environment_generation: ENVIRONMENT_GENERATION,
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
    service: Mutex<Option<Value>>,
    node: Mutex<Option<Value>>,
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
            service: Mutex::new(None),
            node: Mutex::new(None),
        })
    }

    /// A scheduled Pod on a zoned node, with a provisioned direct-UDP
    /// LoadBalancer.
    fn placed() -> Arc<Self> {
        let cluster = Self::new(
            valid_review(),
            vec![Some(scheduled_pod())],
            vec![Some(sandbox())],
        );
        *cluster.service.lock().unwrap() = Some(direct_udp_service());
        *cluster.node.lock().unwrap() = Some(zoned_node());
        cluster
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
                } else if method == "GET"
                    && path
                        == format!(
                            "/api/v1/namespaces/{NAMESPACE}/services/{}",
                            crate::sandbox::template::gateway_direct_udp_service_name(
                                ENVIRONMENT_ID
                            )
                        )
                {
                    match cluster.service.lock().unwrap().clone() {
                        Some(service) => json_response(StatusCode::OK, service),
                        None => not_found(),
                    }
                } else if method == "GET" && path == format!("/api/v1/nodes/{NODE_NAME}") {
                    match cluster.node.lock().unwrap().clone() {
                        Some(node) => json_response(StatusCode::OK, node),
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
    /// Host keys by (environment, generation), and who recorded them.
    host_keys: Mutex<HashMap<(String, i64), (String, String)>>,
    zones: Mutex<HashMap<String, RuntimeTransportZone>>,
}

impl FakeStore {
    fn returning(results: Vec<Result<Option<LiveBinding>, BindingStoreUnavailable>>) -> Arc<Self> {
        Arc::new(Self {
            results: Sequence::of(results),
            available_after: None,
            queries: AtomicUsize::new(0),
            host_keys: Mutex::new(HashMap::new()),
            zones: Mutex::new(HashMap::from([(ZONE.into(), zone())])),
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

    async fn record_host_key(
        &self,
        environment_id: &str,
        generation: i64,
        pod_uid: &str,
        public_key: &str,
    ) -> Result<HostKeyRecord, BindingStoreUnavailable> {
        let mut keys = self.host_keys.lock().unwrap();
        match keys.get(&(environment_id.to_owned(), generation)) {
            Some((existing, _)) if existing == public_key => Ok(HostKeyRecord::Unchanged),
            Some(_) => Ok(HostKeyRecord::Conflict),
            None => {
                keys.insert(
                    (environment_id.to_owned(), generation),
                    (public_key.to_owned(), pod_uid.to_owned()),
                );
                Ok(HostKeyRecord::Recorded)
            }
        }
    }

    async fn transport_zone(
        &self,
        name: &str,
    ) -> Result<Option<RuntimeTransportZone>, BindingStoreUnavailable> {
        Ok(self.zones.lock().unwrap().get(name).cloned())
    }
}

/// Records allocator calls and answers like the UDP relay allocator.
#[derive(Default)]
struct FakeAllocator {
    calls: Mutex<Vec<(String, RelayAllocationRequest)>>,
    refuse: Option<RelayError>,
}

#[async_trait]
impl RelayAllocator for FakeAllocator {
    async fn allocate(
        &self,
        allocator_url: &str,
        request: &RelayAllocationRequest,
    ) -> Result<RelayAllocation, RelayError> {
        self.calls
            .lock()
            .unwrap()
            .push((allocator_url.to_owned(), request.clone()));
        if let Some(error) = self.refuse {
            return Err(error);
        }
        Ok(RelayAllocation {
            generation: request.generation,
            endpoint: RelayEndpoint {
                server_disco: disco(0xee),
                client_disco: request.client_disco.clone(),
                lamport_id: 3,
                vni: 17,
                bind_lifetime_ns: 5_000_000_000,
                steady_state_lifetime_ns: 300_000_000_000,
                addr_ports: vec!["198.51.100.4:41641".into()],
            },
        })
    }
}

struct Fixture {
    cluster: Arc<FakeCluster>,
    store: Arc<FakeStore>,
    notifications: Arc<BindingNotifications>,
    allocator: Arc<FakeAllocator>,
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
    fixture_allocating(
        cluster,
        store,
        Arc::new(FakeAllocator::default()),
        configure,
    )
}

fn fixture_allocating(
    cluster: Arc<FakeCluster>,
    store: Arc<FakeStore>,
    allocator: Arc<FakeAllocator>,
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
        .with_access(
            AccessSettings {
                coordinator_url: COORDINATOR_URL.into(),
            },
            allocator.clone(),
        )
        .with_timing(Duration::from_millis(300), Duration::from_millis(50)),
    ));
    Fixture {
        cluster,
        store,
        notifications,
        allocator,
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
    // Another peer is not rate limited, and is reviewed, but it is not the
    // reviewed Pod's address (S1).
    assert_eq!(
        fixture
            .state
            .bind(&valid_bearer(), Some(OTHER_PEER), 0)
            .await,
        Err(BindError::PermissionDenied)
    );
    assert_eq!(fixture.reviews(), 1);
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
        host_keys: Mutex::new(HashMap::new()),
        zones: Mutex::new(HashMap::new()),
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
        (
            BindError::InvalidArgument,
            connectrpc::ErrorCode::InvalidArgument,
        ),
        (
            BindError::FailedPrecondition,
            connectrpc::ErrorCode::FailedPrecondition,
        ),
    ] {
        let rendered = error.connect();
        assert_eq!(rendered.code, code);
        let message = rendered.message.unwrap_or_default();
        for value in [POD_UID, POD_NAME, ENVIRONMENT_ID, NAMESPACE, SECRET] {
            assert!(!message.contains(value));
        }
    }
}

// ------------------------------------------- daemon-hosted access (S1–S5)

fn validated_peer_token(
    access: &codewire_proto::codewire::internal::v1::WorkspaceAccess,
) -> codewire_server_core::peer_token::PeerClaims {
    codewire_server_core::peer_token::validate(SECRET, &access.peer_token, unix_now() as i64)
        .expect("a valid peer token")
}

#[tokio::test]
async fn a_bound_pod_gets_a_generation_bound_peer_token_and_its_public_endpoints() {
    let fixture = fixture(
        FakeCluster::placed(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let response = fixture.bind(0).await.unwrap();
    let access = response.access.as_option().expect("an access grant");
    let claims = validated_peer_token(access);
    assert_eq!(claims.environment_id, ENVIRONMENT_ID);
    // The environment's current generation, not the binding's.
    assert_eq!(claims.generation, ENVIRONMENT_GENERATION);
    assert_eq!(access.operation_generation, ENVIRONMENT_GENERATION);
    assert_eq!(response.operation_generation, 7);
    assert_eq!(access.peer_token_expires_at, claims.expires_at);
    let lifetime = claims.expires_at - unix_now() as i64;
    assert!((595..=600).contains(&lifetime), "{lifetime}");
    assert_eq!(access.coordinator_url, COORDINATOR_URL);
    assert_eq!(access.direct_udp_endpoints, vec!["203.0.113.7:41700"]);
    assert_eq!(access.peer_relay_endpoints, vec!["198.51.100.4:41641"]);
    // Never the allocator or its token, and the token never prints.
    let debug = format!("{response:?}");
    assert!(!debug.contains(&access.peer_token));
    assert!(!debug.contains(ALLOCATOR_URL));
    assert!(fixture.allocator.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_endpoints_only_narrow_the_grant() {
    // No direct-UDP Service, no node: the grant still carries the token.
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let response = fixture.bind(0).await.unwrap();
    let access = response.access.as_option().unwrap();
    validated_peer_token(access);
    assert!(access.direct_udp_endpoints.is_empty());
    assert!(access.peer_relay_endpoints.is_empty());
}

#[tokio::test]
async fn every_method_refuses_a_token_presented_from_another_workload() {
    let fixture = fixture(
        FakeCluster::placed(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let headers = valid_bearer();
    let state = &fixture.state;
    let request = codewire_proto::codewire::internal::v1::AllocatePeerRelayRequest {
        disco_keys: vec![disco(1), disco(2)],
        relay_generation: 1,
        ..Default::default()
    };
    assert_eq!(
        state.bind(&headers, Some(OTHER_PEER), 0).await,
        Err(BindError::PermissionDenied)
    );
    assert_eq!(
        state.refresh_access(&headers, Some(OTHER_PEER)).await,
        Err(BindError::PermissionDenied)
    );
    assert_eq!(
        state
            .record_host_key(&headers, Some(OTHER_PEER), HOST_KEY)
            .await,
        Err(BindError::PermissionDenied)
    );
    assert_eq!(
        state
            .allocate_peer_relay(&headers, Some(OTHER_PEER), &request)
            .await,
        Err(BindError::PermissionDenied)
    );
    // Refused at the live Pod, before any binding, record or allocation.
    assert_eq!(fixture.reviews(), 4);
    assert_eq!(fixture.store.queries(), 0);
    assert!(fixture.store.host_keys.lock().unwrap().is_empty());
    assert!(fixture.allocator.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_pod_without_an_address_serves_no_one() {
    let mut pod = workspace_pod();
    pod.status.as_mut().unwrap().pod_ip = None;
    let fixture = fixture(
        FakeCluster::new(valid_review(), vec![Some(pod)], vec![Some(sandbox())]),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    assert_eq!(fixture.bind(0).await, Err(BindError::PermissionDenied));
    assert_eq!(fixture.store.queries(), 0);
}

#[tokio::test]
async fn refresh_issues_a_fresh_grant_only_while_bound() {
    let fixture = fixture(
        FakeCluster::placed(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let response = fixture
        .state
        .refresh_access(&valid_bearer(), Some(PEER))
        .await
        .unwrap();
    let access = response.access.as_option().unwrap();
    assert_eq!(
        validated_peer_token(access).generation,
        ENVIRONMENT_GENERATION
    );
    assert_eq!(access.peer_relay_endpoints, vec!["198.51.100.4:41641"]);
    // The lookup, then the re-check after the live re-reads.
    assert_eq!(fixture.store.queries(), 2);

    // Released or never bound: not found at once, without a wait.
    let unbound = self::fixture(FakeCluster::valid(), FakeStore::returning(vec![Ok(None)]));
    let started = tokio::time::Instant::now();
    assert_eq!(
        unbound
            .state
            .refresh_access(&valid_bearer(), Some(PEER))
            .await,
        Err(BindError::NotFound)
    );
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(unbound.store.queries(), 1);

    // A binding that no longer matches the live chain refreshes nothing.
    let mut moved = binding(WorkspaceCredentialScope::Pod);
    moved.sandbox_uid = OTHER_POD_UID.into();
    let mismatched = self::fixture(
        FakeCluster::valid(),
        FakeStore::returning(vec![Ok(Some(moved))]),
    );
    assert_eq!(
        mismatched
            .state
            .refresh_access(&valid_bearer(), Some(PEER))
            .await,
        Err(BindError::PermissionDenied)
    );
}

#[tokio::test]
async fn host_keys_are_write_once_per_environment_generation() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let record = |key: &'static str| {
        let state = fixture.state.clone();
        async move {
            state
                .record_host_key(&valid_bearer(), Some(PEER), key)
                .await
        }
    };
    assert!(record(HOST_KEY).await.is_ok());
    // Repeating the same key is idempotent; another key is refused.
    assert!(record(HOST_KEY).await.is_ok());
    assert_eq!(
        record(OTHER_HOST_KEY).await,
        Err(BindError::FailedPrecondition)
    );
    let keys = fixture.store.host_keys.lock().unwrap().clone();
    assert_eq!(
        keys,
        HashMap::from([(
            (ENVIRONMENT_ID.to_owned(), ENVIRONMENT_GENERATION),
            (HOST_KEY.to_owned(), POD_UID.to_owned())
        )])
    );

    // The next generation records its own key.
    let mut next = binding(WorkspaceCredentialScope::Pod);
    next.environment_generation += 1;
    let rotated = self::fixture(
        FakeCluster::valid(),
        FakeStore::returning(vec![Ok(Some(next))]),
    );
    *rotated.store.host_keys.lock().unwrap() = keys;
    assert!(
        rotated
            .state
            .record_host_key(&valid_bearer(), Some(PEER), OTHER_HOST_KEY)
            .await
            .is_ok()
    );
    assert_eq!(rotated.store.host_keys.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn malformed_host_keys_are_refused_before_review() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    for key in [
        "",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0",
        &format!("{HOST_KEY} user@host"),
        &format!("{HOST_KEY}\n"),
    ] {
        assert_eq!(
            fixture
                .state
                .record_host_key(&valid_bearer(), Some(PEER), key)
                .await,
            Err(BindError::InvalidArgument),
            "{key:?}"
        );
    }
    assert_eq!(fixture.reviews(), 0);
    assert!(fixture.store.host_keys.lock().unwrap().is_empty());
}

fn relay_request(
    keys: &[String],
) -> codewire_proto::codewire::internal::v1::AllocatePeerRelayRequest {
    codewire_proto::codewire::internal::v1::AllocatePeerRelayRequest {
        disco_keys: keys.to_vec(),
        relay_generation: 4,
        ..Default::default()
    }
}

#[tokio::test]
async fn relay_slots_are_allocated_on_the_pods_zone_with_orchestrations_allocator() {
    let fixture = fixture(
        FakeCluster::placed(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let response = fixture
        .state
        .allocate_peer_relay(
            &valid_bearer(),
            Some(PEER),
            &relay_request(&[disco(1), disco(2)]),
        )
        .await
        .unwrap();
    assert_eq!(response.relay_generation, 4);
    assert_eq!(response.server_disco_key, disco(0xee));
    assert_eq!(response.disco_keys, vec![disco(1), disco(2)]);
    assert_eq!((response.lamport_id, response.vni), (3, 17));
    assert_eq!(response.bind_lifetime_ns, 5_000_000_000);
    assert_eq!(response.steady_state_lifetime_ns, 300_000_000_000);
    assert_eq!(response.addr_ports, vec!["198.51.100.4:41641"]);
    assert_eq!(
        *fixture.allocator.calls.lock().unwrap(),
        vec![(
            ALLOCATOR_URL.to_owned(),
            RelayAllocationRequest {
                client_disco: [disco(1), disco(2)],
                generation: 4,
            }
        )]
    );
}

#[tokio::test]
async fn relay_requests_are_validated_before_review() {
    let fixture = fixture(
        FakeCluster::placed(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    for keys in [
        vec![],
        vec![disco(1)],
        vec![disco(1), disco(1)],
        vec![disco(1), disco(2), disco(3)],
        vec![disco(1), disco(0xab).to_uppercase()],
    ] {
        assert_eq!(
            fixture
                .state
                .allocate_peer_relay(&valid_bearer(), Some(PEER), &relay_request(&keys))
                .await,
            Err(BindError::InvalidArgument),
            "{keys:?}"
        );
    }
    assert_eq!(fixture.reviews(), 0);
    assert!(fixture.allocator.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn relay_allocation_fails_closed_without_a_relay_or_allocator() {
    let keys = [disco(1), disco(2)];
    // An unscheduled Pod, or a node without a zone, has no relay.
    let unplaced = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    assert_eq!(
        unplaced
            .state
            .allocate_peer_relay(&valid_bearer(), Some(PEER), &relay_request(&keys))
            .await,
        Err(BindError::FailedPrecondition)
    );
    assert!(unplaced.allocator.calls.lock().unwrap().is_empty());

    for (refusal, expected) in [
        (RelayError::Refused, BindError::FailedPrecondition),
        (RelayError::Unavailable, BindError::Unavailable),
    ] {
        let fixture = fixture_allocating(
            FakeCluster::placed(),
            FakeStore::bound(WorkspaceCredentialScope::Pod),
            Arc::new(FakeAllocator {
                refuse: Some(refusal),
                ..Default::default()
            }),
            |state| state,
        );
        assert_eq!(
            fixture
                .state
                .allocate_peer_relay(&valid_bearer(), Some(PEER), &relay_request(&keys))
                .await,
            Err(expected)
        );
    }
}

#[tokio::test]
async fn each_method_has_the_smallest_body_limit_that_fits_it() {
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let app = app(workspace_binding_router(fixture.state.clone()));
    let token = token_expiring_at(unix_now() + 600);
    let call = |method: &str, body: String| {
        let mut request = Request::post(format!(
            "/codewire.internal.v1.WorkspaceBindingService/{method}"
        ))
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap();
        request
            .extensions_mut()
            .insert(PeerAddr(std::net::SocketAddr::new(PEER, 40_000)));
        app.clone().oneshot(request)
    };
    let host_key = serde_json::to_string(&json!({"publicKeyOpenssh": HOST_KEY})).unwrap();
    assert!(host_key.len() > super::DEFAULT_BODY_BYTES);
    assert_eq!(
        call("RecordHostKey", host_key).await.unwrap().status(),
        StatusCode::OK
    );
    let relay = serde_json::to_string(
        &json!({"discoKeys": [disco(1), disco(2)], "relayGeneration": u32::MAX}),
    )
    .unwrap();
    assert!(relay.len() > super::RECORD_HOST_KEY_BODY_BYTES);
    assert!(relay.len() <= super::ALLOCATE_PEER_RELAY_BODY_BYTES);
    // The relay call passes the limit and fails later: this Pod has no zone.
    assert_ne!(
        call("AllocatePeerRelay", relay).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for (method, limit) in [
        ("BindWorkspace", super::DEFAULT_BODY_BYTES),
        ("RefreshAccess", super::DEFAULT_BODY_BYTES),
        ("RecordHostKey", super::RECORD_HOST_KEY_BODY_BYTES),
        ("AllocatePeerRelay", super::ALLOCATE_PEER_RELAY_BODY_BYTES),
    ] {
        let oversized = format!(r#"{{"x":"{}"}}"#, "a".repeat(limit));
        assert_eq!(
            call(method, oversized).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{method}"
        );
    }
}

#[tokio::test]
async fn the_listener_serves_http1_over_the_internal_tls_identity_only() {
    use codewire_server_core::bounded_http1::serve_bounded_http1_upgraded_until;
    let host = crate::worker::create::workspace_binding_tls_host("dev");
    let pki = codewire_tls::test_support::SyntheticPki::new(&host);
    let fixture = fixture(
        FakeCluster::valid(),
        FakeStore::bound(WorkspaceCredentialScope::Pod),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_bounded_http1_upgraded_until(
        app(workspace_binding_router(fixture.state.clone())),
        listener,
        super::LISTENER_LIMITS,
        super::WorkspaceBindingTls(pki.files.clone()),
        async {
            let _ = stopped.await;
        },
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .http1_only()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&pki.roots).unwrap()).unwrap(),
        )
        .resolve(&host, address)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    // Verified for the binding Service name; no bearer is refused by the
    // service itself, so the request crossed TLS and HTTP/1.1.
    let response = client
        .post(format!(
            "https://{host}:{}/codewire.internal.v1.WorkspaceBindingService/BindWorkspace",
            address.port()
        ))
        .header("content-type", "application/json")
        .body(r#"{"waitSeconds":0}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.version(), reqwest::Version::HTTP_11);

    // Plaintext HTTP gets no response.
    let mut plain = tokio::net::TcpStream::connect(address).await.unwrap();
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    plain
        .write_all(b"POST /codewire.internal.v1.WorkspaceBindingService/BindWorkspace HTTP/1.1\r\nhost: b\r\ncontent-length: 2\r\n\r\n{}")
        .await
        .unwrap();
    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(6), plain.read_to_end(&mut received)).await;
    assert!(!String::from_utf8_lossy(&received).contains("HTTP/1.1"));

    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
