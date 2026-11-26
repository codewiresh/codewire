//! `EgressService` through the real Kubernetes driver against an in-process
//! fake API server: every method authenticates the caller, and every method
//! that names a guest refuses one off the caller's node (#4000).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header::AUTHORIZATION};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_daemon_proto::{
    EGRESS_NODE_SERVICE_ACCOUNT, EGRESS_NODE_TOKEN_AUDIENCE, EGRESS_TOKEN_AUDIENCE,
    SANDBOX_SERVICE_ACCOUNT,
};
use http_body_util::BodyExt as _;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use k8s_openapi::api::core::v1::{Pod, PodSpec, PodStatus};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use serde_json::{Value, json};
use tower::{ServiceExt, service_fn};

use super::*;
use crate::egress::admission::{EGRESS_MODE_BROKER, EGRESS_MODE_LABEL};
use crate::runtime::kubernetes::rendering::KubernetesRenderConfig;
use crate::sandbox::{LABEL_ENV_ID, LABEL_TYPE};
use crate::worker::environment_auth::WorkspaceCredentialScope;
use crate::workspace_binding::store::{BindingStoreUnavailable, LiveBinding};

mod front_door;

const SERVER: &str = "dev";
const SANDBOXES: &str = "dev-sandboxes";
const NODE: &str = "runtime-a";
const CALLER: &str = "codewire-egress-abc";
const CALLER_UID: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";
const GUEST: &str = "workspace-1";
const GUEST_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const GUEST_IP: &str = "10.92.4.7";
/// The guest's Sandbox, whose UID the binding records.
const GUEST_SANDBOX: &str = "sandbox-workspace-1";
const GUEST_SANDBOX_UID: &str = "5a4db0c5-0bd2-4f11-8b16-9c239851eb52";

fn sandbox_path(name: &str) -> String {
    format!("/apis/agents.x-k8s.io/v1beta1/namespaces/{SANDBOXES}/sandboxes/{name}")
}

/// The guest's Sandbox with the broker label, the fence revision and the TUN
/// init as asked: all three are the whole broker shape.
fn guest_sandbox(label: bool, fence: bool, tun: bool) -> Value {
    let mut template = json!({
        "metadata": {"labels": {LABEL_TYPE: "workspace"}},
        "spec": {"runtimeClassName": "commodity", "containers": []},
    });
    if label {
        template["metadata"]["labels"][EGRESS_MODE_LABEL] = json!(EGRESS_MODE_BROKER);
    }
    if fence {
        template["metadata"]["annotations"] = json!({"codewire.sh/egress-fence-revision": "4"});
    }
    if tun {
        template["spec"]["initContainers"] = json!([{"name": "hosted-egress-tun"}]);
    }
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
        "metadata": {"name": GUEST_SANDBOX, "namespace": SANDBOXES, "uid": GUEST_SANDBOX_UID},
        "spec": {"podTemplate": template},
    })
}

fn token() -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
    format!("{header}.{payload}.c2ln")
}

fn review(
    namespace: &str,
    account: &str,
    audience: &str,
    pod: &str,
    uid: &str,
) -> TokenReviewStatus {
    TokenReviewStatus {
        authenticated: Some(true),
        audiences: Some(vec![audience.into()]),
        user: Some(UserInfo {
            username: Some(format!("system:serviceaccount:{namespace}:{account}")),
            extra: Some(BTreeMap::from([
                (
                    "authentication.kubernetes.io/pod-name".into(),
                    vec![pod.into()],
                ),
                (
                    "authentication.kubernetes.io/pod-uid".into(),
                    vec![uid.into()],
                ),
            ])),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn pod(
    namespace: &str,
    name: &str,
    uid: &str,
    account: &str,
    node: &str,
    labels: &[(&str, &str)],
) -> Pod {
    Pod {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(namespace.into()),
            uid: Some(uid.into()),
            labels: Some(
                labels
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
            ),
            ..Default::default()
        },
        spec: Some(PodSpec {
            service_account_name: Some(account.into()),
            node_name: Some(node.into()),
            containers: Vec::new(),
            ..Default::default()
        }),
        status: Some(PodStatus {
            phase: Some("Running".into()),
            pod_ip: Some(GUEST_IP.into()),
            ..Default::default()
        }),
    }
}

/// The API server: a review per audience, and Pods by namespace and name.
struct Cluster {
    reviews: HashMap<&'static str, TokenReviewStatus>,
    pods: Mutex<HashMap<String, Pod>>,
    /// Pod reads still to fail with a server error, as an API blip.
    failing_reads: AtomicUsize,
    /// Pod reads never answer while set.
    hang_reads: std::sync::atomic::AtomicBool,
    /// TokenReviews of guest egress tokens served.
    guest_reviews: AtomicUsize,
    /// TokenReviews of guest egress tokens answer with a server error while
    /// set; cw-egress's own review still answers.
    guest_reviews_down: std::sync::atomic::AtomicBool,
    /// NetworkPolicies by path, for the lockdown check.
    policies: Mutex<HashMap<String, Value>>,
    /// Sandboxes and Claims by path, for the lockdown check's read of the
    /// guest's own and the startup re-apply's.
    sandboxes: Mutex<HashMap<String, Value>>,
    /// NetworkPolicies replaced.
    replaced: AtomicUsize,
}

impl Cluster {
    fn healthy() -> Arc<Self> {
        let caller = pod(
            SERVER,
            CALLER,
            CALLER_UID,
            EGRESS_NODE_SERVICE_ACCOUNT,
            NODE,
            &[],
        );
        let mut guest = pod(
            SANDBOXES,
            GUEST,
            GUEST_UID,
            SANDBOX_SERVICE_ACCOUNT,
            NODE,
            &[
                (LABEL_TYPE, "workspace"),
                (EGRESS_MODE_LABEL, EGRESS_MODE_BROKER),
            ],
        );
        guest.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "agents.x-k8s.io/v1beta1".into(),
                kind: "Sandbox".into(),
                name: GUEST_SANDBOX.into(),
                uid: GUEST_SANDBOX_UID.into(),
                controller: Some(true),
                ..Default::default()
            },
        ]);
        Arc::new(Self {
            reviews: HashMap::from([
                (
                    EGRESS_NODE_TOKEN_AUDIENCE,
                    review(
                        SERVER,
                        EGRESS_NODE_SERVICE_ACCOUNT,
                        EGRESS_NODE_TOKEN_AUDIENCE,
                        CALLER,
                        CALLER_UID,
                    ),
                ),
                (
                    EGRESS_TOKEN_AUDIENCE,
                    review(
                        SANDBOXES,
                        SANDBOX_SERVICE_ACCOUNT,
                        EGRESS_TOKEN_AUDIENCE,
                        GUEST,
                        GUEST_UID,
                    ),
                ),
            ]),
            pods: Mutex::new(HashMap::from([
                (format!("/api/v1/namespaces/{SERVER}/pods/{CALLER}"), caller),
                (
                    format!("/api/v1/namespaces/{SANDBOXES}/pods/{GUEST}"),
                    guest,
                ),
            ])),
            failing_reads: AtomicUsize::new(0),
            hang_reads: std::sync::atomic::AtomicBool::new(false),
            guest_reviews: AtomicUsize::new(0),
            guest_reviews_down: std::sync::atomic::AtomicBool::new(false),
            policies: Mutex::new(HashMap::new()),
            sandboxes: Mutex::new(HashMap::from([(
                sandbox_path(GUEST_SANDBOX),
                guest_sandbox(true, true, true),
            )])),
            replaced: AtomicUsize::new(0),
        })
    }

    fn with(self: Arc<Self>, edit: impl FnOnce(&mut Self)) -> Arc<Self> {
        let mut cluster = Arc::try_unwrap(self).ok().expect("unshared cluster");
        edit(&mut cluster);
        Arc::new(cluster)
    }

    fn edit_guest(&mut self, edit: impl FnOnce(&mut Pod)) {
        let path = format!("/api/v1/namespaces/{SANDBOXES}/pods/{GUEST}");
        edit(self.pods.get_mut().unwrap().get_mut(&path).unwrap());
    }

    fn client(self: &Arc<Self>) -> kube::Client {
        let cluster = self.clone();
        let service = service_fn(move |request: Request<kube::client::Body>| {
            let cluster = cluster.clone();
            async move {
                let path = request.uri().path().to_owned();
                let replaces = request.method() == axum::http::Method::PUT;
                let response = if path == "/apis/authentication.k8s.io/v1/tokenreviews" {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let asked: TokenReview = serde_json::from_slice(&body).unwrap();
                    let audience = asked.spec.audiences.unwrap_or_default().join(",");
                    if audience == EGRESS_TOKEN_AUDIENCE {
                        cluster.guest_reviews.fetch_add(1, Ordering::SeqCst);
                        if cluster.guest_reviews_down.load(Ordering::SeqCst) {
                            return Ok(json_response(
                                StatusCode::SERVICE_UNAVAILABLE,
                                json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 503}),
                            ));
                        }
                    }
                    let status = cluster
                        .reviews
                        .get(audience.as_str())
                        .cloned()
                        .unwrap_or_default();
                    json_response(
                        StatusCode::CREATED,
                        serde_json::to_value(TokenReview {
                            status: Some(status),
                            ..Default::default()
                        })
                        .unwrap(),
                    )
                } else if cluster.hang_reads.load(Ordering::SeqCst) {
                    return std::future::pending().await;
                } else if cluster
                    .failing_reads
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                        left.checked_sub(1)
                    })
                    .is_ok()
                {
                    json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 500}),
                    )
                } else if path.ends_with("/networkpolicies") {
                    let prefix = format!("{path}/");
                    let items: Vec<Value> = cluster
                        .policies
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|(key, _)| key.starts_with(&prefix))
                        .map(|(_, policy)| policy.clone())
                        .collect();
                    json_response(
                        StatusCode::OK,
                        json!({"kind": "NetworkPolicyList", "apiVersion": "networking.k8s.io/v1", "metadata": {}, "items": items}),
                    )
                } else if path.contains("/networkpolicies/") && replaces {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let policy: Value = serde_json::from_slice(&body).unwrap();
                    cluster.replaced.fetch_add(1, Ordering::SeqCst);
                    cluster
                        .policies
                        .lock()
                        .unwrap()
                        .insert(path, policy.clone());
                    json_response(StatusCode::OK, policy)
                } else if path.contains("/sandboxes/") || path.contains("/sandboxclaims/") {
                    match cluster.sandboxes.lock().unwrap().get(&path) {
                        Some(sandbox) => json_response(StatusCode::OK, sandbox.clone()),
                        None => json_response(
                            StatusCode::NOT_FOUND,
                            json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404}),
                        ),
                    }
                } else if path.contains("/networkpolicies/") {
                    match cluster.policies.lock().unwrap().get(&path) {
                        Some(policy) => json_response(StatusCode::OK, policy.clone()),
                        None => json_response(
                            StatusCode::NOT_FOUND,
                            json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404}),
                        ),
                    }
                } else {
                    match cluster.pods.lock().unwrap().get(&path) {
                        Some(pod) => {
                            json_response(StatusCode::OK, serde_json::to_value(pod).unwrap())
                        }
                        None => json_response(
                            StatusCode::NOT_FOUND,
                            json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404}),
                        ),
                    }
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        kube::Client::new(service, SERVER)
    }
}

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// No Pod is bound: every guest is an unbound warm member, on `locked`.
struct Unbound;

#[async_trait]
impl BindingStore for Unbound {
    async fn live_binding(
        &self,
        _pod_uid: &str,
        _namespace: &str,
        _pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(None)
    }

    /// No record yet: each first writer's answer is recorded.
    async fn record_trust(
        &self,
        _pod_uid: &str,
        ca_given: bool,
    ) -> Result<bool, BindingStoreUnavailable> {
        Ok(ca_given)
    }
}

/// What the deployment under test renders workspaces with.
fn rendering() -> KubernetesRenderConfig {
    KubernetesRenderConfig {
        server_namespace: SERVER.into(),
        ..Default::default()
    }
}

fn state(
    cluster: &Arc<Cluster>,
    bindings: Arc<dyn BindingStore>,
    front_doors: Option<Arc<crate::front_door::FrontDoorEpochs>>,
) -> EgressServiceState {
    let driver =
        crate::runtime::kubernetes::KubernetesDriver::shared(cluster.client(), rendering());
    let attestation: Arc<dyn RuntimeAttestation> = driver;
    EgressServiceState {
        attestation,
        bindings,
        pool: unreachable_pool(),
        network_policies: true,
        server_namespace: SERVER.into(),
        sandbox_namespace: SANDBOXES.into(),
        platform: vec![PlatformDestination {
            host: "codewire-dev.sh".into(),
            port: 443,
        }],
        interception: false,
        starts: Default::default(),
        front_doors,
        interception_cas: None,
        reapplied: crate::egress::reapply::PoliciesReapplied::finished(),
        draining: tokio_util::sync::CancellationToken::new(),
    }
}

fn app(cluster: &Arc<Cluster>) -> axum::Router {
    app_with(cluster, Arc::new(Unbound), None)
}

fn app_with(
    cluster: &Arc<Cluster>,
    bindings: Arc<dyn BindingStore>,
    front_doors: Option<Arc<crate::front_door::FrontDoorEpochs>>,
) -> axum::Router {
    codewire_server_core::connect::connect_router(egress_router(Arc::new(state(
        cluster,
        bindings,
        front_doors,
    ))))
}

async fn call(cluster: &Arc<Cluster>, method: &str, body: Value) -> (StatusCode, Value) {
    call_app(app(cluster), method, body).await
}

async fn call_app(app: axum::Router, method: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(format!("/codewire.internal.v1.EgressService/{method}"))
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", token()))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A server stream's first frame: the message, or the end-of-stream error.
async fn first_frame(cluster: &Arc<Cluster>, body: Value) -> Value {
    first_frame_of(cluster, "WatchAssignment", body).await
}

/// The first frame of METHOD's response stream, for one request frame.
async fn first_frame_of(cluster: &Arc<Cluster>, method: &str, body: Value) -> Value {
    let payload = serde_json::to_vec(&body).unwrap();
    let mut framed = vec![0_u8];
    framed.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&payload);
    let request = Request::post(format!("/codewire.internal.v1.EgressService/{method}"))
        .header("content-type", "application/connect+json")
        .header(AUTHORIZATION, format!("Bearer {}", token()))
        .body(Body::from(framed))
        .unwrap();
    let response = app(cluster).oneshot(request).await.unwrap();
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while bytes.len() < 5 || bytes.len() < 5 + frame_len(&bytes) {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            _ => break,
        }
    }
    serde_json::from_slice(&bytes[5..5 + frame_len(&bytes)]).unwrap()
}

fn frame_len(bytes: &[u8]) -> usize {
    usize::try_from(u32::from_be_bytes(bytes[1..5].try_into().unwrap())).unwrap()
}

fn admit_body() -> Value {
    json!({"guestToken": token(), "peerIp": GUEST_IP})
}

fn named_guest() -> Value {
    json!({"podUid": GUEST_UID, "podName": GUEST})
}

#[tokio::test]
async fn a_broker_mode_guest_on_the_callers_node_is_admitted_with_its_assignment() {
    let (status, body) = call(&Cluster::healthy(), "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["podUid"], GUEST_UID);
    assert_eq!(body["podName"], GUEST);
    assert!(body["assignment"]["unbound"].is_object(), "{body}");
    assert_eq!(
        body["assignment"]["platformAllows"][0]["host"],
        "codewire-dev.sh"
    );
}

/// An interception CA source that answers as told and counts its asks.
struct Cas {
    certificate: Option<Vec<u8>>,
    asked: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl crate::egress::interception_ca::InterceptionCaSource for Cas {
    async fn ensure(
        &self,
        pod_uid: &str,
        pod_name: &str,
    ) -> Result<Vec<u8>, crate::egress::interception_ca::CaUnavailable> {
        assert_eq!((pod_uid, pod_name), (GUEST_UID, GUEST));
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.certificate
            .clone()
            .ok_or(crate::egress::interception_ca::CaUnavailable::Refused)
    }
}

/// Admit, with interception on or off and `cas` as the CA source.
async fn admit_intercepting(interception: bool, cas: &Arc<Cas>) -> (StatusCode, Value) {
    let cluster = Cluster::healthy();
    let mut state = state(&cluster, Arc::new(Unbound), None);
    state.interception = interception;
    state.interception_cas =
        Some(Arc::clone(cas)
            as Arc<
                dyn crate::egress::interception_ca::InterceptionCaSource,
            >);
    let app = codewire_server_core::connect::connect_router(egress_router(Arc::new(state)));
    call_app(app, "Admit", admit_body()).await
}

#[tokio::test]
async fn an_intercepting_guest_is_admitted_with_its_ca_certificate() {
    let cas = Arc::new(Cas {
        certificate: Some(b"synthetic-ca-der".to_vec()),
        asked: Default::default(),
    });
    let (status, body) = admit_intercepting(true, &cas).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    use base64::Engine as _;
    assert_eq!(
        body["caCertificateDer"],
        base64::engine::general_purpose::STANDARD.encode(b"synthetic-ca-der")
    );
    assert_eq!(cas.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_intercepting_guest_whose_ca_cannot_be_had_is_refused_never_admitted_without_one() {
    let cas = Arc::new(Cas {
        certificate: None,
        asked: Default::default(),
    });
    let (status, body) = admit_intercepting(true, &cas).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.get("caCertificateDer").is_none(), "{body}");
}

#[tokio::test]
async fn a_guest_that_does_not_intercept_carries_no_ca_and_asks_for_none() {
    let cas = Arc::new(Cas {
        certificate: Some(b"synthetic-ca-der".to_vec()),
        asked: Default::default(),
    });
    let (status, body) = admit_intercepting(false, &cas).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("caCertificateDer").is_none(), "{body}");
    assert_eq!(cas.asked.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_guest_on_another_node_is_refused_by_every_method_that_names_it() {
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| pod.spec.as_mut().unwrap().node_name = Some("runtime-b".into()));
    });
    let (status, body) = call(&cluster, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let frame = first_frame(&cluster, named_guest()).await;
    assert_eq!(frame["error"]["code"], "permission_denied", "{frame}");
}

#[tokio::test]
async fn an_unlabelled_guest_with_a_valid_token_node_and_address_is_refused() {
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| {
            pod.metadata
                .labels
                .as_mut()
                .unwrap()
                .remove(EGRESS_MODE_LABEL);
        });
    });
    let (status, _) = call(&cluster, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_stream_from_another_address_is_refused() {
    let (status, _) = call(
        &Cluster::healthy(),
        "Admit",
        json!({"guestToken": token(), "peerIp": "10.92.4.8"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_sandbox_presenting_the_egress_node_purpose_is_refused_by_every_method() {
    // A guest reading its own token cannot call EgressService itself.
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.reviews.insert(
            EGRESS_NODE_TOKEN_AUDIENCE,
            review(
                SANDBOXES,
                SANDBOX_SERVICE_ACCOUNT,
                EGRESS_NODE_TOKEN_AUDIENCE,
                GUEST,
                GUEST_UID,
            ),
        );
    });
    for (method, body) in [
        ("Admit", admit_body()),
        ("ReportEnforcement", named_guest()),
        ("ReportRecords", named_guest()),
    ] {
        let (status, body) = call(&cluster, method, body).await;
        // Authenticated, as the wrong account: not permitted.
        assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {body}");
    }
    let frame = first_frame(&cluster, named_guest()).await;
    assert_eq!(frame["error"]["code"], "permission_denied", "{frame}");
    let frame = first_frame_of(&cluster, "FrontDoorSession", json!({"open": named_guest()})).await;
    assert_eq!(frame["error"]["code"], "permission_denied", "{frame}");
}

#[tokio::test]
async fn cw_egress_in_another_namespace_is_refused() {
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.reviews.insert(
            EGRESS_NODE_TOKEN_AUDIENCE,
            review(
                "elsewhere",
                EGRESS_NODE_SERVICE_ACCOUNT,
                EGRESS_NODE_TOKEN_AUDIENCE,
                CALLER,
                CALLER_UID,
            ),
        );
    });
    let (status, _) = call(&cluster, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cw_egress_cannot_report_a_lockdown_refusal() {
    // Only orchestration's own check records one (#5068). The store's pool
    // connects nowhere: reaching it would answer 503.
    for detail in [
        "lockdown_not_applied",
        "not_broker_mode",
        "not_labelled_for_its_binding",
        "policy_unmanaged",
        "policy_missing",
        "policy_differs",
        "policy_does_not_select",
    ] {
        let body = json!({
            "podUid": GUEST_UID,
            "podName": GUEST,
            "state": "EGRESS_ENFORCEMENT_STATE_FAILED_CLOSED",
            "detail": detail,
        });
        let (status, response) = call(&Cluster::healthy(), "ReportEnforcement", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{detail}: {response}");
    }
}

#[tokio::test]
async fn malformed_reports_are_refused_before_anything_is_stored() {
    // The store's pool connects nowhere: reaching it would answer 503.
    let guest = json!({"podUid": GUEST_UID, "podName": GUEST});
    let with = |extra: Value| {
        let mut body = guest.clone();
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    let digest = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    for body in [
        with(json!({})),
        with(json!({"state": "EGRESS_ENFORCEMENT_STATE_FAILED_CLOSED", "detail": "anything"})),
        with(json!({"state": "EGRESS_ENFORCEMENT_STATE_DISCONNECTED", "revision": 3})),
        with(json!({"state": "EGRESS_ENFORCEMENT_STATE_ENFORCED", "revision": 1, "digest": "AQ"})),
    ] {
        let (status, response) = call(&Cluster::healthy(), "ReportEnforcement", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {response}");
    }
    let record = |transport: &str, port: u32| {
        json!({
            "name": "example.com",
            "transport": transport,
            "port": port,
            "refusal": "name_not_allowed",
            "policyReference": "locked",
            "policyDigest": digest,
            "firstSeenUnixMs": 1,
            "lastSeenUnixMs": 2,
            "count": 1,
        })
    };
    for records in [
        vec![record("EGRESS_TRANSPORT_TCP", 0)],
        vec![record("EGRESS_TRANSPORT_DNS", 53)],
        vec![
            record("EGRESS_TRANSPORT_TCP", 443);
            crate::egress::reports::MAX_RECORDS_PER_REPORT + 1
        ],
    ] {
        let (status, response) = call(
            &Cluster::healthy(),
            "ReportRecords",
            with(json!({"records": records})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    }
}

#[tokio::test]
async fn a_front_door_session_answers_unimplemented_while_interception_is_off() {
    // Authenticated first: the wrong caller still sees its own refusal.
    let frame = first_frame_of(
        &Cluster::healthy(),
        "FrontDoorSession",
        json!({"open": named_guest()}),
    )
    .await;
    assert_eq!(frame["error"]["code"], "unimplemented", "{frame}");
}

#[tokio::test]
async fn a_watch_starts_with_the_current_assignment() {
    let frame = first_frame(&Cluster::healthy(), named_guest()).await;
    assert!(frame["assignment"]["unbound"].is_object(), "{frame}");
}

#[tokio::test]
async fn a_bound_policy_never_changes_the_platform_allows() {
    // A policy that denies a platform host and allows another one: the
    // assignment still carries exactly the configured allows, separately.
    let policy = codewire_egress_policy::PolicyDocument::parse_yaml(
        br#"version: 1
default: deny
rules:
  - id: deny-control-plane
    action: deny
    protocols: [tcp]
    ports: [443]
    destinations: ["codewire-dev.sh"]
    route_classes: [general]
  - id: allow-other
    action: allow
    protocols: [tcp]
    ports: [8443]
    destinations: ["platform.example.com"]
    route_classes: [general]
"#,
    )
    .unwrap();
    let configured = vec![
        PlatformDestination {
            host: "codewire-dev.sh".into(),
            port: 443,
        },
        PlatformDestination {
            host: "derp.codewire-dev.sh".into(),
            port: 443,
        },
    ];
    let attestation: Arc<dyn RuntimeAttestation> =
        crate::runtime::kubernetes::KubernetesDriver::shared(
            Cluster::healthy().client(),
            Default::default(),
        );
    let state = EgressServiceState {
        attestation,
        bindings: Arc::new(Unbound),
        pool: unreachable_pool(),
        network_policies: true,
        server_namespace: SERVER.into(),
        sandbox_namespace: SANDBOXES.into(),
        platform: configured.clone(),
        interception: false,
        starts: Default::default(),
        front_doors: None,
        interception_cas: None,
        reapplied: crate::egress::reapply::PoliciesReapplied::finished(),
        draining: tokio_util::sync::CancellationToken::new(),
    };
    let bound = Assignment::Bound {
        environment_id: "env".into(),
        operation_generation: 1,
        policy: AssignedPolicy {
            name: "platform:strict".into(),
            revision: 1,
            document: policy.canonical_json().unwrap(),
            digest: *policy.digest().as_bytes(),
        },
        intercepts: Vec::new(),
    };
    for assignment in [&Assignment::Unbound, &bound] {
        let sent: Vec<(String, u32)> = state
            .proto(assignment)
            .platform_allows
            .iter()
            .map(|allow| (allow.host.clone(), allow.port))
            .collect();
        let expected: Vec<(String, u32)> = configured
            .iter()
            .map(|destination| (destination.host.clone(), u32::from(destination.port)))
            .collect();
        assert_eq!(sent, expected);
    }
}

#[tokio::test]
async fn interception_reaches_only_a_bound_sandbox_and_only_when_switched_on() {
    use buffa::Message as _;

    let state = |interception| {
        let attestation: Arc<dyn RuntimeAttestation> =
            crate::runtime::kubernetes::KubernetesDriver::shared(
                Cluster::healthy().client(),
                Default::default(),
            );
        EgressServiceState {
            attestation,
            bindings: Arc::new(Unbound),
            pool: PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
            network_policies: true,
            server_namespace: SERVER.into(),
            sandbox_namespace: SANDBOXES.into(),
            platform: Vec::new(),
            interception,
            starts: Default::default(),
            front_doors: None,
            interception_cas: None,
            reapplied: crate::egress::reapply::PoliciesReapplied::finished(),
            draining: tokio_util::sync::CancellationToken::new(),
        }
    };
    let bound = |interception| Assignment::Bound {
        environment_id: "env".into(),
        operation_generation: 7,
        policy: AssignedPolicy {
            name: "platform:egress".into(),
            revision: 3,
            document: br#"{"rules":[]}"#.to_vec(),
            digest: [9; 32],
        },
        intercepts: crate::egress::assignment::interception_bindings(
            interception,
            codewire_access::ManagedCredentialClients::from_profile_slots([
                "anthropic",
                "openai",
                "codex",
            ])
            .unwrap(),
        )
        .unwrap(),
    };
    // The assignment as it was before interception existed.
    let today = || BoundAssignment {
        environment_id: "env".into(),
        operation_generation: 7,
        policy: Some(EgressPolicyRevision {
            reference: "platform:egress".into(),
            revision: 3,
            document: br#"{"rules":[]}"#.to_vec(),
            digest: vec![9; 32],
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let encoded = |bound: BoundAssignment| {
        EgressAssignment {
            binding: Some(Binding::Bound(Box::new(bound))),
            ..Default::default()
        }
        .encode_to_vec()
    };

    // Off: byte for byte the assignment a bound sandbox gets today.
    assert_eq!(
        state(false).proto(&bound(false)).encode_to_vec(),
        encoded(today())
    );
    // On: today's assignment, the switch, and each front door host with its
    // port and suffix flag; nothing else, so no credential, key or
    // placeholder can travel in it.
    let mut hosts: Vec<(&str, bool)> = codewire_access::FRONT_DOOR_HOSTS
        .iter()
        .map(|host| (host.host, host.suffix))
        .collect();
    hosts.sort();
    assert!(!hosts.is_empty());
    let on = BoundAssignment {
        interception: true,
        interception_bindings: hosts
            .into_iter()
            .map(|(host, suffix)| InterceptionBinding {
                host: host.into(),
                port: 443,
                suffix,
                ..Default::default()
            })
            .collect(),
        ..today()
    };
    assert_eq!(state(true).proto(&bound(true)).encode_to_vec(), encoded(on));
    // On, for a binding whose selection names no host (#5215): today's
    // assignment, with interception off, so cw-egress runs the pair without a
    // front door rather than failing it closed on an empty set. The Pod's
    // trust frame and delivery still follow its interception decision.
    let mut names_none = bound(true);
    if let Assignment::Bound { intercepts, .. } = &mut names_none {
        *intercepts = crate::egress::assignment::interception_bindings(
            true,
            codewire_access::ManagedCredentialClients::default(),
        )
        .unwrap();
    }
    assert_eq!(
        state(true).proto(&names_none).encode_to_vec(),
        encoded(today())
    );
    // An unbound warm-pool member gets none either way.
    for interception in [false, true] {
        assert!(matches!(
            state(interception).proto(&Assignment::Unbound).binding,
            Some(Binding::Unbound(_))
        ));
    }
}

#[tokio::test]
async fn the_reports_refuse_a_guest_on_another_node() {
    let cluster = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| pod.spec.as_mut().unwrap().node_name = Some("runtime-b".into()));
    });
    for method in ["ReportEnforcement", "ReportRecords"] {
        let (status, body) = call(&cluster, method, named_guest()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {body}");
    }
}

#[tokio::test]
async fn admit_refuses_a_guest_that_is_not_running_or_an_unparsable_peer() {
    let pending = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| pod.status.as_mut().unwrap().phase = Some("Pending".into()));
    });
    let (status, _) = call(&pending, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &Cluster::healthy(),
        "Admit",
        json!({"guestToken": token(), "peerIp": "not-an-address"}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

fn watch(cluster: &Arc<Cluster>, expires_in: Duration) -> Watch {
    let attestation: Arc<dyn RuntimeAttestation> =
        crate::runtime::kubernetes::KubernetesDriver::shared(cluster.client(), Default::default());
    Watch {
        state: Arc::new(EgressServiceState {
            attestation,
            bindings: Arc::new(Unbound),
            pool: unreachable_pool(),
            network_policies: true,
            server_namespace: SERVER.into(),
            sandbox_namespace: SANDBOXES.into(),
            platform: Vec::new(),
            interception: false,
            starts: Default::default(),
            front_doors: None,
            interception_cas: None,
            reapplied: crate::egress::reapply::PoliciesReapplied::finished(),
            draining: tokio_util::sync::CancellationToken::new(),
        }),
        caller: Caller {
            namespace: SERVER.into(),
            name: CALLER.into(),
            uid: CALLER_UID.into(),
            node: NODE.into(),
            expires_at: tokio::time::Instant::now() + expires_in,
        },
        guest: GuestPod {
            namespace: SANDBOXES.into(),
            name: GUEST.into(),
            uid: GUEST_UID.into(),
        },
        sent: None,
        next: None,
        withheld_since: None,
        read_failures: 0,
        ended: false,
    }
}

fn later() -> Duration {
    Duration::from_secs(600)
}

#[tokio::test]
async fn an_open_watch_ends_when_its_caller_is_replaced_moved_or_expired() {
    assert!(watch(&Cluster::healthy(), later()).recheck().await.is_ok());

    let expired = watch(&Cluster::healthy(), Duration::ZERO)
        .recheck()
        .await
        .unwrap_err();
    assert_eq!(expired.code, connectrpc::ErrorCode::Unauthenticated);

    let caller_path = format!("/api/v1/namespaces/{SERVER}/pods/{CALLER}");
    let replaced = Cluster::healthy().with(|cluster| {
        cluster
            .pods
            .get_mut()
            .unwrap()
            .get_mut(&caller_path)
            .unwrap()
            .metadata
            .uid = Some("another-uid".into());
    });
    let error = watch(&replaced, later()).recheck().await.unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);

    let moved = Cluster::healthy().with(|cluster| {
        cluster
            .pods
            .get_mut()
            .unwrap()
            .get_mut(&caller_path)
            .unwrap()
            .spec
            .as_mut()
            .unwrap()
            .node_name = Some("runtime-b".into());
    });
    let error = watch(&moved, later()).recheck().await.unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn a_draining_cw_egress_admits_no_new_stream_but_keeps_serving_the_ones_it_holds() {
    // A terminating cw-egress drains for its deadline (#6483): ending its
    // watches would end every pair with an open connection at once.
    let caller_path = format!("/api/v1/namespaces/{SERVER}/pods/{CALLER}");
    let draining = Cluster::healthy().with(|cluster| {
        cluster
            .pods
            .get_mut()
            .unwrap()
            .get_mut(&caller_path)
            .unwrap()
            .metadata
            .deletion_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
        ));
    });
    let (status, body) = call(&draining, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    assert!(watch(&draining, later()).recheck().await.is_ok());
    let frame = first_frame(&draining, named_guest()).await;
    assert!(frame["assignment"].is_object(), "{frame}");
    // Past the caller check, a malformed report is refused as malformed. The
    // store's pool connects nowhere, so nothing is stored.
    for (method, body) in [
        ("ReportEnforcement", named_guest()),
        (
            "ReportRecords",
            json!({"podUid": GUEST_UID, "podName": GUEST, "records": [{}]}),
        ),
    ] {
        let (status, response) = call(&draining, method, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method}: {response}");
    }
}

#[tokio::test]
async fn a_watch_refuses_a_uid_that_is_not_the_pods() {
    let frame = first_frame(
        &Cluster::healthy(),
        json!({"podUid": "0b8f6a52-0000-0000-0000-000000000000", "podName": GUEST}),
    )
    .await;
    assert_eq!(frame["error"]["code"], "permission_denied", "{frame}");
}

#[tokio::test(start_paused = true)]
async fn a_watch_ends_once_when_its_guest_leaves_the_node_or_ends() {
    for edit in [
        (|pod: &mut Pod| pod.spec.as_mut().unwrap().node_name = Some("runtime-b".into()))
            as fn(&mut Pod),
        |pod: &mut Pod| {
            pod.metadata.deletion_timestamp =
                Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
                ))
        },
    ] {
        let cluster = Cluster::healthy().with(|cluster| cluster.edit_guest(edit));
        let (first, watch) = watch(&cluster, later()).step().await.unwrap();
        assert_eq!(
            first.unwrap_err().code,
            connectrpc::ErrorCode::PermissionDenied
        );
        assert!(
            watch.step().await.is_none(),
            "the stream ends after one error"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_watch_rides_out_a_few_failed_kubernetes_reads_but_not_more() {
    // Each recheck reads the caller Pod first; failing those reads is a blip.
    let blip = Cluster::healthy();
    blip.failing_reads.store(
        usize::try_from(WATCH_READ_FAILURES).unwrap(),
        Ordering::SeqCst,
    );
    let (message, _) = watch(&blip, later()).step().await.unwrap();
    assert!(
        message.unwrap().assignment.binding.is_some(),
        "the watch carried on"
    );

    let outage = Cluster::healthy();
    outage.failing_reads.store(
        usize::try_from(WATCH_READ_FAILURES).unwrap() + 1,
        Ordering::SeqCst,
    );
    let (error, watch) = watch(&outage, later()).step().await.unwrap();
    assert_eq!(error.unwrap_err().code, connectrpc::ErrorCode::Unavailable);
    assert!(watch.step().await.is_none());
}

#[tokio::test]
async fn admits_from_one_peer_are_limited_before_any_guest_review_is_spent() {
    let cluster = Cluster::healthy();
    let app = app(&cluster);
    let call = |app: axum::Router| async move {
        let request = Request::post("/codewire.internal.v1.EgressService/Admit")
            .header("content-type", "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", token()))
            .body(Body::from(serde_json::to_vec(&admit_body()).unwrap()))
            .unwrap();
        app.oneshot(request).await.unwrap().status()
    };
    let limit = codewire_egress_node::replacement::STARTS_PER_WINDOW;
    for _ in 0..limit {
        assert_eq!(call(app.clone()).await, StatusCode::OK);
    }
    assert_eq!(cluster.guest_reviews.load(Ordering::SeqCst), limit);
    assert_eq!(call(app.clone()).await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        cluster.guest_reviews.load(Ordering::SeqCst),
        limit,
        "the limited start spent no guest review"
    );
}

#[tokio::test(start_paused = true)]
async fn a_hung_read_ends_the_watch_at_the_tokens_expiry_not_after_it() {
    // The token runs out one second into a recheck whose reads hang: the
    // watch ends then, not after the full read timeout and another poll.
    let cluster = Cluster::healthy();
    cluster.hang_reads.store(true, Ordering::SeqCst);
    let mut expiring = watch(&cluster, WATCH_INTERVAL + Duration::from_secs(1));
    expiring.sent = Some(Assignment::Unbound);
    let started = tokio::time::Instant::now();
    let (error, watch) = expiring.step().await.unwrap();
    assert_eq!(
        error.unwrap_err().code,
        connectrpc::ErrorCode::Unauthenticated
    );
    assert!(
        started.elapsed() <= WATCH_INTERVAL + Duration::from_secs(1),
        "ended {:?} after the watch started",
        started.elapsed()
    );
    assert!(watch.step().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_hung_read_counts_as_one_failed_read() {
    let cluster = Cluster::healthy();
    cluster.hang_reads.store(true, Ordering::SeqCst);
    let error = watch(&cluster, later()).recheck().await.unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::Unavailable);
}

#[tokio::test(start_paused = true)]
async fn a_good_read_resets_the_failed_read_count() {
    let mut flaky = watch(&Cluster::healthy(), later());
    flaky.read_failures = WATCH_READ_FAILURES;
    let (message, flaky) = flaky.step().await.unwrap();
    assert!(message.is_ok());
    assert_eq!(flaky.read_failures, 0);
}

#[tokio::test]
async fn a_guest_review_that_cannot_run_is_unavailable_not_a_refusal() {
    let cluster = Cluster::healthy();
    cluster.guest_reviews_down.store(true, Ordering::SeqCst);
    let (status, body) = call(&cluster, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
}

const BOUND_ENVIRONMENT: &str = "0f8c2f6e-2c1e-4a8e-9c55-3b1f0f7d9a11";
const ANOTHER_ENVIRONMENT: &str = "9d2a4b7c-51f3-4e0a-8b66-2a7c1e5f3d08";

fn binding() -> LiveBinding {
    LiveBinding {
        environment_id: BOUND_ENVIRONMENT.into(),
        pod_uid: GUEST_UID.into(),
        namespace: SANDBOXES.into(),
        pod_name: GUEST.into(),
        claim_uid: "c0ffee00-0bd2-4f11-8b16-9c239851eb52".into(),
        sandbox_uid: GUEST_SANDBOX_UID.into(),
        operation_generation: 3,
        projection_selection_sha256: None,
        managed_credential_clients: String::new(),
        credential_scope: WorkspaceCredentialScope::Pod,
        environment_generation: 3,
        isolation_tier: "standard".into(),
        working_directory: String::new(),
        defaults: None,
        interception: None,
    }
}

/// Orchestration's record binds the guest to `BOUND_ENVIRONMENT`, whatever
/// the Pod's labels say.
struct Bound;

/// [`Bound`], with the interception decision its first bind stored.
struct Decided(Option<bool>);

#[async_trait]
impl BindingStore for Decided {
    async fn live_binding(
        &self,
        _pod_uid: &str,
        _namespace: &str,
        _pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(Some(decided(self.0)))
    }

    /// No record yet: each first writer's answer is recorded.
    async fn record_trust(
        &self,
        _pod_uid: &str,
        ca_given: bool,
    ) -> Result<bool, BindingStoreUnavailable> {
        Ok(ca_given)
    }
}

fn decided(interception: Option<bool>) -> LiveBinding {
    LiveBinding {
        interception,
        managed_credential_clients: codewire_access::ManagedCredentialClients::from_profile_slots(
            ["anthropic"],
        )
        .unwrap()
        .encode()
        .to_owned(),
        ..binding()
    }
}

#[async_trait]
impl BindingStore for Bound {
    async fn live_binding(
        &self,
        _pod_uid: &str,
        _namespace: &str,
        _pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(Some(binding()))
    }

    /// No record yet: each first writer's answer is recorded.
    async fn record_trust(
        &self,
        _pod_uid: &str,
        ca_given: bool,
    ) -> Result<bool, BindingStoreUnavailable> {
        Ok(ca_given)
    }
}

fn policy_path(environment: &str) -> String {
    let name = crate::sandbox::template::workspace_daemon_network_policy_name(environment);
    format!("/apis/networking.k8s.io/v1/namespaces/{SANDBOXES}/networkpolicies/{name}")
}

/// The NetworkPolicy the access stack applies for `BOUND_ENVIRONMENT`.
fn rendered_policy() -> Value {
    rendering()
        .workspace_network_policy(
            SANDBOXES,
            BOUND_ENVIRONMENT,
            crate::runtime::Isolation::Standard,
        )
        .expect("the default deployment manages workspace NetworkPolicies")
}

/// A guest labelled for `label`, with `policy` as its bound environment's
/// NetworkPolicy in the cluster.
fn bound_guest(label: Option<&str>, policy: Option<Value>) -> Arc<Cluster> {
    Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| {
            let labels = pod.metadata.labels.get_or_insert_with(BTreeMap::new);
            if let Some(environment) = label {
                labels.insert(LABEL_ENV_ID.into(), environment.into());
            }
        });
        if let Some(policy) = policy {
            cluster
                .policies
                .get_mut()
                .unwrap()
                .insert(policy_path(BOUND_ENVIRONMENT), policy);
        }
    })
}

/// The guest's template hash, and the policy the sandbox controller makes
/// from that template (#4964).
const TEMPLATE_HASH: &str = "2f9c41ab";
const TEMPLATE_POLICY: &str = "warm-2000m-4096mi-20gi-r7-network-policy";

/// The template policy for the guest, exactly as orchestration renders it.
fn rendered_template_policy() -> Value {
    let mut policy = rendering()
        .template_network_policy(crate::runtime::Isolation::Standard, TEMPLATE_HASH)
        .expect("the default deployment manages workspace NetworkPolicies");
    policy["metadata"] = json!({"name": TEMPLATE_POLICY, "namespace": SANDBOXES});
    policy
}

/// The controller's default for a template with no `networkPolicy`, which a
/// template made before hosted egress has: every public address.
fn wide_template_policy() -> Value {
    json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": TEMPLATE_POLICY, "namespace": SANDBOXES},
        "spec": {
            "podSelector": {"matchLabels": {crate::sandbox::warm_pool::TEMPLATE_REF_HASH_LABEL: TEMPLATE_HASH}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "sandbox-router"}}}]}],
            "egress": [{"to": [
                {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]}},
                {"ipBlock": {"cidr": "::/0", "except": ["fc00::/7", "fe80::/10"]}},
            ]}],
        },
    })
}

/// `cluster`'s guest made from a template whose controller policy is
/// `template`.
fn from_template(cluster: Arc<Cluster>, template: Value) -> Arc<Cluster> {
    cluster.with(|cluster| {
        cluster.edit_guest(|pod| {
            pod.metadata
                .labels
                .get_or_insert_with(BTreeMap::new)
                .insert(crate::sandbox::warm_pool::TEMPLATE_REF_HASH_LABEL.into(), TEMPLATE_HASH.into());
        });
        cluster.policies.get_mut().unwrap().insert(
            format!("/apis/networking.k8s.io/v1/namespaces/{SANDBOXES}/networkpolicies/{TEMPLATE_POLICY}"),
            template,
        );
    })
}

fn rendered_with(edit: impl FnOnce(&mut Value)) -> Option<Value> {
    let mut policy = rendered_policy();
    edit(&mut policy["spec"]);
    Some(policy)
}

/// The lockdown decision Admit takes for the bound guest, between the
/// guest's review and its assignment. Admit itself goes on to read the
/// environment's policy from the database, which these tests have none of.
async fn lockdown(cluster: &Arc<Cluster>) -> Result<(), connectrpc::ErrorCode> {
    let state = state(cluster, Arc::new(Bound), None);
    let guest = state.named_guest(GUEST, GUEST_UID);
    let facts = state
        .attestation
        .attested_pod(SANDBOXES, GUEST)
        .await
        .unwrap()
        .unwrap();
    state
        .lockdown_applied(&guest, &facts, &binding())
        .await
        .map_err(|error| error.code)
}

/// What a deployment with the switch off and the broker settings kept
/// renders with (#6070).
fn kept() -> KubernetesRenderConfig {
    crate::egress::gateway_check::assume_verified();
    KubernetesRenderConfig {
        runtime_profile: crate::sandbox::template::RUNTIME_PROFILE_COMMODITY.into(),
        hosted_egress: crate::egress::own_mode::HostedEgress {
            enabled: false,
            broker: Some(crate::sandbox::template::HostedEgressTemplate {
                stream_addr: "10.44.0.89:8089".into(),
                binding_addr: "10.44.0.87:8087".into(),
                fence_revision: "4".into(),
                gateway: crate::sandbox::template::GatewayPeer {
                    namespace: "gateway-proxies".into(),
                    gateway_name: "public".into(),
                    gateway_namespace: "gateway".into(),
                    port: 10443,
                },
                derp_tls_port: 8443,
                gateway_addr: "10.44.0.43:443".into(),
                derp_addr: "derp.example.test=10.44.0.84:8443".into(),
                cluster_dns_ip: "10.44.0.10".into(),
            }),
        },
        ..rendering()
    }
}

/// The lockdown refusal, if any, of a service whose driver renders with
/// `rendering`. Read without failing the guest closed, so no refusal is
/// counted.
async fn lockdown_rendered(
    cluster: &Arc<Cluster>,
    rendering: KubernetesRenderConfig,
) -> Option<lockdown::LockdownRefusal> {
    let state = EgressServiceState {
        attestation: crate::runtime::kubernetes::KubernetesDriver::shared(
            cluster.client(),
            rendering,
        ),
        ..state(cluster, Arc::new(Bound), None)
    };
    let guest = state.named_guest(GUEST, GUEST_UID);
    let facts = state
        .attestation
        .attested_pod(SANDBOXES, GUEST)
        .await
        .unwrap()
        .unwrap();
    state
        .lockdown_refusal(&guest, &facts, &binding())
        .await
        .unwrap()
}

async fn admit_bound(cluster: &Arc<Cluster>) -> StatusCode {
    let (status, _) = call_app(
        app_with(cluster, Arc::new(Bound), None),
        "Admit",
        admit_body(),
    )
    .await;
    status
}

#[tokio::test]
async fn a_bound_guest_under_exactly_the_rendered_policy_passes_the_lockdown_check() {
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), Some(rendered_policy()));
    assert_eq!(lockdown(&cluster).await, Ok(()));

    // The API server's defaults and an applied manifest's empty lists are
    // not differences.
    let cluster = bound_guest(
        Some(BOUND_ENVIRONMENT),
        rendered_with(|spec| {
            spec["podSelector"]["matchExpressions"] = json!([]);
            spec["egress"][0]["ports"] = json!([]);
        }),
    );
    assert_eq!(lockdown(&cluster).await, Ok(()));
}

#[tokio::test]
async fn a_live_policy_that_is_not_the_rendered_one_is_refused() {
    let allow_all = rendered_with(|spec| spec["egress"] = json!([{}]));
    let extra_rule = rendered_with(|spec| {
        spec["egress"]
            .as_array_mut()
            .unwrap()
            .push(json!({"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}));
    });
    let widened_rule = rendered_with(|spec| {
        spec["egress"][1]["to"][0]["namespaceSelector"] = json!({});
    });
    let widened_selector = rendered_with(|spec| {
        spec["podSelector"] = json!({"matchLabels": {LABEL_TYPE: "workspace"}});
    });
    let ingress_only = rendered_with(|spec| spec["policyTypes"] = json!(["Ingress"]));
    let extra_ingress = rendered_with(|spec| {
        spec["ingress"].as_array_mut().unwrap().push(json!({}));
    });
    for (what, policy) in [
        ("no policy", None),
        ("allow-all egress", allow_all),
        ("an extra egress rule", extra_rule),
        ("a widened egress peer", widened_rule),
        ("a widened Pod selector", widened_selector),
        ("egress not governed", ingress_only),
        ("an extra ingress rule", extra_ingress),
    ] {
        let cluster = bound_guest(Some(BOUND_ENVIRONMENT), policy);
        assert_eq!(
            lockdown(&cluster).await,
            Err(connectrpc::ErrorCode::PermissionDenied),
            "{what}"
        );
        assert_eq!(admit_bound(&cluster).await, StatusCode::FORBIDDEN, "{what}");
    }
}

#[tokio::test]
async fn a_bound_guest_cannot_leave_the_check_by_its_labels() {
    // Stripped of its environment label, the Pod looks like a warm member.
    // The binding still says it is bound, so it is checked and refused.
    let stripped = bound_guest(None, Some(rendered_policy()));
    // Labelled for another environment whose policy is in place and exact.
    let relabelled =
        bound_guest(Some(ANOTHER_ENVIRONMENT), Some(rendered_policy())).with(|cluster| {
            let other = rendering()
                .workspace_network_policy(
                    SANDBOXES,
                    ANOTHER_ENVIRONMENT,
                    crate::runtime::Isolation::Standard,
                )
                .unwrap();
            cluster
                .policies
                .get_mut()
                .unwrap()
                .insert(policy_path(ANOTHER_ENVIRONMENT), other);
        });
    for cluster in [stripped, relabelled] {
        assert_eq!(
            lockdown(&cluster).await,
            Err(connectrpc::ErrorCode::PermissionDenied)
        );
        assert_eq!(admit_bound(&cluster).await, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn an_unbound_member_is_admitted_unbound_on_locked_whatever_label_it_wears() {
    // No live binding: the label alone binds nothing and assigns no policy,
    // so cw-egress keeps the member on `locked`.
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), None);
    let (status, body) = call(&cluster, "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["assignment"]["unbound"].is_object(), "{body}");
}

/// The guest's self-check result can only fail a sandbox closed (#4000 P6).
/// Admit runs before the guest has sent any result and reads none: a guest
/// whose lockdown is not applied is refused, and stays refused when the
/// request also claims its probes passed.
#[tokio::test]
async fn admit_refuses_a_guest_whose_lockdown_is_not_applied_whatever_it_reports() {
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), None);
    assert_eq!(admit_bound(&cluster).await, StatusCode::FORBIDDEN);

    let mut claiming = admit_body();
    claiming["selfCheck"] = json!("PASSED");
    claiming["selfCheckPassed"] = json!(true);
    let (status, body) =
        call_app(app_with(&cluster, Arc::new(Bound), None), "Admit", claiming).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(body.get("assignment").is_none(), "{body}");
}

/// A warm member: unbound until `claim` records its binding, as a claim does
/// after the member's stream was admitted.
#[derive(Default)]
struct Claimable(std::sync::atomic::AtomicBool);

impl Claimable {
    fn claim(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl BindingStore for Claimable {
    async fn live_binding(
        &self,
        _pod_uid: &str,
        _namespace: &str,
        _pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(self.0.load(Ordering::SeqCst).then(binding))
    }

    /// No record yet: each first writer's answer is recorded.
    async fn record_trust(
        &self,
        _pod_uid: &str,
        ca_given: bool,
    ) -> Result<bool, BindingStoreUnavailable> {
        Ok(ca_given)
    }
}

/// The watch cw-egress opens for the guest once its stream is admitted.
fn watch_of(state: EgressServiceState) -> Watch {
    Watch {
        state: Arc::new(state),
        caller: Caller {
            namespace: SERVER.into(),
            name: CALLER.into(),
            uid: CALLER_UID.into(),
            node: NODE.into(),
            expires_at: tokio::time::Instant::now() + later(),
        },
        guest: GuestPod {
            namespace: SANDBOXES.into(),
            name: GUEST.into(),
            uid: GUEST_UID.into(),
        },
        sent: None,
        next: None,
        withheld_since: None,
        read_failures: 0,
        ended: false,
    }
}

/// A pool that connects nowhere, and says so at once rather than after the
/// default acquire timeout: reaching the store answers 503.
fn unreachable_pool() -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://unused@127.0.0.1:1/unused")
        .unwrap()
}

/// A member admitted unbound and its open watch, which has sent "unbound".
async fn admitted_unbound(cluster: &Arc<Cluster>) -> (Arc<Claimable>, Watch) {
    let member = Arc::new(Claimable::default());
    let (status, body) = call_app(
        app_with(cluster, member.clone(), None),
        "Admit",
        admit_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["assignment"]["unbound"].is_object(), "{body}");

    let state = state(cluster, member.clone(), None);
    let guest = state.named_guest(GUEST, GUEST_UID);
    let first = state.watched_assignment(&guest, None).await.unwrap();
    let mut watch = watch_of(state);
    watch.take(first).await.unwrap();
    let (first, watch) = watch.step().await.unwrap();
    assert!(
        matches!(first.unwrap().assignment.binding, Some(Binding::Unbound(_))),
        "an unbound member's watch starts unbound"
    );
    (member, watch)
}

/// The warm-pool path (#4000 P6): a member is admitted while unbound, with
/// nothing to check, and is claimed later. Its bound assignment arrives on
/// the watch, so the lockdown is checked there, before the first one. With
/// the environment's policy widened the assignment is never sent: the watch
/// says nothing more, and ends failing closed once the grace has run out.
#[tokio::test(start_paused = true)]
async fn a_member_claimed_under_a_widened_policy_never_gets_its_bound_assignment() {
    let widened = rendered_with(|spec| spec["egress"] = json!([{}]));
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), widened);
    let (member, watch) = admitted_unbound(&cluster).await;
    let refusal = lockdown::LockdownRefusal::PolicyDiffers {
        policy: lockdown::policy_name(BOUND_ENVIRONMENT),
    };
    let counted = lockdown::failed_closed(&refusal);

    member.claim();
    let claimed_at = tokio::time::Instant::now();
    // The next thing the stream carries is the refusal: no bound assignment,
    // and no other message, came before it.
    let (ended, watch) = watch.step().await.unwrap();
    assert_eq!(
        ended.unwrap_err().code,
        connectrpc::ErrorCode::PermissionDenied
    );
    assert!(claimed_at.elapsed() >= LOCKDOWN_BIND_GRACE);
    assert!(claimed_at.elapsed() < LOCKDOWN_BIND_GRACE + 2 * WATCH_INTERVAL);
    assert!(lockdown::failed_closed(&refusal) > counted);
    assert!(watch.step().await.is_none(), "the stream ends after it");
}

#[tokio::test]
async fn a_guest_under_its_rendered_template_policy_passes_the_lockdown_check() {
    let cluster = from_template(
        bound_guest(Some(BOUND_ENVIRONMENT), Some(rendered_policy())),
        rendered_template_policy(),
    );
    assert_eq!(lockdown(&cluster).await, Ok(()));
}

/// #4964: the environment's policy is exactly the rendered one, but the
/// template the member came from was made before hosted egress, so the
/// controller's policy for it adds every public address. The bound
/// assignment is never sent, and the member fails closed after the grace.
#[tokio::test(start_paused = true)]
async fn a_member_from_a_wide_template_never_gets_its_bound_assignment() {
    let cluster = from_template(
        bound_guest(Some(BOUND_ENVIRONMENT), Some(rendered_policy())),
        wide_template_policy(),
    );
    let (member, watch) = admitted_unbound(&cluster).await;
    let refusal = lockdown::LockdownRefusal::PolicyDiffers {
        policy: TEMPLATE_POLICY.to_owned(),
    };
    let counted = lockdown::failed_closed(&refusal);

    member.claim();
    let claimed_at = tokio::time::Instant::now();
    let (ended, watch) = watch.step().await.unwrap();
    assert_eq!(
        ended.unwrap_err().code,
        connectrpc::ErrorCode::PermissionDenied
    );
    assert!(claimed_at.elapsed() >= LOCKDOWN_BIND_GRACE);
    assert!(lockdown::failed_closed(&refusal) > counted);
    assert!(watch.step().await.is_none(), "the stream ends after it");
}

/// A claim records the binding before it applies the environment's policy,
/// so a watch can read the binding first. That is not a failure: the bound
/// assignment is withheld, and once the policy is the rendered one within
/// the grace the watch goes on to read the assignment. These tests have no
/// database for that read, so it keeps what it sent; what matters here is
/// that the watch does not fail closed.
#[tokio::test(start_paused = true)]
async fn a_policy_applied_within_the_grace_does_not_fail_the_member_closed() {
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), None);
    let (member, watch) = admitted_unbound(&cluster).await;

    member.claim();
    let applied = cluster.clone();
    let apply = tokio::spawn(async move {
        tokio::time::sleep(LOCKDOWN_BIND_GRACE / 2).await;
        applied
            .policies
            .lock()
            .unwrap()
            .insert(policy_path(BOUND_ENVIRONMENT), rendered_policy());
    });
    let (ended, _) = watch.step().await.unwrap();
    apply.await.unwrap();
    // It ran on to its caller's token expiry, long past the grace.
    assert_eq!(
        ended.unwrap_err().code,
        connectrpc::ErrorCode::Unauthenticated
    );
}

/// The gate itself, where a claimed member's policy is exactly the rendered
/// one: the watch may send the bound assignment, and reads it. A stream that
/// was already sent as bound to this environment is not checked again.
#[tokio::test(start_paused = true)]
async fn a_member_claimed_under_the_rendered_policy_passes_the_gate() {
    let member = Arc::new(Claimable::default());
    member.claim();

    let intact = bound_guest(Some(BOUND_ENVIRONMENT), Some(rendered_policy()));
    let state_intact = state(&intact, member.clone(), None);
    let guest = state_intact.named_guest(GUEST, GUEST_UID);
    // Past the gate, the read of the environment's policy is what fails
    // here, for want of a database: unavailable, never a refusal.
    let read = state_intact.watched_assignment(&guest, None).await;
    assert_eq!(
        read.err().map(|error| error.code),
        Some(connectrpc::ErrorCode::Unavailable)
    );

    let missing = bound_guest(Some(BOUND_ENVIRONMENT), None);
    let state_missing = state(&missing, member, None);
    assert!(matches!(
        state_missing.watched_assignment(&guest, None).await,
        Ok(Watched::Withheld(lockdown::LockdownRefusal::PolicyMissing))
    ));
    let already_bound = state_missing
        .watched_assignment(&guest, Some(BOUND_ENVIRONMENT))
        .await;
    assert_eq!(
        already_bound.err().map(|error| error.code),
        Some(connectrpc::ErrorCode::Unavailable),
        "a later change under an already bound stream is not checked again yet"
    );
}

/// A sandbox failed closed is counted by its reason, which an alert reads,
/// and still fails closed when its status cannot be recorded: the store's
/// pool here connects nowhere (#5068). Nothing else in these tests fails a
/// guest closed for this reason, so the count is exact.
#[tokio::test]
async fn a_sandbox_failed_closed_is_counted_by_its_reason_even_when_it_cannot_be_recorded() {
    let state = state(&Cluster::healthy(), Arc::new(Unbound), None);
    let guest = state.named_guest(GUEST, GUEST_UID);
    let refusal = lockdown::LockdownRefusal::NotBrokerMode;
    let before = lockdown::failed_closed(&refusal);
    let error = state.failed_closed(&guest, &refusal).await;
    assert_eq!(error.code, connectrpc::ErrorCode::PermissionDenied);
    assert_eq!(lockdown::failed_closed(&refusal), before + 1);
    assert_eq!(refusal.reason(), "not_broker_mode");
}

/// A router whose state binds the guest and, when `intercepting`, has the
/// deployment's interception switched on.
fn signing_app(
    cluster: &Arc<Cluster>,
    bindings: Arc<dyn BindingStore>,
    intercepting: bool,
) -> axum::Router {
    signing_app_with(cluster, bindings, intercepting, None)
}

fn signing_app_with(
    cluster: &Arc<Cluster>,
    bindings: Arc<dyn BindingStore>,
    intercepting: bool,
    front_doors: Option<Arc<crate::front_door::FrontDoorEpochs>>,
) -> axum::Router {
    let mut state = state(cluster, bindings, front_doors);
    state.interception = intercepting;
    codewire_server_core::connect::connect_router(egress_router(Arc::new(state)))
}

fn sign_body() -> Value {
    json!({"podUid": GUEST_UID, "podName": GUEST, "leafPublicKey": "AAEC"})
}

/// The key of the relay epoch [`Decided`]'s binding runs.
fn signing_key() -> crate::front_door::BindingKey {
    crate::front_door::BindingKey {
        environment_id: uuid::Uuid::parse_str(BOUND_ENVIRONMENT).unwrap(),
        pod_uid: GUEST_UID.into(),
        generation: u64::try_from(binding().operation_generation).unwrap(),
    }
}

/// A registered epoch for `key` that answers one signing ask with `answer`,
/// and returns the key it was asked to sign.
fn signing_epoch(
    front_doors: &Arc<crate::front_door::FrontDoorEpochs>,
    key: crate::front_door::BindingKey,
    answer: Result<
        codewire_daemon_proto::broker::v1::SignInterceptionLeavesResponse,
        tonic::Status,
    >,
) -> (
    crate::front_door::Registration,
    tokio::task::JoinHandle<Vec<u8>>,
) {
    let (asks, mut asked) = tokio::sync::mpsc::channel(1);
    let registration = front_doors.register(key, asks);
    let epoch = tokio::spawn(async move {
        let Some(crate::front_door::EpochRequest::Sign(crate::front_door::Sign {
            leaf_public_key,
            reply,
        })) = asked.recv().await
        else {
            panic!("the epoch was asked to sign");
        };
        let _ = reply.send(answer);
        leaf_public_key
    });
    (registration, epoch)
}

/// A bound, intercepting Pod's front door gets exactly the leaves its
/// binding's current epoch had the credential service sign, for the key it
/// sent, and the service's renewal time (N3b).
#[tokio::test]
async fn interception_leaves_are_signed_through_the_bindings_current_epoch() {
    let cluster = Cluster::healthy();
    let front_doors = Arc::new(crate::front_door::FrontDoorEpochs::default());
    let leaves = codewire_daemon_proto::broker::v1::SignInterceptionLeavesResponse {
        leaves: vec![codewire_daemon_proto::broker::v1::InterceptionLeaf {
            certificate_der: vec![1, 2, 3],
            hosts: vec!["api.anthropic.com".into()],
        }],
        renew_at_unix: 1_900_000_000,
    };
    let (_registration, epoch) = signing_epoch(&front_doors, signing_key(), Ok(leaves));
    let (status, body) = call_app(
        signing_app_with(
            &cluster,
            Arc::new(Decided(Some(true))),
            true,
            Some(front_doors),
        ),
        "SignInterceptionLeaves",
        sign_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        epoch.await.unwrap(),
        vec![0, 1, 2],
        "the key cw-egress sent"
    );
    assert_eq!(
        body["leaves"],
        json!([{"certificateDer": "AQID"}]),
        "{body}"
    );
    assert_eq!(
        body["renewAtUnix"].to_string().trim_matches('"'),
        "1900000000",
        "{body}"
    );
}

/// With no epoch admitted for the Pod's live binding on this process, or
/// only one for another generation, cw-egress is told UNAVAILABLE and
/// retries, its hosts failing closed meanwhile.
#[tokio::test]
async fn interception_leaves_are_unavailable_without_the_bindings_epoch() {
    let cluster = Cluster::healthy();
    let stale = crate::front_door::BindingKey {
        generation: signing_key().generation + 1,
        ..signing_key()
    };
    let other = Arc::new(crate::front_door::FrontDoorEpochs::default());
    let (_registration, _epoch) =
        signing_epoch(&other, stale, Err(tonic::Status::internal("never asked")));
    for front_doors in [
        None,
        Some(Arc::new(crate::front_door::FrontDoorEpochs::default())),
        Some(other),
    ] {
        let (status, body) = call_app(
            signing_app_with(&cluster, Arc::new(Decided(Some(true))), true, front_doors),
            "SignInterceptionLeaves",
            sign_body(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["code"], "unavailable", "{body}");
    }
}

/// The epoch's refusals reach cw-egress by code alone.
#[tokio::test]
async fn an_epochs_signing_refusal_reaches_cw_egress_by_code_alone() {
    let cluster = Cluster::healthy();
    for (refusal, status, code) in [
        (
            tonic::Status::permission_denied("relay detail"),
            StatusCode::FORBIDDEN,
            "permission_denied",
        ),
        (
            tonic::Status::invalid_argument("relay detail"),
            StatusCode::BAD_REQUEST,
            "invalid_argument",
        ),
        (
            tonic::Status::unavailable("relay detail"),
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
        ),
    ] {
        let front_doors = Arc::new(crate::front_door::FrontDoorEpochs::default());
        let (_registration, _epoch) = signing_epoch(&front_doors, signing_key(), Err(refusal));
        let (answered, body) = call_app(
            signing_app_with(
                &cluster,
                Arc::new(Decided(Some(true))),
                true,
                Some(front_doors),
            ),
            "SignInterceptionLeaves",
            sign_body(),
        )
        .await;
        assert_eq!(answered, status, "{body}");
        assert_eq!(body["code"], code, "{body}");
        assert!(!body.to_string().contains("relay detail"), "{body}");
    }
}

/// Refused as every Pod-naming method refuses: a Pod on another node, one
/// that is not bound, or one the deployment does not intercept.
#[tokio::test]
async fn interception_leaves_are_refused_to_any_other_pod() {
    let elsewhere = Cluster::healthy().with(|cluster| {
        cluster.edit_guest(|pod| pod.spec.as_mut().unwrap().node_name = Some("runtime-b".into()));
    });
    let healthy = Cluster::healthy();
    for (app, case) in [
        (
            signing_app(&elsewhere, Arc::new(Bound), true),
            "another node",
        ),
        (signing_app(&healthy, Arc::new(Unbound), true), "unbound"),
        (
            signing_app(&healthy, Arc::new(Bound), false),
            "not intercepting",
        ),
        (
            signing_app(&healthy, Arc::new(Decided(Some(false))), true),
            "stored as not intercepted, the switch on",
        ),
    ] {
        let (status, body) = call_app(app, "SignInterceptionLeaves", sign_body()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{case}: {body}");
    }
}

/// The decision a Pod's first bind stored governs it, whatever the switch
/// says now; an unbound warm member follows the switch, which its first bind
/// will store. A bound Pod with none stored is not intercepted while the
/// switch is off, which it was, and refused while it is on (C5, #5496).
#[tokio::test]
async fn a_bound_pod_follows_its_stored_decision_and_an_unbound_one_the_switch() {
    let cluster = Cluster::healthy();
    for setting in [false, true] {
        let mut state = state(&cluster, Arc::new(Unbound), None);
        state.interception = setting;
        assert_eq!(state.intercepts(None).unwrap(), setting);
        for stored in [false, true] {
            assert_eq!(
                state.intercepts(Some(&decided(Some(stored)))).unwrap(),
                stored,
                "switch {setting}, stored {stored}"
            );
        }
        let none = state.intercepts(Some(&decided(None)));
        if setting {
            assert_eq!(none.unwrap_err().code, connectrpc::ErrorCode::Unavailable);
        } else {
            assert!(!none.unwrap());
        }
    }
}

/// Once a decision is stored, a bound Pod's CA and its assignment's bindings
/// agree: an intercepted Pod gets both, a Pod stored as not intercepted
/// neither, whatever the switch says now.
#[tokio::test]
async fn a_stored_decision_gives_the_ca_and_the_bindings_together() {
    let cluster = Cluster::healthy();
    for setting in [false, true] {
        for stored in [false, true] {
            let cas = Arc::new(Cas {
                certificate: Some(b"synthetic-ca-der".to_vec()),
                asked: Default::default(),
            });
            let mut state = state(&cluster, Arc::new(Unbound), None);
            state.interception = setting;
            state.interception_cas =
                Some(Arc::clone(&cas)
                    as Arc<
                        dyn crate::egress::interception_ca::InterceptionCaSource,
                    >);
            let binding = decided(Some(stored));
            let guest = state.named_guest(GUEST, GUEST_UID);
            let facts = guest_facts(&state).await;
            let ca = state
                .interception_ca(&guest, &facts, Some(&binding))
                .await
                .unwrap();
            let bindings = binding_intercepts(
                state.intercepts(Some(&binding)).unwrap(),
                &binding.managed_credential_clients,
            )
            .unwrap();
            let case = format!("switch {setting}, stored {stored}");
            assert_eq!(!ca.is_empty(), stored, "{case}");
            assert_eq!(!bindings.is_empty(), stored, "{case}");
        }
    }
}

/// The guest Pod as the service reads it from the API.
async fn guest_facts(state: &EgressServiceState) -> crate::runtime::MemberFacts {
    state
        .attestation
        .attested_pod(SANDBOXES, GUEST)
        .await
        .unwrap()
        .unwrap()
}

/// An unbound guest whose trust another first writer already recorded.
struct Recorded(bool);

#[async_trait]
impl BindingStore for Recorded {
    async fn live_binding(
        &self,
        _pod_uid: &str,
        _namespace: &str,
        _pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        Ok(None)
    }

    async fn record_trust(
        &self,
        pod_uid: &str,
        _ca_given: bool,
    ) -> Result<bool, BindingStoreUnavailable> {
        assert_eq!(pod_uid, GUEST_UID, "the trust is the resolved Pod's");
        Ok(self.0)
    }
}

/// Every admission gives exactly the trust the Pod's record holds, whatever
/// the switch says by then (#6200): a warm member admitted before a flip
/// keeps the trust its guest installed, and its first bind follows it.
#[tokio::test]
async fn an_admission_gives_the_recorded_trust_never_the_switch_now() {
    let cluster = Cluster::healthy();
    for setting in [false, true] {
        for recorded in [false, true] {
            let cas = Arc::new(Cas {
                certificate: Some(b"synthetic-ca-der".to_vec()),
                asked: Default::default(),
            });
            let mut state = state(&cluster, Arc::new(Recorded(recorded)), None);
            state.interception = setting;
            state.interception_cas =
                Some(Arc::clone(&cas)
                    as Arc<
                        dyn crate::egress::interception_ca::InterceptionCaSource,
                    >);
            let guest = state.named_guest(GUEST, GUEST_UID);
            let facts = guest_facts(&state).await;
            let ca = state.interception_ca(&guest, &facts, None).await.unwrap();
            assert_eq!(
                !ca.is_empty(),
                recorded,
                "switch {setting}, recorded {recorded}"
            );
        }
    }
}

/// A binding's clients are read only while the deployment intercepts, so an
/// encoding this build can't read costs no egress with interception off, and
/// withholds the assignment with it on (#4001 step P).
#[test]
fn a_bindings_clients_are_read_only_while_intercepting() {
    assert_eq!(binding_intercepts(false, "unreadable").unwrap(), Vec::new());
    assert!(binding_intercepts(true, "unreadable").is_err());
    let sign_in = codewire_access::ManagedCredentialClients::from_profile_slots(["anthropic"])
        .and_then(codewire_access::ManagedCredentialClients::with_anthropic_sign_in)
        .unwrap();
    let hosts: Vec<String> = binding_intercepts(true, sign_in.encode())
        .unwrap()
        .into_iter()
        .map(|intercept| intercept.binding.hostname().to_owned())
        .collect();
    assert!(
        hosts
            .iter()
            .any(|host| host == codewire_access::CLAUDE_TOKEN_HOST)
    );
}

/// #6070, cw-security's amendment 3: with the switch off and the broker
/// settings kept, a bound guest whose Sandbox is whole broker passes the
/// lockdown check under the broker policy, exactly as with the switch on.
#[tokio::test]
async fn with_the_switch_off_a_whole_broker_guest_passes_under_its_broker_policy() {
    let broker = kept()
        .workspace_network_policy(
            SANDBOXES,
            BOUND_ENVIRONMENT,
            crate::runtime::Isolation::Standard,
        )
        .unwrap();
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), Some(broker.clone()));
    assert_eq!(lockdown_rendered(&cluster, kept()).await, None);
    let on = KubernetesRenderConfig {
        hosted_egress: crate::egress::own_mode::HostedEgress {
            enabled: true,
            ..kept().hosted_egress
        },
        ..kept()
    };
    assert_eq!(lockdown_rendered(&cluster, on).await, None);
    // A direct policy under a broker guest still differs, and is refused.
    let direct = bound_guest(Some(BOUND_ENVIRONMENT), Some(rendered_policy()));
    assert!(matches!(
        lockdown_rendered(&direct, kept()).await,
        Some(lockdown::LockdownRefusal::PolicyDiffers { .. })
    ));
}

/// #6070, cw-security's amendment 3: a bound guest whose Sandbox is direct
/// or hollow is refused with the switch off, whatever its Pod's labels and
/// whatever policy is in place; so is one whose Sandbox is not the one its
/// binding recorded, or is gone.
#[tokio::test]
async fn with_the_switch_off_a_direct_or_hollow_sandboxs_guest_is_refused() {
    let broker = kept()
        .workspace_network_policy(
            SANDBOXES,
            BOUND_ENVIRONMENT,
            crate::runtime::Isolation::Standard,
        )
        .unwrap();
    let sandboxes = [
        ("direct", Some(guest_sandbox(false, false, false))),
        ("label alone", Some(guest_sandbox(true, false, false))),
        ("no fence", Some(guest_sandbox(true, false, true))),
        ("no TUN", Some(guest_sandbox(true, true, false))),
        ("no label", Some(guest_sandbox(false, true, true))),
        ("another Sandbox's UID", {
            let mut other = guest_sandbox(true, true, true);
            other["metadata"]["uid"] = json!("0e6ac1b5-8d1e-4a7c-9b0d-6c3f2a1e4b59");
            Some(other)
        }),
        ("gone", None),
    ];
    for (what, sandbox) in sandboxes {
        for policy in [broker.clone(), rendered_policy()] {
            let cluster = bound_guest(Some(BOUND_ENVIRONMENT), Some(policy)).with(|cluster| {
                let mut sandboxes = cluster.sandboxes.lock().unwrap();
                sandboxes.clear();
                if let Some(sandbox) = sandbox.clone() {
                    sandboxes.insert(sandbox_path(GUEST_SANDBOX), sandbox);
                }
            });
            assert_eq!(
                lockdown_rendered(&cluster, kept()).await,
                Some(lockdown::LockdownRefusal::NotBrokerMode),
                "{what}"
            );
        }
    }
    // A Pod whose controller is not the Sandbox its binding recorded.
    let cluster = bound_guest(Some(BOUND_ENVIRONMENT), Some(broker)).with(|cluster| {
        cluster.edit_guest(|pod| {
            pod.metadata.owner_references.as_mut().unwrap()[0].uid =
                "0e6ac1b5-8d1e-4a7c-9b0d-6c3f2a1e4b59".into();
        });
    });
    assert_eq!(
        lockdown_rendered(&cluster, kept()).await,
        Some(lockdown::LockdownRefusal::NotBrokerMode)
    );
}

/// [`kept`] after a release that moved the gateway's listener port, which
/// every broker Sandbox's policy names (#6070).
fn released() -> KubernetesRenderConfig {
    let mut config = kept();
    if let Some(broker) = config.hosted_egress.broker.as_mut() {
        broker.gateway.port = 10444;
    }
    config
}

fn broker_policy(config: &KubernetesRenderConfig) -> Value {
    config
        .workspace_network_policy(
            SANDBOXES,
            BOUND_ENVIRONMENT,
            crate::runtime::Isolation::Standard,
        )
        .unwrap()
}

/// The bound guest's environment as its access stack renders it.
fn bound_intent() -> crate::runtime::RenderingIntent {
    crate::runtime::RenderingIntent {
        image: crate::sandbox::canonical_workspace_runtime_image().into(),
        template_base: "workspace".into(),
        isolation: crate::runtime::Isolation::Standard,
        dedicated_cpu: false,
        systemd_workspace: false,
        systemd_opted_in: false,
        runtime_profile: "commodity".into(),
        shape: crate::runtime::WorkspaceShape {
            cpu_millicores: 1000,
            memory_mib: 4096,
            disk_gib: 10,
        },
        identity: crate::runtime::RenderingIdentity {
            environment_id: BOUND_ENVIRONMENT.into(),
            organization_id: "org-1".into(),
            operation_generation: 3,
            projection_selection_sha256: None,
            earlier_projection_selection_sha256: Vec::new(),
            managed_credential_clients: Default::default(),
            source_snapshot_id: None,
            confidential_storage_manifest_uri: String::new(),
        },
    }
}

/// A running broker guest whose policy the release before rendered, its
/// Claim bound to its whole broker Sandbox.
fn running_before_the_release() -> Arc<Cluster> {
    bound_guest(Some(BOUND_ENVIRONMENT), Some(broker_policy(&kept()))).with(|cluster| {
        cluster.sandboxes.get_mut().unwrap().insert(
            format!(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{SANDBOXES}/sandboxclaims/{}",
                crate::sandbox::claim_name(BOUND_ENVIRONMENT)
            ),
            json!({
                "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxClaim",
                "metadata": {"name": crate::sandbox::claim_name(BOUND_ENVIRONMENT), "namespace": SANDBOXES},
                "status": {"sandbox": {"name": GUEST_SANDBOX}},
            }),
        );
    })
}

/// #6070 (N3): after a release changes what a broker policy renders, the
/// startup re-apply writes it again through the access stack's writer, so a
/// running broker Sandbox is admitted at once rather than refused as
/// `policy_differs`. A policy tampered with after the sweep is still
/// refused, and Admit never applies it again.
#[tokio::test]
async fn after_a_release_the_startup_reapply_admits_a_running_broker_sandbox_at_once() {
    let cluster = running_before_the_release();
    // Without the re-apply, the first admission after the release refuses.
    assert!(matches!(
        lockdown_rendered(&cluster, released()).await,
        Some(lockdown::LockdownRefusal::PolicyDiffers { .. })
    ));
    let driver = crate::runtime::kubernetes::KubernetesDriver::shared(cluster.client(), released());
    let placement = crate::runtime::Placement::new(SANDBOXES);
    assert_eq!(
        driver
            .reapply_broker_policy(&placement, &bound_intent())
            .await
            .unwrap(),
        crate::egress::reapply::PolicyReapply::Applied
    );
    assert_eq!(lockdown_rendered(&cluster, released()).await, None);
    // Applied once: the next sweep finds it current and writes nothing.
    assert_eq!(
        driver
            .reapply_broker_policy(&placement, &bound_intent())
            .await
            .unwrap(),
        crate::egress::reapply::PolicyReapply::Current
    );
    assert_eq!(cluster.replaced.load(Ordering::SeqCst), 1);

    // Tampered with after the sweep: refused, and not applied again.
    cluster
        .policies
        .lock()
        .unwrap()
        .get_mut(&policy_path(BOUND_ENVIRONMENT))
        .unwrap()["spec"]["egress"]
        .as_array_mut()
        .unwrap()
        .push(json!({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}));
    assert!(matches!(
        lockdown_rendered(&cluster, released()).await,
        Some(lockdown::LockdownRefusal::PolicyDiffers { .. })
    ));
    let state = EgressServiceState {
        attestation: crate::runtime::kubernetes::KubernetesDriver::shared(
            cluster.client(),
            released(),
        ),
        ..state(&cluster, Arc::new(Bound), None)
    };
    let (status, _) = call_app(
        codewire_server_core::connect::connect_router(egress_router(Arc::new(state))),
        "Admit",
        admit_body(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(cluster.replaced.load(Ordering::SeqCst), 1);
}

/// #6070 (N3): until the startup sweep has finished, a bound guest's
/// admission is a retryable UNAVAILABLE, never a refusal, even under a
/// policy that differs; once it has, the difference is refused.
#[tokio::test]
async fn while_the_sweep_runs_admit_is_unavailable_not_a_refusal() {
    let cluster = running_before_the_release();
    let reapplied = crate::egress::reapply::PoliciesReapplied::pending();
    let app = || {
        codewire_server_core::connect::connect_router(egress_router(Arc::new(EgressServiceState {
            attestation: crate::runtime::kubernetes::KubernetesDriver::shared(
                cluster.client(),
                released(),
            ),
            reapplied: reapplied.clone(),
            ..state(&cluster, Arc::new(Bound), None)
        })))
    };
    let (status, body) = call_app(app(), "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "unavailable", "{body}");
    reapplied.finish();
    let (status, _) = call_app(app(), "Admit", admit_body()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
