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
use crate::sandbox::LABEL_TYPE;
use crate::workspace_binding::store::{BindingStoreUnavailable, LiveBinding};

const SERVER: &str = "dev";
const SANDBOXES: &str = "dev-sandboxes";
const NODE: &str = "runtime-a";
const CALLER: &str = "codewire-egress-abc";
const CALLER_UID: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a9e01";
const GUEST: &str = "workspace-1";
const GUEST_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const GUEST_IP: &str = "10.92.4.7";

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
        let guest = pod(
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

/// No Pod is bound: every guest is a warm member on platform allows only.
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
}

fn app(cluster: &Arc<Cluster>) -> axum::Router {
    let driver =
        crate::runtime::kubernetes::KubernetesDriver::shared(cluster.client(), Default::default());
    let attestation: Arc<dyn RuntimeAttestation> = driver;
    codewire_server_core::connect::connect_router(egress_router(Arc::new(EgressServiceState {
        attestation,
        bindings: Arc::new(Unbound),
        pool: PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
        server_namespace: SERVER.into(),
        sandbox_namespace: SANDBOXES.into(),
        platform: vec![PlatformDestination {
            host: "codewire-dev.sh".into(),
            port: 443,
        }],
        starts: Default::default(),
    })))
}

async fn call(cluster: &Arc<Cluster>, method: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(format!("/codewire.internal.v1.EgressService/{method}"))
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", token()))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let response = app(cluster).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A server stream's first frame: the message, or the end-of-stream error.
async fn first_frame(cluster: &Arc<Cluster>, body: Value) -> Value {
    let payload = serde_json::to_vec(&body).unwrap();
    let mut framed = vec![0_u8];
    framed.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&payload);
    let request = Request::post("/codewire.internal.v1.EgressService/WatchAssignment")
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
async fn the_reports_answer_unimplemented_to_a_valid_caller() {
    for method in ["ReportEnforcement", "ReportRecords"] {
        let (status, body) = call(&Cluster::healthy(), method, named_guest()).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{method}: {body}");
    }
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
        pool: PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
        server_namespace: SERVER.into(),
        sandbox_namespace: SANDBOXES.into(),
        platform: configured.clone(),
        starts: Default::default(),
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
            pool: PgPool::connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap(),
            server_namespace: SERVER.into(),
            sandbox_namespace: SANDBOXES.into(),
            platform: Vec::new(),
            starts: Default::default(),
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
