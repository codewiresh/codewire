//! Fairness of the 8087 request limits for two workspace Pods on one node
//! (B1 review L6). Each Pod normally has its own Pod IP, so one Pod's flood
//! or long-poll never spends the other's peer bucket, per-Pod slot or wait.
//! When a CNI masquerades both Pods behind one node IP the peer bucket, which
//! is checked before any TokenReview and so before the Pod is known, is
//! shared; the per-Pod slots and waits stay independent. Both behaviours are
//! pinned here.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header::AUTHORIZATION};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_gateway_proto::{GATEWAY_BINDING_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE};
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use serde_json::{Value, json};
use tower::service_fn;

use super::service::{BindError, WorkspaceBindingState};
use super::store::{BindingNotifications, BindingStore, BindingStoreUnavailable, LiveBinding};
use crate::worker::gatewayauth::WorkspaceCredentialScope;

const NAMESPACE: &str = "sandboxes";
const SECRET: &str = "synthetic-session-secret";
/// Two Pods scheduled on one node, each with its own Pod IP.
const POD_IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 3, 11));
const POD_IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 244, 3, 12));
/// The node IP a masquerading CNI would present for both.
const NODE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 3));

struct WorkspacePod {
    name: &'static str,
    uid: &'static str,
    sandbox: &'static str,
    sandbox_uid: &'static str,
    claim_uid: &'static str,
    environment: &'static str,
}

const POD_A: WorkspacePod = WorkspacePod {
    name: "sandbox-a",
    uid: "7e7b20f6-0bd2-4f11-8b16-9c239851eb52",
    sandbox: "sandbox-a",
    sandbox_uid: "5a4db0c5-6d1e-4b0f-9b3c-2f0e7c1d9a11",
    claim_uid: "c0ffee00-1d2e-4f3a-8b4c-5d6e7f8a9b0c",
    environment: "550e8400-e29b-41d4-a716-446655440000",
};

const POD_B: WorkspacePod = WorkspacePod {
    name: "sandbox-b",
    uid: "a1560db3-8899-40c9-b521-500f223b04fb",
    sandbox: "sandbox-b",
    sandbox_uid: "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d",
    claim_uid: "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c",
    environment: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
};

fn token(pod: &WorkspacePod) -> String {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp},"sub":"{}"}}"#, pod.name)),
        URL_SAFE_NO_PAD.encode(b"synthetic-signature")
    )
}

fn bearer(pod: &WorkspacePod) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token(pod))).unwrap(),
    );
    headers
}

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// TokenReview answers for whichever Pod's token was presented; Pods and
/// Sandboxes are served by name.
static PODS: [WorkspacePod; 2] = [POD_A, POD_B];

fn cluster(reviews: Arc<AtomicUsize>) -> kube::Client {
    let pods: &'static [WorkspacePod] = &PODS;
    let service = service_fn(move |request: Request<kube::client::Body>| {
        let reviews = reviews.clone();
        async move {
            let path = request.uri().path().to_owned();
            let method = request.method().clone();
            let body = axum::body::to_bytes(Body::new(request.into_body()), 64 * 1024)
                .await
                .unwrap();
            let response = if method == "POST" && path.ends_with("/tokenreviews") {
                reviews.fetch_add(1, Ordering::SeqCst);
                let review: TokenReview = serde_json::from_slice(&body).unwrap();
                let presented = review.spec.token.unwrap_or_default();
                let pod = pods
                    .iter()
                    .find(|pod| token_subject(&presented) == Some(pod.name))
                    .expect("a known Pod's token");
                json_response(
                    StatusCode::CREATED,
                    serde_json::to_value(TokenReview {
                        status: Some(TokenReviewStatus {
                            authenticated: Some(true),
                            audiences: Some(vec![WORKSPACE_BINDING_TOKEN_AUDIENCE.into()]),
                            user: Some(UserInfo {
                                username: Some(format!(
                                    "system:serviceaccount:{NAMESPACE}:{GATEWAY_BINDING_SERVICE_ACCOUNT}"
                                )),
                                extra: Some(std::collections::BTreeMap::from([
                                    (
                                        "authentication.kubernetes.io/pod-name".into(),
                                        vec![pod.name.into()],
                                    ),
                                    (
                                        "authentication.kubernetes.io/pod-uid".into(),
                                        vec![pod.uid.into()],
                                    ),
                                ])),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                    .unwrap(),
                )
            } else if let Some(pod) = pods
                .iter()
                .find(|pod| path == format!("/api/v1/namespaces/{NAMESPACE}/pods/{}", pod.name))
            {
                json_response(
                    StatusCode::OK,
                    json!({
                        "apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": pod.name, "namespace": NAMESPACE, "uid": pod.uid,
                            "labels": {"codewire.sh/type": "workspace",
                                "codewire.sh/environment-id": pod.environment},
                            "ownerReferences": [{"apiVersion": "agents.x-k8s.io/v1beta1",
                                "kind": "Sandbox", "name": pod.sandbox, "uid": pod.sandbox_uid,
                                "controller": true}]},
                        "spec": {"serviceAccountName": GATEWAY_BINDING_SERVICE_ACCOUNT, "containers": []},
                        "status": {"phase": "Running"},
                    }),
                )
            } else if let Some(pod) = pods.iter().find(|pod| {
                path == format!(
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxes/{}",
                    pod.sandbox
                )
            }) {
                json_response(
                    StatusCode::OK,
                    json!({
                        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                        "metadata": {"name": pod.sandbox, "namespace": NAMESPACE,
                            "uid": pod.sandbox_uid,
                            "ownerReferences": [{"apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                                "kind": "SandboxClaim", "name": "claim", "uid": pod.claim_uid,
                                "controller": true}]},
                    }),
                )
            } else {
                panic!("unexpected Kubernetes request {method} {path}");
            };
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    kube::Client::new(service, NAMESPACE)
}

fn token_subject(token: &str) -> Option<&'static str> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    let payload: Value = serde_json::from_slice(&payload).ok()?;
    let subject = payload.get("sub")?.as_str()?;
    [POD_A.name, POD_B.name]
        .into_iter()
        .find(|name| *name == subject)
}

/// Only Pod B is bound; Pod A waits for its binding.
#[derive(Default)]
struct TwoPodStore {
    bound: Mutex<HashMap<&'static str, LiveBinding>>,
    queries: AtomicUsize,
}

impl TwoPodStore {
    fn bind(&self, pod: &WorkspacePod) {
        self.bound.lock().unwrap().insert(
            pod.uid,
            LiveBinding {
                environment_id: pod.environment.into(),
                pod_uid: pod.uid.into(),
                namespace: NAMESPACE.into(),
                pod_name: pod.name.into(),
                claim_uid: pod.claim_uid.into(),
                sandbox_uid: pod.sandbox_uid.into(),
                operation_generation: 3,
                projection_selection_sha256: None,
                managed_credential_clients: String::new(),
                credential_scope: WorkspaceCredentialScope::Pod,
            },
        );
    }
}

#[async_trait]
impl BindingStore for TwoPodStore {
    async fn live_binding(
        &self,
        pod_uid: &str,
        _namespace: &str,
        _pod_name: &str,
    ) -> Result<Option<LiveBinding>, BindingStoreUnavailable> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        Ok(self.bound.lock().unwrap().get(pod_uid).cloned())
    }
}

fn state(store: Arc<TwoPodStore>, reviews: Arc<AtomicUsize>) -> Arc<WorkspaceBindingState> {
    Arc::new(
        WorkspaceBindingState::new(
            Some(cluster(reviews)),
            store,
            Arc::new(BindingNotifications::default()),
            NAMESPACE,
            SECRET,
        )
        .with_timing(Duration::from_millis(400), Duration::from_millis(50)),
    )
}

/// Distinct Pod IPs on one node: Pod A's long-poll and Pod A's flood leave
/// Pod B's bucket, slot and wait untouched, and B binds at once.
#[tokio::test]
async fn two_pods_on_one_node_do_not_starve_each_other() {
    let store = Arc::new(TwoPodStore::default());
    store.bind(&POD_B);
    let reviews = Arc::new(AtomicUsize::new(0));
    let state = state(store.clone(), reviews.clone());

    // A long-polls for a binding that is not recorded yet.
    let waiting = {
        let state = state.clone();
        tokio::spawn(async move { state.bind(&bearer(&POD_A), Some(POD_IP_A), 20).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    // While waiting, A floods: its second request is refused by its own
    // per-Pod slot, then its peer bucket runs dry, before any review.
    for _ in 0..4 {
        assert_eq!(
            state.bind(&bearer(&POD_A), Some(POD_IP_A), 0).await,
            Err(BindError::ResourceExhausted)
        );
    }
    let reviewed = reviews.load(Ordering::SeqCst);
    assert_eq!(
        state.bind(&bearer(&POD_A), Some(POD_IP_A), 0).await,
        Err(BindError::ResourceExhausted)
    );
    assert_eq!(
        reviews.load(Ordering::SeqCst),
        reviewed,
        "a flood spent a review"
    );

    // B, on the same node, binds promptly and is unaffected.
    let started = tokio::time::Instant::now();
    let response = state
        .bind(&bearer(&POD_B), Some(POD_IP_B), 20)
        .await
        .unwrap();
    assert_eq!(response.pod_uid, POD_B.uid);
    assert!(started.elapsed() < Duration::from_millis(300));

    // A's long-poll ends with not_found after its own wait, as the daemon
    // expects, and its next call can bind once recorded.
    assert_eq!(waiting.await.unwrap(), Err(BindError::NotFound));
    store.bind(&POD_A);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        state
            .bind(&bearer(&POD_A), Some(POD_IP_A), 20)
            .await
            .unwrap()
            .pod_uid,
        POD_A.uid
    );
}

/// Behind one masquerading node IP both Pods share the pre-review peer
/// bucket (the Pod is unknown before TokenReview), but their per-Pod slots
/// and waits stay independent: A's long-poll never blocks B's bind. The
/// daemon's one call per wait keeps two Pods far below the shared 1/s.
#[tokio::test]
async fn behind_one_node_ip_the_bucket_is_shared_but_slots_and_waits_are_not() {
    let store = Arc::new(TwoPodStore::default());
    store.bind(&POD_B);
    let reviews = Arc::new(AtomicUsize::new(0));
    let state = state(store.clone(), reviews);

    let waiting = {
        let state = state.clone();
        tokio::spawn(async move { state.bind(&bearer(&POD_A), Some(NODE_IP), 20).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let response = state
        .bind(&bearer(&POD_B), Some(NODE_IP), 20)
        .await
        .unwrap();
    assert_eq!(response.pod_uid, POD_B.uid);
    assert_eq!(waiting.await.unwrap(), Err(BindError::NotFound));

    // The shared bucket (burst 5) has three tokens left; a flood from either
    // Pod drains it for both: the known residual of a masquerading CNI.
    for _ in 0..3 {
        let _ = state.bind(&bearer(&POD_A), Some(NODE_IP), 0).await;
    }
    assert_eq!(
        state.bind(&bearer(&POD_B), Some(NODE_IP), 0).await,
        Err(BindError::ResourceExhausted)
    );
}
