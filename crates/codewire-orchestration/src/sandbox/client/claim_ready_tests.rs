//! The SandboxClaim readiness wait that create and start block on, and the
//! workspace Pod revision wait between the early bind's chain reads.

use super::*;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const NS: &str = "dev-sandboxes";
const ENV: &str = "0d4c2b9e-7a51-4f3e-9c6a-2f8e1b7d5a30";

/// Serves raw bodies in order and records `METHOD path?query` for each call.
fn raw_client(responses: Vec<(StatusCode, String)>) -> (SandboxClient, Arc<Mutex<Vec<String>>>) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let requests = recorded.clone();
    let queued = Arc::new(Mutex::new(VecDeque::from(responses)));
    let service = Router::new().fallback(move |request: Request<Body>| {
        let requests = requests.clone();
        let queued = queued.clone();
        async move {
            requests.lock().unwrap().push(format!(
                "{} {}",
                request.method(),
                request.uri().path_and_query().unwrap()
            ));
            let (status, body) = queued
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected Kubernetes request");
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
    });
    (
        SandboxClient::new(Client::new(service, "default"), NS),
        recorded,
    )
}

fn claim(resource_version: &str, ready: bool) -> Value {
    json!({
        "apiVersion": super::super::EXTENSIONS_API_VERSION,
        "kind": "SandboxClaim",
        "metadata": {
            "name": claim_name(ENV),
            "namespace": NS,
            "resourceVersion": resource_version,
        },
        "status": {
            "conditions": [{
                "type": "Ready",
                "status": if ready { "True" } else { "False" },
                "reason": if ready { "Ready" } else { "SandboxNotReady" },
            }],
        },
    })
}

#[tokio::test]
async fn claim_readiness_wakes_on_the_claim_watch() {
    let ready = claim("21", true);
    let event = json!({"type": "MODIFIED", "object": ready}).to_string() + "\n";
    let (client, requests) = raw_client(vec![
        (StatusCode::OK, claim("20", false).to_string()),
        (StatusCode::OK, event),
        (StatusCode::OK, ready.to_string()),
    ]);
    // The fallback poll outlasts the wait, so only the watch event can end it.
    client
        .wait_for_ready_with_fallback(ENV, Duration::from_secs(5), Duration::from_secs(60))
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3, "{requests:#?}");
    let watch = &requests[1];
    assert!(
        watch.starts_with(&format!(
            "GET /apis/{}/{}/namespaces/{NS}/sandboxclaims?",
            super::super::EXTENSIONS_GROUP,
            super::super::CRD_VERSION
        )),
        "{watch}"
    );
    for part in [
        "watch=true",
        &format!("fieldSelector=metadata.name%3D{}", claim_name(ENV)),
        "resourceVersion=20",
    ] {
        assert!(watch.contains(part), "{watch} lacks {part}");
    }
}

#[tokio::test]
async fn claim_readiness_polls_when_the_watch_is_refused() {
    let forbidden = json!({
        "apiVersion": "v1", "kind": "Status", "status": "Failure",
        "reason": "Forbidden", "code": 403,
    });
    let (client, requests) = raw_client(vec![
        (StatusCode::OK, claim("20", false).to_string()),
        (StatusCode::FORBIDDEN, forbidden.to_string()),
        (StatusCode::OK, claim("21", true).to_string()),
    ]);
    let fallback = Duration::from_millis(200);
    let started = std::time::Instant::now();
    client
        .wait_for_ready_with_fallback(ENV, Duration::from_secs(5), fallback)
        .await
        .unwrap();
    assert!(
        started.elapsed() >= fallback,
        "a refused watch must wait out the fallback instead of re-reading at once"
    );
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn claim_readiness_fails_once_the_deadline_passes() {
    // The watch ends without an event; the wait re-reads once at the
    // deadline and reports the same timeout as before.
    let (client, requests) = raw_client(vec![
        (StatusCode::OK, claim("20", false).to_string()),
        (StatusCode::OK, String::new()),
        (StatusCode::OK, claim("20", false).to_string()),
    ]);
    let timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let error = client
        .wait_for_ready_with_fallback(ENV, timeout, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(started.elapsed() >= timeout);
    assert!(
        error
            .to_string()
            .contains("timeout waiting for SandboxClaim"),
        "{error:#}"
    );
    assert_eq!(requests.lock().unwrap().len(), 3);
}

/// A Kubernetes API on the paused clock: the Claim is bound and turns Ready at
/// `ready_at`, and `refusal` gives the workspace Pod's scheduler message at each
/// moment since the wait began.
fn scheduling_client(
    ready_at: Option<Duration>,
    refusal: impl Fn(Duration) -> Option<&'static str> + Clone + Send + Sync + 'static,
) -> SandboxClient {
    let started = tokio::time::Instant::now();
    let service = Router::new().fallback(move |request: Request<Body>| {
        let refusal = refusal.clone();
        async move {
            let now = started.elapsed();
            let path = request.uri().path_and_query().unwrap().as_str().to_owned();
            let body = if path.contains("watch=true") {
                String::new()
            } else if path.contains("/sandboxclaims/") {
                let ready = ready_at.is_some_and(|at| now >= at);
                let mut object = claim("20", ready);
                object["status"]["sandbox"] = json!({"name": "workspace-sandbox"});
                object.to_string()
            } else if path.contains("/sandboxes/") {
                json!({
                    "apiVersion": "agents.x-k8s.io/v1alpha1",
                    "kind": "Sandbox",
                    "metadata": {"name": "workspace-sandbox", "namespace": NS},
                })
                .to_string()
            } else {
                let conditions = refusal(now).map_or_else(Vec::new, |message| {
                    vec![json!({
                        "type": "PodScheduled",
                        "status": "False",
                        "reason": "Unschedulable",
                        "message": message,
                    })]
                });
                json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "workspace-sandbox", "namespace": NS},
                    "status": {"phase": "Pending", "conditions": conditions},
                })
                .to_string()
            };
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
    });
    SandboxClient::new(Client::new(service, "default"), NS)
}

const FULL: &str = "0/2 nodes are available: 2 Insufficient cpu.";
const TAINTED: &str = "0/2 nodes are available: 2 node(s) had untolerated taint.";
/// Longer than any outcome below, so only the deadline test can reach it.
const LONG_WAIT: Duration = Duration::from_secs(600);

#[tokio::test(start_paused = true)]
async fn a_full_cluster_ends_the_wait_soon_after_the_grace() {
    let client = scheduling_client(None, |_| Some(FULL));
    let started = tokio::time::Instant::now();
    let error = client.wait_for_ready(ENV, LONG_WAIT).await.unwrap_err();
    assert_eq!(error.downcast_ref::<NoCapacity>().unwrap().0, FULL);
    let waited = started.elapsed();
    assert!(
        (NO_CAPACITY_GRACE..NO_CAPACITY_GRACE + Duration::from_secs(15)).contains(&waited),
        "{waited:?}"
    );
}

/// No key is recorded, as for a Pod that never started.
struct NoHostKey;

#[async_trait::async_trait]
impl crate::sandbox::host_keys::HostKeyStore for NoHostKey {
    async fn current_host_key(&self, _: &str) -> Result<Option<(i64, String)>, sqlx::Error> {
        Ok(None)
    }
}

/// A cold create waits here rather than on the Claim.
#[tokio::test(start_paused = true)]
async fn a_full_cluster_ends_the_access_wait_too() {
    let client = scheduling_client(None, |_| Some(FULL));
    let started = tokio::time::Instant::now();
    let error = client
        .prove_workspace_access(ENV, LONG_WAIT, &NoHostKey)
        .await
        .unwrap_err();
    assert_eq!(error.downcast_ref::<NoCapacity>().unwrap().0, FULL);
    assert!(started.elapsed() < NO_CAPACITY_GRACE + Duration::from_secs(15));
}

#[tokio::test(start_paused = true)]
async fn room_freed_during_the_grace_restarts_it() {
    let client = scheduling_client(None, |now| {
        let free = (Duration::from_secs(40)..Duration::from_secs(50)).contains(&now);
        (!free).then_some(FULL)
    });
    let started = tokio::time::Instant::now();
    let error = client.wait_for_ready(ENV, LONG_WAIT).await.unwrap_err();
    assert!(error.downcast_ref::<NoCapacity>().is_some(), "{error:#}");
    assert!(
        started.elapsed() >= Duration::from_secs(50) + NO_CAPACITY_GRACE,
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn a_pod_placed_during_the_grace_is_ready() {
    let client = scheduling_client(Some(Duration::from_secs(30)), |_| Some(FULL));
    client.wait_for_ready(ENV, LONG_WAIT).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_refusal_that_is_not_for_a_resource_waits_for_the_deadline() {
    let client = scheduling_client(None, |_| Some(TAINTED));
    let started = tokio::time::Instant::now();
    let timeout = NO_CAPACITY_GRACE * 2;
    let error = client.wait_for_ready(ENV, timeout).await.unwrap_err();
    assert!(error.downcast_ref::<NoCapacity>().is_none(), "{error:#}");
    assert!(error.to_string().contains("timeout waiting"), "{error:#}");
    assert!(started.elapsed() >= timeout);
}

fn workspace_pod(uid: &str, resource_version: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": claim_name(ENV),
            "namespace": NS,
            "uid": uid,
            "resourceVersion": resource_version,
        },
        "status": { "phase": "Pending" },
    })
}

const POD_UID: &str = "5f0f9a52-8d3c-4b7e-9a61-0c2d4e6f8a10";

fn observed_pod() -> Pod {
    serde_json::from_value(workspace_pod(POD_UID, "30")).unwrap()
}

#[tokio::test]
async fn early_bind_rereads_the_chain_once_the_pod_changes() {
    let not_found = json!({
        "apiVersion": "v1", "kind": "Status", "status": "Failure",
        "reason": "NotFound", "code": 404,
    })
    .to_string();
    for (changed, reads) in [
        // Unchanged, then a new revision: its status landed.
        (
            (StatusCode::OK, workspace_pod(POD_UID, "31").to_string()),
            2,
        ),
        // A replacement Pod under the same name.
        (
            (
                StatusCode::OK,
                workspace_pod("6a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", "30").to_string(),
            ),
            2,
        ),
        // The Pod is gone.
        ((StatusCode::NOT_FOUND, not_found.clone()), 2),
    ] {
        let (client, requests) = raw_client(vec![
            (StatusCode::OK, workspace_pod(POD_UID, "30").to_string()),
            changed,
        ]);
        // The fallback outlasts the test, so only the change can end it.
        tokio::time::timeout(
            Duration::from_secs(5),
            client.wait_for_workspace_pod_revision(
                &observed_pod(),
                Duration::from_millis(10),
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("the Pod's change ends the wait");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), reads, "{requests:#?}");
        for request in requests.iter() {
            assert_eq!(
                request,
                &format!("GET /api/v1/namespaces/{NS}/pods/{}", claim_name(ENV))
            );
        }
    }
}

#[tokio::test]
async fn early_bind_waits_out_the_fallback_while_the_pod_is_unchanged_or_unreadable() {
    let forbidden = json!({
        "apiVersion": "v1", "kind": "Status", "status": "Failure",
        "reason": "Forbidden", "code": 403,
    });
    let unchanged = workspace_pod(POD_UID, "30").to_string();
    let (client, requests) = raw_client(vec![
        (StatusCode::OK, unchanged.clone()),
        // A failed read is not a change, so it never speeds up the full reads.
        (StatusCode::FORBIDDEN, forbidden.to_string()),
        (StatusCode::OK, unchanged.clone()),
        (StatusCode::OK, unchanged.clone()),
        (StatusCode::OK, unchanged),
    ]);
    let fallback = Duration::from_millis(300);
    let started = std::time::Instant::now();
    client
        .wait_for_workspace_pod_revision(&observed_pod(), Duration::from_millis(100), fallback)
        .await;
    assert!(started.elapsed() >= fallback);
    // Reads at about 100 and 200 ms; the next would land on the deadline.
    // A slow read only leaves fewer.
    let reads = requests.lock().unwrap().len();
    assert!((1..=2).contains(&reads), "{reads} reads");
}

#[tokio::test]
async fn early_bind_waits_out_the_fallback_for_a_pod_without_a_revision() {
    let (client, requests) = raw_client(Vec::new());
    let mut pod = observed_pod();
    pod.metadata.resource_version = None;
    let fallback = Duration::from_millis(100);
    let started = std::time::Instant::now();
    client
        .wait_for_workspace_pod_revision(&pod, Duration::from_millis(10), fallback)
        .await;
    assert!(started.elapsed() >= fallback);
    assert!(requests.lock().unwrap().is_empty());
}
