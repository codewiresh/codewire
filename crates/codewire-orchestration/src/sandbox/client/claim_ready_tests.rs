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
