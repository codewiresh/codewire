//! #2705: a Resume's predecessor must be proven gone in Kubernetes. Synthetic
//! Kubernetes answers only; no cluster is contacted.

use super::*;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use codewire_server_core::AppError;
use serde_json::json;
use std::sync::{Arc, Mutex};

const NAMESPACE: &str = "runtime-sandboxes";
const POD_NAME: &str = "sandbox-fixture";
const POD_UID: &str = "00000000-0000-4000-8000-0000000000a1";

fn predecessor() -> ResumePredecessor {
    ResumePredecessor {
        pod_uid: POD_UID.into(),
        namespace: NAMESPACE.into(),
        pod_name: POD_NAME.into(),
        generation: 1,
        agent: ManagedAgent::Codex,
    }
}

/// Answers a GET of the predecessor's Pod with `answer` and records paths.
fn kube(answer: (StatusCode, serde_json::Value)) -> (kube::Client, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = seen.clone();
    let service = axum::Router::new().fallback(move |request: Request<Body>| {
        let (answer, recorded) = (answer.clone(), recorded.clone());
        async move {
            recorded
                .lock()
                .unwrap()
                .push(format!("{} {}", request.method(), request.uri().path()));
            Response::builder()
                .status(answer.0)
                .header("content-type", "application/json")
                .body(Body::from(answer.1.to_string()))
                .unwrap()
        }
    });
    (kube::Client::new(service, "default"), seen)
}

fn pod(uid: &str, terminating: bool) -> serde_json::Value {
    let mut metadata = json!({"name": POD_NAME, "namespace": NAMESPACE, "uid": uid});
    if terminating {
        metadata["deletionTimestamp"] = json!("2026-10-14T00:00:00Z");
    }
    json!({"apiVersion": "v1", "kind": "Pod", "metadata": metadata})
}

fn refused_as_stopping(result: AppResult<()>) {
    match result {
        Err(AppError::Coded { code, detail, .. }) => {
            assert_eq!(code, "platform_agent_resume_refused");
            assert!(detail.contains("still stopping"), "{detail}");
        }
        other => panic!("expected the still-stopping refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn resume_requires_the_predecessor_pod_proven_gone() {
    // Gone: no such Pod, or another Pod under its name.
    let not_found = json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
        "reason": "NotFound", "code": 404});
    for answer in [
        (StatusCode::NOT_FOUND, not_found),
        (
            StatusCode::OK,
            pod("00000000-0000-4000-8000-0000000000b2", false),
        ),
    ] {
        let (client, seen) = kube(answer);
        require_predecessor_absent(Some(&client), &predecessor())
            .await
            .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [format!(
                "GET /api/v1/namespaces/{NAMESPACE}/pods/{POD_NAME}"
            )]
        );
    }
    // Still there, terminating or not: the Resume waits for it.
    for terminating in [false, true] {
        let (client, _) = kube((StatusCode::OK, pod(POD_UID, terminating)));
        refused_as_stopping(require_predecessor_absent(Some(&client), &predecessor()).await);
    }
}

#[tokio::test]
async fn resume_refuses_as_unavailable_when_absence_cannot_be_read() {
    let unavailable_error = |result: AppResult<()>| match result {
        Err(AppError::Upstream(_)) => {}
        other => panic!("expected unavailable, got {other:?}"),
    };
    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::FORBIDDEN,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (client, _) = kube((
            status,
            json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                   "code": status.as_u16()}),
        ));
        unavailable_error(require_predecessor_absent(Some(&client), &predecessor()).await);
    }
    // No Kubernetes client: nothing is proven.
    unavailable_error(require_predecessor_absent(None, &predecessor()).await);
}
