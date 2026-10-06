use super::*;
use crate::sandbox::template::CredentialRuntimeTemplateConfig;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, Response, StatusCode},
};
use serde_json::json;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const NS: &str = "dev-sandboxes";
type Recorded = Arc<Mutex<Vec<(Method, String, Value)>>>;

fn opts() -> TemplateOpts {
    TemplateOpts {
        environment_id: "be31063a-8ec8-46d5-aa17-75cda1729370".into(),
        organization_id: "synthetic-org".into(),
        operation_generation: 7,
        name: "synthetic-template".into(),
        runtime_profile: "commodity".into(),
        gateway_token: "synthetic-coordinate".into(),
        daemon_auth_token: "synthetic-daemon".into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NS)),
        managed_credential_clients: codewire_access::ManagedCredentialClients::from_profile_slots(
            ["codex"],
        )
        .unwrap(),
        projection_selection_sha256: Some([0xab; 32]),
        ..Default::default()
    }
}

fn client(responses: Vec<(StatusCode, Value)>) -> (SandboxClient, Recorded) {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let requests = recorded.clone();
    let queued = Arc::new(Mutex::new(VecDeque::from(responses)));
    let service = Router::new().fallback(move |request: Request<Body>| {
        let requests = requests.clone();
        let queued = queued.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            requests.lock().unwrap().push((method, path, body));
            let (status, body) = queued
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected Kubernetes request");
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    });
    (
        SandboxClient::new(Client::new(service, "default"), NS),
        recorded,
    )
}

fn missing() -> (StatusCode, Value) {
    (
        StatusCode::NOT_FOUND,
        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
    )
}

/// A gateway Certificate as the previous orchestration created it; an
/// environment created before the gateway's HTTPS listener was removed
/// still owns one.
fn legacy_certificate(opts: &TemplateOpts) -> Value {
    json!({"apiVersion":"cert-manager.io/v1", "kind":"Certificate",
        "metadata":{"name":credential_gateway_certificate_name(&opts.environment_id),
            "namespace":NS, "uid":"synthetic-certificate-uid", "resourceVersion":"10",
            "generation":2,
            "labels":{"app.kubernetes.io/name":"codewire", "app.kubernetes.io/managed-by":"codewire",
                "codewire.sh/environment-id":opts.environment_id,
                "codewire.sh/org-id":opts.organization_id,
                "codewire.sh/type":"credential-bootstrap"}},
        "spec":{"secretName":credential_gateway_certificate_name(&opts.environment_id)},
        "status":{"conditions":[{"type":"Ready","status":"True","observedGeneration":2}]}})
}

fn gateway(opts: &TemplateOpts) -> Value {
    let mut value = render_gateway_deployment(NS, opts);
    value["metadata"]["generation"] = 3.into();
    value["status"] = json!({"observedGeneration":3,"replicas":1,"updatedReplicas":1,"availableReplicas":1,"readyReplicas":1});
    value
}

#[tokio::test]
async fn disabled_credential_bootstrap_does_not_call_kubernetes() {
    let (client, requests) = client(vec![]);
    let opts = TemplateOpts::default();
    client
        .wait_for_credential_gateway_ready(&opts, Duration::ZERO)
        .await
        .unwrap();
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn workspace_template_creates_no_credential_bootstrap_object() {
    // Codex is selected, yet nothing but the template is written: the
    // workspace daemon writes Codex's `~/.codex`, and the gateway has no
    // workspace-facing TLS identity.
    let opts = opts();
    let template = render_sandbox_template(NS, &opts);
    let (client, requests) = client(vec![missing(), (StatusCode::CREATED, template)]);
    client.ensure_sandbox_template(&opts).await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.0.clone())
            .collect::<Vec<_>>(),
        [Method::GET, Method::POST]
    );
    assert!(
        requests
            .iter()
            .all(|request| request.1.ends_with("/sandboxtemplates")
                || request.1.ends_with("/sandboxtemplates/synthetic-template"))
    );
}

#[test]
fn readiness_rejects_old_gateway_rollout() {
    let opts = opts();
    let gateway: DynamicObject = serde_json::from_value(gateway(&opts)).unwrap();
    assert!(gateway_ready(&gateway, &opts));
    for field in [
        "observedGeneration",
        "replicas",
        "updatedReplicas",
        "availableReplicas",
        "readyReplicas",
    ] {
        let mut changed = gateway.clone();
        changed.data["status"][field] = 0.into();
        assert!(!gateway_ready(&changed, &opts), "stale {field}");
    }
    let mut next = opts.clone();
    next.operation_generation += 1;
    assert!(!gateway_ready(&gateway, &next));
}

#[tokio::test]
async fn credential_readiness_observes_only_the_gateway_rollout() {
    let opts = opts();
    let (client, requests) = client(vec![(StatusCode::OK, gateway(&opts))]);
    client
        .wait_for_credential_gateway_ready(&opts, Duration::from_secs(1))
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, Method::GET);
    assert!(requests[0].1.ends_with(&format!(
        "/deployments/{}",
        gateway_workload_name(&opts.environment_id)
    )));
}

#[tokio::test]
async fn bootstrap_cleanup_uses_uid_fence_and_never_reads_secret_material() {
    let opts = opts();
    let success = (
        StatusCode::OK,
        json!({"apiVersion":"v1","kind":"Status","status":"Success","code":200}),
    );
    let mut terminating = legacy_certificate(&opts);
    terminating["metadata"]["deletionTimestamp"] = "2026-09-06T00:00:00Z".into();
    let (client, requests) = client(vec![
        (StatusCode::OK, legacy_certificate(&opts)),
        success.clone(),
        (StatusCode::OK, terminating),
        success,
        missing(),
        missing(),
        missing(),
    ]);
    client
        .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(2))
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[1].0, Method::DELETE);
    assert_eq!(
        requests[1].2["preconditions"]["uid"],
        "synthetic-certificate-uid"
    );
    assert_eq!(requests[1].2["propagationPolicy"], "Background");
    assert_eq!(
        requests[3].2["preconditions"]["uid"],
        "synthetic-certificate-uid"
    );
    assert_eq!(requests[3].2["propagationPolicy"], "Background");
    assert!(
        requests[..5]
            .iter()
            .all(|request| !request.1.contains("/secrets/"))
    );
    assert!(requests[5].1.contains("/secrets/cw-credential-gateway-"));
    assert_eq!(requests[5].0, Method::DELETE);
    assert!(
        requests
            .iter()
            .filter(|request| request.1.contains("/secrets/"))
            .all(|request| request.0 == Method::DELETE)
    );
}

#[tokio::test]
async fn foreign_bootstrap_collision_is_not_deleted_during_compensation() {
    let opts = opts();
    let mut foreign = legacy_certificate(&opts);
    foreign["metadata"]["labels"][LABEL_ENV_ID] = "foreign-environment".into();
    let (client, requests) = client(vec![(StatusCode::OK, foreign)]);
    assert!(
        client
            .delete_credential_bootstrap(&opts.environment_id, Duration::from_secs(1))
            .await
            .unwrap_err()
            .to_string()
            .contains("foreign")
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(requests.lock().unwrap()[0].0, Method::GET);
}

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

fn rolling_gateway(opts: &TemplateOpts) -> Value {
    let mut value = gateway(opts);
    value["metadata"]["resourceVersion"] = "20".into();
    value["status"]["availableReplicas"] = 0.into();
    value["status"]["readyReplicas"] = 0.into();
    value
}

#[tokio::test]
async fn gateway_readiness_wakes_on_the_deployment_watch() {
    let opts = opts();
    let ready = gateway(&opts);
    let event = json!({"type": "MODIFIED", "object": ready}).to_string() + "\n";
    let (client, requests) = raw_client(vec![
        (StatusCode::OK, rolling_gateway(&opts).to_string()),
        (StatusCode::OK, event),
        (StatusCode::OK, ready.to_string()),
    ]);
    // The fallback poll outlasts the wait, so only the watch event can end it.
    client
        .wait_for_credential_gateway_ready_with_fallback(
            &opts,
            Duration::from_secs(5),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3, "{requests:#?}");
    let watch = &requests[1];
    let gateway_name = gateway_workload_name(&opts.environment_id);
    assert!(
        watch.starts_with(&format!("GET /apis/apps/v1/namespaces/{NS}/deployments?")),
        "{watch}"
    );
    for part in [
        "watch=true",
        &format!("fieldSelector=metadata.name%3D{gateway_name}"),
        "resourceVersion=20",
    ] {
        assert!(watch.contains(part), "{watch} lacks {part}");
    }
    assert!(requests.iter().all(|request| !request.contains("/secrets")));
}

#[tokio::test]
async fn gateway_readiness_polls_when_the_watch_is_refused() {
    let opts = opts();
    let forbidden = json!({
        "apiVersion": "v1", "kind": "Status", "status": "Failure",
        "reason": "Forbidden", "code": 403,
    });
    let (client, requests) = raw_client(vec![
        (StatusCode::OK, rolling_gateway(&opts).to_string()),
        (StatusCode::FORBIDDEN, forbidden.to_string()),
        (StatusCode::OK, gateway(&opts).to_string()),
    ]);
    let fallback = Duration::from_millis(200);
    let started = std::time::Instant::now();
    client
        .wait_for_credential_gateway_ready_with_fallback(&opts, Duration::from_secs(5), fallback)
        .await
        .unwrap();
    assert!(
        started.elapsed() >= fallback,
        "a refused watch must wait out the fallback instead of re-reading at once"
    );
    assert_eq!(requests.lock().unwrap().len(), 3);
}
