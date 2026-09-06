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

fn certificate(opts: &TemplateOpts) -> Value {
    let mut value = render_credential_gateway_certificate(NS, opts).unwrap();
    value["metadata"]["uid"] = "synthetic-certificate-uid".into();
    value["metadata"]["resourceVersion"] = "10".into();
    value["metadata"]["generation"] = 2.into();
    value["status"] =
        json!({"conditions":[{"type":"Ready","status":"True","observedGeneration":2}]});
    value
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
    client.ensure_credential_bootstrap(&opts).await.unwrap();
    client
        .wait_for_credential_gateway_ready(&opts, Duration::ZERO)
        .await
        .unwrap();
    assert!(requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn public_bootstrap_is_created_before_workspace_template_without_secret_access() {
    let opts = opts();
    let certificate = certificate(&opts);
    let config = render_credential_codex_config(NS, &opts).unwrap();
    let template = render_sandbox_template(NS, &opts);
    let (client, requests) = client(vec![
        missing(),
        (StatusCode::CREATED, certificate),
        missing(),
        (StatusCode::CREATED, config),
        missing(),
        (StatusCode::CREATED, template),
    ]);
    client.ensure_sandbox_template(&opts).await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.0.clone())
            .collect::<Vec<_>>(),
        [
            Method::GET,
            Method::POST,
            Method::GET,
            Method::POST,
            Method::GET,
            Method::POST
        ]
    );
    assert!(requests[1].1.ends_with("/certificates"));
    assert!(requests[3].1.ends_with("/configmaps"));
    assert!(requests[5].1.ends_with("/sandboxtemplates"));
    assert!(
        requests
            .iter()
            .all(|request| !request.1.contains("/secrets"))
    );
}

#[tokio::test]
async fn unchanged_bootstrap_is_read_only_and_foreign_collision_is_not_adopted() {
    let opts = opts();
    let certificate = certificate(&opts);
    let config = render_credential_codex_config(NS, &opts).unwrap();
    let (client, requests) = client(vec![
        (StatusCode::OK, certificate.clone()),
        (StatusCode::OK, config),
    ]);
    client.ensure_credential_bootstrap(&opts).await.unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.0 == Method::GET)
    );
    let mut foreign = certificate;
    foreign["metadata"]["labels"][LABEL_ENV_ID] = "foreign-environment".into();
    let (client, requests) = self::client(vec![(StatusCode::OK, foreign)]);
    assert!(
        client
            .ensure_credential_bootstrap(&opts)
            .await
            .unwrap_err()
            .to_string()
            .contains("ownership")
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn extra_certificate_authority_is_removed_and_never_accepted_as_ready() {
    let opts = opts();
    let mut changed = certificate(&opts);
    changed["spec"]["uris"] = json!(["spiffe://foreign.example.invalid/"]);
    let config = render_credential_codex_config(NS, &opts).unwrap();
    let (client, requests) = client(vec![
        (StatusCode::OK, changed.clone()),
        (StatusCode::OK, certificate(&opts)),
        (StatusCode::OK, config),
    ]);
    client.ensure_credential_bootstrap(&opts).await.unwrap();
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests[1].0, Method::PUT);
        assert!(requests[1].2["spec"].get("uris").is_none());
        assert_eq!(requests[1].2["metadata"]["resourceVersion"], "10");
    }
    let (client, requests) = self::client(vec![(StatusCode::OK, changed)]);
    assert!(
        client
            .wait_for_credential_gateway_ready(&opts, Duration::from_secs(1))
            .await
            .unwrap_err()
            .to_string()
            .contains("intent changed")
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn readiness_rejects_stale_certificate_generation_and_old_gateway_rollout() {
    let opts = opts();
    let mut cert: DynamicObject = serde_json::from_value(certificate(&opts)).unwrap();
    assert!(certificate_ready(&cert));
    cert.data["status"]["conditions"][0]["observedGeneration"] = 1.into();
    assert!(!certificate_ready(&cert));
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
async fn credential_readiness_observes_current_public_objects_only() {
    let opts = opts();
    let (client, requests) = client(vec![
        (StatusCode::OK, certificate(&opts)),
        (StatusCode::OK, gateway(&opts)),
    ]);
    client
        .wait_for_credential_gateway_ready(&opts, Duration::from_secs(1))
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.0 == Method::GET && !request.1.contains("/secrets"))
    );
}

#[tokio::test]
async fn bootstrap_cleanup_uses_uid_fence_and_never_reads_secret_material() {
    let opts = opts();
    let success = (
        StatusCode::OK,
        json!({"apiVersion":"v1","kind":"Status","status":"Success","code":200}),
    );
    let mut terminating = certificate(&opts);
    terminating["metadata"]["deletionTimestamp"] = "2026-09-06T00:00:00Z".into();
    let (client, requests) = client(vec![
        (StatusCode::OK, certificate(&opts)),
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
    let mut foreign = certificate(&opts);
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
