//! The warm-pool reconciler's configuration and one reconcile pass against a
//! recorded Kubernetes API (Program #2238 C2).

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};

use super::*;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_CONFIDENTIAL,
};
use crate::worker::create::WorkspaceIdentityMode;

const NAMESPACE: &str = "dev-sandboxes";
const API: &str = "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes";

fn dev_cfg(shapes: &str) -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        sandbox_namespace: NAMESPACE.into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NAMESPACE)),
        gateway_image: "registry.example.invalid/codewire/gateway@sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
        dind_image: "docker.io/library/docker:29.7.1-dind@sha256:3333333333333333333333333333333333333333333333333333333333333333".into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        docker_mode: DOCKER_MODE_PROFILE_DEFAULT.into(),
        workspace_storage_class: "linstor-local".into(),
        network_policy_management: "Managed".into(),
        kata_agent_policy_enabled: true,
        api_base_url: "https://codewire-dev.sh".into(),
        coordinator_url: "http://codewire-coordinator.dev.svc.cluster.local:8090".into(),
        pod_namespace: "dev".into(),
        workspace_identity_mode: WorkspaceIdentityMode::Binding,
        warm_pool_shapes: shapes.into(),
        ..Default::default()
    }
}

#[test]
fn no_configured_shape_keeps_the_reconciler_inert() {
    for unset in ["", "   ", "\n"] {
        for cache in [true, false] {
            assert_eq!(
                WarmPoolConfig::from_cfg(&dev_cfg(unset), cache).unwrap(),
                None,
                "{unset:?} configures no pool"
            );
        }
    }
    // The default configuration carries no shape.
    assert!(SandboxWorkerCfg::default().warm_pool_shapes.is_empty());
    assert_eq!(
        WarmPoolConfig::from_cfg(&SandboxWorkerCfg::default(), true).unwrap(),
        None
    );
}

#[test]
fn configured_shapes_render_through_the_identity_free_pool_renderer() {
    let config =
        WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=1"), true)
            .unwrap()
            .unwrap();
    assert_eq!(config.namespace, NAMESPACE);
    assert_eq!(config.pools.len(), 2);
    assert!(
        config.pools[0]
            .objects
            .name
            .starts_with("cw-pool-1000m-4096mi-10gi-")
    );
    assert_eq!(config.pools[1].configured.members, 1);
    assert_eq!(config.pools[1].objects.pool["spec"]["replicas"], 1);
    assert_eq!(config.runtime_class(), Some("commodity"));

    // Every renderer refusal refuses the whole configuration.
    assert!(WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi"), true).is_err());
    let mut rollback = dev_cfg("1000m/4096Mi/10Gi=1");
    rollback.workspace_identity_mode = WorkspaceIdentityMode::EnvironmentToken;
    assert!(WarmPoolConfig::from_cfg(&rollback, true).is_err());
    let mut confidential = dev_cfg("1000m/4096Mi/10Gi=1");
    confidential.runtime_profile = RUNTIME_PROFILE_CONFIDENTIAL.into();
    assert!(WarmPoolConfig::from_cfg(&confidential, true).is_err());
    let mut unpinned = dev_cfg("1000m/4096Mi/10Gi=1");
    unpinned.gateway_image = "registry.example.invalid/codewire/gateway:main".into();
    assert!(WarmPoolConfig::from_cfg(&unpinned, true).is_err());
    let mut no_namespace = dev_cfg("1000m/4096Mi/10Gi=1");
    no_namespace.sandbox_namespace.clear();
    assert!(WarmPoolConfig::from_cfg(&no_namespace, true).is_err());
}

/// A recorded API: canned lists, a mutable set of pool objects, and every
/// request in order.
#[derive(Default)]
struct Cluster {
    templates: Vec<Value>,
    pools: Vec<Value>,
    daemon_set: Option<Value>,
    requests: Vec<(Method, String)>,
    writes: Vec<(Method, String, Value)>,
}

fn list(kind: &str, items: &[Value]) -> Value {
    json!({ "apiVersion": "v1", "kind": format!("{kind}List"), "metadata": {}, "items": items })
}

fn not_found() -> Value {
    json!({ "kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404 })
}

fn runtime_node() -> Value {
    json!({
        "apiVersion": "v1", "kind": "Node",
        "metadata": { "name": "runtime-1", "labels": { "katacontainers.io/kata-runtime": "true" } },
        "spec": {},
        "status": {
            "allocatable": { "cpu": "32", "memory": "128Gi" },
            "conditions": [{ "type": "Ready", "status": "True" }],
        },
    })
}

fn api(cluster: Arc<Mutex<Cluster>>) -> kube::Client {
    let service = Router::new().fallback(move |request: Request<Body>| {
        let cluster = Arc::clone(&cluster);
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let query = request.uri().query().unwrap_or_default().to_owned();
            let bytes = axum::body::to_bytes(request.into_body(), 1 << 20).await.unwrap();
            let mut cluster = cluster.lock().unwrap();
            cluster
                .requests
                .push((method.clone(), format!("{path}?{query}")));
            let (status, body) = match (method.clone(), path.as_str()) {
                (Method::GET, path) if path == format!("{API}/sandboxtemplates") => {
                    (StatusCode::OK, list("SandboxTemplate", &cluster.templates))
                }
                (Method::GET, path) if path == format!("{API}/sandboxwarmpools") => {
                    (StatusCode::OK, list("SandboxWarmPool", &cluster.pools))
                }
                (Method::GET, "/apis/agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes/sandboxes") => {
                    (StatusCode::OK, list("Sandbox", &[]))
                }
                (Method::GET, "/api/v1/namespaces/dev-sandboxes/pods") => {
                    (StatusCode::OK, list("Pod", &[]))
                }
                (Method::GET, "/apis/apps/v1/namespaces/dev-sandboxes/daemonsets/cw-image-cache") => {
                    match cluster.daemon_set.clone() {
                        Some(daemon_set) => (StatusCode::OK, daemon_set),
                        None => (StatusCode::NOT_FOUND, not_found()),
                    }
                }
                (Method::GET, "/apis/node.k8s.io/v1/runtimeclasses/commodity") => (
                    StatusCode::OK,
                    json!({
                        "apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
                        "metadata": { "name": "commodity" }, "handler": "kata-clh",
                        "overhead": { "podFixed": { "cpu": "250m", "memory": "130Mi" } },
                        "scheduling": { "nodeSelector": { "katacontainers.io/kata-runtime": "true" } },
                    }),
                ),
                (Method::GET, "/api/v1/nodes") => (StatusCode::OK, list("Node", &[runtime_node()])),
                (Method::POST, path) => {
                    let mut body: Value = serde_json::from_slice(&bytes).unwrap();
                    body["metadata"]["uid"] = json!(format!("uid-{}", cluster.writes.len()));
                    body["metadata"]["resourceVersion"] = json!("1");
                    cluster.writes.push((method.clone(), path.to_owned(), body.clone()));
                    if path.ends_with("/sandboxtemplates") {
                        cluster.templates.push(body.clone());
                    } else if path.ends_with("/sandboxwarmpools") {
                        cluster.pools.push(body.clone());
                    }
                    (StatusCode::CREATED, body)
                }
                (method, path) => panic!("unexpected request {method} {path}"),
            };
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    });
    kube::Client::new(service, "default")
}

#[tokio::test]
async fn a_pass_creates_the_template_then_the_pool_under_the_node_cap() {
    let cluster = Arc::new(Mutex::new(Cluster::default()));
    let client = api(Arc::clone(&cluster));
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), false)
        .unwrap()
        .unwrap();
    let mut state = LoopState::default();

    let result = reconcile_once(&client, &config, &mut state).await.unwrap();
    assert_eq!(result, PassResult::Wrote);
    {
        let cluster = cluster.lock().unwrap();
        assert_eq!(cluster.writes.len(), 1);
        let (_, path, body) = &cluster.writes[0];
        assert_eq!(path, &format!("{API}/sandboxtemplates"));
        assert_eq!(body["spec"], config.pools[0].objects.template["spec"]);
        let queries: Vec<&str> = cluster
            .requests
            .iter()
            .map(|(_, query)| query.as_str())
            .collect();
        for expected in [
            "sandboxtemplates?&labelSelector=app.kubernetes.io%2Fmanaged-by%3Dcodewire%2Ccodewire.sh%2Ftype%3Dworkspace-pool",
            "sandboxes?&labelSelector=agents.x-k8s.io%2Fwarm-pool-sandbox",
            "sandboxes?&labelSelector=agents.x-k8s.io%2Flaunch-type%3Dwarm",
            "/api/v1/nodes?&labelSelector=katacontainers.io%2Fkata-runtime%3Dtrue",
        ] {
            assert!(
                queries.iter().any(|query| query.ends_with(expected)),
                "missing request {expected}: {queries:?}"
            );
        }
        assert!(
            !queries.iter().any(|query| query.contains("daemonsets")),
            "a disabled image cache is warm without a read"
        );
        assert!(
            !queries.iter().any(|query| query.contains("sandboxclaims")),
            "claims are read only to remove an unconfigured pool"
        );
    }

    // The template is live: the pool follows at the configured count, which
    // fits a quarter of a 32-CPU node.
    let result = reconcile_once(&client, &config, &mut state).await.unwrap();
    assert_eq!(result, PassResult::Wrote);
    let cluster = cluster.lock().unwrap();
    assert_eq!(cluster.writes.len(), 2);
    let (_, path, body) = &cluster.writes[1];
    assert_eq!(path, &format!("{API}/sandboxwarmpools"));
    assert_eq!(body["spec"]["replicas"], 2);
    assert_eq!(body["spec"]["updateStrategy"]["type"], "Recreate");
}

#[tokio::test]
async fn an_enabled_image_cache_without_its_daemon_set_writes_nothing() {
    let cluster = Arc::new(Mutex::new(Cluster::default()));
    let client = api(Arc::clone(&cluster));
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), true)
        .unwrap()
        .unwrap();
    let mut state = LoopState::default();
    let result = reconcile_once(&client, &config, &mut state).await.unwrap();
    assert_eq!(result, PassResult::Unchanged);
    let cluster = cluster.lock().unwrap();
    assert!(cluster.writes.is_empty());
    assert!(
        cluster
            .requests
            .iter()
            .all(|(method, _)| method == Method::GET),
        "a cold cache only reads"
    );
}
