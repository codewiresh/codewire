//! One pass over the warm pools against a recorded Kubernetes API, and which
//! shapes a release rotates (Program #2238 C2, #3572).

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};

use super::*;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
};
use crate::worker::create::SandboxWorkerCfg;
use crate::worker::warm_pool::WarmPoolConfig;

/// The configuration's wanted pools as a driver configured as Dev renders
/// them.
fn rendered(config: &WarmPoolConfig) -> RenderedPools {
    rendered_with(&dev_cfg(""), config)
}

/// The wanted pools as a driver with `cfg`'s rendering renders them.
fn rendered_with(cfg: &SandboxWorkerCfg, config: &WarmPoolConfig) -> RenderedPools {
    render(&cfg.into(), NAMESPACE, &config.wanted).unwrap()
}

const NAMESPACE: &str = "dev-sandboxes";
const API: &str = "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/dev-sandboxes";

fn dev_cfg(shapes: &str) -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        sandbox_namespace: NAMESPACE.into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic(NAMESPACE)),
        daemon_image: "registry.example.invalid/codewire/daemon@sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
        dind_image: "docker.io/library/docker:29.7.1-dind@sha256:3333333333333333333333333333333333333333333333333333333333333333".into(),
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        docker_mode: DOCKER_MODE_PROFILE_DEFAULT.into(),
        workspace_storage_class: "linstor-local".into(),
        network_policy_management: "Managed".into(),
        kata_agent_policy_enabled: true,
        api_base_url: "https://codewire-dev.sh".into(),
        coordinator_url: "http://codewire-coordinator.dev.svc.cluster.local:8090".into(),
        pod_namespace: "dev".into(),
        warm_pool_shapes: shapes.into(),
        ..Default::default()
    }
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

/// An environment's zero-replica shadow whose status a C0 controller wrote.
fn reconciled_shadow() -> Value {
    json!({
        "apiVersion": "extensions.agents.x-k8s.io/v1beta1", "kind": "SandboxWarmPool",
        "metadata": { "name": "shadow-pool-workspace-env", "namespace": NAMESPACE,
            "uid": "shadow-uid", "generation": 1,
            "labels": { "codewire.sh/type": "sandbox-claim-shadow" } },
        "spec": { "replicas": 0, "sandboxTemplateRef": { "name": "workspace-env" } },
        "status": { "replicas": 0, "readyReplicas": 0, "observedGeneration": 1 },
    })
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
    let cluster = Arc::new(Mutex::new(Cluster {
        pools: vec![reconciled_shadow()],
        ..Cluster::default()
    }));
    let client = api(Arc::clone(&cluster));
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), false)
        .unwrap()
        .unwrap();
    let mut state = LoopState::default();

    let result = reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
        .await
        .unwrap();
    assert_eq!(result, PoolPass::Wrote);
    {
        let cluster = cluster.lock().unwrap();
        assert_eq!(cluster.writes.len(), 1);
        let (_, path, body) = &cluster.writes[0];
        assert!(!path.ends_with("/sandboxwarmpools"));
        assert_eq!(path, &format!("{API}/sandboxtemplates"));
        assert_eq!(
            body["spec"],
            rendered(&config).pools[0].objects.template["spec"]
        );
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
    let result = reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
        .await
        .unwrap();
    assert_eq!(result, PoolPass::Wrote);
    let cluster = cluster.lock().unwrap();
    assert_eq!(cluster.writes.len(), 2);
    let (_, path, body) = &cluster.writes[1];
    assert_eq!(path, &format!("{API}/sandboxwarmpools"));
    assert_eq!(body["spec"]["replicas"], 2);
    assert_eq!(body["spec"]["updateStrategy"]["type"], "Recreate");
}

#[tokio::test]
async fn the_configured_percentage_controls_how_many_members_the_reconciler_creates() {
    // Each member reserves just over 17 GiB including DinD and VM overhead.
    // A 128 GiB node admits one under 25%, and all three under 50%.
    for (percent, expected) in [("", 1), ("50", 3)] {
        let cluster = Arc::new(Mutex::new(Cluster {
            pools: vec![reconciled_shadow()],
            ..Cluster::default()
        }));
        let client = api(Arc::clone(&cluster));
        let mut cfg = dev_cfg("2000m/16384Mi/80Gi=3");
        cfg.warm_pool_max_node_percent = percent.into();
        let config = WarmPoolConfig::from_cfg(&cfg, false).unwrap().unwrap();
        let mut state = LoopState::default();
        for _ in 0..2 {
            assert_eq!(
                reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
                    .await
                    .unwrap(),
                PoolPass::Wrote
            );
        }
        let cluster = cluster.lock().unwrap();
        let (_, path, pool) = &cluster.writes[1];
        assert_eq!(path, &format!("{API}/sandboxwarmpools"));
        assert_eq!(pool["spec"]["replicas"], expected, "percentage {percent:?}");
    }
}

#[tokio::test]
async fn an_enabled_image_cache_without_its_daemon_set_writes_nothing() {
    let cluster = Arc::new(Mutex::new(Cluster {
        pools: vec![reconciled_shadow()],
        ..Cluster::default()
    }));
    let client = api(Arc::clone(&cluster));
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), true)
        .unwrap()
        .unwrap();
    let mut state = LoopState::default();
    let result = reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
        .await
        .unwrap();
    assert_eq!(result, PoolPass::Unchanged);
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

/// Review H1: on the pinned controller, which writes no pool
/// `status.observedGeneration`, a configured reconciler reads and holds: it
/// writes no template, pool or member.
#[tokio::test]
async fn pools_are_held_until_the_controller_shows_claim_safety() {
    let mut legacy_shadow = reconciled_shadow();
    legacy_shadow["status"] = json!({ "replicas": 0, "readyReplicas": 0 });
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), false)
        .unwrap()
        .unwrap();
    let mut empty_pool = rendered(&config).pools[0].objects.pool.clone();
    empty_pool["spec"]["replicas"] = json!(0);
    for pools in [vec![legacy_shadow], vec![empty_pool]] {
        let cluster = Arc::new(Mutex::new(Cluster {
            pools,
            ..Cluster::default()
        }));
        let client = api(Arc::clone(&cluster));
        let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), false)
            .unwrap()
            .unwrap();
        let mut state = LoopState::default();
        let result = reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
            .await
            .unwrap();
        assert_eq!(result, PoolPass::Held);
        let cluster = cluster.lock().unwrap();
        assert!(cluster.writes.is_empty());
        assert_eq!(
            cluster.requests.len(),
            1,
            "only the pool list is read: {:?}",
            cluster.requests
        );
    }
}

/// A cluster with no SandboxWarmPool at all has no pool on which a capable
/// controller could show itself, so the held reconciler bootstraps one: the
/// first pool's template, then that pool with zero members. Once a pool
/// exists it holds again, reading only the pool list, until the controller
/// observes it.
#[tokio::test]
async fn a_held_cluster_without_pools_bootstraps_one_empty_pool() {
    let cluster = Arc::new(Mutex::new(Cluster::default()));
    let client = api(Arc::clone(&cluster));
    let config =
        WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2"), false)
            .unwrap()
            .unwrap();
    let mut state = LoopState::default();

    for pass in 0..3 {
        let result = reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
            .await
            .unwrap();
        assert_eq!(result, PoolPass::Held, "pass {pass}");
    }
    let cluster = cluster.lock().unwrap();
    let writes: Vec<(&str, &Value)> = cluster
        .writes
        .iter()
        .map(|(_, path, body)| (path.as_str(), body))
        .collect();
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert_eq!(writes[0].0, format!("{API}/sandboxtemplates"));
    assert_eq!(
        writes[0].1["spec"],
        rendered(&config).pools[0].objects.template["spec"]
    );
    assert_eq!(writes[1].0, format!("{API}/sandboxwarmpools"));
    assert_eq!(
        writes[1].1["metadata"]["name"],
        rendered(&config).pools[0].objects.name
    );
    assert_eq!(writes[1].1["spec"]["replicas"], 0);
    // The third pass found the empty pool and only read the pool list.
    let (_, last) = cluster.requests.last().unwrap();
    assert!(
        last.ends_with("/sandboxwarmpools?"),
        "{:?}",
        cluster.requests
    );
}

/// An enabled image cache that is not warm keeps the bootstrap from creating
/// a template, as it keeps every template change.
#[tokio::test]
async fn a_cold_image_cache_blocks_the_bootstrap() {
    let cluster = Arc::new(Mutex::new(Cluster::default()));
    let client = api(Arc::clone(&cluster));
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), true)
        .unwrap()
        .unwrap();
    let mut state = LoopState::default();
    let result = reconcile_once(&client, NAMESPACE, &rendered(&config), &mut state)
        .await
        .unwrap();
    assert_eq!(result, PoolPass::Held);
    let cluster = cluster.lock().unwrap();
    assert!(cluster.writes.is_empty());
    assert!(
        cluster
            .requests
            .iter()
            .all(|(method, _)| method == Method::GET)
    );
}

/// #3572: a starting replica warms, and holds `/readyz` and its Temporal
/// worker for, only the shapes a release is rotating: its own pool is absent
/// beside another revision's of the same shape. A restart beside its own
/// pools, a fresh cluster and a newly configured shape are ready at once.
#[test]
fn only_a_rotating_shape_holds_readiness() {
    let shapes = "1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=2";
    let current = rendered(
        &WarmPoolConfig::from_cfg(&dev_cfg(shapes), true)
            .unwrap()
            .unwrap(),
    )
    .pools;
    let mut previous_cfg = dev_cfg(shapes);
    previous_cfg.daemon_image = "registry.example.invalid/codewire/daemon@sha256:4444444444444444444444444444444444444444444444444444444444444444".into();
    let previous = rendered_with(
        &previous_cfg,
        &WarmPoolConfig::from_cfg(&previous_cfg, true)
            .unwrap()
            .unwrap(),
    )
    .pools;
    let wanted: Vec<&DesiredPool> = current.iter().collect();
    let live = |pools: &[&DesiredPool]| -> BTreeMap<String, DynamicObject> {
        pools
            .iter()
            .map(|pool| {
                (
                    pool.objects.name.clone(),
                    serde_json::from_value(pool.objects.pool.clone()).unwrap(),
                )
            })
            .collect()
    };
    let rotating = |live: &BTreeMap<String, DynamicObject>| -> Vec<String> {
        rotating_shapes(&wanted, live)
            .into_iter()
            .map(|pool| pool.objects.name.clone())
            .collect()
    };

    // A fresh cluster, and a restart beside this revision's own pools.
    assert!(rotating(&BTreeMap::new()).is_empty());
    assert!(rotating(&live(&[&current[0], &current[1]])).is_empty());
    // A release: the outgoing revision's pools are live and these are not.
    assert_eq!(
        rotating(&live(&[&previous[0], &previous[1]])),
        [
            current[0].objects.name.clone(),
            current[1].objects.name.clone()
        ]
    );
    // Only the shape that rotates; a newly configured shape is the leader's.
    assert_eq!(
        rotating(&live(&[&previous[0], &current[1]])),
        [current[0].objects.name.clone()]
    );
    assert!(rotating(&live(&[&previous[1], &current[1]])).is_empty());
    // An unlabelled object of a pool's name is not a pool.
    let mut unlabelled = live(&[&previous[0]]);
    for object in unlabelled.values_mut() {
        object.metadata.labels = None;
    }
    assert!(rotating(&unlabelled).is_empty());
}

/// The driver remembers each placement's passes apart, and forgets them all
/// when told to.
#[tokio::test]
async fn the_driver_remembers_passes_by_placement_until_told_to_forget() {
    use crate::runtime::RuntimePools;
    use crate::runtime::kubernetes::KubernetesDriver;

    let cluster = Arc::new(Mutex::new(Cluster {
        pools: vec![reconciled_shadow()],
        ..Cluster::default()
    }));
    let driver = KubernetesDriver::new(api(Arc::clone(&cluster)), (&dev_cfg("")).into());
    let config = WarmPoolConfig::from_cfg(&dev_cfg("1000m/4096Mi/10Gi=2"), false)
        .unwrap()
        .unwrap();
    let placement = crate::runtime::Placement::new(NAMESPACE);
    assert_eq!(
        driver.keep_pools(&placement, &config.wanted).await.unwrap(),
        PoolPass::Wrote
    );
    {
        let memory = driver.pool_memory.lock().unwrap();
        assert_eq!(memory.keys().collect::<Vec<_>>(), [NAMESPACE]);
        assert_eq!(memory[NAMESPACE].capable, Some(true));
        assert!(memory[NAMESPACE].budget.is_some());
    }
    driver.forget_pool_memory();
    assert!(driver.pool_memory.lock().unwrap().is_empty());
}

/// Every pool metric a pass records keeps its name and labels (#3628).
#[test]
fn pool_metric_names_and_labels_are_unchanged() {
    use prometheus::core::Collector;

    let named = |collector: &dyn Collector| {
        let desc = collector.desc()[0];
        (desc.fq_name.clone(), desc.variable_labels.clone())
    };
    let expected = |name: &str, labels: &[&str]| {
        (
            name.to_string(),
            labels
                .iter()
                .map(|label| label.to_string())
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        named(members_metric()),
        expected("codewire_warm_pool_members", &["shape", "state"])
    );
    assert_eq!(
        named(template_current_metric()),
        expected("codewire_warm_pool_template_current", &["shape"])
    );
    assert_eq!(
        named(cache_warm_metric()),
        expected("codewire_warm_pool_image_cache_warm", &[])
    );
    assert_eq!(
        named(controller_ready_metric()),
        expected("codewire_warm_pool_controller_ready", &[])
    );
    assert_eq!(
        named(refills_metric()),
        expected("codewire_warm_pool_refills_total", &["shape"])
    );
    assert_eq!(
        named(adoptions_metric()),
        expected("codewire_warm_pool_adoptions_total", &["shape"])
    );
    assert_eq!(
        named(member_deletions_metric()),
        expected(
            "codewire_warm_pool_member_deletions_total",
            &["shape", "reason"]
        )
    );
}

/// #3572: a start rotates only the wanted shapes whose own pool is missing
/// beside another revision's, only beside a controller that shows claim
/// safety, and never while draining.
#[tokio::test]
async fn a_start_rotates_only_beside_a_capable_controller_and_never_while_draining() {
    let shapes = "1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=0";
    let config = WarmPoolConfig::from_cfg(&dev_cfg(shapes), false)
        .unwrap()
        .unwrap();
    let mut previous_cfg = dev_cfg(shapes);
    previous_cfg.daemon_image = "registry.example.invalid/codewire/daemon@sha256:4444444444444444444444444444444444444444444444444444444444444444".into();
    let previous = rendered_with(
        &previous_cfg,
        &WarmPoolConfig::from_cfg(&previous_cfg, false)
            .unwrap()
            .unwrap(),
    )
    .pools;
    let live = |capable: bool| {
        let mut pools: Vec<Value> = previous
            .iter()
            .map(|pool| pool.objects.pool.clone())
            .collect();
        if capable {
            pools.push(reconciled_shadow());
        }
        let cluster = Arc::new(Mutex::new(Cluster {
            pools,
            ..Cluster::default()
        }));
        (api(Arc::clone(&cluster)), cluster)
    };

    // Only the configured shape with members rotates.
    let (client, cluster) = live(true);
    let rotating = rotating_pools(&client, NAMESPACE, &rendered(&config))
        .await
        .unwrap();
    assert_eq!(
        rotating
            .iter()
            .map(|pool| pool.objects.name.as_str())
            .collect::<Vec<_>>(),
        [rendered(&config).pools[0].objects.name.as_str()]
    );
    assert!(
        cluster.lock().unwrap().writes.is_empty(),
        "deciding writes nothing"
    );

    // Beside a controller that shows no claim safety, nothing rotates.
    let (client, _) = live(false);
    assert!(
        rotating_pools(&client, NAMESPACE, &rendered(&config))
            .await
            .unwrap()
            .is_empty()
    );

    // Draining wants nothing, and reads nothing to say so.
    let (client, cluster) = live(true);
    let draining = RenderedPools {
        draining: true,
        ..rendered(&config)
    };
    assert!(
        rotating_pools(&client, NAMESPACE, &draining)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(cluster.lock().unwrap().requests.is_empty());
}
