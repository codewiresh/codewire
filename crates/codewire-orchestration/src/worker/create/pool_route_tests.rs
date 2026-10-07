//! Create routing to shared warm pools (Program #2238 C3).

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use serde_json::{Value, json};

use super::*;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
};
use crate::worker::create::environment_template_opts;
use codewire_project::ProjectSpec;

const NAMESPACE: &str = "dev-sandboxes";

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
        warm_pool_shapes: shapes.into(),
        ..Default::default()
    }
}

const SHAPES: &str = "1000m/4096Mi/10Gi=2,2000m/8192Mi/10Gi=0";

fn environment(cpu: i32, memory: i32, disk: i32) -> EnvironmentRow {
    EnvironmentRow {
        id: "3d6bb495-efac-419f-bf3a-91696e7c7ca4".into(),
        org_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        state: "creating".into(),
        desired_state: "started".into(),
        isolation_tier: "standard".into(),
        external_cleanup_completed_at: None,
        cpu_millicores: cpu,
        memory_mb: memory,
        disk_gb: disk,
        ttl_seconds: None,
        project_spec: ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    }
}

fn opts(cfg: &SandboxWorkerCfg, env: &EnvironmentRow, image: &str) -> TemplateOpts {
    environment_template_opts(cfg, image, "workspace", env, 7, "synthetic-daemon").unwrap()
}

fn candidate(cfg: &SandboxWorkerCfg, env: &EnvironmentRow) -> Result<WarmPoolObjects, ColdReason> {
    pool_candidate(
        cfg,
        env,
        CANONICAL_WORKSPACE_RUNTIME_IMAGE,
        &opts(cfg, env, CANONICAL_WORKSPACE_RUNTIME_IMAGE),
        NAMESPACE,
    )
}

#[test]
fn only_an_exact_canonical_standard_binding_shape_is_a_pool_candidate() {
    let cfg = dev_cfg(SHAPES);
    let small = environment(1000, 4096, 10);
    let objects = candidate(&cfg, &small).expect("the configured shape is a candidate");
    assert!(objects.name.starts_with("cw-pool-1000m-4096mi-10gi-"));

    for unconfigured in ["", "  ", "not-a-shape"] {
        assert_eq!(
            candidate(&dev_cfg(unconfigured), &small),
            Err(ColdReason::Unconfigured)
        );
    }
    // A configured shape with no members, and every other exact shape.
    assert_eq!(
        candidate(&cfg, &environment(2000, 8192, 10)),
        Err(ColdReason::Shape)
    );
    for (cpu, memory, disk) in [(1001, 4096, 10), (1000, 4095, 10), (1000, 4096, 11)] {
        assert_eq!(
            candidate(&cfg, &environment(cpu, memory, disk)),
            Err(ColdReason::Shape),
            "{cpu}/{memory}/{disk}"
        );
    }
    let mut confidential = small.clone();
    confidential.isolation_tier = "confidential".into();
    assert_eq!(
        pool_candidate(
            &cfg,
            &confidential,
            CANONICAL_WORKSPACE_RUNTIME_IMAGE,
            &opts(&cfg, &small, CANONICAL_WORKSPACE_RUNTIME_IMAGE),
            NAMESPACE
        ),
        Err(ColdReason::Tier)
    );
    for image in [
        crate::sandbox::LEGACY_GHCR_CANONICAL_WORKSPACE_RUNTIME_IMAGE,
        "registry.example.invalid/custom/workspace@sha256:4444444444444444444444444444444444444444444444444444444444444444",
    ] {
        assert_eq!(
            pool_candidate(&cfg, &small, image, &opts(&cfg, &small, image), NAMESPACE),
            Err(ColdReason::Image)
        );
    }
    // A rendering that is not identity-free (a configuration without the
    // binding listener, which a sandbox worker refuses at startup) is never
    // pooled.
    let mut unbindable = cfg.clone();
    unbindable.pod_namespace.clear();
    assert_eq!(candidate(&unbindable, &small), Err(ColdReason::Identity));
    // An own rendering that differs from the pool's (here another storage
    // class for this environment's rendering) is never pooled.
    let mut other_class = opts(&cfg, &small, CANONICAL_WORKSPACE_RUNTIME_IMAGE);
    other_class.workspace_storage_class = "local-path".into();
    assert_eq!(
        pool_candidate(
            &cfg,
            &small,
            CANONICAL_WORKSPACE_RUNTIME_IMAGE,
            &other_class,
            NAMESPACE
        ),
        Err(ColdReason::Rendering)
    );
}

/// The pool and template as a C0 controller left them: the pool's status
/// observed its generation.
fn live(objects: &WarmPoolObjects) -> (DynamicObject, DynamicObject) {
    let mut pool = objects.pool.clone();
    pool["metadata"]["uid"] = json!("pool-uid");
    pool["metadata"]["generation"] = json!(3);
    pool["status"] = json!({ "replicas": 2, "readyReplicas": 2, "observedGeneration": 3 });
    let mut template = objects.template.clone();
    template["metadata"]["uid"] = json!("template-uid");
    (
        serde_json::from_value(pool).unwrap(),
        serde_json::from_value(template).unwrap(),
    )
}

#[test]
fn a_live_pool_routes_only_at_this_replicas_revision_with_members() {
    let objects = candidate(&dev_cfg(SHAPES), &environment(1000, 4096, 10)).unwrap();
    let (pool, template) = live(&objects);
    assert!(live_pool_current(Some(&pool), Some(&template), &objects));
    assert!(!live_pool_current(None, Some(&template), &objects));
    assert!(!live_pool_current(Some(&pool), None, &objects));

    let edit = |object: &DynamicObject, edit: &dyn Fn(&mut Value)| -> DynamicObject {
        let mut value = serde_json::to_value(object).unwrap();
        edit(&mut value);
        serde_json::from_value(value).unwrap()
    };
    let other_revision = |value: &mut Value| {
        value["metadata"]["annotations"][POOL_REVISION_ANNOTATION] = json!("0".repeat(64));
    };
    assert!(!live_pool_current(
        Some(&edit(&pool, &other_revision)),
        Some(&template),
        &objects
    ));
    assert!(!live_pool_current(
        Some(&pool),
        Some(&edit(&template, &other_revision)),
        &objects
    ));
    let empty = |value: &mut Value| value["spec"]["replicas"] = json!(0);
    assert!(!live_pool_current(
        Some(&edit(&pool, &empty)),
        Some(&template),
        &objects
    ));
    let deleting = |value: &mut Value| {
        value["metadata"]["deletionTimestamp"] = json!("2026-10-03T00:00:00Z");
    };
    assert!(!live_pool_current(
        Some(&edit(&pool, &deleting)),
        Some(&template),
        &objects
    ));
    let foreign = |value: &mut Value| {
        value["metadata"]["labels"] = json!({ "codewire.sh/type": "workspace-pool" });
    };
    assert!(!live_pool_current(
        Some(&pool),
        Some(&edit(&template, &foreign)),
        &objects
    ));
    let other_template = |value: &mut Value| {
        value["spec"]["sandboxTemplateRef"]["name"] = json!("workspace-env");
    };
    assert!(!live_pool_current(
        Some(&edit(&pool, &other_template)),
        Some(&template),
        &objects
    ));
    // Review L5: the revision annotation alone does not make a template
    // current; its spec must be this replica's rendering.
    let respecified = |value: &mut Value| {
        value["spec"]["podTemplate"]["spec"]["hostNetwork"] = json!(true);
    };
    assert!(!live_pool_current(
        Some(&pool),
        Some(&edit(&template, &respecified)),
        &objects
    ));
}

/// A member Sandbox as the controller creates it from `template`.
fn member(objects: &WarmPoolObjects, name: &str) -> Value {
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1",
        "kind": "Sandbox",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "uid": format!("{name}-uid"),
            "labels": {
                crate::sandbox::warm_pool::MEMBER_POOL_LABEL:
                    crate::sandbox::client::sandbox_name_hash(&objects.name),
            },
        },
        "spec": objects.template["spec"].clone(),
    })
}

fn with_marker(mut member: Value, revision: &str) -> Value {
    for entry in member["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
        .as_array_mut()
        .unwrap()
    {
        if entry["name"] == crate::sandbox::warm_pool::POOL_REVISION_ENV {
            entry["value"] = json!(revision);
        }
    }
    member
}

/// Review M1: a member booted from another revision blocks the pool until
/// the reconciler replaces it; a terminating one does not.
#[test]
fn only_members_of_this_revision_keep_a_pool_routable() {
    let objects = candidate(&dev_cfg(SHAPES), &environment(1000, 4096, 10)).unwrap();
    let parse = |values: Vec<Value>| -> Vec<DynamicObject> {
        values
            .into_iter()
            .map(|value| serde_json::from_value(value).unwrap())
            .collect()
    };
    let current = member(&objects, "a");
    assert!(members_current(&[], &objects.revision));
    assert!(members_current(
        &parse(vec![current.clone()]),
        &objects.revision
    ));
    let stale = with_marker(member(&objects, "b"), &"0".repeat(64));
    assert!(!members_current(
        &parse(vec![current.clone(), stale.clone()]),
        &objects.revision
    ));
    let mut unmarked = member(&objects, "c");
    unmarked["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["name"] != crate::sandbox::warm_pool::POOL_REVISION_ENV);
    assert!(!members_current(&parse(vec![unmarked]), &objects.revision));
    let mut terminating = stale;
    terminating["metadata"]["deletionTimestamp"] = json!("2026-10-03T00:00:00Z");
    assert!(members_current(
        &parse(vec![current, terminating]),
        &objects.revision
    ));
}

/// A recorded API serving one pool, its template and its members, or failing
/// every request.
fn api(objects: Option<&WarmPoolObjects>, fail: bool) -> (SandboxClient, Arc<Mutex<Vec<String>>>) {
    api_with(objects.map(live), Vec::new(), fail)
}

fn api_with(
    served: Option<(DynamicObject, DynamicObject)>,
    members: Vec<Value>,
    fail: bool,
) -> (SandboxClient, Arc<Mutex<Vec<String>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let service = Router::new().fallback(move |request: Request<Body>| {
        let recorded = Arc::clone(&recorded);
        let served = served.clone();
        let members = members.clone();
        async move {
            let path = request.uri().path().to_owned();
            recorded.lock().unwrap().push(format!("{} {path}", request.method()));
            let (status, body) = match (&served, fail) {
                (_, true) => (
                    StatusCode::FORBIDDEN,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}),
                ),
                (Some((pool, _)), false) if path.contains("/sandboxwarmpools/") => {
                    (StatusCode::OK, serde_json::to_value(pool).unwrap())
                }
                (Some((_, template)), false) if path.contains("/sandboxtemplates/") => {
                    (StatusCode::OK, serde_json::to_value(template).unwrap())
                }
                (_, false) if path.ends_with("/sandboxes") => (
                    StatusCode::OK,
                    json!({
                        "apiVersion": "agents.x-k8s.io/v1beta1",
                        "kind": "SandboxList",
                        "metadata": {},
                        "items": members,
                    }),
                ),
                _ => (
                    StatusCode::NOT_FOUND,
                    json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}),
                ),
            };
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    });
    (
        SandboxClient::new(kube::Client::new(service, "default"), NAMESPACE),
        requests,
    )
}

#[tokio::test]
async fn routing_reads_nothing_without_configuration_and_claims_only_a_current_pool() {
    let env = environment(1000, 4096, 10);
    let canonical = CANONICAL_WORKSPACE_RUNTIME_IMAGE;

    // Inert: no shape configured is decided before any Kubernetes read.
    let cfg = dev_cfg("");
    let (client, requests) = api(None, true);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        &client,
        false,
    )
    .await;
    assert_eq!(decided, Route::Cold(ColdReason::Unconfigured));
    assert!(requests.lock().unwrap().is_empty());

    let cfg = dev_cfg(SHAPES);
    let objects = candidate(&cfg, &env).unwrap();
    let (client, requests) = api(Some(&objects), false);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        &client,
        false,
    )
    .await;
    assert_eq!(
        decided,
        Route::Pool {
            name: objects.name.clone()
        }
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET ")
                && (request.ends_with(&objects.name) || request.ends_with("/sandboxes"))),
        "routing only reads the one pool, its template and its members"
    );

    // A re-claimed create is cold without a read; a missing pool is a
    // revision miss; an unreadable one is unavailable.
    let (client, requests) = api(Some(&objects), false);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        &client,
        true,
    )
    .await;
    assert_eq!(decided, Route::Cold(ColdReason::Reclaimed));
    assert!(requests.lock().unwrap().is_empty());
    let (client, _) = api(None, false);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        &client,
        false,
    )
    .await;
    assert_eq!(decided, Route::Cold(ColdReason::Revision));
    let (client, _) = api(Some(&objects), true);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        &client,
        false,
    )
    .await;
    assert_eq!(decided, Route::Cold(ColdReason::Unavailable));
}

#[test]
fn a_pool_claim_carries_only_the_pool_reference_and_identity_labels() {
    let cfg = dev_cfg(SHAPES);
    let env = environment(1000, 4096, 10);
    let objects = candidate(&cfg, &env).unwrap();
    let mut claim = crate::worker::create::environment_claim_opts(
        CANONICAL_WORKSPACE_RUNTIME_IMAGE,
        "workspace",
        &env,
        7,
    );
    claim.warm_pool_ref = objects.name.clone();
    claim.template_ref = objects.name.clone();
    let rendered = crate::sandbox::render_sandbox_claim(NAMESPACE, &claim);
    let spec = rendered["spec"].as_object().unwrap();
    let mut keys: Vec<&str> = spec.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["additionalPodMetadata", "warmPoolRef"]);
    assert_eq!(
        rendered["spec"]["warmPoolRef"]["name"],
        objects.name.as_str()
    );
    let labels = rendered["spec"]["additionalPodMetadata"]["labels"]
        .as_object()
        .unwrap();
    let mut label_keys: Vec<&str> = labels.keys().map(String::as_str).collect();
    label_keys.sort_unstable();
    assert_eq!(
        label_keys,
        [
            "codewire.sh/environment-id",
            "codewire.sh/environment-operation-generation",
            "codewire.sh/org-id",
            "codewire.sh/type",
        ]
    );
}

/// Review H1 and M1: a pool the C0 controller has not observed, or one that
/// still holds a member of another revision, routes cold.
#[tokio::test]
async fn routing_needs_a_capable_controller_and_current_members() {
    let env = environment(1000, 4096, 10);
    let canonical = CANONICAL_WORKSPACE_RUNTIME_IMAGE;
    let cfg = dev_cfg(SHAPES);
    let objects = candidate(&cfg, &env).unwrap();
    let decide = |client: SandboxClient| {
        let cfg = cfg.clone();
        let env = env.clone();
        async move {
            route(
                &cfg,
                &env,
                canonical,
                &opts(&cfg, &env, canonical),
                &client,
                false,
            )
            .await
        }
    };

    let (pool, template) = live(&objects);
    for status in [
        json!(null),
        json!({ "replicas": 2, "readyReplicas": 2 }),
        json!({ "replicas": 2, "readyReplicas": 2, "observedGeneration": 2 }),
    ] {
        let mut legacy = serde_json::to_value(&pool).unwrap();
        legacy["status"] = status.clone();
        let (client, requests) = api_with(
            Some((serde_json::from_value(legacy).unwrap(), template.clone())),
            vec![member(&objects, "a")],
            false,
        );
        assert_eq!(
            decide(client).await,
            Route::Cold(ColdReason::Controller),
            "{status}"
        );
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| request.ends_with("/sandboxes")),
            "members are read only on a capable controller"
        );
    }

    let (client, _) = api_with(
        Some(live(&objects)),
        vec![member(&objects, "a"), member(&objects, "b")],
        false,
    );
    assert_eq!(
        decide(client).await,
        Route::Pool {
            name: objects.name.clone()
        }
    );
    let (client, _) = api_with(
        Some(live(&objects)),
        vec![
            member(&objects, "a"),
            with_marker(member(&objects, "b"), &"0".repeat(64)),
        ],
        false,
    );
    assert_eq!(decide(client).await, Route::Cold(ColdReason::StaleMembers));
}

/// Review M3 and L3: a definitive bind refusal or a failed readiness wait may
/// re-claim cold; a bare error or lost authority may not. Marking a wait
/// never changes how its error reads.
#[tokio::test]
async fn only_a_definitive_refusal_or_a_failed_readiness_wait_reclaims() {
    use crate::worker::activity_authority::AuthorityLost;
    use crate::worker::create::{readiness_wait, reclaim_eligible};
    use crate::worker::workspace_binding::BindRefused;

    let message = "timeout waiting for SandboxClaim sandbox-x to become Ready";
    let expired = readiness_wait(async { Err::<(), _>(anyhow::anyhow!(message)) })
        .await
        .unwrap_err();
    assert!(reclaim_eligible(&expired));
    assert_eq!(format!("{expired:#}"), message);
    let chained = readiness_wait(async {
        Err::<(), _>(anyhow::anyhow!("inner").context("credential gateway readiness"))
    })
    .await
    .unwrap_err();
    assert_eq!(
        format!("{chained:#}"),
        "credential gateway readiness: inner"
    );
    assert!(reclaim_eligible(&chained));
    assert!(!reclaim_eligible(&anyhow::anyhow!(message)));
    let lost = readiness_wait(async { Err::<(), _>(anyhow::Error::from(AuthorityLost)) })
        .await
        .unwrap_err();
    assert!(crate::worker::activity_authority::is_authority_lost(&lost));
    assert!(!reclaim_eligible(&lost));
    assert!(reclaim_eligible(&anyhow::Error::from(BindRefused::Denied(
        "pool rendering"
    ))));
    assert!(!reclaim_eligible(&anyhow::Error::from(
        BindRefused::NotConverged
    )));
    assert_eq!(
        readiness_wait(async { Ok::<_, anyhow::Error>(7) })
            .await
            .unwrap(),
        7
    );
}
