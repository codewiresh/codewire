//! Create routing to shared warm pools (Program #2238 C3).

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use kube::api::DynamicObject;
use serde_json::{Value, json};

use super::*;
use crate::runtime::kubernetes::KubernetesDriver;
use crate::runtime::kubernetes::pools::{live_pool_current, members_current};
use crate::sandbox::template::render_sandbox_template;
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
};
use crate::sandbox::warm_pool::POOL_REVISION_ANNOTATION;
use crate::sandbox::warm_pool::WarmPoolObjects;
use crate::worker::create::environment_template_opts;
use codewire_project::ProjectSpec;

const NAMESPACE: &str = "dev-sandboxes";

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
        dedicated_cpu: false,
        never_ran: false,
        external_cleanup_completed_at: None,
        cpu_millicores: cpu,
        memory_mb: memory,
        disk_gb: disk,
        source_snapshot_id: None,
        ttl_seconds: None,
        project_spec: ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    }
}

fn opts(cfg: &SandboxWorkerCfg, env: &EnvironmentRow, image: &str) -> TemplateOpts {
    environment_template_opts(cfg, image, "workspace", env, 7).unwrap()
}

fn candidate(cfg: &SandboxWorkerCfg, env: &EnvironmentRow) -> Result<WantedPool, ColdReason> {
    pool_candidate(
        cfg,
        env,
        canonical_workspace_runtime_image(),
        &opts(cfg, env, canonical_workspace_runtime_image()),
    )
}

/// The candidate pool as the driver renders it.
fn objects(cfg: &SandboxWorkerCfg, env: &EnvironmentRow) -> WarmPoolObjects {
    crate::runtime::kubernetes::warm_pools::render_pool(NAMESPACE, &candidate(cfg, env).unwrap())
        .unwrap()
        .objects
}

#[test]
fn only_an_exact_canonical_standard_binding_shape_is_a_pool_candidate() {
    let cfg = dev_cfg(SHAPES);
    let small = environment(1000, 4096, 10);
    let objects = objects(&cfg, &small);
    assert!(objects.name.starts_with("cw-pool-1000m-4096mi-10gi-"));

    for unconfigured in ["", "  ", "not-a-shape"] {
        assert_eq!(
            candidate(&dev_cfg(unconfigured), &small).err(),
            Some(ColdReason::Unconfigured)
        );
    }
    // A configured shape with no members, and every other exact shape.
    assert_eq!(
        candidate(&cfg, &environment(2000, 8192, 10)).err(),
        Some(ColdReason::Shape)
    );
    for (cpu, memory, disk) in [(1001, 4096, 10), (1000, 4095, 10), (1000, 4096, 11)] {
        assert_eq!(
            candidate(&cfg, &environment(cpu, memory, disk)).err(),
            Some(ColdReason::Shape),
            "{cpu}/{memory}/{disk}"
        );
    }
    // Only the standard tier pools (codewire#3626 condition 4): any other
    // tier, spelled any way, goes cold before anything else is read.
    for tier in [
        "confidential",
        "",
        "Standard",
        "standard ",
        " standard",
        "dedicated",
        "premium",
    ] {
        let mut other = small.clone();
        other.isolation_tier = tier.into();
        assert_eq!(
            pool_candidate(
                &cfg,
                &other,
                canonical_workspace_runtime_image(),
                &opts(&cfg, &small, canonical_workspace_runtime_image())
            )
            .err(),
            Some(ColdReason::Tier),
            "{tier:?}"
        );
    }
    // Only exactly the canonical image pools: never its public mirror,
    // another digest or tag of a first-party repository, or a custom image,
    // whose entrypoint would start beside the unbound daemon and could
    // listen on 7777 or 2222 before the bind (codewire#3626 condition 4).
    let canonical = canonical_workspace_runtime_image();
    let (repository, _) = canonical
        .split_once('@')
        .expect("canonical image is digest-pinned");
    let other_digest = format!(
        "{repository}@sha256:5555555555555555555555555555555555555555555555555555555555555555"
    );
    let tagged = format!("{repository}:latest");
    let suffixed = format!("{canonical}-custom");
    for image in [
        crate::sandbox::PUBLIC_CANONICAL_WORKSPACE_RUNTIME_IMAGE,
        "registry.example.invalid/custom/workspace@sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "ghcr.io/codewiresh/workspace-node@sha256:4444444444444444444444444444444444444444444444444444444444444444",
        other_digest.as_str(),
        tagged.as_str(),
        suffixed.as_str(),
        "",
    ] {
        assert_ne!(image, canonical);
        assert_eq!(
            pool_candidate(&cfg, &small, image, &opts(&cfg, &small, image)).err(),
            Some(ColdReason::Image),
            "{image:?}"
        );
        // Whatever its own opts, a non-canonical image is refused even when
        // paired with the canonical rendering.
        assert_eq!(
            pool_candidate(&cfg, &small, image, &opts(&cfg, &small, canonical)).err(),
            Some(ColdReason::Image),
            "{image:?}"
        );
    }
    // A rendering that is not identity-free (a configuration without the
    // binding listener, which a sandbox worker refuses at startup) is never
    // pooled.
    let mut unbindable = cfg.clone();
    unbindable.pod_namespace.clear();
    assert_eq!(
        candidate(&unbindable, &small).err(),
        Some(ColdReason::Identity)
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

/// #3635: while the deployment shares, a dedicated organization renders 1:1 and
/// goes cold under its own label. With sharing off, its rendering equals the
/// pool's, so it claims from the pool like any other.
#[test]
fn a_dedicated_organization_goes_cold_only_while_the_pools_share() {
    let shared = SandboxWorkerCfg {
        cpu_sharing_ratio: CpuSharingRatio::parse(Some("2")).unwrap(),
        ..dev_cfg(SHAPES)
    };
    let sharing = environment(1000, 4096, 10);
    let dedicated = EnvironmentRow {
        dedicated_cpu: true,
        never_ran: false,
        ..environment(1000, 4096, 10)
    };
    assert!(candidate(&shared, &sharing).is_ok());
    assert_eq!(
        candidate(&shared, &dedicated).unwrap_err(),
        ColdReason::DedicatedCpu
    );
    assert_eq!(ColdReason::DedicatedCpu.as_str(), "cold_dedicated_cpu");

    let off = dev_cfg(SHAPES);
    assert!(candidate(&off, &dedicated).is_ok());

    let workspace_cpu = |opts: &TemplateOpts| {
        let rendered = render_sandbox_template(NAMESPACE, opts);
        let containers = rendered["spec"]["podTemplate"]["spec"]["containers"].clone();
        let workspace = containers
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "workspace")
            .unwrap()
            .clone();
        (
            workspace["resources"]["requests"]["cpu"].clone(),
            workspace["resources"]["limits"]["cpu"].clone(),
        )
    };
    let image = canonical_workspace_runtime_image();
    assert_eq!(
        workspace_cpu(&opts(&shared, &dedicated, image)),
        (json!("1000m"), json!("1000m"))
    );
    assert_eq!(
        workspace_cpu(&opts(&shared, &sharing, image)),
        (json!("500m"), json!("1000m"))
    );
}

#[test]
fn a_live_pool_routes_only_at_this_replicas_revision_with_members() {
    let objects = objects(&dev_cfg(SHAPES), &environment(1000, 4096, 10));
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
    let objects = objects(&dev_cfg(SHAPES), &environment(1000, 4096, 10));
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
fn api(
    objects: Option<&WarmPoolObjects>,
    fail: bool,
) -> (Arc<dyn RuntimeDriver>, Arc<Mutex<Vec<String>>>) {
    api_with(objects.map(live), Vec::new(), fail)
}

fn api_with(
    served: Option<(DynamicObject, DynamicObject)>,
    members: Vec<Value>,
    fail: bool,
) -> (Arc<dyn RuntimeDriver>, Arc<Mutex<Vec<String>>>) {
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
        KubernetesDriver::shared(kube::Client::new(service, "default")),
        requests,
    )
}

#[tokio::test]
async fn routing_reads_nothing_without_configuration_and_claims_only_a_current_pool() {
    let env = environment(1000, 4096, 10);
    let canonical = canonical_workspace_runtime_image();

    // Inert: no shape configured is decided before any Kubernetes read.
    let cfg = dev_cfg("");
    let (client, requests) = api(None, true);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        client.as_ref(),
        &Placement::new(NAMESPACE),
        false,
    )
    .await;
    assert_eq!(decided, Route::Cold(ColdReason::Unconfigured));
    assert!(requests.lock().unwrap().is_empty());

    let cfg = dev_cfg(SHAPES);
    let objects = objects(&cfg, &env);
    let (client, requests) = api(Some(&objects), false);
    let decided = route(
        &cfg,
        &env,
        canonical,
        &opts(&cfg, &env, canonical),
        client.as_ref(),
        &Placement::new(NAMESPACE),
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
        client.as_ref(),
        &Placement::new(NAMESPACE),
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
        client.as_ref(),
        &Placement::new(NAMESPACE),
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
        client.as_ref(),
        &Placement::new(NAMESPACE),
        false,
    )
    .await;
    assert_eq!(decided, Route::Cold(ColdReason::Unavailable));
}

#[test]
fn a_pool_claim_carries_only_the_pool_reference_and_identity_labels() {
    let cfg = dev_cfg(SHAPES);
    let env = environment(1000, 4096, 10);
    let objects = objects(&cfg, &env);
    let mut claim = crate::worker::create::environment_claim_opts(
        canonical_workspace_runtime_image(),
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
    let canonical = canonical_workspace_runtime_image();
    let cfg = dev_cfg(SHAPES);
    let objects = objects(&cfg, &env);
    let decide = |client: Arc<dyn RuntimeDriver>| {
        let cfg = cfg.clone();
        let env = env.clone();
        async move {
            route(
                &cfg,
                &env,
                canonical,
                &opts(&cfg, &env, canonical),
                client.as_ref(),
                &Placement::new(NAMESPACE),
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

#[test]
fn a_create_from_a_snapshot_never_takes_a_pool_member() {
    let cfg = dev_cfg(SHAPES);
    let mut env = environment(1000, 4096, 10);
    assert!(candidate(&cfg, &env).is_ok());
    env.source_snapshot_id = Some("11266ba6-274b-4e2b-b0ce-ff236d0cf2a3".into());
    assert_eq!(
        candidate(&cfg, &env).err(),
        Some(ColdReason::SourceSnapshot)
    );
    assert_eq!(ColdReason::SourceSnapshot.as_str(), "cold_source_snapshot");
}

/// An environment whose own rendering differs from the pool's (here another
/// storage class) is never pooled: the driver says so before reading
/// anything (`cold_rendering`).
#[tokio::test]
async fn an_own_rendering_that_differs_from_the_pools_goes_cold() {
    let cfg = dev_cfg(SHAPES);
    let small = environment(1000, 4096, 10);
    let pool = candidate(&cfg, &small).unwrap();
    let mut other_class = opts(&cfg, &small, canonical_workspace_runtime_image());
    other_class.workspace_storage_class = "local-path".into();
    let (driver, requests) = api(None, false);
    assert_eq!(
        driver
            .pool_state(&Placement::new(NAMESPACE), &pool, &other_class)
            .await
            .unwrap(),
        PoolState::RenderingDiffers
    );
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(ColdReason::Rendering.as_str(), "cold_rendering");
}

/// A pool that cannot render is a `cold_shape` route, answered without any
/// API read.
#[tokio::test]
async fn an_unrenderable_pool_goes_cold_without_a_read() {
    let cfg = dev_cfg(SHAPES);
    let small = environment(1000, 4096, 10);
    let mut pool = candidate(&cfg, &small).unwrap();
    // A pool rendering never names an environment.
    pool.rendering.environment_id = small.id.clone();
    let (driver, requests) = api(None, false);
    assert_eq!(
        driver
            .pool_state(
                &Placement::new(NAMESPACE),
                &pool,
                &opts(&cfg, &small, canonical_workspace_runtime_image())
            )
            .await
            .unwrap(),
        PoolState::Unrenderable
    );
    assert!(requests.lock().unwrap().is_empty());
}

/// #3628 PR 5c: each answer of the driver is the route it was before the
/// driver gave it, under its own label.
#[tokio::test]
async fn each_pool_answer_routes_under_its_label() {
    let cfg = dev_cfg(SHAPES);
    let env = environment(1000, 4096, 10);
    let canonical = canonical_workspace_runtime_image();
    for (state, expected) in [
        (
            PoolState::Claimable {
                pool: "cw-pool-a".into(),
            },
            Route::Pool {
                name: "cw-pool-a".into(),
            },
        ),
        (PoolState::NoPools, Route::Cold(ColdReason::Unconfigured)),
        (PoolState::Unrenderable, Route::Cold(ColdReason::Shape)),
        (
            PoolState::RenderingDiffers,
            Route::Cold(ColdReason::Rendering),
        ),
        (PoolState::NotCurrent, Route::Cold(ColdReason::Revision)),
        (
            PoolState::ControllerIncapable,
            Route::Cold(ColdReason::Controller),
        ),
        (
            PoolState::StaleMembers,
            Route::Cold(ColdReason::StaleMembers),
        ),
    ] {
        let driver = crate::runtime::fake::FakeRuntimeDriver::default();
        *driver.pool_state.lock().unwrap() = Some(state.clone());
        let decided = route(
            &cfg,
            &env,
            canonical,
            &opts(&cfg, &env, canonical),
            &driver,
            &Placement::new(NAMESPACE),
            false,
        )
        .await;
        assert_eq!(decided, expected, "{state:?}");
    }
}
