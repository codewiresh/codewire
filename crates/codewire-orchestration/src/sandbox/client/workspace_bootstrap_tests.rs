use super::*;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use serde_json::json;
use std::sync::{Arc, Mutex};

const NS: &str = "dev-sandboxes";
const ENV: &str = "4b0d7d98-d965-4070-ae2b-04c98bde5cb7";
const ORG: &str = "org-bootstrap-fixture";
const CLAIM_UID: &str = "claim-incarnation";
const SANDBOX: &str = "allocated-workspace";
const POD: &str = "tracked-workspace";

fn opts() -> TemplateOpts {
    TemplateOpts {
        name: format!("workspace-{ENV}"),
        environment_id: ENV.into(),
        organization_id: ORG.into(),
        operation_generation: 7,
        projection_selection_sha256: Some([0xab; 32]),
        credential_runtime: Some(
            super::super::template::CredentialRuntimeTemplateConfig::synthetic(NS),
        ),
        daemon_auth_token: "synthetic-daemon-capability".into(),
        gateway_token: "synthetic-coordinate-capability".into(),
        ..Default::default()
    }
}
fn claim_opts() -> ClaimOpts {
    ClaimOpts {
        environment_id: ENV.into(),
        org_id: ORG.into(),
        operation_generation: 7,
        ..Default::default()
    }
}
fn owner(api: &str, kind: &str, name: &str, uid: &str) -> Value {
    json!({"apiVersion":api,"kind":kind,"name":name,"uid":uid,"controller":true})
}
fn old_env() -> Vec<Value> {
    vec![
        json!({"name":"UNRELATED","value":"preserve"}),
        json!({"name":WORKSPACE_BOOTSTRAP_KEYS[0],"value":ENV}),
        json!({"name":WORKSPACE_BOOTSTRAP_KEYS[1],"value":"6"}),
        json!({"name":WORKSPACE_BOOTSTRAP_KEYS[2],"value":"cd".repeat(32)}),
        json!({"name":"UNRELATED_FROM","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}}),
    ]
}
fn blueprint() -> Value {
    json!({"metadata":{"labels":{"preserve":"label"},"annotations":{"preserve":"annotation"}},
        "spec":{"securityContext":{"runAsUser":1000,"fsGroupChangePolicy":"Always"},
            "volumes":[{"name":"workspace","persistentVolumeClaim":{"claimName":"saved-pvc"}}],
            "initContainers":[super::super::template::render_workspace_client_bootstrap(&opts())["init"]],
            "containers":[{"name":"dind","image":"unchanged-dind"},
                {"name":"workspace","image":"unchanged-workspace","command":["unchanged-entrypoint"],
                    "resources":{"requests":{"cpu":"900m"}},"env":old_env()}]}})
}
#[derive(Clone, Copy)]
enum Race {
    SandboxUid,
    SandboxVersion,
    SandboxMode,
    TemplateVersion,
    ClaimAfterPatch,
}
struct Fixture {
    claim: Value,
    pool: Value,
    template: Value,
    sandbox: Value,
    pod: Value,
    certificate: Option<Value>,
    config_map: Option<Value>,
    requests: Vec<(Method, String, Value)>,
    race: Option<Race>,
}
fn fixture() -> Fixture {
    let opts = opts();
    let claim = claim_name(ENV);
    let mut pool = render_sandbox_shadow_pool(
        NS,
        &super::super::shadow_warm_pool_name(&opts.name),
        &opts.name,
        ENV,
    );
    pool["metadata"]["uid"] = json!("pool-incarnation");
    Fixture {
        claim: json!({"apiVersion":super::super::EXTENSIONS_API_VERSION,"kind":"SandboxClaim",
            "metadata":{"name":claim,"namespace":NS,"uid":CLAIM_UID,"resourceVersion":"10",
                "labels":runtime_identity_labels(ENV, ORG, 6, "sandbox")},
            "spec":{"warmPoolRef":{"name":super::super::shadow_warm_pool_name(&opts.name)}},
            "status":{"sandbox":{"name":SANDBOX}}}),
        pool,
        template: json!({"apiVersion":super::super::EXTENSIONS_API_VERSION,"kind":"SandboxTemplate",
            "metadata":{"name":opts.name,"namespace":NS,"uid":"template-incarnation","resourceVersion":"20","labels":{LABEL_ENV_ID:ENV}},
            "spec":{"podTemplate":blueprint(),"volumeClaimTemplates":[{"fixture":"immutable"}]}}),
        sandbox: json!({"apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
            "metadata":{"name":SANDBOX,"namespace":NS,"uid":"sandbox-incarnation","resourceVersion":"30","generation":9,
                "annotations":{"agents.x-k8s.io/pod-name":POD},
                "ownerReferences":[owner(super::super::EXTENSIONS_API_VERSION,"SandboxClaim",&claim,CLAIM_UID)]},
            "spec":{"operatingMode":"Suspended","podTemplate":blueprint(),"volumeClaimTemplates":[{"fixture":"immutable"}]},
            "status":{"conditions":[{"type":"Suspended","status":"True","reason":"PodTerminated","observedGeneration":9}]}}),
        pod: json!({"apiVersion":"v1","kind":"Pod",
            "metadata":{"name":POD,"namespace":NS,"uid":"pod-incarnation",
                "ownerReferences":[owner("agents.x-k8s.io/v1beta1","Sandbox",SANDBOX,"sandbox-incarnation")]},
            "spec":blueprint()["spec"]}),
        requests: vec![],
        certificate: None,
        config_map: None,
        race: None,
    }
}

// Synthetic apiserver implements only the emitted JSON Patch operations, on a
// temporary clone so a failed UID/version test cannot leave a partial write.
fn apply_patch_fixture(object: &mut Value, patch: &Value) -> bool {
    let mut next = object.clone();
    for operation in patch.as_array().unwrap() {
        let path = operation["path"].as_str().unwrap();
        if operation["op"] == "test" {
            if next.pointer(path) != Some(&operation["value"]) {
                return false;
            }
            continue;
        }
        let (parent, key) = path.rsplit_once('/').unwrap();
        let key = key.replace("~1", "/").replace("~0", "~");
        let parent = next
            .pointer_mut(parent)
            .expect("patch parent must already exist");
        if operation["op"] == "remove" {
            parent
                .as_array_mut()
                .unwrap()
                .remove(key.parse::<usize>().unwrap());
        } else if operation["op"] == "replace" {
            let member = parent
                .get_mut(&key)
                .expect("a replaced member must already exist");
            *member = operation["value"].clone();
        } else {
            assert_eq!(operation["op"], "add");
            match parent {
                Value::Array(values) => {
                    assert_eq!(key, "-");
                    values.push(operation["value"].clone());
                }
                Value::Object(values) => {
                    values.insert(key, operation["value"].clone());
                }
                _ => panic!("unexpected patch target"),
            }
        }
    }
    *object = next;
    true
}
fn client(fixture: Fixture) -> (SandboxClient, Arc<Mutex<Fixture>>) {
    let state = Arc::new(Mutex::new(fixture));
    let shared = state.clone();
    let service = Router::new().fallback(move |request: Request<Body>| {
        let shared = shared.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let bytes = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
            let patch = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
            let mut state = shared.lock().unwrap();
            state.requests.push((method.clone(), path.clone(), patch.clone()));
            if path.contains("/certificates") || path.contains("/configmaps") {
                let object = if path.contains("/certificates") { &mut state.certificate } else { &mut state.config_map };
                let (status, body) = if method == Method::GET {
                    match object.as_ref() {
                        Some(value) => (StatusCode::OK, value.clone()),
                        None => (StatusCode::NOT_FOUND, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404})),
                    }
                } else {
                    assert_eq!(method, Method::POST);
                    assert!(object.is_none());
                    *object = Some(patch.clone());
                    (StatusCode::CREATED, patch)
                };
                return Response::builder().status(status).header("content-type","application/json")
                    .body(Body::from(body.to_string())).unwrap();
            }
            let is_template = path.contains("/sandboxtemplates/");
            let is_sandbox = path.contains("/sandboxes/");
            if method == Method::PATCH {
                if is_sandbox && matches!(state.race, Some(Race::SandboxUid)) { state.sandbox["metadata"]["uid"] = json!("replacement"); }
                if is_sandbox && matches!(state.race, Some(Race::SandboxVersion)) { state.sandbox["metadata"]["resourceVersion"] = json!("31"); }
                if is_sandbox && matches!(state.race, Some(Race::SandboxMode)) { state.sandbox["spec"]["operatingMode"] = json!("Running"); }
                if is_template && matches!(state.race, Some(Race::TemplateVersion)) { state.template["metadata"]["resourceVersion"] = json!("21"); }
            }
            let object = if path.contains("/sandboxclaims/") { &mut state.claim }
                else if path.contains("/sandboxwarmpools/") { &mut state.pool }
                else if is_template { &mut state.template }
                else if is_sandbox { &mut state.sandbox }
                else if path.contains("/pods/") { &mut state.pod }
                else { panic!("unexpected Kubernetes route {path}") };
            let (status, body) = if method == Method::GET { (StatusCode::OK, object.clone()) }
                else {
                    assert_eq!(method, Method::PATCH);
                    assert!(is_template || is_sandbox, "must never patch a Pod");
                    if apply_patch_fixture(object, &patch) { (StatusCode::OK, object.clone()) }
                    else { (StatusCode::CONFLICT, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Conflict","code":409})) }
                };
            if is_sandbox && method == Method::PATCH && matches!(state.race, Some(Race::ClaimAfterPatch)) {
                state.claim["metadata"]["uid"] = json!("replacement-claim");
            }
            Response::builder().status(status).header("content-type","application/json")
                .body(Body::from(body.to_string())).unwrap()
        }
    });
    (
        SandboxClient::new(Client::new(service, "default"), NS),
        state,
    )
}
fn dynamic(value: &Value) -> DynamicObject {
    serde_json::from_value(value.clone()).unwrap()
}
fn expected_pod() -> WorkspacePodIdentity {
    WorkspacePodIdentity {
        name: POD.into(),
        uid: "pod-incarnation".into(),
    }
}
fn expected_sandbox() -> WorkspaceSandboxIdentity {
    WorkspaceSandboxIdentity {
        name: SANDBOX.into(),
        uid: "sandbox-incarnation".into(),
    }
}

#[test]
fn expected_tuple_matches_renderer_and_clear_is_absence() {
    for selected in [false, true] {
        let mut opts = opts();
        if !selected {
            opts.projection_selection_sha256 = None;
        }
        let rendered = dynamic(&render_sandbox_template(NS, &opts));
        assert!(
            bootstrap_template_matches(&rendered, &workspace_bootstrap_values(&opts).unwrap())
                .unwrap()
        );
    }
    let mut opts = opts();
    opts.projection_selection_sha256 = Some([0; 32]);
    assert!(workspace_bootstrap_values(&opts).is_err());
    opts.projection_selection_sha256 = Some([1; 32]);
    opts.credential_runtime = None;
    assert!(workspace_bootstrap_values(&opts).is_err());
}

#[tokio::test]
async fn suspended_reconcile_refreshes_only_owned_fields_without_reading_a_pod() {
    let before = fixture();
    let original = before.sandbox.clone();
    let (client, state) = client(before);
    client
        .reconcile_workspace_bootstrap(&opts(), &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    client
        .reconcile_workspace_bootstrap(&opts(), &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(
        state
            .requests
            .iter()
            .filter(|(method, _, _)| *method == Method::PATCH)
            .count(),
        2,
        "second call must be idempotent"
    );
    assert!(
        state
            .requests
            .iter()
            .all(|(_, path, _)| !path.contains("/pods/"))
    );
    let mut restored = state.sandbox.clone();
    restored["spec"]["podTemplate"]["spec"]["containers"][1]["env"] =
        original["spec"]["podTemplate"]["spec"]["containers"][1]["env"].clone();
    assert_eq!(
        restored, original,
        "unrelated container/PVC/security/metadata fields changed"
    );
    let expected = workspace_bootstrap_values(&opts()).unwrap();
    assert!(bootstrap_template_matches(&dynamic(&state.sandbox), &expected).unwrap());
    assert!(bootstrap_template_matches(&dynamic(&state.template), &expected).unwrap());
    for (_, _, patch) in state
        .requests
        .iter()
        .filter(|(method, _, _)| *method == Method::PATCH)
    {
        assert_eq!(patch[0]["path"], "/metadata/uid");
        assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
        assert!(!patch.to_string().contains("UNRELATED"));
    }
}

#[tokio::test]
async fn selected_to_clear_removes_entries_from_both_recipes() {
    let (client, state) = client(fixture());
    let mut opts = opts();
    opts.projection_selection_sha256 = None;
    opts.credential_runtime = None;
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    {
        let state = state.lock().unwrap();
        for object in [&state.template, &state.sandbox] {
            let env = object
                .pointer("/spec/podTemplate/spec/containers/1/env")
                .unwrap()
                .as_array()
                .unwrap();
            assert_eq!(env.len(), 2);
            assert!(bootstrap_environment_matches(env, &BTreeMap::new()));
        }
    }
    assert!(
        !client
            .workspace_bootstrap_matches(&opts, &claim_name(ENV), CLAIM_UID, &expected_pod())
            .await
            .unwrap(),
        "cleared recipes cannot certify the old selected Pod"
    );
    {
        let mut state = state.lock().unwrap();
        state.pod["spec"]["containers"][1]["env"] = json!([]);
        state.pod["metadata"]["uid"] = json!("replacement-pod");
    }
    assert!(
        client
            .workspace_bootstrap_matches(
                &opts,
                &claim_name(ENV),
                CLAIM_UID,
                &WorkspacePodIdentity {
                    name: POD.into(),
                    uid: "replacement-pod".into()
                }
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn confidential_reconcile_also_refreshes_only_kernel_and_fs_group_policy() {
    let mut opts = opts();
    opts.runtime_profile = super::super::template::RUNTIME_PROFILE_CONFIDENTIAL.into();
    opts.kata_coco_init_data_enabled = true;
    opts.kata_coco_kbs_url = "https://kbs.example.test".into();
    let recovery = rendered_runtime_recovery_patch(NS, &opts).unwrap().1;
    let (client, state) = client(fixture());
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    let state = state.lock().unwrap();
    for object in [&state.template, &state.sandbox] {
        assert_eq!(
            object
                .pointer("/spec/podTemplate/metadata/annotations")
                .unwrap()[KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY],
            recovery
                .pointer("/spec/podTemplate/metadata/annotations")
                .unwrap()[KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY]
        );
        assert_eq!(
            object.pointer("/spec/podTemplate/metadata/annotations/preserve"),
            Some(&json!("annotation"))
        );
        assert_eq!(
            object.pointer("/spec/podTemplate/spec/securityContext"),
            Some(&json!({"runAsUser":1000,"fsGroupChangePolicy":"OnRootMismatch"}))
        );
    }
}

#[tokio::test]
async fn wrong_claim_pool_template_or_controller_identity_prevents_every_write() {
    for invalid in 0..11 {
        let mut fixture = fixture();
        match invalid {
            0 => fixture.claim["metadata"]["uid"] = json!("other-claim"),
            1 => fixture.claim["metadata"]["labels"][LABEL_ORG_ID] = json!("other-org"),
            2 => {
                fixture.claim["metadata"]["labels"][super::super::LABEL_OPERATION_GENERATION] =
                    json!("8")
            }
            3 => fixture.sandbox["metadata"]["ownerReferences"][0]["uid"] = json!("other-claim"),
            4 => fixture.pool["spec"]["replicas"] = json!(1),
            5 => fixture.pool["spec"]["sandboxTemplateRef"]["name"] = json!("shared"),
            6 => fixture.template["metadata"]["labels"][LABEL_ENV_ID] = json!("other-env"),
            7 => fixture.template["metadata"]["deletionTimestamp"] = json!("2026-09-07T00:00:00Z"),
            8 => {
                fixture.claim["spec"]["env"] = json!([{"containerName":"workspace","name":WORKSPACE_BOOTSTRAP_KEYS[2],"value":"competing"}])
            }
            9 => {
                fixture.claim["spec"]["env"] =
                    json!([{"name":WORKSPACE_BOOTSTRAP_KEYS[2],"value":"competing-default"}])
            }
            10 => fixture.pool["metadata"]["labels"][LABEL_ENV_ID] = json!("other-env"),
            _ => unreachable!(),
        }
        let (client, state) = client(fixture);
        assert!(
            client
                .reconcile_workspace_bootstrap(
                    &opts(),
                    &claim_name(ENV),
                    CLAIM_UID,
                    &expected_sandbox()
                )
                .await
                .is_err()
        );
        assert!(
            state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|(method, _, _)| *method == Method::GET)
        );
    }
}

#[tokio::test]
async fn conditional_conflicts_and_claim_replacement_cannot_report_publication_success() {
    for race in [
        Race::SandboxUid,
        Race::SandboxVersion,
        Race::TemplateVersion,
        Race::ClaimAfterPatch,
    ] {
        let mut fixture = fixture();
        fixture.race = Some(race);
        let (client, state) = client(fixture);
        assert!(
            client
                .reconcile_workspace_bootstrap(
                    &opts(),
                    &claim_name(ENV),
                    CLAIM_UID,
                    &expected_sandbox()
                )
                .await
                .is_err()
        );
        let state = state.lock().unwrap();
        assert!(
            state
                .requests
                .iter()
                .filter(|(method, _, _)| *method == Method::PATCH)
                .count()
                <= 2,
            "must not blind retry a conflict"
        );
        assert!(
            state
                .requests
                .iter()
                .all(|(method, path, _)| *method != Method::DELETE && !path.contains("/pods/"))
        );
    }
}

#[tokio::test]
async fn actual_pod_tuple_not_recipe_or_relabeling_certifies_bootstrap() {
    for actual in [false, true] {
        let mut fixture = fixture();
        fixture.pod["metadata"]["labels"] =
            serde_json::to_value(runtime_identity_labels(ENV, ORG, 7, "workspace")).unwrap();
        if actual {
            fixture.pod["spec"]["containers"][1]["env"] = json!(
                workspace_bootstrap_values(&opts())
                    .unwrap()
                    .iter()
                    .map(|(name, value)| json!({"name":name,"value":value}))
                    .collect::<Vec<_>>()
            );
        }
        let (client, _) = client(fixture);
        assert_eq!(
            client
                .workspace_bootstrap_matches(&opts(), &claim_name(ENV), CLAIM_UID, &expected_pod())
                .await
                .unwrap(),
            actual
        );
    }
}

#[tokio::test]
async fn immutable_pod_tuple_rejects_duplicate_source_and_identity_changes() {
    for invalid in 0..5 {
        let mut fixture = fixture();
        fixture.pod["spec"]["containers"][1]["env"] = json!(
            workspace_bootstrap_values(&opts())
                .unwrap()
                .iter()
                .map(|(name, value)| json!({"name":name,"value":value}))
                .collect::<Vec<_>>()
        );
        match invalid {
            0 => fixture.pod["spec"]["containers"][1]["env"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":WORKSPACE_BOOTSTRAP_KEYS[0],"value":ENV})),
            1 => {
                fixture.pod["spec"]["containers"][1]["env"][0]["valueFrom"] =
                    json!({"fieldRef":{"fieldPath":"metadata.name"}})
            }
            2 => fixture.pod["metadata"]["uid"] = json!("new-pod"),
            3 => fixture.pod["metadata"]["ownerReferences"][0]["uid"] = json!("new-sandbox"),
            4 => {
                fixture.sandbox["metadata"]["annotations"]["agents.x-k8s.io/pod-name"] =
                    json!("other-pod")
            }
            _ => unreachable!(),
        }
        let (client, _) = client(fixture);
        let result = client
            .workspace_bootstrap_matches(&opts(), &claim_name(ENV), CLAIM_UID, &expected_pod())
            .await;
        if invalid < 2 {
            assert!(!result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn suspension_requires_one_current_generation_controller_completion() {
    let original = fixture().sandbox;
    assert!(sandbox_suspension_observed(&dynamic(&original)));
    for invalid in 0..7 {
        let mut sandbox = original.clone();
        match invalid {
            0 => sandbox["spec"]["operatingMode"] = json!("Running"),
            1 => sandbox["status"]["conditions"][0]["status"] = json!("False"),
            2 => sandbox["status"]["conditions"][0]["status"] = json!("Unknown"),
            3 => sandbox["status"]["conditions"][0]["reason"] = json!("PodTerminating"),
            4 => sandbox["status"]["conditions"][0]["observedGeneration"] = json!(8),
            5 => sandbox["metadata"]["generation"] = json!(0),
            6 => {
                let duplicate = sandbox["status"]["conditions"][0].clone();
                sandbox["status"]["conditions"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            _ => unreachable!(),
        }
        assert!(!sandbox_suspension_observed(&dynamic(&sandbox)));
    }
}

#[tokio::test]
async fn suspension_uses_only_owned_claim_and_sandbox_even_with_stale_claim_generation() {
    let (client, state) = client(fixture());
    assert!(
        client
            .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap()
            .is_some()
    );
    let state = state.lock().unwrap();
    assert_eq!(state.requests.len(), 2);
    assert!(
        state
            .requests
            .iter()
            .all(|(method, path, _)| *method == Method::GET
                && (path.contains("/sandboxclaims/") || path.contains("/sandboxes/")))
    );
}

#[tokio::test]
async fn refresh_refuses_rebound_or_no_longer_completed_suspension_before_every_write() {
    for invalid in 0..6 {
        let (client, state) = client(fixture());
        let suspended = client
            .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap()
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            match invalid {
                0 => state.sandbox["spec"]["operatingMode"] = json!("Running"),
                1 => state.sandbox["status"]["conditions"][0]["status"] = json!("False"),
                2 => state.sandbox["metadata"]["generation"] = json!(10),
                3 => state.sandbox["metadata"]["uid"] = json!("rebound-sandbox"),
                4 => {
                    state.claim["status"]["sandbox"]["name"] = json!("rebound-name");
                    state.sandbox["metadata"]["name"] = json!("rebound-name");
                }
                5 => state.claim["metadata"]["uid"] = json!("replacement-claim"),
                _ => unreachable!(),
            }
        }
        assert!(
            client
                .reconcile_workspace_bootstrap(&opts(), &claim_name(ENV), CLAIM_UID, &suspended)
                .await
                .is_err(),
            "invalid suspension case {invalid}"
        );
        assert!(
            state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|(method, _, _)| *method == Method::GET)
        );
    }
}

#[tokio::test]
async fn pinned_resume_retains_completed_suspension_across_bootstrap_generation_change() {
    let (client, state) = client(fixture());
    let suspended = client
        .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
        .await
        .unwrap()
        .unwrap();
    client
        .reconcile_workspace_bootstrap(&opts(), &claim_name(ENV), CLAIM_UID, &suspended)
        .await
        .unwrap();
    {
        let mut state = state.lock().unwrap();
        // The apiserver advances these for the preceding spec publication;
        // the controller's completed suspension still acknowledges generation9.
        state.sandbox["metadata"]["generation"] = json!(10);
        state.sandbox["metadata"]["resourceVersion"] = json!("31");
        assert!(!sandbox_suspension_observed(&dynamic(&state.sandbox)));
    }
    client
        .set_replicas_for_identity(&claim_opts(), &claim_name(ENV), CLAIM_UID, &suspended, 1)
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.sandbox["spec"]["operatingMode"], "Running");
    let (_, path, patch) = state
        .requests
        .iter()
        .rev()
        .find(|(method, _, _)| *method == Method::PATCH)
        .unwrap();
    assert!(path.ends_with(SANDBOX));
    assert_eq!(
        patch,
        &json!([
            {"op":"test","path":"/metadata/uid","value":"sandbox-incarnation"},
            {"op":"test","path":"/metadata/resourceVersion","value":"31"},
            {"op":"test","path":"/spec/operatingMode","value":"Suspended"},
            {"op":"add","path":"/spec/operatingMode","value":"Running"}
        ])
    );
}

#[tokio::test]
async fn pinned_resume_refuses_replaced_claim_sandbox_or_running_target_without_writes() {
    for invalid in 0..4 {
        let (client, state) = client(fixture());
        let suspended = client
            .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap()
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            match invalid {
                0 => state.claim["metadata"]["uid"] = json!("replacement-claim"),
                1 => state.sandbox["metadata"]["uid"] = json!("replacement-sandbox"),
                2 => {
                    state.claim["status"]["sandbox"]["name"] = json!("replacement-name");
                    state.sandbox["metadata"]["name"] = json!("replacement-name");
                }
                3 => state.sandbox["spec"]["operatingMode"] = json!("Running"),
                _ => unreachable!(),
            }
        }
        assert!(
            client
                .set_replicas_for_identity(
                    &claim_opts(),
                    &claim_name(ENV),
                    CLAIM_UID,
                    &suspended,
                    1
                )
                .await
                .is_err(),
            "replacement case {invalid}"
        );
        assert!(
            state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|(method, _, _)| *method == Method::GET)
        );
    }
}

#[tokio::test]
async fn pinned_resume_conditional_races_fail_without_retry_or_replacement_success() {
    for race in [
        Race::SandboxUid,
        Race::SandboxVersion,
        Race::SandboxMode,
        Race::ClaimAfterPatch,
    ] {
        let mut fixture = fixture();
        fixture.race = Some(race);
        let (client, state) = client(fixture);
        let suspended = client
            .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap()
            .unwrap();
        assert!(
            client
                .set_replicas_for_identity(
                    &claim_opts(),
                    &claim_name(ENV),
                    CLAIM_UID,
                    &suspended,
                    1
                )
                .await
                .is_err()
        );
        let state = state.lock().unwrap();
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|(method, _, _)| *method == Method::PATCH)
                .count(),
            1
        );
        if matches!(race, Race::SandboxUid | Race::SandboxVersion) {
            assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
        }
        assert!(
            state
                .requests
                .iter()
                .all(|(_, path, _)| !path.contains("/pods/"))
        );
    }
}

#[tokio::test]
async fn exact_claim_suspend_needs_no_pod_and_does_not_certify_completion() {
    let mut fixture = fixture();
    fixture.sandbox["spec"]["operatingMode"] = json!("Running");
    fixture.sandbox["status"]["conditions"][0]["status"] = json!("False");
    let (client, state) = client(fixture);
    client
        .suspend_workspace(&claim_opts(), &claim_name(ENV), CLAIM_UID)
        .await
        .unwrap();
    assert!(
        client
            .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap()
            .is_none()
    );
    let state = state.lock().unwrap();
    assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
    let patches: Vec<_> = state
        .requests
        .iter()
        .filter(|(method, _, _)| *method == Method::PATCH)
        .collect();
    assert_eq!(patches.len(), 1);
    assert_eq!(
        patches[0].2,
        json!([
            {"op":"test","path":"/metadata/uid","value":"sandbox-incarnation"},
            {"op":"test","path":"/metadata/resourceVersion","value":"30"},
            {"op":"add","path":"/spec/operatingMode","value":"Suspended"}
        ])
    );
    assert!(
        state
            .requests
            .iter()
            .all(|(_, path, _)| !path.contains("/pods/"))
    );
}

#[tokio::test]
async fn exact_claim_suspend_refuses_wrong_claim_or_owner_before_every_write() {
    for invalid in 0..5 {
        let mut fixture = fixture();
        fixture.sandbox["spec"]["operatingMode"] = json!("Running");
        match invalid {
            0 => fixture.claim["metadata"]["uid"] = json!("replacement-claim"),
            1 => fixture.sandbox["metadata"]["ownerReferences"][0]["uid"] = json!("foreign-claim"),
            2 => fixture.sandbox["metadata"]["ownerReferences"][0]["controller"] = json!(false),
            3 => fixture.claim["metadata"]["labels"][LABEL_ORG_ID] = json!("foreign-org"),
            4 => fixture.sandbox["metadata"]["resourceVersion"] = json!(""),
            _ => unreachable!(),
        }
        let (client, state) = client(fixture);
        assert!(
            client
                .suspend_workspace(&claim_opts(), &claim_name(ENV), CLAIM_UID)
                .await
                .is_err(),
            "invalid owner case {invalid}"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.sandbox["spec"]["operatingMode"], "Running");
        assert!(
            state
                .requests
                .iter()
                .all(|(method, _, _)| *method == Method::GET)
        );
    }
}

#[tokio::test]
async fn exact_claim_suspend_fences_replacement_during_conditional_write() {
    for race in [
        Race::SandboxUid,
        Race::SandboxVersion,
        Race::ClaimAfterPatch,
    ] {
        let mut fixture = fixture();
        fixture.sandbox["spec"]["operatingMode"] = json!("Running");
        fixture.race = Some(race);
        let (client, state) = client(fixture);
        assert!(
            client
                .suspend_workspace(&claim_opts(), &claim_name(ENV), CLAIM_UID)
                .await
                .is_err()
        );
        let state = state.lock().unwrap();
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|(method, _, _)| *method == Method::PATCH)
                .count(),
            1
        );
        if matches!(race, Race::SandboxUid | Race::SandboxVersion) {
            assert_eq!(state.sandbox["spec"]["operatingMode"], "Running");
        }
        assert!(
            state
                .requests
                .iter()
                .all(|(_, path, _)| !path.contains("/pods/"))
        );
    }
}

fn install_selected_client_recipe(fixture: &mut Fixture, opts: &TemplateOpts) {
    let expected = workspace_bootstrap_values(opts).unwrap();
    let clients = super::super::template::render_workspace_client_bootstrap(opts);
    for object in [&mut fixture.template, &mut fixture.sandbox] {
        if let Some(Patch::Json(patch)) =
            workspace_bootstrap_patch(&dynamic(object), &expected, None, &clients).unwrap()
        {
            assert!(apply_patch_fixture(
                object,
                &serde_json::to_value(patch).unwrap()
            ));
        }
    }
    fixture.pod["spec"] = fixture.sandbox["spec"]["podTemplate"]["spec"].clone();
}

const LEGACY_CODEX_HOME: &str = "/run/codewire-codex/home";

/// The Codex recipe orchestration rendered before the daemon wrote
/// `~/.codex`: a per-environment ConfigMap, a memory home mounted in the
/// workspace, an init copy between them and `CODEX_HOME` in that home. An
/// image-volume Pod had a separate client-bootstrap init container instead
/// of extending the daemon copy.
fn install_legacy_codex_recipe(fixture: &mut Fixture) {
    let mut legacy = opts();
    legacy.managed_credential_clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
    install_selected_client_recipe(fixture, &legacy);
    let copy = format!(
        " && mkdir -p -m 0700 {LEGACY_CODEX_HOME} && cp /codewire/codex-bootstrap/config.toml {LEGACY_CODEX_HOME}/config.toml"
    );
    let init_mounts = json!([
        {"name":"credential-codex-config","mountPath":"/codewire/codex-bootstrap","readOnly":true},
        {"name":"credential-codex-home","mountPath":"/run/codewire-codex"},
    ]);
    for spec in [
        &mut fixture.template["spec"]["podTemplate"]["spec"],
        &mut fixture.sandbox["spec"]["podTemplate"]["spec"],
        &mut fixture.pod["spec"],
    ] {
        let volumes = spec["volumes"].as_array_mut().unwrap();
        let image_volume = volumes.iter().any(|volume| volume.get("image").is_some());
        volumes.push(json!({"name":"credential-codex-config","configMap":{"name":format!("cw-credential-codex-{ENV}"),"defaultMode":0o644}}));
        volumes.push(json!({"name":"credential-codex-home","emptyDir":{"medium":"Memory","sizeLimit":"256Mi"}}));
        spec["containers"][1]["volumeMounts"] =
            json!([{"name":"credential-codex-home","mountPath":"/run/codewire-codex"}]);
        for entry in spec["containers"][1]["env"].as_array_mut().unwrap() {
            if entry["name"] == "CODEX_HOME" {
                entry["value"] = json!(LEGACY_CODEX_HOME);
            }
        }
        if image_volume {
            spec["initContainers"] = json!([{
                "name":"codewire-client-bootstrap", "image":DAEMON_IMAGE,
                "command":["sh","-c",format!("umask 077{copy}")],
                "volumeMounts":init_mounts,
            }]);
        } else {
            let init = &mut spec["initContainers"][0];
            init["command"][2] = json!(format!("{}{copy}", init["command"][2].as_str().unwrap()));
            init["volumeMounts"]
                .as_array_mut()
                .unwrap()
                .extend(init_mounts.as_array().unwrap().iter().cloned());
        }
    }
}

/// Rollback (`environment-token`) and confidential Pods keep their
/// environment-scope recipe. A suspended legacy Codex recipe converges on the
/// next start: no Codex volume, mount or init copy remains, only `CODEX_HOME`
/// at `~/.codex` when Codex stays selected. The old Pod is stale exactly once;
/// the Pod rendered from the converged Sandbox certifies, so the
/// bootstrap-mismatch restart cannot repeat (#2364).
#[tokio::test]
async fn suspended_legacy_codex_recipe_converges_and_preserves_unrelated_spec() {
    for slots in [vec![], vec!["openai"], vec!["github"], vec!["codex"]] {
        let mut fixture = fixture();
        install_legacy_codex_recipe(&mut fixture);
        let (client, state) = client(fixture);
        let mut target = opts();
        target.managed_credential_clients =
            codewire_access::ManagedCredentialClients::from_profile_slots(slots).unwrap();
        client
            .reconcile_workspace_bootstrap(
                &target,
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox(),
            )
            .await
            .unwrap();
        assert!(
            !client
                .workspace_bootstrap_matches(&target, &claim_name(ENV), CLAIM_UID, &expected_pod())
                .await
                .unwrap(),
            "old immutable Codex Pod must not certify replacement"
        );
        {
            let mut state = state.lock().unwrap();
            for object in [&state.template, &state.sandbox] {
                let spec = &object["spec"]["podTemplate"]["spec"];
                for legacy in ["credential-codex", "codex-bootstrap", "/run/codewire-codex"] {
                    assert!(!spec.to_string().contains(legacy), "{legacy}");
                }
                assert_eq!(
                    spec["containers"][1]["env"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|entry| entry["name"] == "CODEX_HOME")
                        .map(|entry| entry["value"].clone()),
                    target
                        .managed_credential_clients
                        .contains(codewire_access::ManagedCredentialClient::Codex)
                        .then(|| json!(codewire_access::CODEX_PLATFORM_HOME))
                );
                assert_eq!(
                    spec["initContainers"],
                    json!([
                        super::super::template::render_workspace_client_bootstrap(&target)["init"]
                    ])
                );
                assert_eq!(
                    spec["containers"][1]["resources"]["requests"]["cpu"],
                    "900m"
                );
                assert_eq!(
                    spec["volumes"][0]["persistentVolumeClaim"]["claimName"],
                    "saved-pvc"
                );
                assert!(
                    spec["containers"][1]["env"]
                        .as_array()
                        .unwrap()
                        .contains(&json!({"name":"UNRELATED","value":"preserve"}))
                );
                assert!(
                    bootstrap_template_matches(
                        &dynamic(object),
                        &workspace_bootstrap_values(&target).unwrap()
                    )
                    .unwrap()
                );
            }
            state.pod["spec"] = state.sandbox["spec"]["podTemplate"]["spec"].clone();
            state.pod["metadata"]["uid"] = json!("replacement-pod");
        }
        assert!(
            client
                .workspace_bootstrap_matches(
                    &target,
                    &claim_name(ENV),
                    CLAIM_UID,
                    &WorkspacePodIdentity {
                        name: POD.into(),
                        uid: "replacement-pod".into()
                    }
                )
                .await
                .unwrap()
        );
        // A second start publishes nothing, and nothing creates a ConfigMap.
        let writes = state.lock().unwrap().requests.len();
        client
            .reconcile_workspace_bootstrap(
                &target,
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox(),
            )
            .await
            .unwrap();
        let state = state.lock().unwrap();
        assert!(
            state.requests[writes..]
                .iter()
                .all(|(method, _, _)| *method == Method::GET)
        );
        assert!(
            state
                .requests
                .iter()
                .all(|(_, path, _)| !path.contains("/configmaps"))
        );
        assert!(state.config_map.is_none());
    }
}

#[tokio::test]
async fn actual_pod_clients_require_exact_token_env_mounts_and_init_not_just_selection_sha() {
    let mut opts = opts();
    opts.managed_credential_clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
    let mut current = fixture();
    install_selected_client_recipe(&mut current, &opts);
    let (current, _) = client(current);
    assert!(
        current
            .workspace_bootstrap_matches(&opts, &claim_name(ENV), CLAIM_UID, &expected_pod())
            .await
            .unwrap()
    );
    for corruption in 0..7 {
        let mut fixture = fixture();
        install_selected_client_recipe(&mut fixture, &opts);
        match corruption {
            0 => {
                let token = fixture.pod["spec"]["containers"][1]["env"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|entry| entry["name"] == WORKSPACE_BOOTSTRAP_KEYS[3])
                    .unwrap();
                token["value"] = json!("v1:openai");
            }
            1 => fixture.pod["spec"]["containers"][1]["env"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"OPENAI_API_KEY","value":"unexpected-routing-placeholder"})),
            // A Pod that still carries any piece of the legacy Codex recipe.
            2 => fixture.pod["spec"]["volumes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"credential-codex-home","emptyDir":{"medium":"Memory","sizeLimit":"256Mi"}})),
            3 => {
                fixture.pod["spec"]["containers"][1]["volumeMounts"] =
                    json!([{"name":"credential-codex-home","mountPath":"/run/codewire-codex"}]);
            }
            4 => fixture.pod["spec"]["initContainers"][0]["command"] = json!(["sh", "-c", "true"]),
            5 => fixture.pod["spec"]["initContainers"][0]["volumeMounts"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"credential-codex-config","mountPath":"/codewire/codex-bootstrap","readOnly":true})),
            6 => fixture.pod["spec"]["containers"][1]["env"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry["name"] == "CODEX_HOME")
                .unwrap()["value"] = json!(LEGACY_CODEX_HOME),
            _ => unreachable!(),
        }
        let (client, _) = client(fixture);
        assert!(
            !client
                .workspace_bootstrap_matches(&opts, &claim_name(ENV), CLAIM_UID, &expected_pod())
                .await
                .unwrap(),
            "corruption {corruption}"
        );
    }
}

#[tokio::test]
async fn stored_pod_omitting_blank_client_values_still_certifies_its_bootstrap() {
    let mut opts = opts();
    opts.managed_credential_clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(["openai", "anthropic"])
            .unwrap();
    // The Pod API omits an empty `value`, so a stored Pod keeps only the name
    // of each blank placeholder the Anthropic client renders.
    let stored = |opts: &TemplateOpts| {
        let mut fixture = fixture();
        install_selected_client_recipe(&mut fixture, opts);
        let mut blank = Vec::new();
        for entry in fixture.pod["spec"]["containers"][1]["env"]
            .as_array_mut()
            .unwrap()
        {
            if entry["value"] == "" {
                entry.as_object_mut().unwrap().remove("value");
                blank.push(entry["name"].as_str().unwrap().to_owned());
            }
        }
        (fixture, blank)
    };
    let (fixture, blank) = stored(&opts);
    assert!(blank.contains(&"ANTHROPIC_API_KEY".to_owned()), "{blank:?}");
    let (stored_client, _) = client(fixture);
    assert!(
        stored_client
            .workspace_bootstrap_matches(&opts, &claim_name(ENV), CLAIM_UID, &expected_pod())
            .await
            .unwrap()
    );

    // A placeholder that must stay blank still fails when it carries a value.
    let (mut fixture, _) = stored(&opts);
    fixture.pod["spec"]["containers"][1]["env"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| entry["name"] == "ANTHROPIC_API_KEY")
        .unwrap()["value"] = json!("unexpected-routing-placeholder");
    let (valued_client, _) = client(fixture);
    assert!(
        !valued_client
            .workspace_bootstrap_matches(&opts, &claim_name(ENV), CLAIM_UID, &expected_pod())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn newly_selected_codex_publishes_only_its_environment_and_no_config_map() {
    let (client, state) = client(fixture());
    let mut opts = opts();
    opts.managed_credential_clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert!(state.requests.iter().all(|(_, path, _)| {
        !path.contains("/configmaps") && !path.contains("/secrets") && !path.contains("/pods/")
    }));
    assert!(state.config_map.is_none());
    for object in [&state.template, &state.sandbox] {
        let spec = &object["spec"]["podTemplate"]["spec"];
        assert!(!spec.to_string().contains("credential-codex"));
        assert!(
            spec["containers"][1]["env"].as_array().unwrap().contains(
                &json!({"name":"CODEX_HOME","value":codewire_access::CODEX_PLATFORM_HOME})
            )
        );
        assert!(
            workspace_client_changes(
                object,
                &super::super::template::render_workspace_client_bootstrap(&opts),
                "/spec/podTemplate/spec"
            )
            .unwrap()
            .is_empty()
        );
    }
}

const DAEMON_IMAGE: &str = "registry.example.invalid/codewire/gateway@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab";

/// A commodity recipe whose daemon is an image volume: no init container
/// until a selected client needs its bootstrap.
fn image_volume_fixture() -> Fixture {
    let mut fixture = fixture();
    for spec in [
        &mut fixture.template["spec"]["podTemplate"]["spec"],
        &mut fixture.sandbox["spec"]["podTemplate"]["spec"],
        &mut fixture.pod["spec"],
    ] {
        spec.as_object_mut().unwrap().remove("initContainers");
        spec["volumes"].as_array_mut().unwrap().push(json!({
            "name":"codewire-bin","image":{"reference":DAEMON_IMAGE,"pullPolicy":"IfNotPresent"}
        }));
    }
    fixture
}

fn with_clients(slots: &[&str]) -> TemplateOpts {
    let mut opts = opts();
    opts.managed_credential_clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().copied())
            .unwrap();
    opts
}

/// An image-volume Pod's legacy client bootstrap is removed on the next
/// start, and no selection adds one back.
#[tokio::test]
async fn image_volume_legacy_client_bootstrap_is_removed_and_never_added() {
    let codex = with_clients(&["codex"]);
    // A current image-volume recipe gains no init container for Codex.
    let (fresh, fresh_state) = client(image_volume_fixture());
    fresh
        .reconcile_workspace_bootstrap(&codex, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    assert!(
        fresh_state.lock().unwrap().sandbox["spec"]["podTemplate"]["spec"]
            .get("initContainers")
            .is_none()
    );

    let mut legacy = image_volume_fixture();
    install_legacy_codex_recipe(&mut legacy);
    assert_eq!(
        legacy.pod["spec"]["initContainers"][0]["name"],
        "codewire-client-bootstrap"
    );
    let (client, state) = client(legacy);
    client
        .reconcile_workspace_bootstrap(&codex, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    {
        let state = state.lock().unwrap();
        for object in [&state.template, &state.sandbox] {
            let spec = &object["spec"]["podTemplate"]["spec"];
            assert_eq!(spec["initContainers"], json!([]));
            assert!(!spec.to_string().contains("codewire-daemon-init"));
            assert!(!spec.to_string().contains("credential-codex"));
            assert!(
                spec["volumes"]
                    .as_array()
                    .unwrap()
                    .contains(&json!({"name":"codewire-bin","image":{"reference":DAEMON_IMAGE,"pullPolicy":"IfNotPresent"}}))
            );
            assert_eq!(
                spec["volumes"][0]["persistentVolumeClaim"]["claimName"],
                "saved-pvc"
            );
        }
    }
    assert!(
        !client
            .workspace_bootstrap_matches(&codex, &claim_name(ENV), CLAIM_UID, &expected_pod())
            .await
            .unwrap(),
        "a Pod with the legacy client bootstrap must not certify its removal"
    );
    let replacement = WorkspacePodIdentity {
        name: POD.into(),
        uid: "replacement-pod".into(),
    };
    {
        let mut state = state.lock().unwrap();
        state.pod["spec"] = state.sandbox["spec"]["podTemplate"]["spec"].clone();
        state.pod["metadata"]["uid"] = json!("replacement-pod");
    }
    for (index, selection) in [codex.clone(), with_clients(&[])].iter().enumerate() {
        if index > 0 {
            client
                .reconcile_workspace_bootstrap(
                    selection,
                    &claim_name(ENV),
                    CLAIM_UID,
                    &expected_sandbox(),
                )
                .await
                .unwrap();
            let mut state = state.lock().unwrap();
            state.pod["spec"] = state.sandbox["spec"]["podTemplate"]["spec"].clone();
        }
        assert!(
            client
                .workspace_bootstrap_matches(selection, &claim_name(ENV), CLAIM_UID, &replacement)
                .await
                .unwrap()
        );
        // Reconciling the same selection again writes nothing.
        let writes = state.lock().unwrap().requests.len();
        client
            .reconcile_workspace_bootstrap(
                selection,
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox(),
            )
            .await
            .unwrap();
        assert!(
            state.lock().unwrap().requests[writes..]
                .iter()
                .all(|(method, _, _)| *method != Method::PATCH)
        );
        let state = state.lock().unwrap();
        assert_eq!(
            state.sandbox["spec"]["podTemplate"]["spec"]["initContainers"],
            json!([])
        );
    }
}

#[test]
fn daemon_delivery_must_be_exactly_one_route() {
    let clients = super::super::template::render_workspace_client_bootstrap(&with_clients(&[]));
    let legacy = blueprint();
    assert!(
        workspace_client_changes(&legacy, &clients, "/spec")
            .unwrap()
            .is_empty()
    );
    let image = image_volume_fixture().pod;
    assert!(
        workspace_client_changes(&image, &clients, "/spec")
            .unwrap()
            .is_empty()
    );

    let daemon_init = legacy["spec"]["initContainers"][0].clone();
    let mut client_init = clients["init"].clone();
    client_init["name"] = json!("codewire-client-bootstrap");
    let mut both_routes = image.clone();
    both_routes["spec"]["initContainers"] = json!([daemon_init]);
    let mut neither_route = legacy.clone();
    neither_route["spec"]["initContainers"] = json!([]);
    let mut copy_with_client_init = legacy.clone();
    copy_with_client_init["spec"]["initContainers"]
        .as_array_mut()
        .unwrap()
        .push(client_init.clone());
    let mut duplicate_client_init = image.clone();
    duplicate_client_init["spec"]["initContainers"] = json!([client_init, client_init]);
    let mut duplicate_daemon_volume = image.clone();
    duplicate_daemon_volume["spec"]["volumes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"codewire-bin","emptyDir":{}}));
    let mut unnamed_image = image.clone();
    unnamed_image["spec"]["volumes"][1]["image"] = json!({"pullPolicy":"IfNotPresent"});
    for (case, spec) in [
        ("both routes", both_routes),
        ("neither route", neither_route),
        ("copy with client init", copy_with_client_init),
        ("duplicate client init", duplicate_client_init),
        ("duplicate daemon volume", duplicate_daemon_volume),
        ("image without reference", unnamed_image),
    ] {
        assert!(
            workspace_client_changes(&spec, &clients, "/spec").is_err(),
            "{case}"
        );
    }
}

// ------------------------------------------ identity-free upgrade (B2 §12)

fn binding_opts() -> TemplateOpts {
    TemplateOpts {
        server_namespace: "dev".into(),
        workspace_identity: super::super::template::WorkspaceIdentity::Binding {
            binding_url:
                "http://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087".into(),
        },
        ..opts()
    }
}

fn legacy_fixture() -> Fixture {
    let mut fixture = fixture();
    for object in [&mut fixture.template, &mut fixture.sandbox] {
        object["spec"]["podTemplate"]["spec"]["containers"][1]["env"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"name":"CODEWIRE_DAEMON_AUTH_TOKEN","value":"synthetic-daemon-capability"}),
            );
    }
    fixture
}

fn patches(state: &Fixture) -> Vec<&Value> {
    state
        .requests
        .iter()
        .filter(|(method, _, _)| *method == Method::PATCH)
        .map(|(_, _, patch)| patch)
        .collect()
}

/// With the mode at `binding`, start replaces a suspended legacy
/// environment's whole workspace Pod spec in its template and Sandbox, and
/// the template's egress, keeping volumeClaimTemplates and Pod metadata, so
/// the resumed Pod binds with Pod scope. A second start changes nothing.
#[tokio::test]
async fn binding_mode_upgrades_a_suspended_legacy_environment_on_start() {
    let before = legacy_fixture();
    let original_metadata = before.sandbox["spec"]["podTemplate"]["metadata"].clone();
    let (sandboxes, state) = client(before);
    let opts = binding_opts();
    for _ in 0..2 {
        sandboxes
            .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
            .await
            .unwrap();
    }
    let state = state.lock().unwrap();
    let rendered = render_sandbox_template(NS, &opts);
    assert_eq!(patches(&state).len(), 2, "the second start must be a no-op");
    for object in [&state.template, &state.sandbox] {
        assert_eq!(
            object["spec"]["podTemplate"]["spec"],
            rendered["spec"]["podTemplate"]["spec"]
        );
        assert_eq!(
            object["spec"]["volumeClaimTemplates"],
            json!([{"fixture":"immutable"}])
        );
        assert!(
            !object["spec"]["podTemplate"]
                .to_string()
                .contains("CODEWIRE_DAEMON_AUTH_TOKEN")
        );
    }
    assert_eq!(
        state.template["spec"]["networkPolicy"],
        rendered["spec"]["networkPolicy"]
    );
    assert!(state.sandbox["spec"].get("networkPolicy").is_none());
    assert_eq!(
        state.sandbox["spec"]["podTemplate"]["metadata"],
        original_metadata
    );
    assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
    for patch in patches(&state) {
        assert_eq!(patch[0]["path"], "/metadata/uid");
        assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
    }
    // No Pod is read or written, and no Codex ConfigMap is created.
    assert!(
        state
            .requests
            .iter()
            .all(|(_, path, _)| !path.contains("/pods/"))
    );
    assert!(state.config_map.is_none());
}

/// A suspended legacy Codex environment upgrades to the identity-free
/// rendering, which carries no Codex volume, mount or init copy and no
/// `CODEX_HOME`: the bound daemon writes `~/.codex` and sets it for children.
#[tokio::test]
async fn binding_mode_upgrades_a_legacy_codex_environment_to_the_daemon_written_home() {
    let mut before = legacy_fixture();
    install_legacy_codex_recipe(&mut before);
    let (sandboxes, state) = client(before);
    let mut opts = binding_opts();
    opts.managed_credential_clients =
        codewire_access::ManagedCredentialClients::from_profile_slots(["codex"]).unwrap();
    for _ in 0..2 {
        sandboxes
            .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
            .await
            .unwrap();
    }
    let state = state.lock().unwrap();
    assert_eq!(patches(&state).len(), 2, "the second start must be a no-op");
    let rendered = render_sandbox_template(NS, &opts);
    for object in [&state.template, &state.sandbox] {
        let spec = &object["spec"]["podTemplate"]["spec"];
        assert_eq!(spec, &rendered["spec"]["podTemplate"]["spec"]);
        for legacy in [
            "credential-codex",
            "codex-bootstrap",
            "/run/codewire-codex",
            "CODEX_HOME",
        ] {
            assert!(!spec.to_string().contains(legacy), "{legacy}");
        }
    }
    assert!(state.config_map.is_none());
}

/// An identity-free environment created before the daemon wrote `~/.codex`
/// still mounts Codex's memory home. Its next start replaces its Pod spec
/// with the current identity-free rendering once; later starts are no-ops.
#[tokio::test]
async fn binding_mode_converges_an_identity_free_environment_with_a_memory_codex_home() {
    let mut before = fixture();
    let rendered = render_sandbox_template(NS, &binding_opts());
    for object in [&mut before.template, &mut before.sandbox] {
        let spec = &mut object["spec"]["podTemplate"]["spec"];
        *spec = rendered["spec"]["podTemplate"]["spec"].clone();
        spec["volumes"].as_array_mut().unwrap().push(
            json!({"name":"credential-codex-home","emptyDir":{"medium":"Memory","sizeLimit":"256Mi"}}),
        );
        spec["containers"][0]["volumeMounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"credential-codex-home","mountPath":"/run/codewire-codex"}));
    }
    before.template["metadata"]["labels"] = json!({});
    before.template["spec"]["networkPolicy"] = rendered["spec"]["networkPolicy"].clone();
    let (sandboxes, state) = client(before);
    for _ in 0..2 {
        sandboxes
            .reconcile_workspace_bootstrap(
                &binding_opts(),
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox(),
            )
            .await
            .unwrap();
    }
    let state = state.lock().unwrap();
    assert_eq!(patches(&state).len(), 2, "the second start must be a no-op");
    for object in [&state.template, &state.sandbox] {
        assert_eq!(
            object["spec"]["podTemplate"]["spec"],
            rendered["spec"]["podTemplate"]["spec"]
        );
    }
    assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
    assert!(
        state
            .requests
            .iter()
            .all(|(_, path, _)| !path.contains("/pods/") && !path.contains("/configmaps"))
    );
}

/// A conflicting write during the upgrade never reports success.
#[tokio::test]
async fn an_upgrade_that_races_another_writer_fails_closed() {
    for race in [
        Race::TemplateVersion,
        Race::SandboxVersion,
        Race::SandboxUid,
    ] {
        let mut before = legacy_fixture();
        before.race = Some(race);
        let (sandboxes, _) = client(before);
        assert!(
            sandboxes
                .reconcile_workspace_bootstrap(
                    &binding_opts(),
                    &claim_name(ENV),
                    CLAIM_UID,
                    &expected_sandbox()
                )
                .await
                .is_err()
        );
    }
}

/// Rollback (`environment-token`) renders legacy Pods for new environments
/// but leaves an identity-free one untouched: it keeps binding with Pod
/// scope. Its template carries no environment label; the environment-owned
/// shadow pool names it.
#[tokio::test]
async fn rollback_mode_leaves_an_identity_free_environment_untouched() {
    let mut before = fixture();
    let rendered = render_sandbox_template(NS, &binding_opts());
    for object in [&mut before.template, &mut before.sandbox] {
        object["spec"]["podTemplate"]["spec"] = rendered["spec"]["podTemplate"]["spec"].clone();
    }
    before.template["metadata"]["labels"] = json!({});
    let (sandboxes, state) = client(before);
    sandboxes
        .reconcile_workspace_bootstrap(&opts(), &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    // Binding mode accepts the unlabelled identity-free template too.
    sandboxes
        .reconcile_workspace_bootstrap(
            &binding_opts(),
            &claim_name(ENV),
            CLAIM_UID,
            &expected_sandbox(),
        )
        .await
        .unwrap();
    assert!(patches(&state.lock().unwrap()).is_empty());
}

/// Review L5: an upgrade interrupted after the template but before the
/// Sandbox is finished under rollback too, so the resumed Pod renders from an
/// identity-free Sandbox instead of looping on a legacy one beside an
/// identity-free template. The finished state is stable on the next start.
#[tokio::test]
async fn rollback_mode_finishes_a_partial_identity_upgrade() {
    for upgraded_template in [true, false] {
        let mut before = legacy_fixture();
        let rendered = render_sandbox_template(NS, &binding_opts());
        let upgraded = if upgraded_template {
            &mut before.template
        } else {
            &mut before.sandbox
        };
        upgraded["spec"]["podTemplate"]["spec"] = rendered["spec"]["podTemplate"]["spec"].clone();
        if upgraded_template {
            before.template["spec"]["networkPolicy"] = rendered["spec"]["networkPolicy"].clone();
        }
        let (sandboxes, state) = client(before);
        let rollback = TemplateOpts {
            server_namespace: "dev".into(),
            ..opts()
        };
        for _ in 0..2 {
            sandboxes
                .reconcile_workspace_bootstrap(
                    &rollback,
                    &claim_name(ENV),
                    CLAIM_UID,
                    &expected_sandbox(),
                )
                .await
                .unwrap();
        }
        let state = state.lock().unwrap();
        assert_eq!(
            patches(&state).len(),
            1,
            "only the legacy half is patched, once"
        );
        for object in [&state.template, &state.sandbox] {
            assert_eq!(
                object["spec"]["podTemplate"]["spec"],
                rendered["spec"]["podTemplate"]["spec"]
            );
        }
        assert_eq!(
            state.template["spec"]["networkPolicy"],
            rendered["spec"]["networkPolicy"]
        );
        assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
    }

    // Without the orchestration namespace the half upgrade is refused, never
    // skipped.
    let mut before = legacy_fixture();
    before.template["spec"]["podTemplate"]["spec"] =
        render_sandbox_template(NS, &binding_opts())["spec"]["podTemplate"]["spec"].clone();
    let (sandboxes, state) = client(before);
    assert!(
        sandboxes
            .reconcile_workspace_bootstrap(
                &opts(),
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox()
            )
            .await
            .is_err()
    );
    assert!(patches(&state.lock().unwrap()).is_empty());
}

/// An unlabelled template that is not identity-free is not this
/// environment's, and an object rendering both identities is ambiguous.
#[tokio::test]
async fn unowned_or_ambiguous_templates_are_refused_without_writes() {
    let mut unlabelled = legacy_fixture();
    unlabelled.template["metadata"]["labels"] = json!({});
    let (sandboxes, state) = client(unlabelled);
    assert!(
        sandboxes
            .reconcile_workspace_bootstrap(
                &binding_opts(),
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox()
            )
            .await
            .is_err()
    );
    assert!(patches(&state.lock().unwrap()).is_empty());

    let mut ambiguous = legacy_fixture();
    ambiguous.sandbox["spec"]["podTemplate"]["spec"]["containers"][1]["env"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"CODEWIRE_WORKSPACE_BINDING_URL","value":"http://x:8087"}));
    let (sandboxes, state) = client(ambiguous);
    assert!(
        sandboxes
            .reconcile_workspace_bootstrap(
                &binding_opts(),
                &claim_name(ENV),
                CLAIM_UID,
                &expected_sandbox()
            )
            .await
            .is_err()
    );
    assert!(
        patches(&state.lock().unwrap())
            .iter()
            .all(|patch| !patch.to_string().contains("sandbox-incarnation"))
    );
}

// ------------------------------------- pool-born restart (Program #2238 C3)

const SHARED_POOL: &str = "cw-pool-1000m-4096mi-10gi-78909fe3";

/// A pool-born environment: its Claim selects a shared warm pool whose
/// template is Codewire's identity-free pool template, and the adopted
/// Sandbox carries that rendering.
fn pool_born_fixture() -> Fixture {
    let mut fixture = fixture();
    let rendered = render_sandbox_template(NS, &binding_opts());
    let labels =
        json!({"app.kubernetes.io/managed-by":"codewire","codewire.sh/type":"workspace-pool"});
    fixture.claim["spec"]["warmPoolRef"]["name"] = json!(SHARED_POOL);
    fixture.pool = json!({"apiVersion":super::super::EXTENSIONS_API_VERSION,"kind":"SandboxWarmPool",
        "metadata":{"name":SHARED_POOL,"namespace":NS,"uid":"shared-pool","labels":labels},
        "spec":{"replicas":2,"sandboxTemplateRef":{"name":SHARED_POOL},"updateStrategy":{"type":"Recreate"}}});
    fixture.template = json!({"apiVersion":super::super::EXTENSIONS_API_VERSION,"kind":"SandboxTemplate",
        "metadata":{"name":SHARED_POOL,"namespace":NS,"uid":"shared-template","resourceVersion":"20",
            "labels":labels},
        "spec":rendered["spec"].clone()});
    fixture.sandbox["spec"]["podTemplate"]["spec"] =
        rendered["spec"]["podTemplate"]["spec"].clone();
    fixture
}

/// Start accepts a shared pool while the owned Sandbox is identity-free, in
/// either identity mode, and never writes the shared template. A Sandbox
/// that still mounts Codex's retired memory home is upgraded alone.
#[tokio::test]
async fn a_pool_born_restart_never_writes_the_shared_template() {
    let (sandboxes, state) = client(pool_born_fixture());
    for opts in [binding_opts(), opts()] {
        sandboxes
            .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
            .await
            .unwrap();
    }
    assert!(patches(&state.lock().unwrap()).is_empty());

    let mut legacy_home = pool_born_fixture();
    for object in [&mut legacy_home.template, &mut legacy_home.sandbox] {
        object["spec"]["podTemplate"]["spec"]["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"credential-codex-home","emptyDir":{"medium":"Memory"}}));
    }
    let template_before = legacy_home.template.clone();
    let (sandboxes, state) = client(legacy_home);
    sandboxes
        .reconcile_workspace_bootstrap(
            &binding_opts(),
            &claim_name(ENV),
            CLAIM_UID,
            &expected_sandbox(),
        )
        .await
        .unwrap();
    let state = state.lock().unwrap();
    let written: Vec<&String> = state
        .requests
        .iter()
        .filter(|(method, _, _)| *method == Method::PATCH)
        .map(|(_, path, _)| path)
        .collect();
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(written[0].contains("/sandboxes/"));
    assert_eq!(state.template, template_before);
    assert!(
        !state.sandbox["spec"]["podTemplate"]
            .to_string()
            .contains("credential-codex-home")
    );
}

/// A legacy Sandbox under a shared pool, a pool or template that is not
/// Codewire's identity-free pool, is refused before any write.
#[tokio::test]
async fn a_pool_born_restart_refuses_anything_but_codewires_identity_free_pool() {
    type Case = (&'static str, fn(&mut Fixture));
    let cases: [Case; 4] = [
        ("legacy Sandbox", |fixture| {
            fixture.sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
                .as_array_mut()
                .unwrap()
                .retain(|entry| entry["name"] != "CODEWIRE_WORKSPACE_BINDING_URL");
        }),
        ("foreign pool", |fixture| {
            fixture.pool["metadata"]["labels"] = json!({});
        }),
        ("pool of another template", |fixture| {
            fixture.pool["spec"]["sandboxTemplateRef"]["name"] = json!("workspace-other");
        }),
        ("environment template", |fixture| {
            fixture.template["metadata"]["labels"][LABEL_ENV_ID] = json!(ENV);
        }),
    ];
    for (label, mutate) in cases {
        let mut before = pool_born_fixture();
        mutate(&mut before);
        let (sandboxes, state) = client(before);
        assert!(
            sandboxes
                .reconcile_workspace_bootstrap(
                    &binding_opts(),
                    &claim_name(ENV),
                    CLAIM_UID,
                    &expected_sandbox()
                )
                .await
                .is_err(),
            "{label} was accepted"
        );
        assert!(patches(&state.lock().unwrap()).is_empty(), "{label} wrote");
    }
}
