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
        workspace_binding_url: BINDING_URL.into(),
        support_image: DAEMON_IMAGE.into(),
        ..Default::default()
    }
}
const BINDING_URL: &str =
    "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087";
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
        json!({"name":"CODEWIRE_ENVIRONMENT_ID","value":ENV}),
        json!({"name":"CODEWIRE_ENVIRONMENT_OPERATION_GENERATION","value":"6"}),
        json!({"name":"CODEWIRE_ENVIRONMENT_PROJECTION_SHA256","value":"cd".repeat(32)}),
        json!({"name":"UNRELATED_FROM","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}}),
    ]
}
/// The daemon copy as a Sandbox renders it: the reconciled init container on
/// the image the Sandbox was created with.
fn daemon_init() -> Value {
    let copying = TemplateOpts {
        runtime_profile: super::super::template::RUNTIME_PROFILE_RUNC.into(),
        ..opts()
    };
    let mut init =
        render_sandbox_template(NS, &copying)["spec"]["podTemplate"]["spec"]["initContainers"][0]
            .clone();
    init["image"] = json!(DAEMON_IMAGE);
    init
}
fn blueprint() -> Value {
    json!({"metadata":{"labels":{"preserve":"label"},"annotations":{"preserve":"annotation"}},
        "spec":{"securityContext":{"runAsUser":1000,"fsGroupChangePolicy":"Always"},
            "volumes":[{"name":"workspace","persistentVolumeClaim":{"claimName":"saved-pvc"}}],
            "initContainers":[daemon_init()],
            "containers":[{"name":"dind","image":"unchanged-dind"},
                {"name":"workspace","image":"unchanged-workspace","command":["unchanged-entrypoint"],
                    "resources":{"requests":{"cpu":"900m"}},"env":old_env()}]}})
}
#[derive(Clone, Copy)]
enum Race {
    SandboxUid,
    SandboxVersion,
    /// Upstream JSON Patch test failure, with only resourceVersion changed.
    SandboxVersionApi422,
    SandboxVersionEveryPatchApi422,
    StableApi422,
    SandboxSpecApi422,
    ClaimSpecApi422,
    SandboxModeApi422,
    SandboxUidApi422,
    MalformedPatchResponse,
    PostPublicationRead409,
    PostPublicationRead422,
    SandboxMode,
    TemplateVersion,
    ClaimAfterPatch,
    /// Another writer changes the daemon volume's image before the patch.
    DaemonImage,
    /// Another writer inserts a volume ahead of the daemon volume.
    DaemonVolumeMoved,
    /// The controller updates the Sandbox before every write.
    SandboxVersionEveryPatch,
    /// Another writer replaces the workspace Pod once the Sandbox is read.
    PodReplacedOnSandboxRead,
    /// Another writer deletes the workspace Pod once the Sandbox is read.
    PodGoneOnSandboxRead,
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
            match parent {
                Value::Array(values) => {
                    values.remove(key.parse::<usize>().unwrap());
                }
                Value::Object(values) => {
                    values.remove(&key).expect("a removed member must exist");
                }
                _ => panic!("unexpected patch target"),
            }
        } else if operation["op"] == "replace" {
            let member = match parent {
                Value::Array(values) => values.get_mut(key.parse::<usize>().unwrap()),
                _ => parent.get_mut(&key),
            }
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
            if is_sandbox && method == Method::GET
                && matches!(state.race, Some(Race::PostPublicationRead409 | Race::PostPublicationRead422))
                && state.requests.iter().any(|(method, _, _)| *method == Method::PATCH) {
                let (code, reason) = if matches!(state.race, Some(Race::PostPublicationRead409)) { (409, "Conflict") } else { (422, "Invalid") };
                return Response::builder().status(code).header("content-type", "application/json")
                    .body(Body::from(json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":reason,"code":code}).to_string())).unwrap();
            }
            if method == Method::PATCH {
                if is_sandbox && matches!(state.race, Some(Race::SandboxUid)) { state.sandbox["metadata"]["uid"] = json!("replacement"); }
                if is_sandbox && matches!(state.race, Some(Race::SandboxVersion | Race::SandboxVersionApi422)) { state.sandbox["metadata"]["resourceVersion"] = json!("31"); }
                if is_sandbox && matches!(state.race, Some(Race::SandboxSpecApi422 | Race::ClaimSpecApi422 | Race::SandboxModeApi422 | Race::SandboxUidApi422)) {
                    state.sandbox["metadata"]["resourceVersion"] = json!("31");
                    match state.race {
                        Some(Race::SandboxSpecApi422) => { *daemon_reference_mut(&mut state.sandbox) = json!(CONCURRENT_DAEMON_IMAGE); }
                        Some(Race::ClaimSpecApi422) => { state.claim["spec"]["warmPoolRef"]["name"] = json!("another-pool"); }
                        Some(Race::SandboxModeApi422) => { state.sandbox["spec"]["operatingMode"] = json!("Running"); }
                        Some(Race::SandboxUidApi422) => { state.sandbox["metadata"]["uid"] = json!("replacement-sandbox"); }
                        _ => unreachable!(),
                    }
                }
                if is_sandbox && matches!(state.race, Some(Race::SandboxMode)) { state.sandbox["spec"]["operatingMode"] = json!("Running"); }
                if is_template && matches!(state.race, Some(Race::TemplateVersion)) { state.template["metadata"]["resourceVersion"] = json!("21"); }
                if is_sandbox && matches!(state.race, Some(Race::SandboxVersionEveryPatch | Race::SandboxVersionEveryPatchApi422)) {
                    let version: u64 = state.sandbox["metadata"]["resourceVersion"].as_str().unwrap().parse().unwrap();
                    state.sandbox["metadata"]["resourceVersion"] = json!((version + 1).to_string());
                }
                if is_sandbox && matches!(state.race, Some(Race::DaemonImage)) { *daemon_reference_mut(&mut state.sandbox) = json!(CONCURRENT_DAEMON_IMAGE); }
                if is_sandbox && matches!(state.race, Some(Race::DaemonVolumeMoved)) {
                    state.sandbox["spec"]["podTemplate"]["spec"]["volumes"].as_array_mut().unwrap()
                        .insert(0, json!({"name":"inserted","emptyDir":{}}));
                }
            }
            if method == Method::DELETE {
                assert!(path.ends_with(&format!("/pods/{POD}")), "only the workspace Pod is ever deleted");
                return Response::builder().status(StatusCode::OK).header("content-type","application/json")
                    .body(Body::from(json!({"apiVersion":"v1","kind":"Status","status":"Success","code":200}).to_string())).unwrap();
            }
            if is_sandbox && method == Method::GET {
                match state.race {
                    Some(Race::PodReplacedOnSandboxRead) => state.pod["metadata"]["uid"] = json!("replacement-pod"),
                    Some(Race::PodGoneOnSandboxRead) => state.pod = Value::Null,
                    _ => {}
                }
            }
            if path.contains("/pods/") && state.pod.is_null() {
                return Response::builder().status(StatusCode::NOT_FOUND).header("content-type","application/json")
                    .body(Body::from(json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}).to_string())).unwrap();
            }
            let upstream_422 = matches!(state.race, Some(Race::SandboxVersionApi422 | Race::SandboxVersionEveryPatchApi422 | Race::StableApi422 | Race::SandboxSpecApi422 | Race::ClaimSpecApi422 | Race::SandboxModeApi422 | Race::SandboxUidApi422));
            let stable_422 = is_sandbox && matches!(state.race, Some(Race::StableApi422));
            let malformed_reply = is_sandbox && method == Method::PATCH && matches!(state.race, Some(Race::MalformedPatchResponse));
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
                    if stable_422 { (StatusCode::UNPROCESSABLE_ENTITY, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Invalid","code":422,"message":"the server rejected our request due to an error in our request","details":{"causes":[]}})) }
                    else if apply_patch_fixture(object, &patch) { (StatusCode::OK, object.clone()) }
                    else if upstream_422 { (StatusCode::UNPROCESSABLE_ENTITY, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Invalid","code":422,"message":"the server rejected our request due to an error in our request","details":{"causes":[]}})) }
                    else { (StatusCode::CONFLICT, json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Conflict","code":409})) }
                };
            if is_sandbox && method == Method::PATCH && matches!(state.race, Some(Race::PostPublicationRead409 | Race::PostPublicationRead422)) {
                state.sandbox["metadata"]["resourceVersion"] = json!("31");
            }
            if is_sandbox && method == Method::PATCH && matches!(state.race, Some(Race::ClaimAfterPatch)) {
                state.claim["metadata"]["uid"] = json!("replacement-claim");
            }
            Response::builder().status(status).header("content-type","application/json")
                .body(Body::from(if malformed_reply { "{".to_owned() } else { body.to_string() })).unwrap()
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

fn expected_sandbox() -> WorkspaceSandboxIdentity {
    WorkspaceSandboxIdentity {
        name: SANDBOX.into(),
        uid: "sandbox-incarnation".into(),
    }
}

/// A confidential workspace as orchestration renders it (B2c).
fn measured_opts() -> TemplateOpts {
    TemplateOpts {
        runtime_profile: super::super::template::RUNTIME_PROFILE_CONFIDENTIAL.into(),
        workspace_binding_url: "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087"
                .into(),
        measured_binding_roots:
            "-----BEGIN CERTIFICATE-----\nMIIBsynthetic\n-----END CERTIFICATE-----\n".into(),
        confidential_storage_manifest_uri: "kbs:///default/codewire-storage-manifests/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        disk_gib: 20,
        kata_coco_init_data_enabled: true,
        kata_coco_kbs_url: "https://kbs.example.test".into(),
        ..opts()
    }
}

fn patch_count(state: &Fixture) -> usize {
    state
        .requests
        .iter()
        .filter(|(method, _, _)| *method == Method::PATCH)
        .count()
}

#[tokio::test]
async fn confidential_start_publishes_its_whole_measured_runtime_before_resume() {
    let opts = measured_opts();
    let measured = MeasuredPodTemplate::render(NS, &opts).unwrap();
    let (client, state) = client(fixture());
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    {
        let state = state.lock().unwrap();
        for object in [&state.template, &state.sandbox] {
            // Exactly the Pod the init-data authorizes: a legacy rendering's
            // env token and stale containers are gone.
            assert_eq!(
                object.pointer("/spec/podTemplate/spec"),
                Some(&measured.spec)
            );
            assert!(!object.to_string().contains("CODEWIRE_DAEMON_AUTH_TOKEN"));
            let annotations = object
                .pointer("/spec/podTemplate/metadata/annotations")
                .unwrap();
            for (key, value) in &measured.annotations {
                assert_eq!(
                    annotations.get(*key).and_then(Value::as_str),
                    value.as_deref()
                );
            }
            assert_eq!(annotations["preserve"], json!("annotation"));
            assert_eq!(
                annotations[KATA_COCO_INIT_DATA_ANNOTATION_KEY],
                json!(measured.init_data())
            );
        }
        assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
        assert_eq!(patch_count(&state), 2);
    }
    // Starting again with nothing changed writes nothing.
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    assert_eq!(patch_count(&state.lock().unwrap()), 2);
    // A changed measured input (here orchestration's roots, as after a CA
    // change; a release that changes the policy text behaves the same)
    // changes the init-data, so the next start republishes.
    let released = TemplateOpts {
        measured_binding_roots:
            "-----BEGIN CERTIFICATE-----\nMIIBrotated\n-----END CERTIFICATE-----\n".into(),
        ..measured_opts()
    };
    client
        .reconcile_workspace_bootstrap(&released, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(patch_count(&state), 4);
    let republished = MeasuredPodTemplate::render(NS, &released).unwrap();
    assert_ne!(republished.init_data(), measured.init_data());
    assert!(republished.published_on(&DynamicObject {
        types: None,
        metadata: Default::default(),
        data: state.sandbox.clone(),
    }));
}

/// A confidential template rendered before B2c carries the old egress, with
/// no route to the binding listener. Start republishes the rendered egress
/// onto the template even when the measurement is already current, and
/// never gives the Sandbox one.
#[tokio::test]
async fn confidential_start_republishes_a_stale_template_egress() {
    let opts = measured_opts();
    let measured = MeasuredPodTemplate::render(NS, &opts).unwrap();
    let rendered_egress = measured.network_policy.clone().expect("rendered egress");
    let (client, state) = client(fixture());
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    {
        let mut state = state.lock().unwrap();
        assert_eq!(state.template["spec"]["networkPolicy"], rendered_egress);
        assert!(state.sandbox["spec"].get("networkPolicy").is_none());
        state.template["spec"]["networkPolicy"] = json!({ "egress": [] });
    }
    let before = patch_count(&state.lock().unwrap());
    client
        .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
        .await
        .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(
        patch_count(&state),
        before + 1,
        "only the template is patched"
    );
    assert_eq!(state.template["spec"]["networkPolicy"], rendered_egress);
    assert!(state.sandbox["spec"].get("networkPolicy").is_none());
    assert!(measured.published_on(&DynamicObject {
        types: None,
        metadata: Default::default(),
        data: state.template.clone(),
    }));
}

#[tokio::test]
async fn confidential_start_refuses_a_rendering_without_measured_anchors() {
    let opts = TemplateOpts {
        measured_binding_roots: String::new(),
        ..measured_opts()
    };
    let (client, state) = client(fixture());
    assert!(
        client
            .reconcile_workspace_bootstrap(&opts, &claim_name(ENV), CLAIM_UID, &expected_sandbox())
            .await
            .is_err()
    );
    assert_eq!(patch_count(&state.lock().unwrap()), 0);
}

#[test]
fn a_measured_annotation_the_rendering_drops_is_removed() {
    let measured = MeasuredPodTemplate::render(
        NS,
        &TemplateOpts {
            kata_coco_kbs_url: String::new(),
            ..measured_opts()
        },
    )
    .unwrap();
    // Without a KBS URL there are no kernel parameters to measure.
    assert!(measured.annotations.iter().any(|(key, value)| {
        *key == KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY && value.is_none()
    }));
    let mut sandbox = fixture().sandbox;
    sandbox["spec"]["podTemplate"]["metadata"]["annotations"]
        [KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY] = json!("agent.log_vport=1025");
    let object: DynamicObject = serde_json::from_value(sandbox.clone()).unwrap();
    let Some(Patch::Json(patch)) = measured.json_patch(&object, false).unwrap() else {
        panic!("a stale measurement must be republished");
    };
    let patch = serde_json::to_value(patch).unwrap();
    assert!(apply_patch_fixture(&mut sandbox, &patch));
    assert!(
        sandbox["spec"]["podTemplate"]["metadata"]["annotations"]
            .get(KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY)
            .is_none()
    );
    let merge = measured.merge_patch();
    assert_eq!(
        merge["spec"]["podTemplate"]["metadata"]["annotations"]
            [KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY],
        Value::Null
    );
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
                fixture.claim["spec"]["env"] = json!([{"containerName":"workspace","name":codewire_daemon_proto::WORKSPACE_BINDING_URL_ENV,"value":"competing"}])
            }
            9 => {
                fixture.claim["spec"]["env"] = json!([{"name":codewire_daemon_proto::WORKSPACE_MEASURED_BINDING_ROOTS_ENV,"value":"competing-default"}])
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
        .set_replicas_for_identity(
            &claim_opts(),
            &claim_name(ENV),
            CLAIM_UID,
            &suspended,
            1,
            DAEMON_IMAGE,
        )
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
                    1,
                    DAEMON_IMAGE,
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
    for race in [Race::SandboxUid, Race::SandboxMode, Race::ClaimAfterPatch] {
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
                    1,
                    DAEMON_IMAGE,
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
    for race in [Race::SandboxUid, Race::ClaimAfterPatch] {
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

/// What a pre-binding rendering wrote for its selected clients: their
/// platform environment in the workspace container.
fn install_selected_client_recipe(fixture: &mut Fixture, opts: &TemplateOpts) {
    let env: Vec<Value> = opts
        .managed_credential_clients
        .for_placement(codewire_access::ManagedCredentialClientPlacement::Platform)
        .environment
        .into_iter()
        .map(|(name, value)| json!({"name":name,"value":value}))
        .collect();
    for spec in [
        &mut fixture.template["spec"]["podTemplate"]["spec"],
        &mut fixture.sandbox["spec"]["podTemplate"]["spec"],
    ] {
        spec["containers"][1]["env"]
            .as_array_mut()
            .unwrap()
            .extend(env.iter().cloned());
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

const DAEMON_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab";

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

// ------------------------------------------ identity-free upgrade (B2 §12)

fn binding_opts() -> TemplateOpts {
    TemplateOpts {
        server_namespace: "dev".into(),
        workspace_binding_url:
            "https://codewire-orchestration-workspace-binding.dev.svc.cluster.local:8087".into(),
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

// ------------------- daemon image re-pin on resume (owner decision 2026-10-05)

/// The image a Sandbox was created with, before a support-image rollout.
const OLD_DAEMON_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0";
const OLD_DAEMON_DIGEST: &str =
    "sha256:a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0a59dfec0";
const CONCURRENT_DAEMON_IMAGE: &str = "registry.example.invalid/codewire/daemon@sha256:3333333333333333333333333333333333333333333333333333333333333333";

fn daemon_reference_mut(object: &mut Value) -> &mut Value {
    object["spec"]["podTemplate"]["spec"]["volumes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|volume| volume["name"] == "codewire-bin")
        .map(|volume| &mut volume["image"]["reference"])
        .unwrap()
}

/// A suspended image-volume Sandbox, its per-environment template and its
/// old Pod, all still on the image the Sandbox was created with.
fn stale_daemon_fixture() -> Fixture {
    let mut fixture = image_volume_fixture();
    for object in [&mut fixture.template, &mut fixture.sandbox] {
        *daemon_reference_mut(object) = json!(OLD_DAEMON_IMAGE);
    }
    fixture.pod["spec"]["volumes"][1]["image"]["reference"] = json!(OLD_DAEMON_IMAGE);
    fixture
}

/// A suspended Sandbox that copies its daemon into an emptyDir (commodity
/// before the image volume, runc, Kind and confidential), on `runtime_class`.
fn stale_copy_fixture(runtime_class: Option<&str>) -> Fixture {
    let mut fixture = fixture();
    for spec in [
        &mut fixture.template["spec"]["podTemplate"]["spec"],
        &mut fixture.sandbox["spec"]["podTemplate"]["spec"],
        &mut fixture.pod["spec"],
    ] {
        spec["initContainers"][0]["image"] = json!(OLD_DAEMON_IMAGE);
        spec["volumes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"codewire-bin","emptyDir":{}}));
        if let Some(class) = runtime_class {
            spec["runtimeClassName"] = json!(class);
        }
    }
    fixture
}

/// The exact re-pin operations for the fixture's daemon volume, at index 1
/// behind the workspace PVC.
fn repin_operations(from: &str, to: &str) -> [Value; 3] {
    [
        json!({"op":"test","path":"/spec/podTemplate/spec/volumes/1/name","value":"codewire-bin"}),
        json!({"op":"test","path":"/spec/podTemplate/spec/volumes/1/image/reference","value":from}),
        json!({"op":"replace","path":"/spec/podTemplate/spec/volumes/1/image/reference","value":to}),
    ]
}

/// The exact re-pin operations for the fixture's daemon init container.
fn init_repin_operations(from: &str, to: &str) -> [Value; 3] {
    [
        json!({"op":"test","path":"/spec/podTemplate/spec/initContainers/0/name","value":"codewire-daemon-init"}),
        json!({"op":"test","path":"/spec/podTemplate/spec/initContainers/0/image","value":from}),
        json!({"op":"replace","path":"/spec/podTemplate/spec/initContainers/0/image","value":to}),
    ]
}

/// The pinned resume's patch: its fences, then `between`, then the mode.
fn pinned_resume_patch(version: &str, between: &[Value]) -> Value {
    let mut patch = vec![
        json!({"op":"test","path":"/metadata/uid","value":"sandbox-incarnation"}),
        json!({"op":"test","path":"/metadata/resourceVersion","value":version}),
        json!({"op":"test","path":"/spec/operatingMode","value":"Suspended"}),
    ];
    patch.extend_from_slice(between);
    patch.push(json!({"op":"add","path":"/spec/operatingMode","value":"Running"}));
    Value::Array(patch)
}

/// The generic writer's patch: its UID fence, then `between`, then the mode.
fn generic_mode_patch(mode: &str, between: &[Value]) -> Value {
    let mut patch = vec![json!({"op":"test","path":"/metadata/uid","value":"sandbox-incarnation"})];
    patch.extend_from_slice(between);
    patch.push(json!({"op":"add","path":"/spec/operatingMode","value":mode}));
    Value::Array(patch)
}

/// Resume through the lifecycle's pinned writer, as Start and the
/// bootstrap-mismatch restart do.
async fn pinned_resume(
    client: &SandboxClient,
    state: &Arc<Mutex<Fixture>>,
    support_image: &str,
) -> anyhow::Result<()> {
    let suspended = client
        .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
        .await
        .unwrap()
        .unwrap();
    assert!(patches(&state.lock().unwrap()).is_empty());
    client
        .set_replicas_for_identity(
            &claim_opts(),
            &claim_name(ENV),
            CLAIM_UID,
            &suspended,
            1,
            support_image,
        )
        .await
}

/// Resume `before` through one writer and return the final state.
async fn resume_through(
    before: Fixture,
    generic: bool,
    support_image: &str,
) -> (anyhow::Result<()>, Arc<Mutex<Fixture>>) {
    let (client, state) = client(before);
    let result = if generic {
        client.set_replicas(ENV, 1, support_image).await
    } else {
        pinned_resume(&client, &state, support_image).await
    };
    (result, state)
}

/// The patch a resume through one writer sends with these re-pin operations.
fn resume_patch(generic: bool, between: &[Value]) -> Value {
    if generic {
        generic_mode_patch("Running", between)
    } else {
        pinned_resume_patch("30", between)
    }
}

/// The incident (Sandbox 1a67b6b2): a Sandbox created before a support-image
/// rollout resumes on the current image. Start's one patch re-pins exactly
/// the daemon volume's reference; every other volume, container and field,
/// the per-environment template and the Pod are untouched.
#[tokio::test]
async fn resume_re_pins_only_the_daemon_image_reference() {
    let before = stale_daemon_fixture();
    let (template, sandbox) = (before.template.clone(), before.sandbox.clone());
    let (client, state) = client(before);
    pinned_resume(&client, &state, DAEMON_IMAGE).await.unwrap();
    let state = state.lock().unwrap();
    let written = patches(&state);
    assert_eq!(written.len(), 1);
    assert_eq!(
        written[0],
        &pinned_resume_patch("30", &repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE))
    );
    let mut expected = sandbox;
    *daemon_reference_mut(&mut expected) = json!(DAEMON_IMAGE);
    expected["spec"]["operatingMode"] = json!("Running");
    assert_eq!(state.sandbox, expected);
    assert_eq!(state.template, template);
    assert!(
        state
            .requests
            .iter()
            .all(|(method, path, _)| *method == Method::GET
                || path.ends_with(&format!("/sandboxes/{SANDBOX}")))
    );
}

/// Setup recovery resumes through the generic writer; it re-pins the same
/// way, under its UID fence and the volume's own tests.
#[tokio::test]
async fn generic_resume_re_pins_and_suspend_never_does() {
    let mut before = stale_daemon_fixture();
    before.sandbox["spec"]["operatingMode"] = json!("Suspended");
    let sandbox = before.sandbox.clone();
    let (sandboxes, state) = client(before);
    sandboxes.set_replicas(ENV, 1, DAEMON_IMAGE).await.unwrap();
    {
        let state = state.lock().unwrap();
        assert_eq!(
            patches(&state),
            [&generic_mode_patch(
                "Running",
                &repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE)
            )]
        );
        let mut expected = sandbox.clone();
        *daemon_reference_mut(&mut expected) = json!(DAEMON_IMAGE);
        expected["spec"]["operatingMode"] = json!("Running");
        assert_eq!(state.sandbox, expected);
    }

    // Suspending a stale Sandbox, through either writer, changes only its
    // mode: the next resume re-pins.
    for copy in [false, true] {
        let stale = || {
            let mut running = if copy {
                stale_copy_fixture(None)
            } else {
                stale_daemon_fixture()
            };
            running.sandbox["spec"]["operatingMode"] = json!("Running");
            running
        };
        let before = stale();
        let spec = before.sandbox["spec"]["podTemplate"].clone();
        let (sandboxes, state) = client(before);
        sandboxes.set_replicas(ENV, 0, DAEMON_IMAGE).await.unwrap();
        assert_eq!(
            patches(&state.lock().unwrap()),
            [&generic_mode_patch("Suspended", &[])]
        );
        let (sandboxes, state) = client(stale());
        sandboxes
            .suspend_workspace(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap();
        let state = state.lock().unwrap();
        assert_eq!(
            patches(&state),
            [&json!([
                {"op":"test","path":"/metadata/uid","value":"sandbox-incarnation"},
                {"op":"test","path":"/metadata/resourceVersion","value":"30"},
                {"op":"add","path":"/spec/operatingMode","value":"Suspended"}
            ])]
        );
        assert_eq!(state.sandbox["spec"]["podTemplate"], spec);
    }
}

/// A daemon from the configured support image's repository re-pins, with a
/// tag, a digest or both.
#[tokio::test]
async fn the_support_image_repository_re_pins_to_the_support_image() {
    let repository = "registry.example.invalid/codewire/daemon";
    assert!(DAEMON_IMAGE.starts_with(&format!("{repository}@")));
    let froms = [
        "registry.example.invalid/codewire/daemon:v0.3.359@sha256:1bc918a7c16ac72c4d3f84641efb12343372fa70a0e8839466ab26e660c81173".to_owned(),
        "registry.example.invalid/codewire/daemon:main-4b5b65d".to_owned(),
        format!("{repository}@{OLD_DAEMON_DIGEST}"),
        format!("{repository}:v0.3.381@{OLD_DAEMON_DIGEST}"),
    ];
    for from in &froms {
        for generic in [false, true] {
            let mut before = stale_daemon_fixture();
            *daemon_reference_mut(&mut before.sandbox) = json!(from);
            let (result, state) = resume_through(before, generic, DAEMON_IMAGE).await;
            result.unwrap();
            let mut state = state.lock().unwrap();
            assert_eq!(
                patches(&state),
                [&resume_patch(
                    generic,
                    &repin_operations(from, DAEMON_IMAGE)
                )],
                "{from}"
            );
            assert_eq!(
                *daemon_reference_mut(&mut state.sandbox),
                json!(DAEMON_IMAGE)
            );
        }
    }
}

/// A Sandbox that copies its daemon re-pins its `codewire-daemon-init` image
/// on the none, runc and commodity runtimes: commodity Sandboxes from before
/// the image volume keep that copy for life.
#[tokio::test]
async fn the_copied_daemon_is_re_pinned_off_confidential_runtimes() {
    for runtime_class in [None, Some("runc"), Some("commodity")] {
        for generic in [false, true] {
            let before = stale_copy_fixture(runtime_class);
            let (template, sandbox) = (before.template.clone(), before.sandbox.clone());
            let (result, state) = resume_through(before, generic, DAEMON_IMAGE).await;
            result.unwrap();
            let state = state.lock().unwrap();
            assert_eq!(
                patches(&state),
                [&resume_patch(
                    generic,
                    &init_repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE)
                )],
                "{runtime_class:?}"
            );
            let mut expected = sandbox;
            expected["spec"]["podTemplate"]["spec"]["initContainers"][0]["image"] =
                json!(DAEMON_IMAGE);
            expected["spec"]["operatingMode"] = json!("Running");
            assert_eq!(state.sandbox, expected, "{runtime_class:?}");
            assert_eq!(state.template, template);
        }
    }
}

/// A confidential guest's Pod is measured and attested, so neither its
/// copied daemon nor any other runtime class this does not know is touched:
/// the resume changes only the mode.
#[tokio::test]
async fn a_confidential_or_unknown_runtime_keeps_its_daemon() {
    for runtime_class in ["confidential", "kata-qemu-snp"] {
        for copy in [false, true] {
            for generic in [false, true] {
                let mut before = if copy {
                    stale_copy_fixture(Some(runtime_class))
                } else {
                    stale_daemon_fixture()
                };
                before.sandbox["spec"]["podTemplate"]["spec"]["runtimeClassName"] =
                    json!(runtime_class);
                let sandbox = before.sandbox.clone();
                let (result, state) = resume_through(before, generic, DAEMON_IMAGE).await;
                result.unwrap();
                let state = state.lock().unwrap();
                assert_eq!(patches(&state), [&resume_patch(generic, &[])]);
                let mut expected = sandbox;
                expected["spec"]["operatingMode"] = json!("Running");
                assert_eq!(state.sandbox, expected, "{runtime_class} copy={copy}");
            }
        }
    }
}

/// A current daemon, one from a repository no release used, or an unpinned
/// support image gets exactly the mode patch it got before the re-pin
/// existed, and keeps its daemon. A repository is compared exactly, never by
/// suffix.
#[tokio::test]
async fn resume_keeps_a_current_unlisted_or_unpinned_daemon_image() {
    type Case = (&'static str, fn() -> Fixture, &'static str);
    let cases: [Case; 10] = [
        (
            "current image volume",
            || {
                let mut fixture = stale_daemon_fixture();
                *daemon_reference_mut(&mut fixture.sandbox) = json!(DAEMON_IMAGE);
                fixture
            },
            DAEMON_IMAGE,
        ),
        ("current copy", fixture, DAEMON_IMAGE),
        (
            "another repository",
            || {
                let mut fixture = stale_daemon_fixture();
                *daemon_reference_mut(&mut fixture.sandbox) = json!(format!(
                    "registry.example.invalid/codewire/workspace@{OLD_DAEMON_DIGEST}"
                ));
                fixture
            },
            DAEMON_IMAGE,
        ),
        (
            "another registry",
            || {
                let mut fixture = stale_daemon_fixture();
                *daemon_reference_mut(&mut fixture.sandbox) = json!(format!(
                    "registry.example/codewire/daemon@{OLD_DAEMON_DIGEST}"
                ));
                fixture
            },
            DAEMON_IMAGE,
        ),
        (
            "a listed repository as a path suffix",
            || {
                let mut fixture = stale_daemon_fixture();
                *daemon_reference_mut(&mut fixture.sandbox) = json!(format!(
                    "mirror.example/registry.example.invalid/codewire/daemon@{OLD_DAEMON_DIGEST}"
                ));
                fixture
            },
            DAEMON_IMAGE,
        ),
        (
            "a listed repository as a prefix",
            || {
                let mut fixture = stale_copy_fixture(None);
                fixture.sandbox["spec"]["podTemplate"]["spec"]["initContainers"][0]["image"] = json!(
                    format!("registry.example.invalid/codewire/daemon-next@{OLD_DAEMON_DIGEST}")
                );
                fixture
            },
            DAEMON_IMAGE,
        ),
        (
            "no daemon volume",
            || {
                let mut fixture = stale_daemon_fixture();
                fixture.sandbox["spec"]["podTemplate"]["spec"]["volumes"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|volume| volume["name"] != "codewire-bin");
                fixture
            },
            DAEMON_IMAGE,
        ),
        (
            "an emptyDir with no copy",
            || {
                let mut fixture = stale_daemon_fixture();
                fixture.sandbox["spec"]["podTemplate"]["spec"]["volumes"][1] =
                    json!({"name":"codewire-bin","emptyDir":{}});
                fixture
            },
            DAEMON_IMAGE,
        ),
        (
            "Kind's unpinned support image",
            || stale_copy_fixture(Some("runc")),
            "codewire-daemon:e2e",
        ),
        (
            "a tag-only support image",
            stale_daemon_fixture,
            "registry.example.invalid/codewire/daemon:v0.3.400",
        ),
    ];
    for (label, before, support_image) in cases {
        for generic in [false, true] {
            let before = before();
            let sandbox = before.sandbox.clone();
            let (result, state) = resume_through(before, generic, support_image).await;
            result.unwrap();
            let state = state.lock().unwrap();
            assert_eq!(patches(&state), [&resume_patch(generic, &[])], "{label}");
            let mut expected = sandbox;
            expected["spec"]["operatingMode"] = json!("Running");
            assert_eq!(state.sandbox, expected, "{label}");
        }
    }
}

/// A daemon source no Pod could be built from fails closed: the resume
/// writes nothing, operating mode included.
#[tokio::test]
async fn resume_refuses_an_ambiguous_daemon_source_without_writes() {
    type Case = (&'static str, bool, fn(&mut Value));
    let cases: [Case; 10] = [
        ("duplicated volume", false, |spec| {
            let daemon = spec["volumes"][1].clone();
            spec["volumes"].as_array_mut().unwrap().push(daemon);
        }),
        ("no reference", false, |spec| {
            spec["volumes"][1]["image"] = json!({"pullPolicy":"IfNotPresent"});
        }),
        ("empty reference", false, |spec| {
            spec["volumes"][1]["image"]["reference"] = json!("");
        }),
        ("volumes not a list", false, |spec| {
            spec["volumes"] = json!({"codewire-bin": {}});
        }),
        ("both routes", false, |spec| {
            spec["initContainers"] = json!([daemon_init()]);
        }),
        ("duplicated copy", true, |spec| {
            let init = spec["initContainers"][0].clone();
            spec["initContainers"].as_array_mut().unwrap().push(init);
        }),
        ("copy without an image", true, |spec| {
            spec["initContainers"][0]
                .as_object_mut()
                .unwrap()
                .remove("image");
        }),
        ("copy with an empty image", true, |spec| {
            spec["initContainers"][0]["image"] = json!("");
        }),
        ("init containers not a list", true, |spec| {
            spec["initContainers"] = json!({});
        }),
        ("runtime class not a string", true, |spec| {
            spec["runtimeClassName"] = json!(7);
        }),
    ];
    for (label, copy, mutate) in cases {
        for generic in [false, true] {
            let mut before = if copy {
                stale_copy_fixture(None)
            } else {
                stale_daemon_fixture()
            };
            mutate(&mut before.sandbox["spec"]["podTemplate"]["spec"]);
            let (result, state) = resume_through(before, generic, DAEMON_IMAGE).await;
            assert!(result.is_err(), "{label}");
            let state = state.lock().unwrap();
            assert!(patches(&state).is_empty(), "{label}");
            assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
        }
    }
}

/// The generic writer has no resourceVersion fence; the volume's own tests
/// refuse a concurrent change to its image or index, and the whole patch,
/// operating mode included, fails without a retry.
#[tokio::test]
async fn a_concurrent_daemon_volume_change_fails_the_whole_resume() {
    for race in [Race::DaemonImage, Race::DaemonVolumeMoved] {
        let mut before = stale_daemon_fixture();
        before.race = Some(race);
        let (client, state) = client(before);
        assert!(client.set_replicas(ENV, 1, DAEMON_IMAGE).await.is_err());
        let state = state.lock().unwrap();
        assert_eq!(patches(&state).len(), 1);
        assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
        let volumes = state.sandbox["spec"]["podTemplate"]["spec"]["volumes"]
            .as_array()
            .unwrap();
        assert!(
            volumes
                .iter()
                .all(|volume| volume["image"]["reference"] != DAEMON_IMAGE)
        );
    }
}

/// A rejected resume reports the API's reason, not only that it failed.
#[tokio::test]
async fn a_rejected_resume_names_its_cause() {
    let mut before = stale_daemon_fixture();
    before.race = Some(Race::SandboxVersionEveryPatch);
    let (client, state) = client(before);
    let error = pinned_resume(&client, &state, DAEMON_IMAGE)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("workspace operating mode update was not admitted: ")
            && error.contains("Conflict"),
        "{error}"
    );
}

/// A claimed warm-pool member resumes the same way: its own Sandbox is
/// re-pinned, and the shared pool template is never written.
#[tokio::test]
async fn a_claimed_warm_member_is_re_pinned_and_its_pool_template_is_not() {
    let commodity = |support_image: &str| TemplateOpts {
        runtime_profile: super::super::template::RUNTIME_PROFILE_COMMODITY.into(),
        support_image: support_image.into(),
        ..binding_opts()
    };
    let mut before = pool_born_fixture();
    // The pool rotated to the current image after this member was claimed.
    before.template["spec"] = render_sandbox_template(NS, &commodity(DAEMON_IMAGE))["spec"].clone();
    before.sandbox["spec"]["podTemplate"]["spec"] =
        render_sandbox_template(NS, &commodity(OLD_DAEMON_IMAGE))["spec"]["podTemplate"]["spec"]
            .clone();
    let index = before.sandbox["spec"]["podTemplate"]["spec"]["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .position(|volume| volume["name"] == "codewire-bin")
        .unwrap();
    let (template, sandbox) = (before.template.clone(), before.sandbox.clone());
    let (client, state) = client(before);
    pinned_resume(&client, &state, DAEMON_IMAGE).await.unwrap();
    let state = state.lock().unwrap();
    let path = format!("/spec/podTemplate/spec/volumes/{index}");
    // Its Docker data init follows the support image in the same patch.
    let init = "/spec/podTemplate/spec/initContainers/0";
    assert_eq!(
        patches(&state),
        [&pinned_resume_patch(
            "30",
            &[
                json!({"op":"test","path":format!("{path}/name"),"value":"codewire-bin"}),
                json!({"op":"test","path":format!("{path}/image/reference"),"value":OLD_DAEMON_IMAGE}),
                json!({"op":"replace","path":format!("{path}/image/reference"),"value":DAEMON_IMAGE}),
                json!({"op":"test","path":format!("{init}/name"),"value":DOCKER_DATA_INIT_CONTAINER}),
                json!({"op":"test","path":format!("{init}/image"),"value":OLD_DAEMON_IMAGE}),
                json!({"op":"replace","path":format!("{init}/image"),"value":DAEMON_IMAGE}),
            ]
        )]
    );
    let mut expected = sandbox;
    *daemon_reference_mut(&mut expected) = json!(DAEMON_IMAGE);
    expected["spec"]["podTemplate"]["spec"]["initContainers"][0]["image"] = json!(DAEMON_IMAGE);
    expected["spec"]["operatingMode"] = json!("Running");
    assert_eq!(state.sandbox, expected);
    assert_eq!(state.template, template);
    assert!(
        state
            .requests
            .iter()
            .all(|(method, path, _)| *method == Method::GET || path.contains("/sandboxes/"))
    );
}

#[test]
fn daemon_image_plan_compares_repositories_not_tags_or_digests() {
    for (reference, repository) in [
        (
            "registry.example.invalid/codewire/daemon@sha256:aa",
            "registry.example.invalid/codewire/daemon",
        ),
        (
            "registry.example.invalid/codewire/daemon:v0.3.359@sha256:aa",
            "registry.example.invalid/codewire/daemon",
        ),
        (
            "registry.example.invalid/codewire/daemon:main-4b5b65d",
            "registry.example.invalid/codewire/daemon",
        ),
        (
            "localhost:5000/codewire/daemon:local",
            "localhost:5000/codewire/daemon",
        ),
        (
            "localhost:5000/codewire/daemon",
            "localhost:5000/codewire/daemon",
        ),
        ("codewire-daemon:e2e", "codewire-daemon"),
    ] {
        assert_eq!(image_repository(reference), repository, "{reference}");
    }
    let tagged_current = "registry.example.invalid/codewire/daemon:v0.3.400@sha256:1f5972c44d7063815d4d5163f06fc8db5428a5a57dacc4816841cc5cd97ce190";
    let volume = |reference: &str| {
        json!({"spec":{"podTemplate":{"spec":{"runtimeClassName":"commodity","volumes":[
            {"name":"workspace","persistentVolumeClaim":{"claimName":"saved-pvc"}},
            {"name":"codewire-bin","image":{"reference":reference,"pullPolicy":"IfNotPresent"}},
        ]}}}})
    };
    let old = volume(OLD_DAEMON_IMAGE);
    assert_eq!(
        plan_daemon_image(&old, tagged_current).unwrap(),
        DaemonImagePlan::Repin(DaemonImageEntry {
            path: "/spec/podTemplate/spec/volumes/1".into(),
            name: "codewire-bin",
            field: "image/reference",
            from: OLD_DAEMON_IMAGE,
        })
    );
    assert_eq!(
        plan_daemon_image(&old, OLD_DAEMON_IMAGE).unwrap(),
        DaemonImagePlan::Current
    );
    // Another registry is not the support image's repository: a daemon
    // still rendered from it is kept, not re-pinned.
    let legacy = volume(&format!(
        "git.example.invalid/codewire/daemon:v0.3.359@sha256:{}",
        "b".repeat(64)
    ));
    assert_eq!(
        plan_daemon_image(&legacy, tagged_current).unwrap(),
        DaemonImagePlan::Kept(DaemonImageKept::UnlistedRepository)
    );
    for unpinned in [
        "registry.example.invalid/codewire/daemon:v0.3.400",
        "registry.example.invalid/codewire/daemon@sha256:1f59",
    ] {
        assert_eq!(
            plan_daemon_image(&old, unpinned).unwrap(),
            DaemonImagePlan::Kept(DaemonImageKept::UnpinnedSupportImage)
        );
    }
    let copy = json!({"spec":{"podTemplate":{"spec":{"runtimeClassName":"confidential",
        "volumes":[{"name":"codewire-bin","emptyDir":{}}],
        "initContainers":[{"name":"codewire-daemon-init","image":OLD_DAEMON_IMAGE}]}}}});
    assert_eq!(
        plan_daemon_image(&copy, DAEMON_IMAGE).unwrap(),
        DaemonImagePlan::Kept(DaemonImageKept::ConfidentialRuntime)
    );
}

// ------------- daemon image re-pin before a Pod replacement (review of #2445)

/// A running copy of `before`, whose Pod is the observed incarnation.
fn running(mut before: Fixture) -> Fixture {
    before.sandbox["spec"]["operatingMode"] = json!("Running");
    before
}

/// The fenced re-pin a Pod replacement writes: UID and resourceVersion
/// tests, then the entry's tests and replace. No operating mode.
fn replacement_patch(version: &str, repin: impl IntoIterator<Item = Value>) -> Value {
    let mut patch = vec![
        json!({"op":"test","path":"/metadata/uid","value":"sandbox-incarnation"}),
        json!({"op":"test","path":"/metadata/resourceVersion","value":version}),
    ];
    patch.extend(repin);
    Value::Array(patch)
}

/// The methods and paths after the Claim and Pod reads, in order.
fn writes(state: &Fixture) -> Vec<(Method, String)> {
    state
        .requests
        .iter()
        .filter(|(method, _, _)| *method != Method::GET)
        .map(|(method, path, _)| (method.clone(), path.rsplit('/').next().unwrap().to_owned()))
        .collect()
}

async fn replace_pod(
    before: Fixture,
    support_image: &str,
) -> (anyhow::Result<WorkspacePodReplacement>, Arc<Mutex<Fixture>>) {
    let (client, state) = client(before);
    let result = client
        .replace_workspace_pod_if_uid(ENV, POD, "pod-incarnation", support_image)
        .await;
    (result, state)
}

/// Daemon repair, restart-mode resize and terminal-Pod replacement rebuild
/// the Pod from the Sandbox's spec: they re-pin it, with the fenced entry
/// operations and no operating mode, before deleting the Pod.
#[tokio::test]
async fn a_pod_replacement_re_pins_the_running_sandbox_first() {
    for (copy, repin) in [
        (false, repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE)),
        (true, init_repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE)),
    ] {
        let before = running(if copy {
            stale_copy_fixture(Some("commodity"))
        } else {
            stale_daemon_fixture()
        });
        let sandbox = before.sandbox.clone();
        let (result, state) = replace_pod(before, DAEMON_IMAGE).await;
        assert_eq!(result.unwrap(), WorkspacePodReplacement::Replaced);
        let state = state.lock().unwrap();
        assert_eq!(patches(&state), [&replacement_patch("30", repin)]);
        assert_eq!(
            writes(&state),
            [
                (Method::PATCH, SANDBOX.to_owned()),
                (Method::DELETE, POD.to_owned())
            ]
        );
        let mut expected = sandbox;
        if copy {
            expected["spec"]["podTemplate"]["spec"]["initContainers"][0]["image"] =
                json!(DAEMON_IMAGE);
        } else {
            *daemon_reference_mut(&mut expected) = json!(DAEMON_IMAGE);
        }
        assert_eq!(state.sandbox, expected, "copy={copy}");
        assert_eq!(state.sandbox["spec"]["operatingMode"], "Running");
    }
}

/// A current, kept or confidential daemon is not written; the Pod is still
/// replaced. A Pod already gone or replaced is neither re-pinned for nor
/// deleted.
#[tokio::test]
async fn a_pod_replacement_writes_only_a_re_pinnable_daemon() {
    for (label, before) in [
        ("current", running(fixture())),
        (
            "confidential",
            running(stale_copy_fixture(Some("confidential"))),
        ),
        ("unlisted", {
            let mut fixture = running(stale_daemon_fixture());
            *daemon_reference_mut(&mut fixture.sandbox) = json!(format!(
                "registry.example/codewire/daemon@{OLD_DAEMON_DIGEST}"
            ));
            fixture
        }),
    ] {
        let (result, state) = replace_pod(before, DAEMON_IMAGE).await;
        result.unwrap();
        assert_eq!(
            writes(&state.lock().unwrap()),
            [(Method::DELETE, POD.to_owned())],
            "{label}"
        );
    }
    let mut replaced = running(stale_daemon_fixture());
    replaced.pod["metadata"]["uid"] = json!("replacement-pod");
    let (result, state) = replace_pod(replaced, DAEMON_IMAGE).await;
    assert_eq!(result.unwrap(), WorkspacePodReplacement::AlreadyReplaced);
    let state = state.lock().unwrap();
    assert!(writes(&state).is_empty());
    assert!(
        state
            .requests
            .iter()
            .all(|(_, path, _)| path.contains("/pods/"))
    );
}

/// The controller's status writes change a running Sandbox's
/// resourceVersion: a conflicting re-pin is read and planned again, up to
/// three times, and a re-pin that keeps conflicting or finds another
/// Sandbox fails before the Pod is deleted, naming its cause.
#[tokio::test]
async fn a_pod_replacement_re_pin_retries_conflicts_within_its_bound() {
    let mut once = running(stale_daemon_fixture());
    once.race = Some(Race::SandboxVersion);
    let (result, state) = replace_pod(once, DAEMON_IMAGE).await;
    result.unwrap();
    {
        let state = state.lock().unwrap();
        assert_eq!(
            patches(&state),
            [
                &replacement_patch("30", repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE)),
                &replacement_patch("31", repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE)),
            ]
        );
        assert_eq!(writes(&state).last().unwrap().0, Method::DELETE);
    }

    let mut always = running(stale_daemon_fixture());
    always.race = Some(Race::SandboxVersionEveryPatch);
    let (result, state) = replace_pod(always, DAEMON_IMAGE).await;
    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("daemon image kept conflicting") && error.contains("Conflict"),
        "{error}"
    );
    {
        let state = state.lock().unwrap();
        assert_eq!(patches(&state).len(), 3);
        assert!(
            writes(&state)
                .iter()
                .all(|(method, _)| *method != Method::DELETE)
        );
    }

    let mut replaced = running(stale_daemon_fixture());
    replaced.race = Some(Race::SandboxUid);
    let (result, state) = replace_pod(replaced, DAEMON_IMAGE).await;
    assert!(result.unwrap_err().to_string().contains("was replaced"));
    let state = state.lock().unwrap();
    assert_eq!(patches(&state).len(), 1);
    assert!(
        writes(&state)
            .iter()
            .all(|(method, _)| *method != Method::DELETE)
    );
}

/// The Pod is read again immediately before the re-pin patch. Gone, or
/// carrying another UID, it was already replaced from the Sandbox's current
/// spec: no re-pin, no delete, and the outcome counts as a replacement.
#[tokio::test]
async fn a_pod_replaced_before_the_re_pin_is_neither_re_pinned_nor_deleted() {
    for race in [Race::PodGoneOnSandboxRead, Race::PodReplacedOnSandboxRead] {
        for copy in [false, true] {
            let mut before = running(if copy {
                stale_copy_fixture(None)
            } else {
                stale_daemon_fixture()
            });
            before.race = Some(race);
            let sandbox = before.sandbox.clone();
            let (result, state) = replace_pod(before, DAEMON_IMAGE).await;
            assert_eq!(
                result.unwrap(),
                WorkspacePodReplacement::AlreadyReplaced,
                "copy={copy}"
            );
            let state = state.lock().unwrap();
            assert!(writes(&state).is_empty(), "copy={copy}");
            assert_eq!(state.sandbox, sandbox, "copy={copy}");
            // The second Pod read follows the Sandbox read and precedes any
            // write.
            let reads: Vec<_> = state
                .requests
                .iter()
                .map(|(_, path, _)| path.rsplit('/').nth(1).unwrap().to_owned())
                .collect();
            assert_eq!(reads, ["pods", "sandboxclaims", "sandboxes", "pods"]);
        }
    }
}

/// The data variables a commodity or runc guest DinD renders for a 40 GiB
/// disk, after Docker's own TLS setting.
fn loop_dind_env() -> Value {
    json!([
        {"name":"DOCKER_TLS_CERTDIR","value":""},
        {"name":"CODEWIRE_DOCKER_DATA_IMAGE","value":"/workspace/.codewire/docker-data.ext4"},
        {"name":"CODEWIRE_DOCKER_DATA_ROOT","value":"/var/lib/docker"},
        {"name":"CODEWIRE_DOCKER_DATA_SIZE","value":"38G"},
        {"name":"CODEWIRE_DOCKER_MOUNT_MODE","value":"loop"},
    ])
}

/// The Docker data init a Start re-renders beside [`loop_dind_env`].
fn data_init(support_image: &str) -> Value {
    docker_data_init_container(
        support_image,
        loop_dind_env().as_array().unwrap()[1..]
            .iter()
            .filter(|entry| entry["name"] != "CODEWIRE_DOCKER_DATA_ROOT")
            .cloned()
            .collect(),
    )
}

/// `before` with a loop-mounted DinD bootstrap of `command` in its template,
/// Sandbox and Pod, and the Sandbox on `runtime_class`.
fn with_dind(mut before: Fixture, command: Value, runtime_class: Option<&str>) -> Fixture {
    for spec in [
        &mut before.template["spec"]["podTemplate"]["spec"],
        &mut before.sandbox["spec"]["podTemplate"]["spec"],
        &mut before.pod["spec"],
    ] {
        assert_eq!(spec["containers"][0]["name"], "dind");
        spec["containers"][0]["command"] = command.clone();
        spec["containers"][0]["env"] = loop_dind_env();
        if let Some(class) = runtime_class {
            spec["runtimeClassName"] = json!(class);
        }
    }
    before
}

/// #2639: a Sandbox rendered before 531fc0f7e, whose DinD made the workspace
/// home's `.codewire` 0775 at every Pod start.
fn legacy_dind(before: Fixture) -> Fixture {
    with_dind(
        before,
        json!(["sh", "-ec", LEGACY_DIND_BOOTSTRAP_SCRIPT]),
        None,
    )
}

/// The exact operations that re-render the fixture's `prior` DinD bootstrap
/// and add its Docker data init: after `inits`, the init containers the
/// Sandbox already has, or as its only one.
fn dind_operations(prior: &str, inits: Option<&Value>) -> Vec<Value> {
    let mut operations = vec![
        json!({"op":"test","path":"/spec/podTemplate/spec/containers/0/name","value":"dind"}),
        json!({"op":"test","path":"/spec/podTemplate/spec/containers/0/command/2","value":prior}),
        json!({"op":"replace","path":"/spec/podTemplate/spec/containers/0/command/2","value":dind_bootstrap_script()}),
    ];
    match inits {
        Some(inits) => {
            for (index, init) in inits.as_array().unwrap().iter().enumerate() {
                operations.push(json!({"op":"test","path":format!("/spec/podTemplate/spec/initContainers/{index}/name"),"value":init["name"]}));
            }
            operations.push(json!({"op":"add","path":"/spec/podTemplate/spec/initContainers/-","value":data_init(DAEMON_IMAGE)}));
        }
        None => operations.push(
            json!({"op":"add","path":"/spec/podTemplate/spec/initContainers","value":[data_init(DAEMON_IMAGE)]}),
        ),
    }
    operations
}

/// The fixture's operations for its legacy bootstrap beside its daemon copy.
fn legacy_operations() -> Vec<Value> {
    dind_operations(LEGACY_DIND_BOOTSTRAP_SCRIPT, Some(&json!([daemon_init()])))
}

/// `sandbox` with the current DinD bootstrap, its Docker data init last, and
/// `mode`.
fn re_rendered(mut sandbox: Value, mode: &str) -> Value {
    let spec = &mut sandbox["spec"]["podTemplate"]["spec"];
    spec["containers"][0]["command"][2] = json!(dind_bootstrap_script());
    match spec.get_mut("initContainers").and_then(Value::as_array_mut) {
        Some(inits) => inits.push(data_init(DAEMON_IMAGE)),
        None => spec["initContainers"] = json!([data_init(DAEMON_IMAGE)]),
    }
    sandbox["spec"]["operatingMode"] = json!(mode);
    sandbox
}

/// Start, through either writer, re-renders exactly the legacy DinD script
/// and adds the Docker data init in the same patch as the mode (and any
/// daemon re-pin). The DinD image and environment, the workspace container
/// and image, the volumes, the per-environment template and the Pod are
/// untouched; no workspace image is re-pinned.
#[tokio::test]
async fn start_re_renders_a_legacy_dind_bootstrap_and_nothing_else() {
    for generic in [false, true] {
        let before = legacy_dind(fixture());
        let (template, sandbox, pod) = (
            before.template.clone(),
            before.sandbox.clone(),
            before.pod.clone(),
        );
        let (result, state) = resume_through(before, generic, DAEMON_IMAGE).await;
        result.unwrap();
        let state = state.lock().unwrap();
        assert_eq!(
            patches(&state),
            [&resume_patch(generic, &legacy_operations())],
            "generic={generic}"
        );
        assert_eq!(state.sandbox, re_rendered(sandbox, "Running"));
        assert_eq!(state.template, template);
        assert_eq!(state.pod, pod);
        let spec = &state.sandbox["spec"]["podTemplate"]["spec"];
        assert_eq!(spec["containers"][0]["image"], "unchanged-dind");
        assert_eq!(spec["containers"][0]["env"], loop_dind_env());
        let names: Vec<_> = spec["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|init| init["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["codewire-daemon-init", DOCKER_DATA_INIT_CONTAINER]);
    }
    // With a stale daemon image volume the one patch carries both, the
    // daemon first, and the data init becomes the only init container.
    let before = legacy_dind(stale_daemon_fixture());
    let sandbox = before.sandbox.clone();
    let (result, state) = resume_through(before, false, DAEMON_IMAGE).await;
    result.unwrap();
    let state = state.lock().unwrap();
    let mut between = repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE).to_vec();
    between.extend(dind_operations(LEGACY_DIND_BOOTSTRAP_SCRIPT, None));
    assert_eq!(patches(&state), [&resume_patch(false, &between)]);
    let mut expected = re_rendered(sandbox, "Running");
    *daemon_reference_mut(&mut expected) = json!(DAEMON_IMAGE);
    assert_eq!(state.sandbox, expected);
}

/// A runc Sandbox that copies its daemon from an older support image
/// re-pins the copy and re-renders DinD in one patch: the daemon copy's image
/// changes first, and the data init still follows it.
#[tokio::test]
async fn start_re_pins_a_daemon_copy_and_re_renders_dind_in_one_patch() {
    let before = legacy_dind(stale_copy_fixture(Some("runc")));
    let sandbox = before.sandbox.clone();
    let (result, state) = resume_through(before, false, DAEMON_IMAGE).await;
    result.unwrap();
    let state = state.lock().unwrap();
    let mut between = init_repin_operations(OLD_DAEMON_IMAGE, DAEMON_IMAGE).to_vec();
    between.extend(dind_operations(
        LEGACY_DIND_BOOTSTRAP_SCRIPT,
        sandbox.pointer("/spec/podTemplate/spec/initContainers"),
    ));
    assert_eq!(patches(&state), [&resume_patch(false, &between)]);
    let mut expected = re_rendered(sandbox, "Running");
    expected["spec"]["podTemplate"]["spec"]["initContainers"][0]["image"] = json!(DAEMON_IMAGE);
    assert_eq!(state.sandbox, expected);
    let names: Vec<_> = expected["spec"]["podTemplate"]["spec"]["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|init| init["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["codewire-daemon-init", DOCKER_DATA_INIT_CONTAINER]);
}

/// #3554 and #3208: every bootstrap a stored Sandbox carries is re-rendered
/// like the legacy one, so its next Pod prepares the Docker data image in
/// the data init and DinD only mounts it. That includes the one that grew
/// the image inside DinD, which a Sandbox created while Dev briefly ran
/// Docker 29.9.2 carries beside that image: its DinD image is kept, and the
/// current bootstrap runs on it.
#[tokio::test]
async fn start_re_renders_every_prior_dind_bootstrap() {
    const DIND_29_9_2: &str = "docker.io/library/docker:29.9.2-dind@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977";
    for (label, prior, image) in [
        ("legacy", LEGACY_DIND_BOOTSTRAP_SCRIPT.to_owned(), None),
        ("eager mkfs", eager_mkfs_dind_bootstrap_script(), None),
        ("pre-growth", pre_growth_dind_bootstrap_script(), None),
        ("growth in DinD", growth_in_dind_bootstrap_script(), None),
        (
            "growth in DinD on 29.9.2",
            growth_in_dind_bootstrap_script(),
            Some(DIND_29_9_2),
        ),
    ] {
        for copy in [false, true] {
            let mut before = with_dind(
                if copy {
                    fixture()
                } else {
                    image_volume_fixture()
                },
                json!(["sh", "-ec", prior.clone()]),
                None,
            );
            if let Some(image) = image {
                before.sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["image"] =
                    json!(image);
            }
            let (template, sandbox, pod) = (
                before.template.clone(),
                before.sandbox.clone(),
                before.pod.clone(),
            );
            let (result, state) = resume_through(before, false, DAEMON_IMAGE).await;
            result.unwrap();
            let state = state.lock().unwrap();
            let inits = copy.then(|| json!([daemon_init()]));
            assert_eq!(
                patches(&state),
                [&resume_patch(
                    false,
                    &dind_operations(&prior, inits.as_ref())
                )],
                "{label} copy={copy}"
            );
            assert_eq!(
                state.sandbox,
                re_rendered(sandbox.clone(), "Running"),
                "{label} copy={copy}"
            );
            assert_eq!(
                state.sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["image"],
                sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["image"],
                "{label}: the DinD image is kept"
            );
            assert_eq!(state.template, template, "{label} copy={copy}");
            assert_eq!(state.pod, pod, "{label} copy={copy}");
        }
    }
}

/// A Sandbox spec with `spec` as its Pod spec.
fn sandbox_object(spec: Value) -> DynamicObject {
    serde_json::from_value(json!({
        "apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
        "metadata":{"name":SANDBOX,"namespace":NS,"uid":"sandbox-incarnation"},
        "spec":{"podTemplate":{"spec":spec}},
    }))
    .unwrap()
}

/// A Sandbox rendered with an earlier bootstrap is, once re-rendered, exactly
/// the Pod spec a fresh render gives it: the same DinD script, and on runc
/// the same data init after the daemon copy. On commodity `mount-workspace`
/// prepares the data image, so only the script changes (#3718).
#[test]
fn a_re_rendered_sandbox_matches_a_fresh_render() {
    for profile in [
        super::super::template::RUNTIME_PROFILE_COMMODITY,
        super::super::template::RUNTIME_PROFILE_RUNC,
    ] {
        let opts = TemplateOpts {
            runtime_profile: profile.into(),
            docker_mode: super::super::template::DOCKER_MODE_GUEST_DIND.into(),
            support_image: DAEMON_IMAGE.into(),
            disk_gib: 40,
            ..binding_opts()
        };
        let fresh = render_sandbox_template(NS, &opts)["spec"]["podTemplate"]["spec"].clone();
        let dind = fresh["containers"]
            .as_array()
            .unwrap()
            .iter()
            .position(|container| container["name"] == "dind")
            .unwrap();
        for prior in [
            LEGACY_DIND_BOOTSTRAP_SCRIPT.to_owned(),
            eager_mkfs_dind_bootstrap_script(),
            pre_growth_dind_bootstrap_script(),
            growth_in_dind_bootstrap_script(),
            dind_bootstrap_script(),
        ] {
            if profile != super::super::template::RUNTIME_PROFILE_COMMODITY
                && prior == dind_bootstrap_script()
            {
                continue;
            }
            let mut stored = fresh.clone();
            stored["containers"][dind]["command"][2] = json!(prior);
            let inits = stored["initContainers"].as_array_mut().unwrap();
            inits.retain(|init| init["name"] != DOCKER_DATA_INIT_CONTAINER);
            if inits.is_empty() {
                stored.as_object_mut().unwrap().remove("initContainers");
            }
            let object = sandbox_object(stored);
            let operations = dind_bootstrap_refresh(&object, DAEMON_IMAGE)
                .unwrap()
                .expect("a prior bootstrap is re-rendered");
            let mut patched = object.data.clone();
            assert!(apply_patch_fixture(&mut patched, &json!(operations)));
            assert_eq!(patched["spec"]["podTemplate"]["spec"], fresh, "{profile}");
            // The re-rendered Sandbox has nothing left to refresh.
            let current = sandbox_object(fresh.clone());
            assert!(
                dind_bootstrap_refresh(&current, DAEMON_IMAGE)
                    .unwrap()
                    .is_none(),
                "{profile}"
            );
        }
    }
}

/// A current Sandbox's data init follows the support image as its daemon
/// does, within the support image's repository and only to a digest; a
/// prior bootstrap beside a data init is ambiguous and left alone. Commodity
/// renders no data init (#3718), so runc shows it.
#[test]
fn the_docker_data_init_follows_the_support_image() {
    let opts = TemplateOpts {
        runtime_profile: super::super::template::RUNTIME_PROFILE_RUNC.into(),
        docker_mode: super::super::template::DOCKER_MODE_GUEST_DIND.into(),
        support_image: OLD_DAEMON_IMAGE.into(),
        disk_gib: 40,
        ..binding_opts()
    };
    let stale = render_sandbox_template(NS, &opts)["spec"]["podTemplate"]["spec"].clone();
    let index = stale["initContainers"]
        .as_array()
        .unwrap()
        .iter()
        .position(|init| init["name"] == DOCKER_DATA_INIT_CONTAINER)
        .unwrap();
    let path = format!("/spec/podTemplate/spec/initContainers/{index}");
    assert_eq!(
        dind_bootstrap_refresh(&sandbox_object(stale.clone()), DAEMON_IMAGE).unwrap(),
        Some(vec![
            json!({"op":"test","path":format!("{path}/name"),"value":DOCKER_DATA_INIT_CONTAINER}),
            json!({"op":"test","path":format!("{path}/image"),"value":OLD_DAEMON_IMAGE}),
            json!({"op":"replace","path":format!("{path}/image"),"value":DAEMON_IMAGE}),
        ])
    );
    for (label, support) in [
        ("current", OLD_DAEMON_IMAGE),
        (
            "another repository",
            "registry.example.invalid/other/daemon@sha256:48549d19114407c712d043af3ba2136d97052a2c30c82935190f75a3a61f13ab",
        ),
        ("unpinned", "registry.example.invalid/codewire/daemon:e2e"),
    ] {
        assert_eq!(
            dind_bootstrap_refresh(&sandbox_object(stale.clone()), support).unwrap(),
            None,
            "{label}"
        );
    }
    let mut ambiguous = stale;
    let dind = ambiguous["containers"]
        .as_array()
        .unwrap()
        .iter()
        .position(|container| container["name"] == "dind")
        .unwrap();
    ambiguous["containers"][dind]["command"][2] = json!(growth_in_dind_bootstrap_script());
    assert_eq!(
        dind_bootstrap_refresh(&sandbox_object(ambiguous), DAEMON_IMAGE).unwrap(),
        None
    );
}

/// Only an exact prior script on a loop-mounted image is re-rendered: a
/// current, unknown or direct dockerd command, a plain directory, and a
/// confidential runtime, are left as they are.
#[tokio::test]
async fn start_keeps_any_other_dind_bootstrap() {
    let cases = [
        (
            "current",
            json!(["sh", "-ec", dind_bootstrap_script()]),
            None,
        ),
        (
            "pre-growth as an argument",
            json!(["sh", "-ec", pre_growth_dind_bootstrap_script(), "extra"]),
            None,
        ),
        (
            "confidential pre-growth",
            json!(["sh", "-ec", pre_growth_dind_bootstrap_script()]),
            Some("confidential"),
        ),
        (
            "confidential growth in DinD",
            json!(["sh", "-ec", growth_in_dind_bootstrap_script()]),
            Some("confidential"),
        ),
        ("unknown", json!(["sh", "-ec", "exec dockerd"]), None),
        (
            "direct",
            json!(["dockerd", "--host", "unix:///var/run/docker/docker.sock"]),
            None,
        ),
        (
            "legacy as an argument",
            json!(["sh", "-ec", LEGACY_DIND_BOOTSTRAP_SCRIPT, "extra"]),
            None,
        ),
        (
            "confidential",
            json!(["sh", "-ec", LEGACY_DIND_BOOTSTRAP_SCRIPT]),
            Some("confidential"),
        ),
    ];
    for (label, command, runtime_class) in cases {
        let before = with_dind(fixture(), command, runtime_class);
        let sandbox = before.sandbox.clone();
        let (result, state) = resume_through(before, false, DAEMON_IMAGE).await;
        result.unwrap();
        let state = state.lock().unwrap();
        assert_eq!(patches(&state), [&resume_patch(false, &[])], "{label}");
        let mut expected = sandbox;
        expected["spec"]["operatingMode"] = json!("Running");
        assert_eq!(state.sandbox, expected, "{label}");
    }
    // A plain directory needs no data image, so it moves nowhere.
    let mut before = legacy_dind(fixture());
    before.sandbox["spec"]["podTemplate"]["spec"]["containers"][0]["env"][4]["value"] =
        json!("none");
    let sandbox = before.sandbox.clone();
    let (result, state) = resume_through(before, false, DAEMON_IMAGE).await;
    result.unwrap();
    let state = state.lock().unwrap();
    assert_eq!(patches(&state), [&resume_patch(false, &[])]);
    let mut expected = sandbox;
    expected["spec"]["operatingMode"] = json!("Running");
    assert_eq!(state.sandbox, expected);
}

/// Daemon repair, restart-mode resize and terminal-Pod replacement rebuild
/// the Pod from the Sandbox's spec, so they re-render the legacy bootstrap
/// and add the data init before deleting the Pod, with no operating mode.
#[tokio::test]
async fn a_pod_replacement_re_renders_a_legacy_dind_bootstrap_first() {
    let before = running(legacy_dind(fixture()));
    let sandbox = before.sandbox.clone();
    let (result, state) = replace_pod(before, DAEMON_IMAGE).await;
    assert_eq!(result.unwrap(), WorkspacePodReplacement::Replaced);
    let state = state.lock().unwrap();
    assert_eq!(
        patches(&state),
        [&replacement_patch("30", legacy_operations())]
    );
    assert_eq!(
        writes(&state),
        [
            (Method::PATCH, SANDBOX.to_owned()),
            (Method::DELETE, POD.to_owned())
        ]
    );
    assert_eq!(state.sandbox, re_rendered(sandbox, "Running"));
}

/// Two DinD containers leave no single script to re-render: nothing is
/// written.
#[tokio::test]
async fn a_duplicated_dind_container_fails_the_start_without_writes() {
    let mut before = legacy_dind(fixture());
    let dind = before.sandbox["spec"]["podTemplate"]["spec"]["containers"][0].clone();
    before.sandbox["spec"]["podTemplate"]["spec"]["containers"]
        .as_array_mut()
        .unwrap()
        .push(dind);
    let sandbox = before.sandbox.clone();
    let (result, state) = resume_through(before, false, DAEMON_IMAGE).await;
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("workspace DinD container is duplicated")
    );
    let state = state.lock().unwrap();
    assert!(patches(&state).is_empty());
    assert_eq!(state.sandbox, sandbox);
}

/// #3718: once a Sandbox's live Pod has mounted its Block workspace, a stop or
/// a Pod replacement turns the rendered `new` into `existing`, so no later
/// Pod may format the volume. A first Pod whose `mount-workspace` failed
/// before or during its format leaves `new`, so its replacement can still
/// format. An `existing` one, a fork's, and a runc workspace are left alone,
/// and a commodity Filesystem workspace from before the Block workspace is
/// refused.
#[test]
fn a_mounted_block_workspace_becomes_existing_and_a_failed_one_stays_new() {
    use super::super::template::{MOUNT_WORKSPACE_CONTAINER, RUNTIME_PROFILE_COMMODITY};
    let sandbox = |spec: Value| -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
            "metadata":{"name":SANDBOX,"namespace":NS,"uid":"sandbox-incarnation"},
            "spec":spec,
        }))
        .unwrap()
    };
    let pod = |init: Value| -> Pod {
        serde_json::from_value(json!({
            "apiVersion":"v1","kind":"Pod","metadata":{"name":SANDBOX},
            "status":{"initContainerStatuses":[
                {"name":MOUNT_WORKSPACE_CONTAINER,"ready":false,"restartCount":0,"image":"i","imageID":"","state":init}
            ]},
        }))
        .unwrap()
    };
    let opts = TemplateOpts {
        runtime_profile: RUNTIME_PROFILE_COMMODITY.into(),
        disk_gib: 40,
        ..binding_opts()
    };
    let rendered = render_sandbox_template(NS, &opts)["spec"].clone();
    let new = sandbox(rendered.clone());
    let index = block_workspace(&new)
        .unwrap()
        .expect("a commodity workspace mounts its Block volume");
    let entry = format!("/spec/podTemplate/spec/initContainers/{index}");

    // Only an exit of 0 is a mounted workspace.
    assert!(workspace_mounted(&pod(
        json!({"terminated":{"exitCode":0}})
    )));
    for unmounted in [
        json!({"terminated":{"exitCode":1}}),
        json!({"running":{}}),
        json!({"waiting":{"reason":"PodInitializing"}}),
    ] {
        assert!(!workspace_mounted(&pod(unmounted.clone())), "{unmounted}");
    }

    // A first Pod that failed before its format is replaced: still `new`.
    assert!(
        workspace_volume_existing(&new, index, false)
            .unwrap()
            .is_empty()
    );
    let operations = workspace_volume_existing(&new, index, true).unwrap();
    assert_eq!(
        operations,
        [
            json!({"op":"test","path":format!("{entry}/name"),"value":MOUNT_WORKSPACE_CONTAINER}),
            json!({"op":"test","path":format!("{entry}/command/4"),"value":"new"}),
            json!({"op":"replace","path":format!("{entry}/command/4"),"value":"existing"}),
        ]
    );
    let mut stopped = new.data.clone();
    assert!(apply_patch_fixture(&mut stopped, &json!(operations)));
    assert_eq!(
        stopped.pointer(&format!("{entry}/command/4")).unwrap(),
        "existing"
    );
    assert!(
        workspace_volume_existing(&sandbox(stopped["spec"].clone()), index, true)
            .unwrap()
            .is_empty()
    );

    // A fork restores a snapshot, so it renders `existing` from the start.
    let fork = render_sandbox_template(
        NS,
        &TemplateOpts {
            workspace_source_snapshot: Some("cw-kept-fork".into()),
            ..opts.clone()
        },
    )["spec"]
        .clone();
    assert_eq!(
        fork["volumeClaimTemplates"][0]["spec"]["volumeMode"],
        "Block"
    );
    assert_eq!(
        fork["podTemplate"]["spec"]["initContainers"][index]["command"][4],
        "existing"
    );
    let fork = sandbox(fork);
    assert!(
        workspace_volume_existing(&fork, block_workspace(&fork).unwrap().unwrap(), true)
            .unwrap()
            .is_empty()
    );

    let mut filesystem = rendered.clone();
    filesystem["volumeClaimTemplates"][0]["spec"]
        .as_object_mut()
        .unwrap()
        .remove("volumeMode");
    let refusal = block_workspace(&sandbox(filesystem))
        .unwrap_err()
        .to_string();
    assert!(
        refusal.contains("a Filesystem volume from before the Block workspace"),
        "{refusal}"
    );

    let runc = render_sandbox_template(
        NS,
        &TemplateOpts {
            runtime_profile: super::super::template::RUNTIME_PROFILE_RUNC.into(),
            ..opts
        },
    )["spec"]
        .clone();
    assert!(
        runc["volumeClaimTemplates"][0]["spec"]
            .get("volumeMode")
            .is_none()
    );
    assert!(block_workspace(&sandbox(runc)).unwrap().is_none());
}

fn old_vfs_block_fixture() -> Fixture {
    let mut before = fixture();
    let options = TemplateOpts {
        runtime_profile: super::super::template::RUNTIME_PROFILE_COMMODITY.into(),
        docker_mode: super::super::template::DOCKER_MODE_GUEST_DIND.into(),
        support_image: OLD_DAEMON_IMAGE.into(),
        disk_gib: 40,
        ..binding_opts()
    };
    let rendered = render_sandbox_template(NS, &options);
    before.sandbox["spec"]["podTemplate"] = rendered["spec"]["podTemplate"].clone();
    before.sandbox["spec"]["volumeClaimTemplates"] =
        rendered["spec"]["volumeClaimTemplates"].clone();
    let spec = &mut before.sandbox["spec"]["podTemplate"]["spec"];
    for container in spec["containers"].as_array_mut().unwrap() {
        if container["name"] == "dind" {
            container["command"][2] = json!(dind_bootstrap_script());
        }
    }
    for init in spec["initContainers"].as_array_mut().unwrap() {
        if init["name"] == MOUNT_WORKSPACE_CONTAINER {
            init["command"][4] = json!(WorkspaceVolume::Existing.as_str());
        }
    }
    before.pod = Value::Null;
    before
}

/// This fixture runs the shipped conditional resume emitter with the former
/// commodity VFS bootstrap, current Block mounts and one status-only write.
/// Kubernetes v1.36 patch.go returns 422/Invalid without causes when Apply
/// rejects a JSON Patch test; that differs from the older fixture's 409.
#[tokio::test]
async fn pinned_resume_retries_status_only_json_patch_422() {
    let mut before = old_vfs_block_fixture();
    let unchanged = before.sandbox.clone();
    before.race = Some(Race::SandboxVersionApi422);
    let (client, state) = client(before);
    let suspended = client
        .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
        .await
        .unwrap()
        .unwrap();
    let result = client
        .set_replicas_for_identity(
            &claim_opts(),
            &claim_name(ENV),
            CLAIM_UID,
            &suspended,
            1,
            DAEMON_IMAGE,
        )
        .await;
    {
        let state = state.lock().unwrap();
        let patch = state
            .requests
            .iter()
            .find(|(method, _, _)| *method == Method::PATCH)
            .unwrap()
            .2
            .clone();
        // Every emitted path and slot is valid on the same observed object.
        let mut uncontended = unchanged.clone();
        assert!(apply_patch_fixture(&mut uncontended, &patch));
        assert_eq!(uncontended["spec"]["operatingMode"], "Running");
        let spec = &uncontended["spec"]["podTemplate"]["spec"];
        let dind = spec["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "dind")
            .unwrap();
        assert_eq!(dind["command"][2], commodity_dind_bootstrap_script());
        assert_eq!(
            spec["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == "codewire-bin")
                .unwrap()["image"]["reference"],
            DAEMON_IMAGE
        );
        // The synthetic controller changes ONLY RV, retaining UID/spec/slots.
        let mut changed = unchanged;
        changed["metadata"]["resourceVersion"] = json!("31");
        let failed: Vec<_> = patch
            .as_array()
            .unwrap()
            .iter()
            .filter(|op| op["op"] == "test")
            .filter_map(|op| {
                let path = op["path"].as_str().unwrap();
                (changed.pointer(path) != Some(&op["value"])).then_some(path)
            })
            .collect();
        assert_eq!(failed, ["/metadata/resourceVersion"]);
        assert!(!apply_patch_fixture(&mut changed, &patch));
        println!(
            "upstream=422/Invalid failed-test=/metadata/resourceVersion all-other-slots-valid=true"
        );
    }
    result.expect("a status-only version conflict should be re-read within the existing bound");
}

#[tokio::test]
async fn operating_mode_status_conflicts_keep_the_original_stop_mode() {
    for mode in ["Running", "Suspended"] {
        for race in [Race::SandboxVersion, Race::SandboxVersionApi422] {
            let mut before = fixture();
            before.sandbox["spec"]["operatingMode"] = json!(mode);
            before.pod = Value::Null;
            before.race = Some(race);
            let (client, state) = client(before);
            client
                .suspend_workspace(&claim_opts(), &claim_name(ENV), CLAIM_UID)
                .await
                .unwrap();
            let state = state.lock().unwrap();
            assert_eq!(patches(&state).len(), 2);
            assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
            assert_eq!(patches(&state)[0][1]["value"], "30");
            assert_eq!(patches(&state)[1][1]["value"], "31");
        }
    }
}

#[tokio::test]
async fn operating_mode_conflicts_refuse_stable_invalid_and_identity_or_spec_drift() {
    for race in [
        Race::StableApi422,
        Race::SandboxSpecApi422,
        Race::ClaimSpecApi422,
        Race::SandboxModeApi422,
        Race::SandboxUidApi422,
    ] {
        let mut before = old_vfs_block_fixture();
        before.race = Some(race);
        let (client, state) = client(before);
        let suspended = client
            .workspace_suspension_observed(&claim_opts(), &claim_name(ENV), CLAIM_UID)
            .await
            .unwrap()
            .unwrap();
        let error = client
            .set_replicas_for_identity(
                &claim_opts(),
                &claim_name(ENV),
                CLAIM_UID,
                &suspended,
                1,
                DAEMON_IMAGE,
            )
            .await
            .unwrap_err();
        let state = state.lock().unwrap();
        assert_eq!(patches(&state).len(), 1, "{error:#}");
        if matches!(race, Race::StableApi422) {
            assert_eq!(state.sandbox["metadata"]["resourceVersion"], "30");
            assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
            assert!(format!("{error:#}").contains("422"));
        }
    }
}

#[tokio::test]
async fn operating_mode_status_conflicts_exhaust_exactly_three_writes() {
    for race in [
        Race::SandboxVersionEveryPatch,
        Race::SandboxVersionEveryPatchApi422,
    ] {
        let mut before = old_vfs_block_fixture();
        let original = before.sandbox["spec"].clone();
        before.race = Some(race);
        let (client, state) = client(before);
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
                    1,
                    DAEMON_IMAGE
                )
                .await
                .is_err()
        );
        let state = state.lock().unwrap();
        assert_eq!(patches(&state).len(), 3);
        let versions: Vec<_> = patches(&state)
            .iter()
            .map(|patch| patch[1]["value"].clone())
            .collect();
        assert_eq!(versions, [json!("30"), json!("31"), json!("32")]);
        assert_eq!(state.sandbox["metadata"]["resourceVersion"], "33");
        assert_eq!(state.sandbox["spec"], original);
    }
}

#[tokio::test]
async fn operating_mode_unknown_reply_never_replays_a_possibly_published_write() {
    let mut before = old_vfs_block_fixture();
    before.race = Some(Race::MalformedPatchResponse);
    let (client, state) = client(before);
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
                1,
                DAEMON_IMAGE
            )
            .await
            .is_err()
    );
    let state = state.lock().unwrap();
    assert_eq!(patches(&state).len(), 1);
    assert_eq!(state.sandbox["spec"]["operatingMode"], "Running");
}

#[tokio::test]
async fn operating_mode_post_publication_read_conflicts_never_replay_the_write() {
    for race in [Race::PostPublicationRead409, Race::PostPublicationRead422] {
        // An idempotent suspend leaves the spec/mode unchanged, and the
        // controller advances RV. Those facts must not turn a later read
        // failure into evidence that the successful PATCH was unapplied.
        let mut before = fixture();
        before.pod = Value::Null;
        before.race = Some(race);
        let (client, state) = client(before);
        assert!(
            client
                .suspend_workspace(&claim_opts(), &claim_name(ENV), CLAIM_UID)
                .await
                .is_err()
        );
        let state = state.lock().unwrap();
        assert_eq!(patches(&state).len(), 1);
        assert_eq!(state.sandbox["spec"]["operatingMode"], "Suspended");
        assert_eq!(state.sandbox["metadata"]["resourceVersion"], "31");
    }
}
