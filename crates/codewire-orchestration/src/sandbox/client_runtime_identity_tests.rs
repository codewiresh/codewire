use super::*;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, Response, StatusCode};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const NS: &str = "dev-sandboxes";
const CLAIM: &str = "sandbox-env-test";
const CLAIM_UID: &str = "claim-uid";
const POD: &str = "workspace-existing";
const SANDBOX: &str = "sandbox-existing";
const POD_UID: &str = "pod-uid";
const TIMEOUT: Duration = Duration::from_secs(2);

fn opts() -> ClaimOpts {
    ClaimOpts {
        environment_id: "env-test".into(),
        org_id: "org-test".into(),
        operation_generation: 7,
        ..Default::default()
    }
}

fn claim(generation: i64) -> Value {
    json!({
        "apiVersion": super::super::EXTENSIONS_API_VERSION, "kind": "SandboxClaim",
        "metadata": { "name": CLAIM, "namespace": NS, "uid": CLAIM_UID, "resourceVersion": "12", "generation": 30,
            "labels": runtime_identity_labels("env-test", "org-test", generation, "sandbox"),
            "annotations": { "fixture": "preserve" }, "finalizers": [DELETION_PROTECTION_FINALIZER] },
        "spec": { "warmPoolRef": { "name": "unchanged-private-shadow" },
            "additionalPodMetadata": { "labels": runtime_identity_labels("env-test", "org-test", generation, "workspace"),
                "annotations": { "fixture": "also-preserve" } } },
        "status": { "sandbox": { "name": SANDBOX },
            "conditions": [{ "type": "Ready", "status": "True", "observedGeneration": 4 }] }
    })
}

fn owner(api: &str, kind: &str, name: &str, uid: &str) -> Value {
    json!({ "apiVersion": api, "kind": kind, "name": name, "uid": uid, "controller": true })
}

fn sandbox(generation: i64) -> Value {
    json!({
        "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
        "metadata": { "name": SANDBOX, "namespace": NS, "uid": "sandbox-uid", "generation": 4,
            "annotations": { "agents.x-k8s.io/pod-name": POD },
            "ownerReferences": [owner(super::super::EXTENSIONS_API_VERSION, "SandboxClaim", CLAIM, CLAIM_UID)] },
        "spec": { "podTemplate": { "metadata": {
            "labels": runtime_identity_labels("env-test", "org-test", generation, "workspace") } } },
        "status": { "conditions": [{ "type": "Ready", "status": "True", "observedGeneration": 4 }] }
    })
}

fn pod(generation: i64) -> Value {
    json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": { "name": POD, "namespace": NS, "uid": POD_UID,
            "labels": runtime_identity_labels("env-test", "org-test", generation, "workspace"),
            "ownerReferences": [owner("agents.x-k8s.io/v1beta1", "Sandbox", SANDBOX, "sandbox-uid")] },
        "status": { "phase": "Running", "conditions": [{ "type": "Ready", "status": "True" }] }
    })
}

type Recorded = Arc<Mutex<Vec<(Method, String, Value)>>>;

fn client(responses: Vec<(StatusCode, Value)>) -> (SandboxClient, Recorded) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let queued = Arc::new(Mutex::new(VecDeque::from(responses)));
    let service = Router::new().fallback(move |request: Request<Body>| {
        let recorded = recorded.clone();
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
            recorded.lock().unwrap().push((method, path, body));
            let (status, body) = queued
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected Kubernetes call");
            Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    });
    (
        SandboxClient::new(Client::new(service, "default"), NS),
        requests,
    )
}

fn observation() -> RuntimeIdentityObservation {
    RuntimeIdentityObservation {
        sandbox_uid: "sandbox-uid".into(),
        pod: WorkspacePodIdentity {
            name: POD.into(),
            uid: POD_UID.into(),
        },
    }
}

#[tokio::test]
async fn observation_resolves_annotated_pod_name_and_pins_both_object_uids() {
    let (client, requests) = client(vec![
        (StatusCode::OK, claim(6)),
        (StatusCode::OK, sandbox(6)),
        (StatusCode::OK, pod(6)),
    ]);
    let actual = tokio::time::timeout(
        TIMEOUT,
        client.observe_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(actual, observation());
    assert!(
        requests.lock().unwrap()[2]
            .1
            .ends_with(&format!("/pods/{POD}"))
    );
}

#[test]
fn claim_patch_is_uid_rv_bound_metadata_only_and_idempotent() {
    let old: DynamicObject = serde_json::from_value(claim(6)).unwrap();
    require_runtime_claim(&old, NS, &opts(), CLAIM, CLAIM_UID).unwrap();
    let patch = runtime_claim_identity_patch(&old, &opts())
        .unwrap()
        .unwrap();
    assert_eq!(patch["metadata"]["uid"], CLAIM_UID);
    assert_eq!(patch["metadata"]["resourceVersion"], "12");
    assert_eq!(patch["metadata"]["labels"][LABEL_TYPE], "sandbox");
    assert_eq!(
        patch["spec"]["additionalPodMetadata"]["labels"][LABEL_TYPE],
        "workspace"
    );
    assert_eq!(patch["spec"].as_object().unwrap().len(), 1);
    assert!(patch.pointer("/metadata/finalizers").is_none());
    assert!(patch.pointer("/metadata/ownerReferences").is_none());
    assert!(patch.pointer("/metadata/annotations").is_none());
    assert!(
        patch
            .pointer("/spec/additionalPodMetadata/annotations")
            .is_none()
    );
    let current: DynamicObject = serde_json::from_value(claim(7)).unwrap();
    assert!(
        runtime_claim_identity_patch(&current, &opts())
            .unwrap()
            .is_none()
    );
    let mut missing_rv = old;
    missing_rv.metadata.resource_version = None;
    assert!(runtime_claim_identity_patch(&missing_rv, &opts()).is_err());
}

#[test]
fn claim_identity_rejects_wrong_owner_uid_scope_deletion_and_future_generation() {
    let mutations = [
        ("/metadata/uid", json!("replacement")),
        ("/metadata/name", json!("other-claim")),
        ("/metadata/namespace", json!("other-namespace")),
        (
            "/metadata/labels/codewire.sh~1environment-id",
            json!("other-env"),
        ),
        ("/metadata/labels/codewire.sh~1org-id", json!("other-org")),
        ("/metadata/labels/codewire.sh~1type", json!("workspace")),
        (
            "/metadata/labels/codewire.sh~1environment-operation-generation",
            json!("8"),
        ),
        (
            "/metadata/labels/codewire.sh~1environment-operation-generation",
            json!("0"),
        ),
        (
            "/metadata/labels/codewire.sh~1environment-operation-generation",
            json!("opaque-canary"),
        ),
    ];
    for (path, value) in mutations {
        let mut object = claim(6);
        *object.pointer_mut(path).unwrap() = value;
        let object = serde_json::from_value(object).unwrap();
        let error = require_runtime_claim(&object, NS, &opts(), CLAIM, CLAIM_UID).unwrap_err();
        assert!(!error.to_string().contains("opaque-canary"));
    }
    let mut object = claim(6);
    object["metadata"]["deletionTimestamp"] = json!("2026-09-06T00:00:00Z");
    let object = serde_json::from_value(object).unwrap();
    assert!(require_runtime_claim(&object, NS, &opts(), CLAIM, CLAIM_UID).is_err());
    let mut absent_generation = opts();
    absent_generation.operation_generation = 0;
    assert!(
        require_runtime_claim(
            &serde_json::from_value(claim(6)).unwrap(),
            NS,
            &absent_generation,
            CLAIM,
            CLAIM_UID
        )
        .is_err()
    );
}

#[test]
fn propagation_requires_all_labels_and_current_sandbox_readiness_not_claim_generation() {
    let evaluate = |claim: Value, sandbox: Value, pod: Value| {
        runtime_identity_converged(
            &serde_json::from_value(claim).unwrap(),
            &serde_json::from_value(sandbox).unwrap(),
            &serde_json::from_value(pod).unwrap(),
            &opts(),
        )
    };
    // Claim generation is deliberately 30; its Ready forwards Sandbox's 4.
    assert!(evaluate(claim(7), sandbox(7), pod(7)));
    assert!(!evaluate(claim(6), sandbox(7), pod(7)));
    assert!(!evaluate(claim(7), sandbox(6), pod(7)));
    assert!(!evaluate(claim(7), sandbox(7), pod(6)));
    let mut stale = sandbox(7);
    stale["status"]["conditions"][0]["observedGeneration"] = json!(3);
    assert!(!evaluate(claim(7), stale, pod(7)));
    let mut not_ready = pod(7);
    not_ready["status"]["conditions"][0]["status"] = json!("False");
    assert!(!evaluate(claim(7), sandbox(7), not_ready));
    let mut stale = claim(7);
    stale["spec"]["additionalPodMetadata"]["labels"][super::super::LABEL_OPERATION_GENERATION] =
        json!("6");
    assert!(!evaluate(stale, sandbox(7), pod(7)));
}

#[tokio::test]
async fn publisher_sends_only_the_validated_conditional_patch() {
    let (client, requests) = client(vec![(StatusCode::OK, claim(6)), (StatusCode::OK, claim(7))]);
    tokio::time::timeout(
        TIMEOUT,
        client.reconcile_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID),
    )
    .await
    .unwrap()
    .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0, Method::GET);
    assert_eq!(requests[1].0, Method::PATCH);
    assert!(requests[1].1.ends_with(&format!("/sandboxclaims/{CLAIM}")));
    assert_eq!(
        requests[1].2,
        runtime_claim_identity_patch(&serde_json::from_value(claim(6)).unwrap(), &opts())
            .unwrap()
            .unwrap()
    );
}

#[tokio::test]
async fn publisher_does_not_rebase_a_patch_after_conflict_or_replacement() {
    let conflict = json!({ "apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "Conflict", "message": "synthetic-canary", "code": 409 });
    let (client, requests) = client(vec![
        (StatusCode::OK, claim(6)),
        (StatusCode::CONFLICT, conflict),
    ]);
    let error = tokio::time::timeout(
        TIMEOUT,
        client.reconcile_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(!error.to_string().contains("canary"));
    assert_eq!(requests.lock().unwrap().len(), 2);
    let mut replaced = claim(6);
    replaced["metadata"]["uid"] = json!("replacement");
    let (client, requests) = self::client(vec![(StatusCode::OK, replaced)]);
    assert!(
        client
            .reconcile_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID)
            .await
            .is_err()
    );
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn identical_retry_does_not_mutate_the_claim() {
    let (client, requests) = client(vec![(StatusCode::OK, claim(7))]);
    client
        .reconcile_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID)
        .await
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(requests.lock().unwrap()[0].0, Method::GET);
}

#[tokio::test]
async fn wait_observes_controller_propagation_without_patching_a_pod_or_sandbox() {
    let (client, requests) = client(vec![
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, sandbox(6)),
        (StatusCode::OK, pod(6)),
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, sandbox(7)),
        (StatusCode::OK, pod(7)),
    ]);
    client
        .wait_for_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID, &observation(), TIMEOUT)
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 6);
    assert!(requests.iter().all(|(method, _, _)| method == Method::GET));
    assert!(requests[1].1.ends_with(&format!("/sandboxes/{SANDBOX}")));
    assert!(requests[2].1.ends_with(&format!("/pods/{POD}")));
}

#[tokio::test]
async fn wait_rejects_replaced_uids_or_mismatched_controller_lineage() {
    for case in 0..5 {
        let mut current_claim = claim(7);
        let mut current_sandbox = sandbox(7);
        let mut current_pod = pod(7);
        match case {
            0 => current_claim["metadata"]["uid"] = json!("replacement"),
            1 => current_sandbox["metadata"]["ownerReferences"][0]["uid"] = json!("other-claim"),
            2 => current_pod["metadata"]["uid"] = json!("replacement"),
            3 => current_pod["metadata"]["ownerReferences"][0]["uid"] = json!("other-sandbox"),
            4 => current_sandbox["metadata"]["uid"] = json!("replacement"),
            _ => unreachable!(),
        }
        let mut responses = Vec::new();
        if case == 4 {
            responses.extend([
                (StatusCode::OK, claim(7)),
                (StatusCode::OK, sandbox(6)),
                (StatusCode::OK, pod(6)),
            ]);
        }
        responses.extend([
            (StatusCode::OK, current_claim),
            (StatusCode::OK, current_sandbox),
            (StatusCode::OK, current_pod),
        ]);
        let (client, requests) = client(responses);
        assert!(
            client
                .wait_for_claim_runtime_identity(&opts(), CLAIM, CLAIM_UID, &observation(), TIMEOUT)
                .await
                .is_err()
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(method, _, _)| method == Method::GET)
        );
    }
}

#[tokio::test]
async fn partial_propagation_wait_is_bounded_and_does_not_mutate() {
    let (client, requests) = client(vec![
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, sandbox(6)),
        (StatusCode::OK, pod(6)),
    ]);
    assert!(
        client
            .wait_for_claim_runtime_identity(
                &opts(),
                CLAIM,
                CLAIM_UID,
                &observation(),
                Duration::from_millis(1)
            )
            .await
            .is_err()
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|(method, _, _)| method == Method::GET)
    );
}

fn unbound_claim() -> Value {
    let mut claim = claim(7);
    claim["status"] = json!({ "conditions": [] });
    claim
}

/// Design §12: the Pod name comes from the bound Sandbox's controller-
/// published annotation, never the Claim's own name.
#[tokio::test]
async fn the_pod_name_follows_the_bound_sandbox_and_never_the_claim_name() {
    let (sandboxes, requests) = client(vec![
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, sandbox(7)),
    ]);
    assert_eq!(sandboxes.get_pod_name("env-test").await.unwrap(), POD);
    assert!(
        requests.lock().unwrap()[1]
            .1
            .ends_with(&format!("/sandboxes/{SANDBOX}"))
    );

    // An unbound Claim has no runtime: no fallback to `sandbox-<env>`.
    let (sandboxes, requests) = client(vec![(StatusCode::OK, unbound_claim())]);
    assert!(sandboxes.get_pod_name("env-test").await.is_err());
    assert!(client_requests_end(&requests, 1));
    let (sandboxes, _) = client(vec![(StatusCode::OK, unbound_claim())]);
    assert!(sandboxes.bound_sandbox_name("env-test").await.is_err());
}

fn client_requests_end(requests: &Recorded, count: usize) -> bool {
    requests.lock().unwrap().len() == count
}

/// Once bound, the current workspace Pod must be the bound incarnation; a
/// replacement under the same name is refused until its own binding exists.
#[tokio::test]
async fn the_current_workspace_pod_is_the_bound_incarnation() {
    let responses = || {
        vec![
            (StatusCode::OK, claim(7)),
            (StatusCode::OK, sandbox(7)),
            (StatusCode::OK, pod(7)),
        ]
    };
    let (sandboxes, _) = client(responses());
    assert_eq!(
        sandboxes
            .current_workspace_pod("env-test", None)
            .await
            .unwrap(),
        WorkspacePodIdentity {
            name: POD.into(),
            uid: POD_UID.into(),
        }
    );
    let (sandboxes, _) = client(responses());
    assert!(
        sandboxes
            .current_workspace_pod("env-test", Some(POD_UID))
            .await
            .is_ok()
    );
    let (sandboxes, _) = client(responses());
    assert!(
        sandboxes
            .current_workspace_pod("env-test", Some("replacement-uid"))
            .await
            .is_err()
    );
    // A Pod the Sandbox does not control is not the workspace.
    let mut foreign = pod(7);
    foreign["metadata"]["ownerReferences"][0]["uid"] = json!("other-sandbox");
    let (sandboxes, _) = client(vec![
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, sandbox(7)),
        (StatusCode::OK, foreign),
    ]);
    assert!(
        sandboxes
            .current_workspace_pod("env-test", None)
            .await
            .is_err()
    );
}

/// The liveness and create probes find the Pod through the bound Sandbox,
/// and report none for an unbound Claim instead of guessing its name.
#[tokio::test]
async fn the_probe_resolves_the_pod_through_the_sandbox_without_a_name_fallback() {
    let (sandboxes, requests) = client(vec![
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, claim(7)),
        (StatusCode::OK, sandbox(7)),
        (StatusCode::OK, pod(7)),
    ]);
    let probe = sandboxes.probe_environment("env-test").await.unwrap();
    assert!(probe.claim_ready && probe.pod_exists);
    assert_eq!(
        (probe.pod_name.as_str(), probe.pod_uid.as_str()),
        (POD, POD_UID)
    );
    assert!(
        requests.lock().unwrap()[3]
            .1
            .ends_with(&format!("/pods/{POD}"))
    );

    let (sandboxes, requests) = client(vec![
        (StatusCode::OK, unbound_claim()),
        (StatusCode::OK, unbound_claim()),
    ]);
    let probe = sandboxes.probe_environment("env-test").await.unwrap();
    assert!(probe.claim_exists && !probe.pod_exists && probe.pod_name.is_empty());
    assert!(
        client_requests_end(&requests, 2),
        "the probe guessed a Pod name"
    );
}
