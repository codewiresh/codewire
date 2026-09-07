//! Synthetic in-process Kubernetes responses and isolated, restricted SQL.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use axum::{Router, body::Body};
use base64::Engine as _;
use codewire_access::{
    AccessProfile, AccessProfileName, CapabilitySlot, CredentialId, EnvironmentAccessBinding,
    EnvironmentId, GrantContext, Owner, OwnerId, Placement, builtin_provider_catalog,
};
use codewire_credential_broker::platform::bridge::{
    PlatformBridgeAuthenticationError, PlatformBridgeAuthenticator,
};
use codewire_credential_broker::platform::{PlatformRuntimeAuthority, PlatformRuntimeError};
use codewire_platform_credentials::PlatformAccessProfileStore;
use codewire_server_core::pod_identity::PodIdentityPurpose;
use http::{Request, Response, StatusCode};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::core::v1::Pod;
use kube::Client;
use kube::api::DynamicObject;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Notify;
use tonic::metadata::{MetadataMap, MetadataValue};
use uuid::Uuid;

use crate::KubernetesPlatformBridgeAuthenticator;
use crate::authority::{Scope, WORKSPACE_AUTHORIZATION, unix_now};
use crate::objects::{gateway_chain, gateway_environment, workspace_chain};

mod database;

const NAMESPACE: &str = "synthetic-workspaces";
const ENVIRONMENT: &str = "a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417";
const GATEWAY: &str = "synthetic-gateway";
const WORKSPACE: &str = "synthetic-workspace";
const GATEWAY_UID: &str = "4646bcca-54bb-4881-9109-2f9c43da021a";
const WORKSPACE_UID: &str = "5334599b-3b66-4363-92b3-bd1cb230d95e";
const RS_UID: &str = "d6df50a9-9c1a-4efb-b071-de2336475347";
const DEPLOYMENT_UID: &str = "ef35a526-2125-418c-995a-e07504e8e135";
const CLAIM_UID: &str = "e78d4729-6710-4ad9-8b05-ecad87013e33";
const SANDBOX_UID: &str = "9a784b09-4c0b-4af7-bc88-275d8f78d5f0";
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const TOKEN_REVIEW_PATH: &str = "/apis/authentication.k8s.io/v1/tokenreviews";

fn scope() -> Scope {
    Scope {
        environment_id: ENVIRONMENT.into(),
        creator: "synthetic-creator".into(),
        organization: "synthetic-org".into(),
        generation: 7,
        namespace: NAMESPACE.into(),
        claim_name: "synthetic-claim".into(),
        claim_uid: CLAIM_UID.into(),
        pod_name: WORKSPACE.into(),
        member_id: "synthetic-membership".into(),
        member_role: "member".into(),
        profile_id: Uuid::new_v4().to_string(),
        profile_revision: 1,
        confirmed_by: "synthetic-creator".into(),
    }
}

fn labels(role: &str) -> Value {
    json!({
        "codewire.sh/environment-id": ENVIRONMENT, "codewire.sh/org-id": "synthetic-org",
        "codewire.sh/type": role, "codewire.sh/environment-operation-generation": "7"
    })
}

fn owner(api: &str, kind: &str, name: &str, uid: &str) -> Value {
    json!({"apiVersion":api,"kind":kind,"name":name,"uid":uid,"controller":true})
}

fn metadata(name: &str, uid: &str, role: &str) -> Value {
    json!({"name":name,"namespace":NAMESPACE,"uid":uid,"labels":labels(role),"generation":3})
}

fn objects() -> BTreeMap<String, Value> {
    let mut gateway = json!({
        "apiVersion":"v1","kind":"Pod","metadata":metadata(GATEWAY,GATEWAY_UID,"gateway"),
        "spec":{"serviceAccountName":PodIdentityPurpose::CredentialGateway.service_account()},
        "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}
    });
    gateway["metadata"]["ownerReferences"] =
        json!([owner("apps/v1", "ReplicaSet", "synthetic-rs", RS_UID)]);
    let deployment_name = format!("cw-gateway-{ENVIRONMENT}");
    let mut replica_set = json!({
        "apiVersion":"apps/v1","kind":"ReplicaSet","metadata":metadata("synthetic-rs",RS_UID,"gateway")
    });
    replica_set["metadata"]["ownerReferences"] = json!([owner(
        "apps/v1",
        "Deployment",
        &deployment_name,
        DEPLOYMENT_UID
    )]);
    let deployment = json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":metadata(&deployment_name,DEPLOYMENT_UID,"gateway"),
        "spec":{"selector":{"matchLabels":labels("gateway")},"template":{"metadata":{"labels":labels("gateway")}}},
        "status":{"observedGeneration":3,"availableReplicas":1,"conditions":[{"type":"Available","status":"True"}]}
    });
    let mut claim = json!({
        "apiVersion":"extensions.agents.x-k8s.io/v1beta1","kind":"SandboxClaim",
        "metadata":metadata("synthetic-claim",CLAIM_UID,"sandbox"),
        "status":{"sandbox":{"name":"synthetic-sandbox"},"conditions":[
            {"type":"Ready","status":"True","observedGeneration":9}
        ]}
    });
    claim["metadata"]["generation"] = json!(27); // Not Sandbox's generation.
    let mut sandbox = json!({
        "apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox",
        "metadata":{"name":"synthetic-sandbox","namespace":NAMESPACE,"uid":SANDBOX_UID,
            "generation":9,"annotations":{"agents.x-k8s.io/pod-name":WORKSPACE}},
        "spec":{"podTemplate":{"metadata":{"labels":labels("workspace")}}},
        "status":{"conditions":[{"type":"Ready","status":"True","observedGeneration":9}]}
    });
    sandbox["metadata"]["ownerReferences"] = json!([owner(
        "extensions.agents.x-k8s.io/v1beta1",
        "SandboxClaim",
        "synthetic-claim",
        CLAIM_UID,
    )]);
    let mut workspace = json!({
        "apiVersion":"v1","kind":"Pod","metadata":metadata(WORKSPACE,WORKSPACE_UID,"workspace"),
        "spec":{"serviceAccountName":PodIdentityPurpose::CredentialWorkspace.service_account()},
        "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}
    });
    workspace["metadata"]["ownerReferences"] = json!([owner(
        "agents.x-k8s.io/v1beta1",
        "Sandbox",
        "synthetic-sandbox",
        SANDBOX_UID,
    )]);
    BTreeMap::from([
        (pod_path(GATEWAY), gateway),
        (pod_path(WORKSPACE), workspace),
        (
            format!("/apis/apps/v1/namespaces/{NAMESPACE}/replicasets/synthetic-rs"),
            replica_set,
        ),
        (
            format!("/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{deployment_name}"),
            deployment,
        ),
        (
            format!(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxclaims/synthetic-claim"
            ),
            claim,
        ),
        (
            format!(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/{NAMESPACE}/sandboxes/synthetic-sandbox"
            ),
            sandbox,
        ),
    ])
}

fn pod_path(name: &str) -> String {
    format!("/api/v1/namespaces/{NAMESPACE}/pods/{name}")
}
fn object(objects: &BTreeMap<String, Value>, kind: &str) -> Value {
    objects
        .values()
        .find(|value| value["kind"] == kind)
        .unwrap()
        .clone()
}

#[derive(Default)]
struct Gate {
    path: Mutex<Option<String>>,
    entered: Notify,
    released: Notify,
}
impl Gate {
    fn arm(&self, path: String) {
        *self.path.lock().unwrap() = Some(path);
    }
    async fn wait(&self) -> Result<()> {
        tokio::time::timeout(TIMEOUT, self.entered.notified())
            .await
            .context("Kube barrier not reached")?;
        Ok(())
    }
    fn release(&self) {
        self.released.notify_one();
    }
    async fn pass(&self, path: &str) {
        let hit = {
            let mut selected = self.path.lock().unwrap();
            if selected.as_deref() == Some(path) {
                selected.take();
                true
            } else {
                false
            }
        };
        if hit {
            self.entered.notify_one();
            self.released.notified().await;
        }
    }
}

#[derive(Clone)]
struct KubeFixture {
    objects: Arc<Mutex<BTreeMap<String, Value>>>,
    paths: Arc<Mutex<Vec<String>>>,
    reviews: Arc<AtomicUsize>,
    gate: Arc<Gate>,
}

impl KubeFixture {
    fn new() -> Self {
        Self {
            objects: Arc::new(Mutex::new(objects())),
            paths: Arc::new(Mutex::new(Vec::new())),
            reviews: Arc::new(AtomicUsize::new(0)),
            gate: Arc::new(Gate::default()),
        }
    }
    fn client(&self) -> Client {
        let fixture = self.clone();
        Client::new(Router::new().fallback(move |request: Request<Body>| {
            let fixture = fixture.clone();
            async move {
                let path = request.uri().path().to_owned();
                fixture.paths.lock().unwrap().push(path.clone());
                let value = if path == TOKEN_REVIEW_PATH {
                    fixture.reviews.fetch_add(1,Ordering::SeqCst);
                    let bytes = axum::body::to_bytes(request.into_body(),40_000).await.unwrap();
                    let review: Value = serde_json::from_slice(&bytes).unwrap();
                    reviewed(&review)
                } else {
                    fixture.objects.lock().unwrap().get(&path).cloned().unwrap_or(json!({
                        "apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404
                    }))
                };
                fixture.gate.pass(&path).await;
                Response::builder().status(if value["code"] == 404 {StatusCode::NOT_FOUND} else {StatusCode::OK})
                    .header("content-type","application/json").body(Body::from(value.to_string())).unwrap()
            }
        }),NAMESPACE)
    }
}

fn token(role: &str, expires: u64) -> String {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!({"exp":expires,"synthetic_role":role})).unwrap());
    format!("e30.{payload}.c3ludGhldGlj")
}

fn reviewed(review: &Value) -> Value {
    let token = review["spec"]["token"].as_str().unwrap();
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).unwrap())
        .unwrap();
    let payload: Value = serde_json::from_slice(&payload).unwrap();
    let role = payload["synthetic_role"].as_str().unwrap();
    let purpose = if role == "gateway" {
        PodIdentityPurpose::CredentialGateway
    } else {
        PodIdentityPurpose::CredentialWorkspace
    };
    let authenticated = review["spec"]["audiences"] == json!([purpose.audience()]);
    json!({
        "apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
        "status":{"authenticated":authenticated,"audiences":[purpose.audience()],
            "user":{"username":format!("system:serviceaccount:{NAMESPACE}:{}",purpose.service_account()),
                "extra":{"authentication.kubernetes.io/pod-name":[if role=="gateway" {GATEWAY} else {WORKSPACE}],
                    "authentication.kubernetes.io/pod-uid":[if role=="gateway" {GATEWAY_UID} else {WORKSPACE_UID}]}
            }}
    })
}

fn headers(expires: u64) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert(
        "authorization",
        format!("Bearer {}", token("gateway", expires + 60))
            .parse()
            .unwrap(),
    );
    let mut forwarded =
        MetadataValue::from_bytes(format!("Bearer {}", token("workspace", expires)).as_bytes());
    forwarded.set_sensitive(true);
    metadata.insert_bin(WORKSPACE_AUTHORIZATION, forwarded);
    metadata
}

async fn closed_pool() -> sqlx::PgPool {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://synthetic:synthetic@127.0.0.1/synthetic")
        .unwrap();
    pool.close().await;
    pool
}

#[tokio::test]
async fn malformed_private_metadata_never_reaches_kubernetes_or_database() {
    let fixture = KubeFixture::new();
    let authenticator =
        KubernetesPlatformBridgeAuthenticator::new(fixture.client(), closed_pool().await);
    for fault in 0..9 {
        let mut metadata = headers(unix_now().unwrap() + 600);
        match fault {
            0 => {
                metadata.remove("authorization");
            }
            1 => {
                metadata.remove_bin(WORKSPACE_AUTHORIZATION);
            }
            2 => {
                metadata.insert(
                    "x-codewire-workspace-authorization",
                    "Bearer fake".parse().unwrap(),
                );
            }
            3 => {
                let value = metadata.get("authorization").unwrap().clone();
                metadata.append("authorization", value);
            }
            4 => {
                let value = metadata.get_bin(WORKSPACE_AUTHORIZATION).unwrap().clone();
                metadata.append_bin(WORKSPACE_AUTHORIZATION, value);
            }
            5 => {
                metadata.insert("authorization", "bearer a.b.c".parse().unwrap());
            }
            6 => {
                metadata.insert_bin(
                    WORKSPACE_AUTHORIZATION,
                    MetadataValue::from_bytes(b"Bearer a.b.c,other"),
                );
            }
            7 => {
                metadata.insert_bin(
                    WORKSPACE_AUTHORIZATION,
                    MetadataValue::from_bytes(
                        format!("Bearer {}.b.c", "x".repeat(16 * 1024)).as_bytes(),
                    ),
                );
            }
            _ => {
                metadata.insert_bin(
                    WORKSPACE_AUTHORIZATION,
                    MetadataValue::from_bytes(b"Bearer a..c"),
                );
            }
        }
        assert!(matches!(
            authenticator.authenticate(&metadata).await,
            Err(PlatformBridgeAuthenticationError::Unauthenticated)
        ));
    }
    assert!(fixture.paths.lock().unwrap().is_empty());
}

#[tokio::test]
async fn real_kube_client_reviews_both_fixed_purposes_before_any_domain_lookup() {
    let fixture = KubeFixture::new();
    let authenticator =
        KubernetesPlatformBridgeAuthenticator::new(fixture.client(), closed_pool().await);
    assert!(matches!(
        authenticator
            .authenticate(&headers(unix_now().unwrap() + 600))
            .await,
        Err(PlatformBridgeAuthenticationError::Unavailable)
    ));
    let paths = fixture.paths.lock().unwrap().clone();
    assert_eq!(&paths[..2], &[TOKEN_REVIEW_PATH, TOKEN_REVIEW_PATH]);
    assert_eq!(&paths[2..], &[pod_path(GATEWAY)]);
    fixture.paths.lock().unwrap().clear();
    let mut swapped = headers(unix_now().unwrap() + 600);
    swapped.insert_bin(
        WORKSPACE_AUTHORIZATION,
        MetadataValue::from_bytes(
            format!("Bearer {}", token("gateway", unix_now().unwrap() + 600)).as_bytes(),
        ),
    );
    assert!(matches!(
        authenticator.authenticate(&swapped).await,
        Err(PlatformBridgeAuthenticationError::Unauthenticated)
    ));
    assert!(
        fixture
            .paths
            .lock()
            .unwrap()
            .iter()
            .all(|path| path == TOKEN_REVIEW_PATH)
    );
}

#[tokio::test]
async fn whole_authentication_deadline_bounds_pending_token_review() -> Result<()> {
    let fixture = KubeFixture::new();
    fixture.gate.arm(TOKEN_REVIEW_PATH.into());
    let authenticator =
        KubernetesPlatformBridgeAuthenticator::new(fixture.client(), closed_pool().await);
    let metadata = headers(unix_now()? + 600);
    let task = tokio::spawn(async move { authenticator.authenticate(&metadata).await });
    fixture.gate.wait().await?;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::time::resume();
    let result = task.await?;
    fixture.gate.release();
    ensure!(matches!(
        result,
        Err(PlatformBridgeAuthenticationError::Unavailable)
    ));
    ensure!(
        fixture
            .paths
            .lock()
            .unwrap()
            .iter()
            .all(|path| path == TOKEN_REVIEW_PATH)
    );
    Ok(())
}

#[test]
fn gateway_chain_rejects_controller_uid_role_scope_generation_and_readiness_changes() {
    let values = objects();
    for fault in 0..12 {
        let mut pod = values[&pod_path(GATEWAY)].clone();
        let mut rs = object(&values, "ReplicaSet");
        let mut deployment = object(&values, "Deployment");
        match fault {
            0 => {}
            1 => rs["metadata"]["uid"] = json!(Uuid::new_v4().to_string()),
            2 => pod["metadata"]["ownerReferences"][0]["apiVersion"] = json!("other/v1"),
            3 => rs["metadata"]["ownerReferences"][0]["name"] = json!("other"),
            4 => deployment["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z"),
            5 => pod["metadata"]["labels"]["codewire.sh/org-id"] = json!("other"),
            6 => {
                pod["metadata"]["labels"]["codewire.sh/environment-operation-generation"] =
                    json!("6")
            }
            7 => rs["metadata"]["labels"]["codewire.sh/type"] = json!("workspace"),
            8 => {
                deployment["spec"]["template"]["metadata"]["labels"]["codewire.sh/environment-operation-generation"] =
                    json!("8")
            }
            9 => deployment["status"]["observedGeneration"] = json!(2),
            10 => deployment["status"]["availableReplicas"] = json!(0),
            _ => pod["metadata"]["ownerReferences"]
                .as_array_mut()
                .unwrap()
                .push(owner("apps/v1", "ReplicaSet", "another", RS_UID)),
        }
        let pod: Pod = serde_json::from_value(pod).unwrap();
        let rs: ReplicaSet = serde_json::from_value(rs).unwrap();
        let deployment: Deployment = serde_json::from_value(deployment).unwrap();
        assert_eq!(
            gateway_chain(&scope(), &pod, &rs, &deployment).is_ok(),
            fault == 0
        );
        assert_eq!(gateway_environment(&pod).unwrap(), ENVIRONMENT);
    }
}

#[test]
fn workspace_chain_checks_live_generation_without_comparing_claim_generation() {
    let values = objects();
    for fault in 0..12 {
        let mut claim = object(&values, "SandboxClaim");
        let mut sandbox = object(&values, "Sandbox");
        let mut pod = values[&pod_path(WORKSPACE)].clone();
        match fault {
            0 => {}
            1 => claim["metadata"]["uid"] = json!(Uuid::new_v4().to_string()),
            2 => {
                sandbox["metadata"]["ownerReferences"][0]["uid"] = json!(Uuid::new_v4().to_string())
            }
            3 => pod["metadata"]["ownerReferences"][0]["controller"] = json!(false),
            4 => sandbox["status"]["conditions"][0]["observedGeneration"] = json!(8),
            5 => sandbox["metadata"]["deletionTimestamp"] = json!("2026-01-01T00:00:00Z"),
            6 => claim["status"]["conditions"][0]["status"] = json!("False"),
            7 => {
                pod["metadata"]["labels"]["codewire.sh/environment-operation-generation"] =
                    json!("6")
            }
            8 => {
                sandbox["spec"]["podTemplate"]["metadata"]["labels"]["codewire.sh/org-id"] =
                    json!("other")
            }
            9 => sandbox["metadata"]["annotations"]["agents.x-k8s.io/pod-name"] = json!("other"),
            10 => claim["status"]["sandbox"]["name"] = json!("other"),
            _ => claim["status"]["conditions"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"Ready","status":"True"})),
        }
        let claim: DynamicObject = serde_json::from_value(claim).unwrap();
        let sandbox: DynamicObject = serde_json::from_value(sandbox).unwrap();
        let pod: Pod = serde_json::from_value(pod).unwrap();
        assert_eq!(
            workspace_chain(&scope(), &claim, &sandbox, &pod).is_ok(),
            fault == 0
        );
    }
    let mut selected = scope();
    selected.pod_name = "synthetic-sandbox".into();
    let mut sandbox = object(&values, "Sandbox");
    sandbox["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("annotations");
    let mut pod = values[&pod_path(WORKSPACE)].clone();
    pod["metadata"]["name"] = json!("synthetic-sandbox");
    assert!(
        workspace_chain(
            &selected,
            &serde_json::from_value(object(&values, "SandboxClaim")).unwrap(),
            &serde_json::from_value(sandbox).unwrap(),
            &serde_json::from_value(pod).unwrap()
        )
        .is_ok()
    );
}

#[test]
fn authority_errors_have_closed_value_blind_display_debug_and_sources() {
    use std::error::Error as _;
    for error in [
        PlatformRuntimeError::Denied,
        PlatformRuntimeError::Unavailable,
    ] {
        assert!(error.source().is_none());
        assert!(!format!("{error} {error:?}").contains("synthetic-sensitive"));
    }
    for error in [
        PlatformBridgeAuthenticationError::Unauthenticated,
        PlatformBridgeAuthenticationError::Denied,
        PlatformBridgeAuthenticationError::Unavailable,
    ] {
        assert!(error.source().is_none());
        assert!(!format!("{error} {error:?}").contains("synthetic-sensitive"));
    }
}
