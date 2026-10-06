//! Disposable-PostgreSQL proof that both gateway RPCs authorize the reviewed
//! gateway Pod by the same ownership chain, against a synthetic Kubernetes API
//! that serves only the gateway Pod, its ReplicaSet and its Deployment. Only
//! synthetic rows in an isolated test database are used.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use anyhow::{Result, ensure};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use k8s_openapi::api::apps::v1::DeploymentSpec;
use k8s_openapi::api::core::v1::{PodSpec, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use sqlx::PgPool;

use super::*;
use crate::sandbox::{LABEL_ENV_ID, LABEL_OPERATION_GENERATION, LABEL_ORG_ID, LABEL_TYPE};
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "gateway-chain-creator";
const ORGANIZATION: &str = "gateway-chain-organization";
const PRESET: &str = "gateway-chain-preset";
const NAMESPACE: &str = "gateway-sandboxes";
const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_ENVIRONMENT: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const GENERATION: i64 = 3;
const DEPLOYMENT_UID: &str = "9d8c7b6a-2222-4f5e-8d4c-3b2a1f0e9d8c";
const REPLICA_SET_UID: &str = "3f2b1c0d-1111-4a2b-8c3d-4e5f6a7b8c9d";
const GATEWAY_POD_UID: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
const WORKSPACE_POD_UID: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const SESSION_SECRET: &str = "synthetic-gateway-chain-session-secret";

/// A running sandbox at `GENERATION` whose workspace Pod is bound, so the
/// daemon-credential RPC has a credential to issue and the binding RPC reaches
/// the workspace once the gateway is authorized.
async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORGANIZATION).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Gateway','gateway', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORGANIZATION)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id,org_id,created_by,preset_id,type,state,desired_state,project_spec, \
          environment_operation_generation) \
         VALUES ($1,$2,$3,$4,'sandbox','running','started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb,$5)",
    )
    .bind(ENVIRONMENT)
    .bind(ORGANIZATION)
    .bind(CREATOR)
    .bind(PRESET)
    .bind(GENERATION)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_environment_backend \
         (environment_id,namespace,sandbox_claim_name,sandbox_claim_uid,pod_name,pod_ip) \
         VALUES ($1,$2,$3,$4,$5,'10.0.0.9')",
    )
    .bind(ENVIRONMENT)
    .bind(NAMESPACE)
    .bind(format!("sandbox-{ENVIRONMENT}"))
    .bind(format!("c0ffee00{}", &ENVIRONMENT[8..]))
    .bind(format!("sandbox-{ENVIRONMENT}"))
    .execute(&db.pool)
    .await?;
    let mut tx = db.pool.begin().await?;
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings \
         (pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid,operation_generation, \
          managed_credential_clients,credential_scope) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'','pod')",
    )
    .bind(WORKSPACE_POD_UID)
    .bind(ENVIRONMENT)
    .bind(NAMESPACE)
    .bind(format!("sandbox-{ENVIRONMENT}"))
    .bind(format!("c0ffee00{}", &ENVIRONMENT[8..]))
    .bind(format!("5a4db0c5{}", &ENVIRONMENT[8..]))
    .bind(GENERATION)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE sandbox_environment_backend SET pod_uid=$2, bound_at=now() WHERE environment_id=$1",
    )
    .bind(ENVIRONMENT)
    .bind(WORKSPACE_POD_UID)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

fn chain_labels(organization: &str, generation: i64) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_ENV_ID.into(), ENVIRONMENT.into()),
        (LABEL_ORG_ID.into(), organization.into()),
        (LABEL_TYPE.into(), "gateway".into()),
        (LABEL_OPERATION_GENERATION.into(), generation.to_string()),
    ])
}

fn owner(kind: &str, name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: "apps/v1".into(),
        kind: kind.into(),
        name: name.into(),
        uid: uid.into(),
        controller: Some(true),
        ..Default::default()
    }
}

fn meta(name: &str, uid: &str, labels: &BTreeMap<String, String>) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: Some(NAMESPACE.into()),
        uid: Some(uid.into()),
        labels: Some(labels.clone()),
        ..Default::default()
    }
}

/// A gateway Pod, its ReplicaSet and its Deployment.
#[derive(Clone)]
struct GatewayFixture {
    pod: Pod,
    replica_set: ReplicaSet,
    deployment: Deployment,
}

impl GatewayFixture {
    /// The environment's own `cw-gateway-<env>` chain, every label set
    /// current.
    fn cold() -> Self {
        Self::new(
            &format!("cw-gateway-{ENVIRONMENT}"),
            &chain_labels(ORGANIZATION, GENERATION),
        )
    }

    fn new(deployment_name: &str, labels: &BTreeMap<String, String>) -> Self {
        let mut pod = Pod {
            metadata: meta("gateway-pod", GATEWAY_POD_UID, labels),
            spec: Some(PodSpec {
                service_account_name: Some(GATEWAY_BINDING_SERVICE_ACCOUNT.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        pod.metadata.owner_references =
            Some(vec![owner("ReplicaSet", "gateway-rs", REPLICA_SET_UID)]);
        let mut replica_set = ReplicaSet {
            metadata: meta("gateway-rs", REPLICA_SET_UID, labels),
            ..Default::default()
        };
        replica_set.metadata.owner_references =
            Some(vec![owner("Deployment", deployment_name, DEPLOYMENT_UID)]);
        let deployment = Deployment {
            metadata: meta(deployment_name, DEPLOYMENT_UID, labels),
            spec: Some(DeploymentSpec {
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels.clone()),
                        ..Default::default()
                    }),
                    spec: None,
                },
                ..Default::default()
            }),
            // Not Available: neither RPC requires availability.
            status: None,
        };
        Self {
            pod,
            replica_set,
            deployment,
        }
    }

    /// A synthetic Kubernetes API serving exactly these three objects and
    /// recording every request path. Everything else is 404.
    fn kubernetes(&self, requests: Arc<Mutex<Vec<String>>>) -> kube::Client {
        let objects = Arc::new(BTreeMap::from([
            (
                format!("/api/v1/namespaces/{NAMESPACE}/pods/gateway-pod"),
                serde_json::to_value(&self.pod).unwrap(),
            ),
            (
                format!("/apis/apps/v1/namespaces/{NAMESPACE}/replicasets/gateway-rs"),
                serde_json::to_value(&self.replica_set).unwrap(),
            ),
            (
                format!(
                    "/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{}",
                    self.deployment.metadata.name.as_deref().unwrap()
                ),
                serde_json::to_value(&self.deployment).unwrap(),
            ),
        ]));
        let service = Router::new().fallback(move |request: Request<Body>| {
            let objects = Arc::clone(&objects);
            let requests = Arc::clone(&requests);
            async move {
                let path = request.uri().path().to_owned();
                requests.lock().unwrap().push(path.clone());
                let (status, body) = match objects.get(&path) {
                    Some(object) => (StatusCode::OK, object.to_string()),
                    None => (
                        StatusCode::NOT_FOUND,
                        serde_json::json!({"apiVersion":"v1","kind":"Status","status":"Failure",
                            "message":"synthetic not found","reason":"NotFound","code":404})
                        .to_string(),
                    ),
                };
                Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }
        });
        kube::Client::new(service, "default")
    }
}

fn identity() -> GatewayPodIdentity {
    GatewayPodIdentity::for_test(NAMESPACE, "gateway-pod", GATEWAY_POD_UID)
}

/// Whether the binding RPC authorized the gateway: only an authorized gateway
/// reads the environment's SandboxClaim. The synthetic API has no Claim, so no
/// binding is issued either way and the RPC answers NotFound, which keeps a
/// refused gateway polling.
async fn binding_reaches_the_workspace(pool: &PgPool, fixture: &GatewayFixture) -> Result<bool> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let client = fixture.kubernetes(Arc::clone(&requests));
    let target = resolve_binding_target_in(&client, pool, &identity()).await?;
    ensure!(target.is_none());
    let reached = requests
        .lock()
        .unwrap()
        .iter()
        .any(|path| path.contains("/sandboxclaims/"));
    Ok(reached)
}

async fn daemon_credential(
    pool: &PgPool,
    fixture: &GatewayFixture,
) -> std::result::Result<String, AppError> {
    let client = fixture.kubernetes(Arc::default());
    issue_gateway_daemon_credential_in(&client, pool, SESSION_SECRET, &identity())
        .await
        .map(|credential| credential.workspace_pod_uid)
}

/// Labelled `type=gateway` Pods for this environment whose chain does not
/// hold.
fn broken_chains() -> Vec<(&'static str, GatewayFixture)> {
    let mut foreign_replica_set = GatewayFixture::cold();
    // The Pod names a ReplicaSet whose live UID is another.
    foreign_replica_set.replica_set.metadata.uid =
        Some("0a1b2c3d-3333-4e5f-8a9b-0c1d2e3f4a5b".into());
    let mut foreign_owner = GatewayFixture::cold();
    // The ReplicaSet is controlled by a Deployment other than the live one.
    foreign_owner.replica_set.metadata.owner_references = Some(vec![owner(
        "Deployment",
        &format!("cw-gateway-{ENVIRONMENT}"),
        "0a1b2c3d-4444-4e5f-8a9b-0c1d2e3f4a5b",
    )]);
    let mut stale_deployment = GatewayFixture::cold();
    stale_deployment.deployment.metadata.labels = Some(chain_labels(ORGANIZATION, GENERATION - 1));
    let mut stale_template = GatewayFixture::cold();
    stale_template
        .deployment
        .spec
        .as_mut()
        .unwrap()
        .template
        .metadata = Some(ObjectMeta {
        labels: Some(chain_labels(ORGANIZATION, GENERATION - 1)),
        ..Default::default()
    });
    let mut other_org = GatewayFixture::cold();
    other_org.replica_set.metadata.labels =
        Some(chain_labels("gateway-chain-other-organization", GENERATION));
    let mut orphan = GatewayFixture::cold();
    orphan.pod.metadata.owner_references = None;
    vec![
        ("foreign ReplicaSet", foreign_replica_set),
        ("ReplicaSet owned by another Deployment", foreign_owner),
        (
            "wrong Deployment name",
            GatewayFixture::new(
                "cw-gateway-impostor",
                &chain_labels(ORGANIZATION, GENERATION),
            ),
        ),
        (
            "another environment's Deployment name",
            GatewayFixture::new(
                &format!("cw-gateway-{OTHER_ENVIRONMENT}"),
                &chain_labels(ORGANIZATION, GENERATION),
            ),
        ),
        ("stale Deployment generation", stale_deployment),
        ("stale template generation", stale_template),
        (
            "stale generation on every object",
            GatewayFixture::new(
                &format!("cw-gateway-{ENVIRONMENT}"),
                &chain_labels(ORGANIZATION, GENERATION - 1),
            ),
        ),
        ("mismatched organization", other_org),
        ("no ReplicaSet controller", orphan),
    ]
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_binding_rpc_requires_the_full_gateway_chain() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        // The environment's own cold chain is authorized.
        ensure!(binding_reaches_the_workspace(&db.pool, &GatewayFixture::cold()).await?);
        // Every one of these Pods is labelled `type=gateway` for this
        // environment. Labels alone used to be enough; each is now refused
        // without reading the workspace.
        for (case, fixture) in broken_chains() {
            ensure!(
                !binding_reaches_the_workspace(&db.pool, &fixture).await?,
                "{case} was authorized"
            );
        }
        // A new operation generation makes the current labels stale.
        sqlx::query("UPDATE environments SET environment_operation_generation = $2 WHERE id = $1")
            .bind(ENVIRONMENT)
            .bind(GENERATION + 1)
            .execute(&db.pool)
            .await?;
        ensure!(!binding_reaches_the_workspace(&db.pool, &GatewayFixture::cold()).await?);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_daemon_credential_rpc_keeps_the_same_gateway_chain() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        ensure!(
            daemon_credential(&db.pool, &GatewayFixture::cold())
                .await
                .ok()
                .as_deref()
                == Some(WORKSPACE_POD_UID)
        );
        for (case, fixture) in broken_chains() {
            ensure!(
                matches!(
                    daemon_credential(&db.pool, &fixture).await,
                    Err(AppError::Forbidden)
                ),
                "{case} was not forbidden"
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}
