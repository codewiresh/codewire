//! #3628 PR 8b, cw-confidential's condition: confidential storage authorizes
//! the init data the driver measures an intent's runtime with, and the driver
//! writes that runtime only while its own init data still hashes to what was
//! authorized. A refusal comes before any request.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{KubernetesDriver, KubernetesRenderConfig};
use crate::runtime::{
    ClaimRef, Isolation, Placement, RenderingIdentity, RenderingIntent, RuntimeDriver,
    SuspendedRuntime, WorkspaceShape,
};
use crate::sandbox::template::{
    CredentialRuntimeTemplateConfig, DOCKER_MODE_PROFILE_DEFAULT, RUNTIME_PROFILE_COMMODITY,
};
use crate::sandbox::{ClaimOpts, shadow_warm_pool_name};
use crate::worker::create::SandboxWorkerCfg;

const ENVIRONMENT: &str = "3d6bb495-efac-419f-bf3a-91696e7c7ca4";

/// Dev with the confidential tier enabled, synthetic values.
fn confidential_cfg() -> SandboxWorkerCfg {
    SandboxWorkerCfg {
        sandbox_namespace: "dev-sandboxes".into(),
        credential_runtime: Some(CredentialRuntimeTemplateConfig::synthetic("dev-sandboxes")),
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
        kata_coco_init_data_enabled: true,
        kata_coco_kbs_url: "https://kbs.example.invalid:8080".into(),
        kata_coco_image_registry_auth_uri: "kbs:///default/containers/auth".into(),
        confidential_workspace_storage_class: "linstor-confidential".into(),
        confidential_binding_roots_pem:
            "-----BEGIN CERTIFICATE-----\nroots\n-----END CERTIFICATE-----\n".into(),
        ..Default::default()
    }
}

fn intent(isolation: Isolation) -> RenderingIntent {
    RenderingIntent {
        image: crate::sandbox::canonical_workspace_runtime_image().into(),
        template_base: "workspace".into(),
        isolation,
        dedicated_cpu: false,
        shape: WorkspaceShape {
            cpu_millicores: 2000,
            memory_mib: 8192,
            disk_gib: 80,
        },
        identity: RenderingIdentity {
            environment_id: ENVIRONMENT.into(),
            organization_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
            operation_generation: 7,
            projection_selection_sha256: None,
            managed_credential_clients: Default::default(),
            source_snapshot_id: None,
            confidential_storage_manifest_uri: "kbs:///default/codewire-storage-manifests/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        },
    }
}

type Requests = Arc<Mutex<Vec<String>>>;

/// A driver over an API that records every request and finds nothing.
fn driver(cfg: &SandboxWorkerCfg) -> (Arc<dyn RuntimeDriver>, Requests) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let service = Router::new().fallback(move |request: Request<Body>| {
        let seen = seen.clone();
        async move {
            seen.lock()
                .unwrap()
                .push(format!("{} {}", request.method(), request.uri().path()));
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"apiVersion": "v1", "kind": "Status", "status": "Failure",
                        "reason": "NotFound", "code": 404})
                    .to_string(),
                ))
                .unwrap()
        }
    });
    (
        KubernetesDriver::shared(kube::Client::new(service, "dev-sandboxes"), cfg.into()),
        requests,
    )
}

fn authorized(driver: &dyn RuntimeDriver, intent: &RenderingIntent) -> [u8; 32] {
    let init_data = driver
        .measured_init_data(intent)
        .unwrap()
        .expect("a confidential runtime is measured");
    Sha256::digest(init_data.as_bytes()).into()
}

fn claim() -> ClaimRef {
    ClaimRef {
        placement: Placement::new("dev-sandboxes"),
        environment_id: ENVIRONMENT.into(),
        organization_id: "76169e1f-3bbf-46be-96e0-cac68e0ac910".into(),
        operation_generation: 7,
        name: format!("claim-{ENVIRONMENT}"),
        uid: "claim-uid".into(),
    }
}

fn suspended() -> SuspendedRuntime {
    SuspendedRuntime::synthetic("sandbox-1", "sandbox-uid")
}

async fn publish(
    driver: &dyn RuntimeDriver,
    intent: &RenderingIntent,
    authorized: &[u8; 32],
) -> anyhow::Result<String> {
    driver
        .publish_measured_runtime(
            &Placement::new("dev-sandboxes"),
            ENVIRONMENT,
            "sandbox-1",
            intent,
            authorized,
        )
        .await
}

const DIFFERS: &str =
    "the measured runtime differs from the init data confidential storage authorized";

/// Only a runtime that is measured has init data to authorize.
#[tokio::test]
async fn only_a_confidential_runtime_with_a_disk_is_measured() {
    let (driver, _) = driver(&confidential_cfg());
    assert!(
        driver
            .measured_init_data(&intent(Isolation::Confidential))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        driver
            .measured_init_data(&intent(Isolation::Standard))
            .unwrap(),
        None
    );
    let mut diskless = intent(Isolation::Confidential);
    diskless.shape.disk_gib = 0;
    assert_eq!(driver.measured_init_data(&diskless).unwrap(), None);
}

/// The authorized init data passes the guard and reaches the API; anything
/// else is refused before a request.
#[tokio::test]
async fn a_measured_runtime_is_published_only_as_authorized() {
    let intent = intent(Isolation::Confidential);
    let (driver, requests) = driver(&confidential_cfg());
    let authorized = authorized(driver.as_ref(), &intent);

    // Authorized: the guard passes, and the publish asks for the claim.
    let error = publish(driver.as_ref(), &intent, &authorized)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("SandboxClaim"), "{error:#}");
    assert!(!requests.lock().unwrap().is_empty());

    // Another hash, or another intent under the same hash: nothing is asked.
    for (case, intent, hash) in [
        ("another hash", intent.clone(), [0; 32]),
        (
            "another environment's intent",
            RenderingIntent {
                identity: RenderingIdentity {
                    environment_id: "9a1fbbea-4c2d-4e8f-9b3a-5d6e7f8a9b0c".into(),
                    ..intent.identity.clone()
                },
                ..intent.clone()
            },
            authorized,
        ),
    ] {
        requests.lock().unwrap().clear();
        let error = publish(driver.as_ref(), &intent, &hash).await.unwrap_err();
        assert_eq!(error.to_string(), DIFFERS, "{case}");
        assert!(requests.lock().unwrap().is_empty(), "{case}");
    }

    // An unmeasured runtime is never published.
    let error = publish(
        driver.as_ref(),
        &self::intent(Isolation::Standard),
        &authorized,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "only a measured confidential runtime is published"
    );
}

/// The deployment changed between authorizing and publishing: the runtime the
/// driver would now render isn't the one authorized, so it is refused.
#[tokio::test]
async fn a_configuration_change_after_authorizing_is_refused() {
    let intent = intent(Isolation::Confidential);
    let (before, _) = driver(&confidential_cfg());
    let authorized = authorized(before.as_ref(), &intent);
    for (case, changed) in [
        (
            "key broker",
            SandboxWorkerCfg {
                kata_coco_kbs_url: "https://kbs-2.example.invalid:8080".into(),
                ..confidential_cfg()
            },
        ),
        (
            "measured roots",
            SandboxWorkerCfg {
                confidential_binding_roots_pem:
                    "-----BEGIN CERTIFICATE-----\nrotated\n-----END CERTIFICATE-----\n".into(),
                ..confidential_cfg()
            },
        ),
    ] {
        let (after, requests) = driver(&changed);
        let error = publish(after.as_ref(), &intent, &authorized)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), DIFFERS, "{case}");
        let error = after
            .refresh_bootstrap(&claim(), &intent, &suspended(), Some(&authorized))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), DIFFERS, "{case}");
        assert!(requests.lock().unwrap().is_empty(), "{case}");
    }
}

/// A refresh carries an authorization exactly when its runtime is measured.
#[tokio::test]
async fn a_refresh_is_authorized_exactly_when_measured() {
    let (driver, requests) = driver(&confidential_cfg());
    let confidential = intent(Isolation::Confidential);
    let authorized = authorized(driver.as_ref(), &confidential);
    for (case, intent, hash, refusal) in [
        (
            "measured without one",
            confidential.clone(),
            None,
            "a measured confidential runtime needs its authorized init data",
        ),
        (
            "unmeasured with one",
            intent(Isolation::Standard),
            Some(&authorized),
            "only a measured confidential runtime has authorized init data",
        ),
    ] {
        let error = driver
            .refresh_bootstrap(&claim(), &intent, &suspended(), hash)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), refusal, "{case}");
        assert!(requests.lock().unwrap().is_empty(), "{case}");
    }
    // Each as it should be reaches the API.
    for (intent, hash) in [
        (confidential, Some(&authorized)),
        (intent(Isolation::Standard), None),
    ] {
        requests.lock().unwrap().clear();
        let _ = driver
            .refresh_bootstrap(&claim(), &intent, &suspended(), hash)
            .await;
        assert!(!requests.lock().unwrap().is_empty());
    }
}

/// A cold claim writes the environment's own runtime, so a measured one is
/// written only as authorized, and anything else is refused before a request
/// (cw-security's review of #4571).
#[tokio::test]
async fn a_cold_claim_writes_a_measured_runtime_only_as_authorized() {
    let cfg = confidential_cfg();
    let (driver, requests) = driver(&cfg);
    let placement = Placement::new("dev-sandboxes");
    let confidential = intent(Isolation::Confidential);
    let authorized = authorized(driver.as_ref(), &confidential);
    let another = [0; 32];
    // A standard runtime names no confidential storage manifest.
    let mut standard = intent(Isolation::Standard);
    standard.identity.confidential_storage_manifest_uri.clear();
    let claim = |intent: &RenderingIntent| {
        let template = KubernetesRenderConfig::from(&cfg)
            .environment(intent)
            .unwrap()
            .name;
        ClaimOpts {
            environment_id: ENVIRONMENT.into(),
            org_id: intent.identity.organization_id.clone(),
            operation_generation: 7,
            warm_pool_ref: shadow_warm_pool_name(&template),
            template_ref: template,
            ..Default::default()
        }
    };
    for (case, intent, hash, refusal) in [
        (
            "another hash",
            confidential.clone(),
            Some(&another),
            DIFFERS,
        ),
        (
            "measured without one",
            confidential.clone(),
            None,
            "a measured confidential runtime needs its authorized init data",
        ),
        (
            "unmeasured with one",
            standard.clone(),
            Some(&authorized),
            "only a measured confidential runtime has authorized init data",
        ),
    ] {
        requests.lock().unwrap().clear();
        let error = driver
            .prepare_cold_claim(&placement, &intent, &claim(&intent), hash)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), refusal, "{case}");
        assert!(requests.lock().unwrap().is_empty(), "{case}");
    }
    // Each as it should be reaches the API.
    for (intent, hash) in [(confidential, Some(&authorized)), (standard, None)] {
        requests.lock().unwrap().clear();
        let outcome = driver
            .prepare_cold_claim(&placement, &intent, &claim(&intent), hash)
            .await;
        assert!(!requests.lock().unwrap().is_empty(), "{outcome:?}");
    }
}
