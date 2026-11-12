//! Daemon repair replaces the workspace Pod under the environment runtime
//! lease. A caller that leaves mid-repair must not strand the lease `active`,
//! which would block every external cleanup in the organization.

use std::sync::Mutex;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use tokio::sync::oneshot;

use super::*;
use crate::api::runtime_lease_test_support::{LeaseFixture, drop_caller_after_operation_starts};

const NAMESPACE: &str = "synthetic-daemon-repair";
const KUBERNETES_FAILURE: &str = r#"{"apiVersion":"v1","kind":"Status","status":"Failure","message":"synthetic Kubernetes failure","reason":"InternalError","code":500}"#;

type Gate = (oneshot::Sender<()>, oneshot::Receiver<()>);

/// A Kubernetes API that records each request and answers it with a server
/// error. With a gate, the first request reports that it arrived and waits
/// for the test before answering.
fn failing_kubernetes(gate: Option<Gate>, requests: Arc<Mutex<Vec<String>>>) -> kube::Client {
    let gate = Arc::new(tokio::sync::Mutex::new(gate));
    let service = Router::new().fallback(move |request: Request<Body>| {
        let gate = Arc::clone(&gate);
        let requests = Arc::clone(&requests);
        async move {
            requests
                .lock()
                .unwrap()
                .push(format!("{} {}", request.method(), request.uri().path()));
            if let Some((entered, finish)) = gate.lock().await.take() {
                let _ = entered.send(());
                let _ = finish.await;
            }
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(KUBERNETES_FAILURE))
                .unwrap()
        }
    });
    kube::Client::new(service, "default")
}

async fn admitted_repair(fixture: &LeaseFixture, kube: kube::Client) -> DaemonRepair {
    let authority = ActivityAuthority::capture_required(&fixture.pool, &fixture.id, "started", 1)
        .await
        .expect("seeded environment carries started authority");
    DaemonRepair {
        pool: fixture.pool.clone(),
        runtime: crate::runtime::kubernetes::KubernetesDriver::shared(kube),
        session_secret: "synthetic-daemon-repair-session-secret".into(),
        daemon_endpoints: EnvironmentDaemonEndpointOverrides::default(),
        namespace: NAMESPACE.into(),
        environment_id: fixture.id.clone(),
        authority,
        current: Incarnation {
            name: "workspace-old".into(),
            uid: "uid-old".into(),
        },
        support_image: crate::sandbox::template::TEST_SUPPORT_IMAGE.into(),
        timeout: daemon_repair_timeout("standard"),
    }
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_repair_settles_its_lease_after_the_caller_is_dropped() {
    let fixture = LeaseFixture::seed(NAMESPACE).await;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sandbox = failing_kubernetes(Some((entered_tx, finish_rx)), Arc::clone(&requests));
    let repair = admitted_repair(&fixture, sandbox).await;

    // The caller leaves while the Pod replacement is talking to Kubernetes.
    drop_caller_after_operation_starts(
        run_daemon_repair(&fixture.pool, &fixture.id, repair),
        entered_rx,
    )
    .await;
    let lease_id = fixture.only_unresolved_lease("active").await;
    let _ = finish_tx.send(());

    // The failed Pod deletion is ambiguous, exactly as for a waiting caller.
    let settled = fixture.settled_lease(&lease_id).await;
    assert_eq!(settled.state, "resolution_required");
    assert_eq!(
        settled.recovery_code.as_deref(),
        Some("environment_daemon_repair_ambiguous")
    );
    assert_eq!(
        *requests.lock().unwrap(),
        [format!(
            "GET /api/v1/namespaces/{NAMESPACE}/pods/workspace-old"
        )],
        "repair stops at the failed Pod read and never deletes or waits"
    );

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_repair_replaces_the_observed_member_then_waits_for_its_replacement() {
    let fixture = LeaseFixture::seed(NAMESPACE).await;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut repair =
        admitted_repair(&fixture, failing_kubernetes(None, Arc::clone(&requests))).await;
    let runtime = Arc::new(crate::runtime::fake::FakeRuntimeDriver {
        replacement: Mutex::new(Some(crate::runtime::MemberReplacement::Replaced)),
        ..Default::default()
    });
    repair.runtime = runtime.clone();
    let image = repair.support_image.clone();

    // The fake's wait fails, so the repair ends there.
    let error = run_daemon_repair(&fixture.pool, &fixture.id, repair)
        .await
        .expect_err("the replacement never came");

    assert!(
        matches!(&error, AppError::Upstream(message) if message == "environment daemon repair did not converge"),
        "{error:?}"
    );
    assert_eq!(
        *runtime.replacement_calls.lock().unwrap(),
        [
            format!("replace {} workspace-old uid-old {image}", fixture.id),
            "wait workspace-old uid-old".to_string(),
        ]
    );
    assert!(
        requests.lock().unwrap().is_empty(),
        "nothing binds a replacement that never came"
    );

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_repair_known_setup_rejection_releases_its_lease() {
    let fixture = LeaseFixture::seed(NAMESPACE).await;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sandbox = failing_kubernetes(None, Arc::clone(&requests));
    let repair = admitted_repair(&fixture, sandbox).await;
    // Setup took the runtime back after the pre-admission check passed.
    sqlx::query(
        "UPDATE sandbox_environment_backend SET setup_complete = false WHERE environment_id = $1",
    )
    .bind(&fixture.id)
    .execute(&fixture.pool)
    .await
    .unwrap();

    let error = run_daemon_repair(&fixture.pool, &fixture.id, repair)
        .await
        .expect_err("busy setup rejects the repair");
    assert!(
        matches!(&error, AppError::Conflict(message) if message == "environment setup or recovery is in progress"),
        "{error:?}"
    );
    fixture.assert_no_unresolved_leases().await;
    assert!(
        requests.lock().unwrap().is_empty(),
        "a known rejection never reaches Kubernetes"
    );

    fixture.cleanup().await;
}
