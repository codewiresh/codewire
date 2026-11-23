//! The Pod check's answers and the sweep's clock, on a fake cluster and fake
//! rows; the store's own behaviour is in codewire-platform-credentials.

use std::sync::Mutex;

use super::*;

const POD: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const OTHER: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";

/// Answers each read with what was set for that name, or NotFound.
#[derive(Default)]
struct Cluster(Mutex<HashMap<String, PodRead>>);

impl Cluster {
    fn set(&self, name: &str, read: PodRead) {
        self.0.lock().unwrap().insert(name.to_owned(), read);
    }
}

#[async_trait]
impl PodReader for Arc<Cluster> {
    async fn read(&self, namespace: &str, name: &str) -> PodRead {
        assert_eq!(namespace, "sandboxes", "only the configured namespace");
        self.0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or(PodRead::NotFound)
    }
}

fn running(uid: &str) -> PodRead {
    PodRead::Found {
        uid: uid.to_owned(),
        broker_mode: true,
        terminating: false,
    }
}

#[tokio::test]
async fn the_check_admits_only_the_named_pods_running_broker_mode_self() {
    let cluster = Arc::new(Cluster::default());
    let pods = SandboxPods::new(cluster.clone(), "sandboxes".to_owned());
    cluster.set("workspace", running(POD));
    let checked = pods.check(POD, "workspace").await.unwrap();
    let pod = checked.intercepted();
    assert_eq!(
        (pod.uid, pod.namespace, pod.name),
        (POD, "sandboxes", "workspace")
    );

    for (read, refusal) in [
        (running(OTHER), PodRefusal::NotFoundOrOtherUid),
        (PodRead::NotFound, PodRefusal::NotFoundOrOtherUid),
        (
            PodRead::Found {
                uid: POD.to_owned(),
                broker_mode: false,
                terminating: false,
            },
            PodRefusal::NotBrokerMode,
        ),
        (
            PodRead::Found {
                uid: POD.to_owned(),
                broker_mode: true,
                terminating: true,
            },
            PodRefusal::Terminating,
        ),
        (PodRead::Unavailable, PodRefusal::Unavailable),
    ] {
        cluster.set("workspace", read.clone());
        assert_eq!(pods.check(POD, "workspace").await, Err(refusal), "{read:?}");
    }
}

/// Unbound rows, and the UIDs forgotten.
#[derive(Default)]
struct Rows {
    unbound: Mutex<Vec<UnboundInterceptionCa>>,
    forgotten: Mutex<Vec<String>>,
    unreadable: AtomicBool,
}

#[async_trait]
impl InterceptionCaRows for Arc<Rows> {
    async fn unbound(&self) -> Result<Vec<UnboundInterceptionCa>, PlatformCredentialError> {
        if self.unreadable.load(Ordering::SeqCst) {
            return Err(PlatformCredentialError::DatabaseUnavailable);
        }
        Ok(self.unbound.lock().unwrap().clone())
    }

    async fn forget(&self, pod_uid: &str) -> Result<bool, PlatformCredentialError> {
        let mut unbound = self.unbound.lock().unwrap();
        let before = unbound.len();
        unbound.retain(|row| row.pod_uid != pod_uid);
        let removed = unbound.len() < before;
        if removed {
            self.forgotten.lock().unwrap().push(pod_uid.to_owned());
        }
        Ok(removed)
    }
}

/// The sweep over the fake rows and cluster.
type TestSweep = InterceptionCaSweep<Arc<Rows>, Arc<Cluster>>;

fn sweep() -> (Arc<Rows>, Arc<Cluster>, TestSweep) {
    let rows = Arc::new(Rows::default());
    rows.unbound.lock().unwrap().push(UnboundInterceptionCa {
        pod_uid: POD.to_owned(),
        pod_namespace: "sandboxes".to_owned(),
        pod_name: "workspace".to_owned(),
    });
    let cluster = Arc::new(Cluster::default());
    let sweep = InterceptionCaSweep::new(rows.clone(), cluster.clone());
    (rows, cluster, sweep)
}

const MINUTE: Duration = Duration::from_secs(60);

#[tokio::test]
async fn an_absent_pods_ca_is_forgotten_ten_minutes_after_the_first_absent_read() {
    let (rows, _cluster, sweep) = sweep();
    let start = Instant::now();
    assert_eq!(sweep.sweep_once(start).await.absent, 1);
    assert_eq!(sweep.sweep_once(start + 9 * MINUTE).await.absent, 1);
    assert!(rows.forgotten.lock().unwrap().is_empty());
    assert_eq!(sweep.sweep_once(start + 10 * MINUTE).await.forgotten, 1);
    assert_eq!(rows.forgotten.lock().unwrap().as_slice(), [POD]);
    // Forgotten once: the row is gone, and so is its clock.
    let after = sweep.sweep_once(start + 15 * MINUTE).await;
    assert_eq!((after.forgotten, after.absent), (0, 0));
}

#[tokio::test]
async fn another_uid_at_the_name_counts_as_absent() {
    let (rows, cluster, sweep) = sweep();
    cluster.set("workspace", running(OTHER));
    let start = Instant::now();
    sweep.sweep_once(start).await;
    assert_eq!(sweep.sweep_once(start + 10 * MINUTE).await.forgotten, 1);
    assert_eq!(rows.forgotten.lock().unwrap().as_slice(), [POD]);
}

/// An API error neither starts the clock nor moves it: only definite reads
/// count, and a wrongly forgotten CA strands a live Sandbox (#5006).
#[tokio::test]
async fn an_unreadable_pod_neither_starts_nor_advances_the_clock() {
    let (rows, cluster, sweep) = sweep();
    let start = Instant::now();
    cluster.set("workspace", PodRead::Unavailable);
    for minutes in [0, 5, 10, 20] {
        let counts = sweep.sweep_once(start + minutes * MINUTE).await;
        assert_eq!((counts.skipped, counts.absent, counts.forgotten), (1, 0, 0));
    }
    // The first definite absence starts the clock now, not at the errors.
    cluster.set("workspace", PodRead::NotFound);
    assert_eq!(sweep.sweep_once(start + 21 * MINUTE).await.absent, 1);
    cluster.set("workspace", PodRead::Unavailable);
    assert_eq!(sweep.sweep_once(start + 25 * MINUTE).await.skipped, 1);
    cluster.set("workspace", PodRead::NotFound);
    assert_eq!(sweep.sweep_once(start + 30 * MINUTE).await.absent, 1);
    assert_eq!(sweep.sweep_once(start + 31 * MINUTE).await.forgotten, 1);
    assert_eq!(rows.forgotten.lock().unwrap().as_slice(), [POD]);
}

#[tokio::test]
async fn a_pod_seen_again_starts_its_clock_over() {
    let (rows, cluster, sweep) = sweep();
    let start = Instant::now();
    sweep.sweep_once(start).await;
    cluster.set("workspace", running(POD));
    assert_eq!(sweep.sweep_once(start + 5 * MINUTE).await.present, 1);
    cluster.set("workspace", PodRead::NotFound);
    sweep.sweep_once(start + 12 * MINUTE).await;
    assert_eq!(sweep.sweep_once(start + 21 * MINUTE).await.absent, 1);
    assert!(rows.forgotten.lock().unwrap().is_empty());
    assert_eq!(sweep.sweep_once(start + 22 * MINUTE).await.forgotten, 1);
}

#[tokio::test]
async fn unreadable_rows_forget_nothing() {
    let (rows, _cluster, sweep) = sweep();
    let start = Instant::now();
    sweep.sweep_once(start).await;
    rows.unreadable.store(true, Ordering::SeqCst);
    let counts = sweep.sweep_once(start + 30 * MINUTE).await;
    assert!(!counts.complete);
    assert!(rows.forgotten.lock().unwrap().is_empty());
}

/// Only the API's own 404 is a missing Pod. A refusal (403), a server error or
/// any other failure is unavailable, which never starts or advances a CA's
/// forget clock, so a namespace this service may not read never empties the
/// table (#4001).
#[tokio::test]
async fn only_a_not_found_answer_reads_as_a_missing_pod() {
    use axum::{Router, body::Body, http::Request, response::Response};

    let status = |code: u16, reason: &str| {
        serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "metadata": {},
            "status": "Failure", "reason": reason, "code": code,
        })
        .to_string()
    };
    let pods = |code: u16, body: String| {
        KubernetesPods::new(kube::Client::new(
            Router::new().fallback(move |request: Request<Body>| {
                let body = body.clone();
                async move {
                    assert_eq!(
                        request.uri().path(),
                        "/api/v1/namespaces/sandboxes/pods/workspace"
                    );
                    Response::builder()
                        .status(code)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap()
                }
            }),
            "synthetic",
        ))
    };
    let read = |code, body| async move { pods(code, body).read("sandboxes", "workspace").await };
    assert!(matches!(
        read(404, status(404, "NotFound")).await,
        PodRead::NotFound
    ));
    for (code, reason) in [
        (403, "Forbidden"),
        (401, "Unauthorized"),
        (500, "InternalError"),
    ] {
        assert!(
            matches!(read(code, status(code, reason)).await, PodRead::Unavailable),
            "{code} read as other than unavailable"
        );
    }
    let pod = serde_json::json!({
        "kind": "Pod", "apiVersion": "v1",
        "metadata": {"name": "workspace", "uid": POD, "labels": {EGRESS_MODE_LABEL: EGRESS_MODE_BROKER}},
    })
    .to_string();
    assert!(matches!(
        read(200, pod).await,
        PodRead::Found {
            broker_mode: true,
            terminating: false,
            ..
        }
    ));
}

/// Every pass logs one line, a clean one too, so silence never stands for a
/// clean pass: it is a sweep that died or hung (#4001).
#[tokio::test(start_paused = true)]
async fn every_sweep_pass_logs_one_line_whether_or_not_it_found_anything() {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let _logging = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let passes = || {
        String::from_utf8(captured.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains("interception CA sweep pass"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let (rows, cluster, sweep) = sweep();
    cluster.set("workspace", running(POD));
    let sweep = Arc::new(sweep);
    sweep.start();
    tokio::time::sleep(SWEEP_INTERVAL / 4 + Duration::from_secs(1)).await;
    let clean = passes();
    assert_eq!(clean.len(), 1, "{clean:#?}");
    assert!(
        clean[0].contains("rows=1") && clean[0].contains("present=1"),
        "{}",
        clean[0]
    );
    assert!(clean[0].contains("complete=true"), "{}", clean[0]);
    rows.unreadable.store(true, Ordering::SeqCst);
    tokio::time::sleep(SWEEP_INTERVAL).await;
    let all = passes();
    assert_eq!(all.len(), 2, "{all:#?}");
    assert!(all[1].contains("complete=false"), "{}", all[1]);
    sweep.shutdown().await;
}
