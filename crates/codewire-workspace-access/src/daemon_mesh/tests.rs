use std::collections::VecDeque;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_daemon::access::{AccessFields, MeshFields};
use codewire_tailnet::conn::{Options as ConnOptions, Transport, WgDatagram};
use codewire_tailnet::node::Prefix;
use codewire_tailnet::wg::StaticSecret;
use rand::rngs::OsRng;
use tokio::sync::mpsc;

use super::*;

const ENVIRONMENT: Uuid = Uuid::from_u128(0x3350_0000_0000_4000_8000_0000_0000_0001);
/// Bounds a wait that ends on its event; it only turns a hang into a failure.
const HANG_GUARD: Duration = Duration::from_secs(60);

fn grant(network: Option<&str>) -> WorkspaceAccessGrant {
    let now = SystemTime::now();
    let seconds = i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    WorkspaceAccessGrant::validate(
        &AccessFields {
            peer_token: "synthetic-peer-token",
            peer_token_expires_at: seconds + 600,
            operation_generation: 4,
            coordinator_url: "https://coordinator.codewire.test",
            direct_udp_endpoints: &[],
            peer_relay_endpoints: &[],
            app_ports: &[],
            mesh: network.map(|network_id| MeshFields {
                mesh_url: "https://mesh.codewire.test",
                org_id: "org-1",
                network_id,
                node_name: "app-1",
            }),
        },
        now,
    )
    .unwrap()
}

/// A tailnet connection whose transport goes nowhere.
fn idle_conn() -> Arc<Conn> {
    let (to_transport, _out) = mpsc::unbounded_channel::<WgDatagram>();
    let (_in, from_transport) = mpsc::unbounded_channel::<WgDatagram>();
    std::mem::forget(_out);
    std::mem::forget(_in);
    Arc::new(
        Conn::new(
            ConnOptions {
                id: Uuid::new_v4(),
                addresses: vec![Prefix::new(
                    IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1)),
                    128,
                )],
                endpoints: Vec::new(),
                private_key: Some(StaticSecret::random_from_rng(OsRng)),
                disco_private: None,
            },
            Transport {
                to_transport,
                from_transport,
                peer_updates: None,
                path_probe: None,
                local_endpoint_updates: None,
            },
        )
        .unwrap(),
    )
}

#[derive(Default)]
struct Plane {
    issued: Mutex<Vec<String>>,
    refuse_issue: AtomicBool,
    reports: Mutex<Vec<MeshReport>>,
    events: tokio::sync::Notify,
}

#[async_trait]
impl MeshControlPlane for Plane {
    async fn issue_mesh_enrollment(&self) -> Result<MeshEnrollment, ControlPlaneError> {
        if self.refuse_issue.load(Ordering::SeqCst) {
            return Err(ControlPlaneError::Refused);
        }
        let mut issued = self.issued.lock().unwrap();
        let code = format!("cw_eenr_synthetic-{}", issued.len());
        issued.push(code.clone());
        self.events.notify_waiters();
        Ok(MeshEnrollment {
            code: Zeroizing::new(code),
            target: grant(Some("work")).mesh().unwrap().clone(),
        })
    }

    async fn report_mesh_attachment(&self, report: MeshReport) -> Result<(), ControlPlaneError> {
        self.reports.lock().unwrap().push(report);
        self.events.notify_waiters();
        Ok(())
    }
}

struct Membership {
    conn: Arc<Conn>,
    ready: Arc<AtomicBool>,
}

impl MeshMembership for Membership {
    fn conn(&self) -> Arc<Conn> {
        self.conn.clone()
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
}

/// Answers each join from a script; an empty script admits.
#[derive(Default)]
struct Joiner {
    answers: Mutex<VecDeque<Result<(), JoinError>>>,
    joined: Mutex<Vec<(String, String)>>,
    /// The readiness of the latest admitted membership.
    latest: Mutex<Option<Arc<AtomicBool>>>,
}

#[async_trait]
impl MeshJoiner for Joiner {
    async fn join(
        &self,
        target: &MeshTarget,
        code: &str,
        environment_id: Uuid,
    ) -> Result<Box<dyn MeshMembership>, JoinError> {
        assert_eq!(environment_id, ENVIRONMENT);
        self.joined
            .lock()
            .unwrap()
            .push((target.network_id().to_owned(), code.to_owned()));
        self.answers.lock().unwrap().pop_front().unwrap_or(Ok(()))?;
        let ready = Arc::new(AtomicBool::new(true));
        *self.latest.lock().unwrap() = Some(ready.clone());
        Ok(Box::new(Membership {
            conn: idle_conn(),
            ready,
        }))
    }
}

struct Harness {
    plane: Arc<Plane>,
    joiner: Arc<Joiner>,
    grants: watch::Sender<WorkspaceAccessGrant>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start(network: Option<&str>, answers: Vec<Result<(), JoinError>>) -> Harness {
    let plane = Arc::new(Plane::default());
    let joiner = Arc::new(Joiner {
        answers: Mutex::new(answers.into()),
        ..Default::default()
    });
    let (grants, grants_rx) = watch::channel(grant(network));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (_ports, ports_rx) = watch::channel(AppPorts::default());
    std::mem::forget(_ports);
    let task = tokio::spawn(run(
        DaemonMeshConfig {
            environment_id: ENVIRONMENT,
            reserved_ports: BTreeSet::new(),
            timing: MeshTiming {
                fault_backoff: Duration::from_millis(10),
                max_fault_backoff: Duration::from_millis(40),
                refused_backoff: Duration::from_millis(30),
                max_refused_backoff: Duration::from_millis(60),
                readiness_poll: Duration::from_millis(10),
            },
        },
        grants_rx,
        plane.clone(),
        joiner.clone(),
        ports_rx,
        shutdown_rx,
    ));
    Harness {
        plane,
        joiner,
        grants,
        shutdown,
        task,
    }
}

impl Harness {
    /// Waits until `condition` holds of the plane and joiner.
    async fn until(&self, condition: impl Fn(&Plane, &Joiner) -> bool) {
        tokio::time::timeout(HANG_GUARD, async {
            while !condition(&self.plane, &self.joiner) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the membership loop did not reach the expected state");
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(HANG_GUARD, self.task)
            .await
            .expect("the membership loop did not stop")
            .unwrap();
    }
}

fn reports(plane: &Plane) -> Vec<MeshReport> {
    plane.reports.lock().unwrap().clone()
}

fn joins(joiner: &Joiner) -> usize {
    joiner.joined.lock().unwrap().len()
}

#[tokio::test]
async fn an_environment_without_a_network_never_asks_to_join() {
    let harness = start(None, Vec::new());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(harness.plane.issued.lock().unwrap().is_empty());
    assert_eq!(joins(&harness.joiner), 0);
    harness.stop().await;
}

#[tokio::test]
async fn each_stream_uses_one_fresh_code_and_an_ended_stream_rejoins() {
    let harness = start(Some("work"), Vec::new());
    harness
        .until(|plane, _| reports(plane) == [MeshReport::Attached])
        .await;
    let first = harness.joiner.joined.lock().unwrap()[0].clone();
    assert_eq!(first.0, "work");
    // The stream ends (a recheck, a revocation, a fault): a new code joins.
    harness
        .joiner
        .latest
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .store(false, Ordering::SeqCst);
    harness.until(|_, joiner| joins(joiner) == 2).await;
    let codes: Vec<String> = harness
        .joiner
        .joined
        .lock()
        .unwrap()
        .iter()
        .map(|(_, code)| code.clone())
        .collect();
    assert_ne!(codes[0], codes[1], "a code is used for one stream only");
    assert_eq!(*harness.plane.issued.lock().unwrap(), codes);
    // A second attach is not reported again.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(reports(&harness.plane), [MeshReport::Attached]);
    harness.stop().await;
}

#[tokio::test]
async fn refusals_are_reported_once_and_retried_slowly_until_repaired() {
    let harness = start(
        Some("work"),
        vec![
            Err(JoinError::Refused(MeshReport::NotAMember)),
            Err(JoinError::Refused(MeshReport::NotAMember)),
            Err(JoinError::CodeRefused),
            Err(JoinError::Unreachable),
        ],
    );
    harness
        .until(|plane, _| {
            reports(plane)
                == [
                    MeshReport::NotAMember,
                    MeshReport::MeshUnreachable,
                    MeshReport::Attached,
                ]
        })
        .await;
    assert_eq!(joins(&harness.joiner), 5);
    harness.stop().await;
}

#[tokio::test]
async fn a_grant_that_drops_the_network_leaves_it() {
    let harness = start(Some("work"), Vec::new());
    harness
        .until(|plane, _| reports(plane) == [MeshReport::Attached])
        .await;
    let membership = harness.joiner.latest.lock().unwrap().clone().unwrap();
    harness.grants.send(grant(None)).unwrap();
    // The membership is dropped and no new code is asked for.
    harness
        .until(|_, _| Arc::strong_count(&membership) == 2)
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.plane.issued.lock().unwrap().len(), 1);
    harness.stop().await;
}

#[tokio::test]
async fn a_platform_refusal_waits_for_the_next_grant() {
    let harness = start(Some("work"), Vec::new());
    harness.plane.refuse_issue.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(joins(&harness.joiner), 0);
    harness.plane.refuse_issue.store(false, Ordering::SeqCst);
    // The next grant wakes it.
    harness.grants.send(grant(Some("work"))).unwrap();
    harness
        .until(|plane, _| reports(plane) == [MeshReport::Attached])
        .await;
    harness.stop().await;
}

#[test]
fn refused_stream_codes_map_to_reports() {
    assert_eq!(
        join_error(Some("not_found")),
        JoinError::Refused(MeshReport::NetworkNotFound)
    );
    assert_eq!(
        join_error(Some("permission_denied")),
        JoinError::Refused(MeshReport::NotAMember)
    );
    assert_eq!(
        join_error(Some("already_exists")),
        JoinError::Refused(MeshReport::NodeNameTaken)
    );
    assert_eq!(
        join_error(Some("failed_precondition")),
        JoinError::Refused(MeshReport::Revoked)
    );
    assert_eq!(join_error(Some("unauthenticated")), JoinError::CodeRefused);
    for other in [Some("unavailable"), Some("none"), None] {
        assert_eq!(join_error(other), JoinError::Unreachable);
    }
    let enrollment = MeshEnrollment {
        code: Zeroizing::new("cw_eenr_secret-canary".to_owned()),
        target: grant(Some("work")).mesh().unwrap().clone(),
    };
    assert!(!format!("{enrollment:?}").contains("secret-canary"));
}
