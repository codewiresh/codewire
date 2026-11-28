use std::sync::Mutex as StdMutex;
use std::time::{SystemTime, UNIX_EPOCH};

use codewire_client::hosts::{
    AccessAnswer, AccessCall, HostAccessGrant, HostAccessRefusal, HostKeyRecorded,
};
use codewire_local_vmm::control::v1 as local;
use codewire_workspace_access::daemon_access::AccessControlPlane;
use tokio::sync::mpsc;

use super::plane::{HostPlane, host_grant};
use super::*;

const ENVIRONMENT: Uuid = Uuid::from_u128(0x3609_0000_0000_4000_8000_0000_0000_0001);
const LOCAL: Uuid = Uuid::from_u128(0x3609_0000_0000_4000_8000_0000_0000_0002);

/// Bounds a wait for an event the test causes; it only turns a hang into a
/// failure. Time is paused, so it passes only while nothing else can run.
const HANG_GUARD: Duration = Duration::from_secs(600);

fn observation(generation: u64, state: HostEnvironmentState) -> HostEnvironmentObservation {
    HostEnvironmentObservation {
        environment_id: ENVIRONMENT.to_string(),
        local_environment_id: LOCAL.to_string(),
        generation,
        state: state.into(),
        ..Default::default()
    }
}

fn running(generation: u64) -> HostEnvironmentObservation {
    observation(
        generation,
        HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
    )
}

fn stopped(generation: u64) -> HostEnvironmentObservation {
    observation(
        generation,
        HostEnvironmentState::HOST_ENVIRONMENT_STATE_STOPPED,
    )
}

/// A computer whose supervisor runs `local`, and whose peers write what they
/// do to `events`. A peer for a generation in `refused` ends at once,
/// refused; any other one takes a while to stop, so a successor that didn't
/// wait for it would start first.
#[derive(Default)]
struct FakeHost {
    local: StdMutex<Vec<HostEnvironmentObservation>>,
    refused: StdMutex<BTreeSet<u64>>,
    events: StdMutex<Vec<String>>,
}

impl FakeHost {
    fn runs(&self, local: Vec<HostEnvironmentObservation>) {
        *self.local.lock().unwrap() = local;
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn note(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }

    /// Waits until the peers did exactly `expected`.
    async fn did(&self, expected: &[&str]) {
        let waited = tokio::time::timeout(HANG_GUARD, async {
            while self.events() != expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "expected {expected:?}, the peers did {:?}",
            self.events()
        );
    }
}

impl PeerHost for FakeHost {
    fn inventory(&self) -> BoxFuture<'_, anyhow::Result<Vec<HostEnvironmentObservation>>> {
        let local = self.local.lock().unwrap().clone();
        Box::pin(async move { Ok(local) })
    }

    fn serve(
        self: Arc<Self>,
        vm: PeerKey,
        mut stop: watch::Receiver<bool>,
    ) -> BoxFuture<'static, PeerEnd> {
        Box::pin(async move {
            self.note(format!("start {}", vm.generation));
            if self.refused.lock().unwrap().contains(&vm.generation) {
                self.note(format!("refused {}", vm.generation));
                return PeerEnd::Refused;
            }
            let _ = stop.wait_for(|stop| *stop).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.note(format!("stop {}", vm.generation));
            PeerEnd::Stopped
        })
    }
}

/// Longer than the peers take to look at the supervisor again.
async fn past_a_poll() {
    tokio::time::sleep(POLL * 3).await;
}

#[tokio::test(start_paused = true)]
async fn a_new_boot_stops_the_old_peer_before_the_new_one_starts() {
    let host = Arc::new(FakeHost::default());
    host.runs(vec![running(1)]);
    let peers = Peers::start(host.clone());
    peers.hello(&[running(1)]);
    host.did(&["start 1"]).await;

    host.runs(vec![running(2)]);
    peers.reported(&running(2));
    host.did(&["start 1", "stop 1", "start 2"]).await;

    peers.stop().await;
    assert_eq!(host.events(), ["start 1", "stop 1", "start 2", "stop 2"]);
}

#[tokio::test(start_paused = true)]
async fn a_peer_runs_only_for_the_boot_both_the_report_and_the_supervisor_name() {
    let host = Arc::new(FakeHost::default());
    let peers = Peers::start(host.clone());
    // Reported running, but the supervisor no longer runs it.
    peers.hello(&[running(1)]);
    past_a_poll().await;
    // The supervisor runs a boot the host hasn't reported: Codewire would
    // refuse its calls for good.
    host.runs(vec![running(2)]);
    past_a_poll().await;
    assert!(host.events().is_empty(), "{:?}", host.events());

    peers.reported(&running(2));
    host.did(&["start 2"]).await;
    // Stopped by an operation.
    host.runs(vec![stopped(2)]);
    peers.reported(&stopped(2));
    host.did(&["start 2", "stop 2"]).await;
    peers.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_vm_that_stops_without_an_operation_loses_its_peer_at_the_next_look() {
    let host = Arc::new(FakeHost::default());
    host.runs(vec![running(1)]);
    let peers = Peers::start(host.clone());
    peers.hello(&[running(1)]);
    host.did(&["start 1"]).await;
    host.runs(Vec::new());
    past_a_poll().await;
    host.did(&["start 1", "stop 1"]).await;
    peers.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_refused_peer_is_not_started_again_for_that_boot() {
    let host = Arc::new(FakeHost::default());
    host.refused.lock().unwrap().insert(1);
    host.runs(vec![running(1)]);
    let peers = Peers::start(host.clone());
    peers.hello(&[running(1)]);
    host.did(&["start 1", "refused 1"]).await;
    past_a_poll().await;
    // A later session reports the same boot again.
    peers.hello(&[running(1)]);
    past_a_poll().await;
    assert_eq!(host.events(), ["start 1", "refused 1"]);

    host.runs(vec![running(2)]);
    peers.reported(&running(2));
    host.did(&["start 1", "refused 1", "start 2"]).await;
    peers.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_server_without_access_calls_leaves_no_peer_running() {
    let host = Arc::new(FakeHost::default());
    host.runs(vec![running(1)]);
    let peers = Peers::start(host.clone());
    peers.hello(&[running(1)]);
    host.did(&["start 1"]).await;
    peers.unsupported();
    host.did(&["start 1", "stop 1"]).await;
    peers.hello(&[running(1)]);
    past_a_poll().await;
    assert_eq!(host.events(), ["start 1", "stop 1"]);
    peers.stop().await;
}

fn vm() -> PeerKey {
    PeerKey {
        environment_id: ENVIRONMENT,
        local_environment_id: LOCAL,
        generation: 3,
    }
}

fn grant(operation_generation: i64) -> AccessAnswer {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    AccessAnswer::Grant(Box::new(HostAccessGrant {
        peer_token: "peer-token".into(),
        peer_token_expires_at: i64::try_from(now).unwrap() + 600,
        operation_generation,
        coordinator_url: "https://coordinator.codewire.test".into(),
        app_ports: vec![8080],
        ..Default::default()
    }))
}

fn refusal(code: &str, retryable: bool) -> AccessAnswer {
    AccessAnswer::Refused(HostAccessRefusal {
        code: code.into(),
        retryable,
        ..Default::default()
    })
}

/// A session that answers each call with what `answer` gives for it, or not
/// at all, and sends the calls it took to `seen`.
fn session(
    mut calls: mpsc::Receiver<Call>,
    answers: Vec<Option<AccessAnswer>>,
) -> mpsc::UnboundedReceiver<AccessCall> {
    let (seen, seen_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut pending = Pending::default();
        let mut answers = answers.into_iter();
        while let Some(call) = calls.recv().await {
            let Some(call) = pending.take(call) else {
                continue;
            };
            let request_id = call.request_id().to_owned();
            let _ = seen.send(call);
            if let Some(Some(answer)) = answers.next() {
                pending.answer(echo(answer, &request_id));
            }
        }
    });
    seen_rx
}

/// `answer`, echoing `request_id`.
fn echo(mut answer: AccessAnswer, request_id: &str) -> AccessAnswer {
    match &mut answer {
        AccessAnswer::Grant(grant) => grant.request_id = request_id.into(),
        AccessAnswer::KeyRecorded(recorded) => recorded.request_id = request_id.into(),
        AccessAnswer::RelayAllocation(allocation) => allocation.request_id = request_id.into(),
        AccessAnswer::Refused(refusal) => refusal.request_id = request_id.into(),
    }
    answer
}

fn plane(
    answers: Vec<Option<AccessAnswer>>,
) -> (
    HostPlane,
    watch::Receiver<bool>,
    mpsc::UnboundedReceiver<AccessCall>,
) {
    let (link, calls) = link();
    let (refused, refused_rx) = watch::channel(false);
    let seen = session(calls, answers);
    (HostPlane::new(link, vm(), refused), refused_rx, seen)
}

#[tokio::test]
async fn a_grant_names_the_vm_and_serves_no_ports_or_endpoints() {
    let (plane, refused, mut seen) = plane(vec![Some(grant(4))]);
    let granted = plane.refresh_access().await.unwrap();
    assert_eq!(granted.operation_generation(), 4);
    assert!(
        granted.app_ports().is_empty(),
        "an application port would be forwarded to this computer's loopback"
    );
    assert!(granted.direct_udp_endpoints().is_empty());
    assert!(granted.peer_relay_endpoints().is_empty());
    assert!(!*refused.borrow());
    let Some(AccessCall::Refresh(call)) = seen.recv().await else {
        panic!("a refresh was sent");
    };
    assert_eq!(
        (
            call.environment_id.as_str(),
            call.local_environment_id.as_str(),
            call.generation
        ),
        (
            ENVIRONMENT.to_string().as_str(),
            LOCAL.to_string().as_str(),
            3
        )
    );
    assert!(Uuid::parse_str(&call.request_id).is_ok());
}

#[tokio::test]
async fn a_final_refusal_stops_the_peer_and_a_retryable_one_does_not() {
    let (plane, refused, _seen) = plane(vec![
        Some(refusal("not_running", true)),
        Some(refusal("stale_generation", false)),
    ]);
    assert_eq!(
        plane.refresh_access().await.unwrap_err(),
        ControlPlaneError::Retryable
    );
    assert!(!*refused.borrow());
    assert_eq!(
        plane.refresh_access().await.unwrap_err(),
        ControlPlaneError::Refused
    );
    assert!(*refused.borrow());
}

#[tokio::test]
async fn a_conflicting_host_key_stops_the_peer() {
    let (plane, refused, _seen) = plane(vec![
        Some(AccessAnswer::KeyRecorded(HostKeyRecorded::default())),
        Some(refusal("key_conflict", false)),
    ]);
    plane.record_host_key("ssh-ed25519 AAAA").await.unwrap();
    assert!(!*refused.borrow());
    assert_eq!(
        plane.record_host_key("ssh-ed25519 BBBB").await.unwrap_err(),
        ControlPlaneError::Refused
    );
    assert!(*refused.borrow());
}

/// An operation generation that moves without a reboot leaves the new
/// generation's host-key slot empty, and the client's lookup answers not ready
/// (cw-security's condition on the slice 3 design, §3). The peer keeps
/// running and records the same key into the new slot.
#[tokio::test]
async fn a_new_operation_generation_gets_the_same_host_key_again() {
    let recorded = || Some(AccessAnswer::KeyRecorded(HostKeyRecorded::default()));
    let (plane, refused, mut seen) =
        plane(vec![Some(grant(4)), recorded(), Some(grant(5)), recorded()]);
    let plane = Arc::new(plane);
    let first = plane.refresh_access().await.unwrap();
    plane.record_host_key("ssh-ed25519 AAAA").await.unwrap();
    let grants = AccessGrants::new(plane.clone(), first);
    let (stop, shutdown) = watch::channel(false);
    let recorder = tokio::spawn(daemon_tailnet::record_host_key_per_generation(
        plane.clone(),
        grants.subscribe(),
        "ssh-ed25519 AAAA".into(),
        4,
        shutdown,
    ));
    grants.refresh().await.unwrap();
    let mut keys = Vec::new();
    tokio::time::timeout(HANG_GUARD, async {
        while keys.len() < 2 {
            if let Some(AccessCall::RecordKey(call)) = seen.recv().await {
                keys.push(call.public_key_openssh);
            }
        }
    })
    .await
    .expect("the key is recorded again for generation 5");
    assert_eq!(keys, ["ssh-ed25519 AAAA", "ssh-ed25519 AAAA"]);
    assert!(!*refused.borrow(), "the peer keeps serving its VM");
    let _ = stop.send(true);
    recorder.await.unwrap();
}

#[tokio::test]
async fn no_relay_leaves_the_peer_running() {
    let (plane, refused, _seen) = plane(vec![Some(refusal("unsupported", false))]);
    assert_eq!(
        plane
            .allocate_peer_relay(["discokey:a".into(), "discokey:b".into()], 1)
            .await
            .unwrap_err(),
        ControlPlaneError::Refused
    );
    assert!(!*refused.borrow(), "the peer stays on DERP");
}

#[tokio::test(start_paused = true)]
async fn a_call_no_session_answers_is_retryable() {
    let (plane, refused, mut seen) = plane(vec![None]);
    assert_eq!(
        plane.refresh_access().await.unwrap_err(),
        ControlPlaneError::Retryable
    );
    assert!(seen.recv().await.is_some());
    assert!(!*refused.borrow());
}

#[test]
fn an_answer_reaches_only_the_call_it_echoes() {
    let (link, mut calls) = link();
    drop(link);
    assert!(calls.try_recv().is_err());
    let mut pending = Pending::default();
    pending.answer(refusal("not_held", false));
    assert!(pending.is_empty(), "an answer to no call is dropped");
}

#[test]
fn a_splice_serves_only_its_own_vm_at_its_own_boot() {
    let environment = |id: Uuid, generation, state: local::EnvironmentState| local::Environment {
        id: id.to_string(),
        generation,
        state: state as i32,
        ..Default::default()
    };
    let running = local::EnvironmentState::Running;
    assert!(splice::serves(&environment(LOCAL, 3, running), &vm()));
    assert!(!splice::serves(&environment(LOCAL, 4, running), &vm()));
    assert!(!splice::serves(
        &environment(ENVIRONMENT, 3, running),
        &vm()
    ));
    assert!(!splice::serves(
        &environment(LOCAL, 3, local::EnvironmentState::Stopped),
        &vm()
    ));
}

#[test]
fn an_invalid_grant_is_not_taken() {
    let AccessAnswer::Grant(mut granted) = grant(4) else {
        unreachable!()
    };
    granted.coordinator_url = "http://coordinator.codewire.test".into();
    assert!(host_grant(&granted, SystemTime::now()).is_none());
}
