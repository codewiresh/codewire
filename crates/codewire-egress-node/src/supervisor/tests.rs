use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use codewire_egress_policy::{BuiltinPolicy, CompiledPolicy, PolicyDigest};
use codewire_network_session::NetworkKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::*;
use crate::admitted::{AdmittedStream, FailureCode, PodEvent, PodEvents};
use crate::interception::{FrontDoorSpec, Interception, InterceptionRefusal, PairIntercepts};
use crate::orchestration::{AssignedPolicy, Assignment, AssignmentError, PlatformAllow};

/// What the fake launcher was asked to do, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Did {
    Started(Uuid, PolicyDigest),
    Replaced(Uuid, PolicyDigest),
    DrainRequested(Uuid),
    Ended(Uuid),
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Acks {
    /// The broker acknowledges the policy it was sent.
    #[default]
    Sent,
    Another,
    Nothing,
}

#[derive(Default)]
struct World {
    did: Vec<Did>,
    /// How each Pod's newest pair is told its next status.
    statuses: HashMap<Uuid, mpsc::UnboundedSender<PairStatus>>,
    failing: Vec<Uuid>,
    /// Starts that wait here until notified.
    held: HashMap<Uuid, Arc<Notify>>,
    /// While set, a pair's reaping waits here.
    reaping: Option<Arc<Notify>>,
    acks: Acks,
    /// What each start intercepts, in order.
    intercepts: Vec<PairIntercepts>,
}

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<World>>);

impl Fake {
    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn did(&self) -> Vec<Did> {
        self.world().did.clone()
    }

    fn tell(&self, pod: Uuid, status: PairStatus) {
        self.world().statuses[&pod].send(status).unwrap();
    }
}

struct FakePair {
    pod: Uuid,
    fake: Fake,
    statuses: mpsc::UnboundedReceiver<PairStatus>,
}

impl Launch for Fake {
    type Pair = FakePair;
    type Error = &'static str;

    async fn start(&self, spec: PairSpec) -> Result<FakePair, &'static str> {
        let held = self.world().held.get(&spec.pod_uid).cloned();
        if let Some(held) = held {
            held.notified().await;
        }
        let mut world = self.world();
        if world.failing.contains(&spec.pod_uid) {
            return Err("the worker did not become ready");
        }
        let (tell, statuses) = mpsc::unbounded_channel();
        world.statuses.insert(spec.pod_uid, tell);
        world
            .did
            .push(Did::Started(spec.pod_uid, spec.policy.digest()));
        world.intercepts.push(spec.intercepts);
        Ok(FakePair {
            pod: spec.pod_uid,
            fake: self.clone(),
            statuses,
        })
    }
}

impl Pair for FakePair {
    type Error = &'static str;

    async fn status(&mut self) -> PairStatus {
        match self.statuses.recv().await {
            Some(status) => status,
            None => std::future::pending().await,
        }
    }

    async fn replace(&mut self, policy: &CompiledPolicy) -> Result<PolicyDigest, &'static str> {
        let mut world = self.fake.world();
        world.did.push(Did::Replaced(self.pod, policy.digest()));
        match world.acks {
            Acks::Sent => Ok(policy.digest()),
            Acks::Another => Ok(PolicyDigest::from_bytes([7; 32])),
            Acks::Nothing => Err("the broker did not acknowledge the policy"),
        }
    }

    async fn request_drain(&mut self) -> Result<(), &'static str> {
        self.fake.world().did.push(Did::DrainRequested(self.pod));
        Ok(())
    }

    async fn end(self) {
        let reaping = self.fake.world().reaping.clone();
        if let Some(reaping) = reaping {
            reaping.notified().await;
        }
        self.fake.world().did.push(Did::Ended(self.pod));
    }
}

const POD: Uuid = Uuid::from_u128(1);
const OTHER_POD: Uuid = Uuid::from_u128(2);
const THIRD_POD: Uuid = Uuid::from_u128(3);

fn platform() -> Vec<PlatformAllow> {
    vec![PlatformAllow {
        host: "control.example.com".into(),
        port: 443,
    }]
}

fn locked() -> CompiledPolicy {
    BuiltinPolicy::Locked.compile()
}

fn open() -> CompiledPolicy {
    BuiltinPolicy::Open.compile()
}

fn unbound() -> Assignment {
    Assignment::Unbound {
        platform: platform(),
    }
}

fn bound(environment: &str, revision: u32, policy: CompiledPolicy) -> Assignment {
    Assignment::Bound {
        environment_id: environment.into(),
        operation_generation: 1,
        policy: AssignedPolicy {
            reference: "platform:web".into(),
            revision,
            policy,
        },
        platform: platform(),
        interception: Box::new(Interception::Off),
    }
}

const ENVIRONMENT: Uuid = Uuid::from_u128(0x6f1c_2a0e_8b4d_4e2a_9c3f_1d2e_3f4a_5b6c);

fn front_door(hosts: &[&str]) -> FrontDoorSpec {
    FrontDoorSpec {
        environment_id: ENVIRONMENT,
        generation: 1,
        intercepts: codewire_egress_policy::intercept::InterceptSet::new(hosts.iter().map(
            |host| codewire_egress_policy::intercept::InterceptBinding::new(host, 443).unwrap(),
        ))
        .unwrap(),
    }
}

/// `ENVIRONMENT` bound with `interception`.
fn intercepting(interception: Interception) -> Assignment {
    let Assignment::Bound {
        environment_id,
        operation_generation,
        policy,
        platform,
        ..
    } = bound(&ENVIRONMENT.to_string(), 1, open())
    else {
        unreachable!("bound");
    };
    Assignment::Bound {
        environment_id,
        operation_generation,
        policy,
        platform,
        interception: Box::new(interception),
    }
}

fn enforced(revision: u32, policy: &CompiledPolicy) -> PodEvent {
    PodEvent::Enforced {
        revision,
        digest: policy.digest(),
    }
}

/// A supervisor on the fake launcher, and the admission side of its seam.
struct Harness {
    fake: Fake,
    admit: mpsc::Sender<AdmittedStream>,
    signals: Signals,
    supervisor: JoinHandle<Drained>,
    listener: TcpListener,
}

/// The admission side of one admitted stream.
struct Admitted {
    changes: watch::Sender<Result<Assignment, AssignmentError>>,
    events: mpsc::Receiver<PodEvent>,
    /// The guest's end, kept open.
    _guest: TcpStream,
}

impl Admitted {
    /// The next event. The clock is paused, so the bound passes at once when
    /// nothing can produce one, and a missing event fails rather than hangs.
    async fn next(&mut self) -> PodEvent {
        tokio::time::timeout(Duration::from_secs(60), self.events.recv())
            .await
            .expect("no event was reported")
            .expect("the Pod's events ended")
    }

    /// Lets every task run until none can, then says whether an event waits.
    async fn has_none(&mut self) -> bool {
        settle().await;
        self.events.is_empty()
    }
}

/// The supervisor's return, which fails rather than hangs if it never comes.
async fn finished(supervisor: JoinHandle<Drained>) -> Drained {
    tokio::time::timeout(Duration::from_secs(60), supervisor)
        .await
        .expect("the supervisor did not return")
        .unwrap()
}

/// Runs every ready task. Time is paused, so nothing else can make progress.
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

impl Harness {
    /// Sockets are made before time is paused: a paused clock runs ahead
    /// while a task waits on real I/O.
    async fn new() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        tokio::time::pause();
        let fake = Fake::default();
        let (admit, admitted) = mpsc::channel(8);
        let signals = Signals::default();
        let supervisor = tokio::spawn(supervisor(admitted, signals.clone(), fake.clone()));
        Self {
            fake,
            admit,
            signals,
            supervisor,
            listener,
        }
    }

    async fn stream(&self) -> (TcpStream, TcpStream, SocketAddr) {
        tokio::time::resume();
        let guest = TcpStream::connect(self.listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, peer) = self.listener.accept().await.unwrap();
        tokio::time::pause();
        (guest, stream, peer)
    }

    async fn admit(&self, pod_uid: Uuid, assignment: Assignment) -> Admitted {
        let (guest, stream, peer) = self.stream().await;
        let (changes, watched) = watch::channel(Ok(assignment.clone()));
        let (events, reported) = mpsc::channel(16);
        self.admit
            .send(AdmittedStream {
                pod_uid,
                pod_name: format!("sandbox-{pod_uid}"),
                peer,
                stream,
                key: NetworkKey::from_derived_bytes([9; 32]).unwrap(),
                assignment,
                changes: watched,
                events: PodEvents::new(events),
            })
            .await
            .unwrap();
        settle().await;
        Admitted {
            changes,
            events: reported,
            _guest: guest,
        }
    }

    /// An admitted Pod whose guest passed its self-check.
    async fn enforcing(&self, pod_uid: Uuid, assignment: Assignment) -> Admitted {
        let mut admitted = self.admit(pod_uid, assignment).await;
        self.fake.tell(pod_uid, PairStatus::SelfCheckPassed);
        assert!(matches!(admitted.next().await, PodEvent::Enforced { .. }));
        admitted
    }
}

#[tokio::test]
async fn nothing_is_reported_enforced_before_the_guests_self_check_passes() {
    let harness = Harness::new().await;
    let web = open();
    let mut pod = harness.admit(POD, bound("env", 3, web.clone())).await;
    assert_eq!(harness.fake.did(), [Did::Started(POD, web.digest())]);

    tokio::time::advance(SELF_CHECK_TIMEOUT - Duration::from_millis(1)).await;
    assert!(pod.has_none().await);

    harness.fake.tell(POD, PairStatus::SelfCheckPassed);
    assert_eq!(pod.next().await, enforced(3, &web));
    assert!(pod.has_none().await);
}

#[tokio::test]
async fn an_unbound_member_runs_locked() {
    let harness = Harness::new().await;
    let mut pod = harness.admit(POD, unbound()).await;
    assert_eq!(harness.fake.did(), [Did::Started(POD, locked().digest())]);
    harness.fake.tell(POD, PairStatus::SelfCheckPassed);
    assert_eq!(pod.next().await, enforced(0, &locked()));
}

#[tokio::test]
async fn a_failed_self_check_fails_closed_with_no_pair() {
    let harness = Harness::new().await;
    let mut pod = harness.admit(POD, bound("env", 1, open())).await;
    harness
        .fake
        .tell(POD, PairStatus::SelfCheckFailed(SelfCheckProbe::Dns));

    assert_eq!(
        pod.next().await,
        PodEvent::FailedClosed(FailureCode::SelfCheckFailed)
    );
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did().last(), Some(&Did::Ended(POD)));
}

#[tokio::test]
async fn a_guest_that_reports_no_self_check_in_time_fails_closed() {
    let harness = Harness::new().await;
    let mut pod = harness.admit(POD, bound("env", 1, open())).await;

    tokio::time::advance(SELF_CHECK_TIMEOUT).await;
    assert_eq!(
        pod.next().await,
        PodEvent::FailedClosed(FailureCode::SelfCheckFailed)
    );
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did().last(), Some(&Did::Ended(POD)));
}

#[tokio::test]
async fn a_stream_that_drops_before_its_self_check_result_fails_closed() {
    let harness = Harness::new().await;
    let mut pod = harness.admit(POD, bound("env", 1, open())).await;
    harness.fake.tell(POD, PairStatus::Ended);

    assert_eq!(
        pod.next().await,
        PodEvent::FailedClosed(FailureCode::SelfCheckFailed)
    );
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did().last(), Some(&Did::Ended(POD)));
}

#[tokio::test]
async fn a_pair_that_does_not_start_ends_the_stream_and_nothing_else() {
    let harness = Harness::new().await;
    harness.fake.world().failing.push(POD);
    let mut pod = harness.admit(POD, bound("env", 1, open())).await;

    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert!(harness.fake.did().is_empty());
}

#[tokio::test]
async fn a_new_revision_is_enforced_by_the_same_pair() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, bound("env", 1, open())).await;

    pod.changes.send(Ok(bound("env", 2, locked()))).unwrap();
    assert_eq!(pod.next().await, enforced(2, &locked()));
    assert_eq!(
        harness.fake.did(),
        [
            Did::Started(POD, open().digest()),
            Did::Replaced(POD, locked().digest()),
        ],
        "one pair, never restarted"
    );

    // The same assignment again asks the broker nothing.
    pod.changes.send(Ok(bound("env", 2, locked()))).unwrap();
    assert!(pod.has_none().await);
    assert_eq!(harness.fake.did().len(), 2);
}

#[tokio::test]
async fn a_bind_moves_an_unbound_pair_to_the_bound_policy_and_reports_it() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, unbound()).await;

    pod.changes.send(Ok(bound("env", 4, open()))).unwrap();
    assert_eq!(pod.next().await, enforced(4, &open()));
    assert_eq!(
        harness.fake.did().last(),
        Some(&Did::Replaced(POD, open().digest()))
    );

    // Bound to `locked`, the document an unbound member already runs: the
    // broker is asked nothing, and the bound revision is still reported.
    let mut other = harness.enforcing(OTHER_POD, unbound()).await;
    other.changes.send(Ok(bound("other", 5, locked()))).unwrap();
    assert_eq!(other.next().await, enforced(5, &locked()));
    assert_eq!(
        harness.fake.did().last(),
        Some(&Did::Started(OTHER_POD, locked().digest()))
    );
}

#[tokio::test]
async fn a_policy_the_broker_does_not_acknowledge_ends_the_pair() {
    let harness = Harness::new().await;
    for (pod_uid, acks) in [(POD, Acks::Nothing), (OTHER_POD, Acks::Another)] {
        harness.fake.world().acks = Acks::Sent;
        let mut pod = harness.enforcing(pod_uid, bound("env", 1, open())).await;
        harness.fake.world().acks = acks;

        pod.changes.send(Ok(bound("env", 2, locked()))).unwrap();
        assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
        assert_eq!(harness.fake.did().last(), Some(&Did::Ended(pod_uid)));
    }
}

#[tokio::test]
async fn an_assignment_that_does_not_parse_fails_closed() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, bound("env", 1, open())).await;

    pod.changes
        .send(Err(AssignmentError::DigestMismatch))
        .unwrap();
    assert_eq!(
        pod.next().await,
        PodEvent::FailedClosed(FailureCode::PolicyDigestMismatch)
    );
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did().last(), Some(&Did::Ended(POD)));
}

#[tokio::test]
async fn an_unbind_another_environment_or_the_pods_end_ends_the_pair() {
    let harness = Harness::new().await;
    let changes = [Some(unbound()), Some(bound("another", 1, open())), None];
    for (pod_uid, change) in [POD, OTHER_POD, THIRD_POD].into_iter().zip(changes) {
        let mut pod = harness.enforcing(pod_uid, bound("env", 1, open())).await;
        match change {
            Some(assignment) => pod.changes.send(Ok(assignment)).unwrap(),
            None => {
                let (closed, _) = watch::channel(Ok(unbound()));
                drop(std::mem::replace(&mut pod.changes, closed));
            }
        }
        assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
        assert_eq!(harness.fake.did().last(), Some(&Did::Ended(pod_uid)));
    }
}

#[tokio::test]
async fn a_silent_orchestration_leaves_the_pair_on_its_last_assignment() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, bound("env", 1, open())).await;

    tokio::time::advance(Duration::from_secs(3600)).await;
    assert!(pod.has_none().await);
    assert_eq!(harness.fake.did().len(), 1);
}

#[tokio::test]
async fn a_newer_stream_replaces_the_pods_pair_once_the_older_is_reaped() {
    let harness = Harness::new().await;
    let mut older = harness.enforcing(POD, bound("env", 1, open())).await;
    let reaping = Arc::new(Notify::new());
    harness.fake.world().reaping = Some(Arc::clone(&reaping));
    let mut newer = harness.admit(POD, bound("env", 1, open())).await;

    // While the older pair is being reaped the newer has not started.
    assert_eq!(harness.fake.did(), [Did::Started(POD, open().digest())]);
    assert!(older.has_none().await);
    harness.fake.world().reaping = None;
    reaping.notify_one();

    assert_eq!(older.next().await, PodEvent::Ended { moved: false });
    settle().await;
    assert_eq!(
        harness.fake.did(),
        [
            Did::Started(POD, open().digest()),
            Did::Ended(POD),
            Did::Started(POD, open().digest()),
        ]
    );
    harness.fake.tell(POD, PairStatus::SelfCheckPassed);
    assert_eq!(newer.next().await, enforced(1, &open()));
}

#[tokio::test]
async fn a_pair_whose_process_exits_is_reaped_and_reported_ended() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, bound("env", 1, open())).await;
    let mut other = harness
        .enforcing(OTHER_POD, bound("other", 1, open()))
        .await;

    harness.fake.tell(POD, PairStatus::Ended);
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did().last(), Some(&Did::Ended(POD)));
    assert!(other.has_none().await, "another Pod's pair is untouched");
}

#[tokio::test]
async fn a_slow_start_holds_up_no_other_pod() {
    let harness = Harness::new().await;
    let held = Arc::new(Notify::new());
    harness.fake.world().held.insert(POD, Arc::clone(&held));
    let mut slow = harness.admit(POD, bound("env", 1, open())).await;

    let mut other = harness
        .enforcing(OTHER_POD, bound("other", 1, open()))
        .await;
    assert!(other.has_none().await);
    assert!(slow.has_none().await);

    held.notify_one();
    settle().await;
    harness.fake.tell(POD, PairStatus::SelfCheckPassed);
    assert_eq!(slow.next().await, enforced(1, &open()));
}

#[tokio::test]
async fn a_drain_ends_only_the_pairs_that_hold_no_flow() {
    let harness = Harness::new().await;
    let mut idle = harness.enforcing(POD, bound("env", 1, open())).await;
    let mut busy = harness
        .enforcing(OTHER_POD, bound("other", 1, open()))
        .await;

    harness.signals.drain.cancel();
    settle().await;
    let did = harness.fake.did();
    assert!(did.contains(&Did::DrainRequested(POD)));
    assert!(did.contains(&Did::DrainRequested(OTHER_POD)));

    harness.fake.tell(POD, PairStatus::NoFlow);
    assert_eq!(idle.next().await, PodEvent::Ended { moved: true });
    assert!(harness.fake.did().contains(&Did::Ended(POD)));
    assert!(busy.has_none().await);
    assert!(!harness.fake.did().contains(&Did::Ended(OTHER_POD)));
}

#[tokio::test]
async fn shutdown_ends_every_pair_and_a_start_in_progress() {
    let harness = Harness::new().await;
    let mut running = harness.enforcing(POD, bound("env", 1, open())).await;
    harness
        .fake
        .world()
        .held
        .insert(OTHER_POD, Arc::new(Notify::new()));
    let mut starting = harness.admit(OTHER_POD, bound("other", 1, open())).await;

    harness.signals.shutdown.cancel();
    let drained = finished(harness.supervisor).await;

    assert_eq!(
        drained,
        Drained::default(),
        "a shutdown with no drain moves nobody"
    );
    assert_eq!(running.next().await, PodEvent::Ended { moved: false });
    assert_eq!(starting.next().await, PodEvent::Ended { moved: false });
    assert_eq!(
        harness.fake.did(),
        [Did::Started(POD, open().digest()), Did::Ended(POD)],
        "the held start never became a pair"
    );
}

#[tokio::test]
async fn admission_closing_its_channel_ends_every_pair() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, bound("env", 1, open())).await;

    drop(harness.admit);
    finished(harness.supervisor).await;
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did().last(), Some(&Did::Ended(POD)));
}

#[tokio::test]
async fn a_drains_deadline_cuts_the_pairs_still_holding_a_flow_and_says_they_moved() {
    let harness = Harness::new().await;
    let mut idle = harness.enforcing(POD, bound("env", 1, open())).await;
    let mut busy = harness
        .enforcing(OTHER_POD, bound("other", 1, open()))
        .await;

    harness.signals.drain.cancel();
    settle().await;
    harness.fake.tell(POD, PairStatus::NoFlow);
    assert_eq!(idle.next().await, PodEvent::Ended { moved: true });
    assert!(busy.has_none().await);

    harness.signals.shutdown.cancel();
    let drained = finished(harness.supervisor).await;

    assert_eq!(busy.next().await, PodEvent::Ended { moved: true });
    assert!(harness.fake.did().contains(&Did::Ended(OTHER_POD)));
    assert_eq!(
        drained,
        Drained {
            moved_idle: 1,
            cut_at_deadline: 1,
        }
    );
}

#[tokio::test]
async fn a_drain_outlives_admission_and_is_over_when_its_last_pair_has_moved() {
    let harness = Harness::new().await;
    let mut first = harness.enforcing(POD, bound("env", 1, open())).await;
    let mut second = harness
        .enforcing(OTHER_POD, bound("other", 1, open()))
        .await;

    harness.signals.drain.cancel();
    settle().await;
    drop(harness.admit);
    assert!(
        first.has_none().await,
        "admission closing in a drain ends no pair"
    );
    assert!(second.has_none().await);

    harness.fake.tell(POD, PairStatus::NoFlow);
    assert_eq!(first.next().await, PodEvent::Ended { moved: true });
    settle().await;
    assert!(
        !harness.supervisor.is_finished(),
        "a pair is still draining"
    );

    harness.fake.tell(OTHER_POD, PairStatus::NoFlow);
    assert_eq!(second.next().await, PodEvent::Ended { moved: true });
    // No shutdown is sent: the supervisor returns because nothing is left.
    assert_eq!(
        finished(harness.supervisor).await,
        Drained {
            moved_idle: 2,
            cut_at_deadline: 0,
        }
    );
}

#[tokio::test]
async fn a_stream_admitted_in_a_drain_is_asked_to_drain_once_it_enforces() {
    let harness = Harness::new().await;
    harness.signals.drain.cancel();

    let mut pod = harness.admit(POD, bound("env", 1, open())).await;
    assert!(
        !harness.fake.did().contains(&Did::DrainRequested(POD)),
        "a guest that has not passed its self-check is not asked yet"
    );

    harness.fake.tell(POD, PairStatus::SelfCheckPassed);
    assert!(matches!(pod.next().await, PodEvent::Enforced { .. }));
    settle().await;
    assert!(harness.fake.did().contains(&Did::DrainRequested(POD)));

    harness.fake.tell(POD, PairStatus::NoFlow);
    assert_eq!(pod.next().await, PodEvent::Ended { moved: true });
}

#[tokio::test]
async fn a_pair_that_ends_by_itself_in_a_drain_is_reported_moved_and_counted_as_neither() {
    let harness = Harness::new().await;
    let mut pod = harness.enforcing(POD, bound("env", 1, open())).await;

    harness.signals.drain.cancel();
    settle().await;
    harness.fake.tell(POD, PairStatus::Ended);
    assert_eq!(pod.next().await, PodEvent::Ended { moved: true });

    drop(harness.admit);
    assert_eq!(finished(harness.supervisor).await, Drained::default());
}

#[tokio::test]
async fn a_shutdown_during_the_self_check_ends_the_pair_and_is_not_a_failed_check() {
    let harness = Harness::new().await;
    let mut pod = harness.admit(POD, bound("env", 1, open())).await;

    harness.signals.shutdown.cancel();
    finished(harness.supervisor).await;

    // Not `FailedClosed` first: the guest was cut off, it did not fail.
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert!(harness.fake.did().contains(&Did::Ended(POD)));
}

/// A pair's front door is started with it from its assignment, and only
/// with interception on and a set cw-egress serves. Off, the pair starts
/// exactly as without interception; unservable, its broker refuses the bound
/// hosts instead.
#[tokio::test]
async fn a_pair_intercepts_what_its_assignment_says() {
    let harness = Harness::new().await;
    let spec = front_door(&["api.openai.com"]);
    let hosts = spec.intercepts.clone();
    let _on = harness
        .enforcing(POD, intercepting(Interception::On(spec.clone())))
        .await;
    let _off = harness
        .enforcing(OTHER_POD, intercepting(Interception::Off))
        .await;
    let _refusing = harness
        .enforcing(
            THIRD_POD,
            intercepting(Interception::RefuseHosts {
                hosts: hosts.clone(),
                why: InterceptionRefusal::Port,
            }),
        )
        .await;
    assert_eq!(
        harness.fake.world().intercepts,
        [
            PairIntercepts::FrontDoor(spec),
            PairIntercepts::Off,
            PairIntercepts::Refuse(hosts)
        ]
    );
}

/// Bindings no broker set can refuse, a suffix among them, start no pair:
/// the bound hosts' requests carry placeholders and are never dialled
/// (#5159). The stream ends as a failed start does.
#[tokio::test]
async fn bindings_no_broker_can_refuse_start_no_pair() {
    let harness = Harness::new().await;
    let mut pod = harness
        .admit(
            POD,
            intercepting(Interception::FailClosed(InterceptionRefusal::Suffix)),
        )
        .await;
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
    assert_eq!(harness.fake.did(), []);
    assert!(harness.fake.world().intercepts.is_empty());
}

/// A pair keeps what it intercepts from its start: a new set, interception
/// turned off or on, a set it must now refuse or one it cannot all end it,
/// and the guest's redial starts the next with what the assignment now says.
/// A new revision of the same set's policy does not.
#[tokio::test]
async fn a_change_to_a_pairs_front_door_ends_the_pair() {
    let harness = Harness::new().await;
    let first = front_door(&["api.openai.com"]);
    let changes = [
        Interception::On(front_door(&["api.openai.com", "chatgpt.com"])),
        Interception::Off,
        Interception::RefuseHosts {
            hosts: first.intercepts.clone(),
            why: InterceptionRefusal::Port,
        },
        Interception::FailClosed(InterceptionRefusal::Suffix),
    ];
    let pods = [POD, OTHER_POD, THIRD_POD, Uuid::from_u128(6)];
    for (pod_uid, change) in pods.into_iter().zip(changes) {
        let mut pod = harness
            .enforcing(pod_uid, intercepting(Interception::On(first.clone())))
            .await;
        pod.changes.send(Ok(intercepting(change))).unwrap();
        assert_eq!(pod.next().await, PodEvent::Ended { moved: false });
        assert_eq!(harness.fake.did().last(), Some(&Did::Ended(pod_uid)));
    }

    let fourth = Uuid::from_u128(4);
    let mut pod = harness
        .enforcing(fourth, intercepting(Interception::Off))
        .await;
    pod.changes
        .send(Ok(intercepting(Interception::On(first.clone()))))
        .unwrap();
    assert_eq!(pod.next().await, PodEvent::Ended { moved: false });

    let fifth = Uuid::from_u128(5);
    let mut pod = harness
        .enforcing(fifth, intercepting(Interception::On(first.clone())))
        .await;
    let Assignment::Bound {
        environment_id,
        operation_generation,
        platform,
        ..
    } = intercepting(Interception::Off)
    else {
        unreachable!("bound");
    };
    pod.changes
        .send(Ok(Assignment::Bound {
            environment_id,
            operation_generation,
            policy: AssignedPolicy {
                reference: "platform:web".into(),
                revision: 2,
                policy: locked(),
            },
            platform,
            interception: Box::new(Interception::On(first)),
        }))
        .unwrap();
    assert_eq!(pod.next().await, enforced(2, &locked()));
    assert_eq!(
        harness.fake.did().last(),
        Some(&Did::Replaced(fifth, locked().digest()))
    );
}
