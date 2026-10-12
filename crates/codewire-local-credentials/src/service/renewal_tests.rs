//! A local broker epoch renews with overlap: each child's successor runs
//! before the child stops, and the child keeps serving until its lifetime ends.

use std::collections::BTreeSet;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use codewire_access::{BrokerOperationId, BrokerRouteId, HttpProvider, builtin_provider_catalog};
use codewire_daemon_proto::codewire::bridge::v1::CredentialBridgeReady;
use codewire_protected_store::{
    EphemeralProtectedStore, ProtectedEntryId, ProtectedStoreError, ProtectedStorePersistence,
};

use super::*;
use crate::{BrokerLeaseChannelError, LocalBrokerSpawnError, LocalCredentialBrokerLeaseClient};

const RENEWAL: BrokerRenewal = BrokerRenewal {
    lifetime: Duration::from_millis(1600),
    lead: Duration::from_millis(600),
};
const PROBE_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Default)]
struct SharedStore(Arc<EphemeralProtectedStore>);

impl ProtectedStore for SharedStore {
    fn persistence(&self) -> ProtectedStorePersistence {
        self.0.persistence()
    }

    fn get(&self, id: &ProtectedEntryId) -> Result<Option<ProtectedValue>, ProtectedStoreError> {
        self.0.get(id)
    }

    fn put(
        &self,
        id: &ProtectedEntryId,
        value: &ProtectedValue,
    ) -> Result<(), ProtectedStoreError> {
        self.0.put(id, value)
    }

    fn delete(&self, id: &ProtectedEntryId) -> Result<(), ProtectedStoreError> {
        self.0.delete(id)
    }
}

/// What one spawned child did, in time since the test started.
#[derive(Clone, Debug, Default)]
struct ChildRecord {
    pid: Option<u32>,
    config: Option<LocalBrokerProcessConfig>,
    spawned: Option<Duration>,
    ready: Option<Duration>,
    /// The last time the authority answered this child's lease channel.
    answered: Option<Duration>,
    /// When its lease channel stopped answering.
    closed: Option<Duration>,
}

/// Each spawn stands in for a broker child: a real process the authority
/// owns and kills, and a task speaking the child's side of its lease channel.
/// A real child resolves its provider addresses once, as it starts.
struct RenewalSpawner {
    started: std::time::Instant,
    store: SharedStore,
    /// Spawn attempts, by index, that fail.
    failing: BTreeSet<usize>,
    attempts: StdMutex<usize>,
    children: Arc<StdMutex<Vec<ChildRecord>>>,
    tasks: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl RenewalSpawner {
    fn new(failing: BTreeSet<usize>) -> Arc<Self> {
        Arc::new(Self {
            started: std::time::Instant::now(),
            store: SharedStore::default(),
            failing,
            attempts: StdMutex::new(0),
            children: Arc::new(StdMutex::new(Vec::new())),
            tasks: StdMutex::new(Vec::new()),
        })
    }

    fn children(&self) -> Vec<ChildRecord> {
        self.children.lock().unwrap().clone()
    }

    fn ready_count(&self) -> usize {
        self.children
            .lock()
            .unwrap()
            .iter()
            .filter(|child| child.ready.is_some())
            .count()
    }

    fn closed(&self, index: usize) -> bool {
        self.children
            .lock()
            .unwrap()
            .get(index)
            .is_some_and(|child| child.closed.is_some())
    }
}

impl LocalBrokerProcessSpawner for RenewalSpawner {
    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        authority_peer: std::os::unix::net::UnixStream,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let attempt = {
            let mut attempts = self.attempts.lock().unwrap();
            *attempts += 1;
            *attempts - 1
        };
        if self.failing.contains(&attempt) {
            return Err(LocalBrokerSpawnError::Spawn);
        }
        authority_peer
            .set_nonblocking(true)
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let stream =
            UnixStream::from_std(authority_peer).map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| LocalBrokerSpawnError::Spawn)?;
        let index = {
            let mut children = self.children.lock().unwrap();
            children.push(ChildRecord {
                pid: child.id(),
                config: Some(config.clone()),
                spawned: Some(self.started.elapsed()),
                ..Default::default()
            });
            children.len() - 1
        };
        let children = Arc::clone(&self.children);
        let started = self.started;
        let store = self.store.clone();
        let environment_id = config.environment_id.clone();
        let generation = config.environment_generation;
        let task = tokio::spawn(async move {
            let record = |update: &dyn Fn(&mut ChildRecord, Duration)| {
                update(&mut children.lock().unwrap()[index], started.elapsed());
            };
            let ready = CredentialBridgeReady {
                protocol_version: codewire_daemon_proto::CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: environment_id.to_string(),
                environment_generation: generation,
            };
            let Ok(mut client) = LocalCredentialBrokerLeaseClient::connect(
                stream,
                store,
                environment_id,
                generation,
            )
            .await
            else {
                return;
            };
            if client.report_ready(ready).await.is_err() {
                return;
            }
            record(&|child, at| child.ready = Some(at));
            // Requests keep reaching the authority through this child until
            // its channel closes. No grant is selected, so each is refused.
            loop {
                let answer = client
                    .lease_operation(
                        uuid::Uuid::new_v4(),
                        CapabilitySlot::codex(),
                        BrokerOperationId::parse("responses").unwrap(),
                        BrokerRouteId::parse("openai-api").unwrap(),
                    )
                    .await;
                if matches!(answer, Err(BrokerLeaseChannelError::Unavailable)) {
                    record(&|child, at| child.closed = Some(at));
                    return;
                }
                record(&|child, at| child.answered = Some(at));
                tokio::time::sleep(PROBE_INTERVAL).await;
            }
        });
        self.tasks.lock().unwrap().push(task);
        Ok(child)
    }
}

struct Lifecycle {
    _directory: tempfile::TempDir,
    spawner: Arc<RenewalSpawner>,
    shutdown: watch::Sender<bool>,
    /// Every state the lifecycle reported, in order.
    states: Arc<StdMutex<Vec<BrokerProcessState>>>,
    task: tokio::task::JoinHandle<()>,
    observer: tokio::task::JoinHandle<()>,
}

impl Lifecycle {
    fn start(spawner: Arc<RenewalSpawner>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let authority = Arc::new(
            LocalCredentialAuthority::open(
                &directory.path().join("authority"),
                EphemeralProtectedStore::default(),
                builtin_provider_catalog(),
            )
            .unwrap(),
        );
        let environment_id = EnvironmentId::parse(Uuid::new_v4().to_string()).unwrap();
        let config = LocalBrokerProcessConfig {
            environment_id: environment_id.clone(),
            environment_generation: 3,
            environment_name: "synthetic".into(),
            runner_socket: directory.path().join(format!("{environment_id}.sock")),
            http_providers: BTreeSet::from([HttpProvider::CodexOAuth]),
            platform_delegated: false,
        };
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (state, mut state_rx) = watch::channel(BrokerProcessState::Starting);
        let states = Arc::new(StdMutex::new(vec![BrokerProcessState::Starting]));
        let observed = Arc::clone(&states);
        let observer = tokio::spawn(async move {
            while state_rx.changed().await.is_ok() {
                let state = *state_rx.borrow_and_update();
                let mut states = observed.lock().unwrap();
                if states.last() != Some(&state) {
                    states.push(state);
                }
            }
        });
        let task = tokio::spawn(run_broker_lifecycle(
            Arc::new(BrokerLaunch {
                authority,
                ssh_runtime: LocalSshOperationRuntime::new(None),
                spawner: Arc::clone(&spawner) as Arc<dyn LocalBrokerProcessSpawner>,
                config,
                audit: Arc::new(BrokerLeaseAuditLog::default()),
                projection: None,
                platform: None,
                local_profile: None,
                renewal: RENEWAL,
            }),
            shutdown_rx,
            state,
        ));
        Self {
            _directory: directory,
            spawner,
            shutdown,
            states,
            task,
            observer,
        }
    }

    async fn until(&self, condition: impl Fn(&RenewalSpawner) -> bool) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !condition(&self.spawner) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("broker lifecycle progress");
    }

    async fn until_states(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while self.states.lock().unwrap().len() < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("broker lifecycle state");
    }

    async fn stop(self) -> (Vec<ChildRecord>, Vec<BrokerProcessState>) {
        let states = self.states.lock().unwrap().clone();
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("lifecycle stops")
            .unwrap();
        drop(self.shutdown);
        self.observer.await.unwrap();
        for task in self.spawner.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        (self.spawner.children(), states)
    }
}

fn process_gone(pid: u32) -> bool {
    let pid = rustix::process::Pid::from_raw(pid as i32).unwrap();
    matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successor_runs_before_its_predecessor_stops_and_no_request_meets_a_gap() {
    let lifecycle = Lifecycle::start(RenewalSpawner::new(BTreeSet::new()));
    // Two renewals: children 0 to 1 and 1 to 2, each predecessor stopped.
    lifecycle
        .until(|spawner| spawner.ready_count() >= 3 && spawner.closed(1))
        .await;
    let (children, states) = lifecycle.stop().await;

    // The lifecycle reported Running once and never Starting again until it
    // was told to stop: callers never saw a broker gap.
    assert_eq!(
        states,
        [BrokerProcessState::Starting, BrokerProcessState::Running]
    );
    for index in 0..2 {
        let predecessor = &children[index];
        let successor = &children[index + 1];
        let successor_ready = successor.ready.unwrap();
        let closed = predecessor.closed.unwrap();
        assert!(
            successor_ready < closed,
            "child {index} stopped before its successor ran: {children:?}"
        );
        // A request sent to the predecessor before the handover still
        // reached the authority after its successor ran.
        assert!(
            predecessor.answered.unwrap() > successor_ready,
            "child {index} stopped serving at its successor's start: {children:?}"
        );
        // It drained until its lifetime ended, and no longer.
        let lifetime_end = predecessor.spawned.unwrap() + RENEWAL.lifetime;
        assert!(
            closed + Duration::from_millis(100) >= lifetime_end,
            "child {index} stopped before its lifetime ended: {children:?}"
        );
        assert!(
            closed <= lifetime_end + Duration::from_secs(1),
            "child {index} outlived its drain: {children:?}"
        );
        assert!(process_gone(predecessor.pid.unwrap()));
    }
    // Each epoch is a new process with the same launch: a real child resolves
    // its provider addresses again as it starts.
    let pids = children
        .iter()
        .filter_map(|child| child.pid)
        .collect::<BTreeSet<_>>();
    assert_eq!(pids.len(), children.len());
    assert!(
        children
            .iter()
            .all(|child| child.config == children[0].config)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_broker_whose_successor_cannot_start_still_stops_when_its_lifetime_ends() {
    // The first successor attempt fails; the next one is not due before the
    // current child's lifetime ends.
    let lifecycle = Lifecycle::start(RenewalSpawner::new(BTreeSet::from([1])));
    lifecycle
        .until(|spawner| spawner.ready_count() >= 2 && spawner.closed(0))
        .await;
    lifecycle.until_states(4).await;
    let (children, states) = lifecycle.stop().await;

    let first = &children[0];
    let lifetime_end = first.spawned.unwrap() + RENEWAL.lifetime;
    let closed = first.closed.unwrap();
    assert!(closed + Duration::from_millis(100) >= lifetime_end);
    assert!(closed <= lifetime_end + Duration::from_secs(1));
    assert!(process_gone(first.pid.unwrap()));
    // It failed closed: the replacement started afresh after it stopped.
    let replacement = &children[1];
    assert!(replacement.spawned.unwrap() + Duration::from_millis(100) >= closed);
    assert_eq!(
        states,
        [
            BrokerProcessState::Starting,
            BrokerProcessState::Running,
            BrokerProcessState::Starting,
            BrokerProcessState::Running,
        ]
    );
}
