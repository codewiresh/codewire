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
use tokio::net::UnixStream;

use super::*;
use crate::{
    BrokerLeaseChannelError, LocalBrokerSpawnError, LocalCredentialBrokerLeaseClient,
    ProviderLookup,
};

const RENEWAL: BrokerRenewal = BrokerRenewal {
    lifetime: Duration::from_millis(1600),
    lead: Duration::from_millis(600),
    ..BrokerRenewal::PRODUCTION
};
/// For the overlap test: a successor has the whole lead to spawn and answer
/// before its predecessor's lifetime ends, and a slow CI slot can stall the
/// test process for seconds. A successor that misses the lead is a gap the
/// test rightly reports, so the lead is far longer than any spawn (#3277).
/// The fail-closed test keeps RENEWAL: it needs a successor retry that is not
/// due before the lifetime ends.
const SLOW_SLOT_RENEWAL: BrokerRenewal = BrokerRenewal {
    lifetime: Duration::from_millis(8000),
    lead: Duration::from_millis(6000),
    ..BrokerRenewal::PRODUCTION
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
    /// When its lease channel stopped answering, as its probe saw it: later
    /// than the close itself by however long the probe waited to run.
    closed: Option<Duration>,
    /// How many earlier children's processes still existed when it spawned.
    predecessors_alive: Option<usize>,
    /// The boot secrets it was started with.
    boot_secrets: Option<crate::BrokerBootSecrets>,
    /// What it was told about provider hosts that do not resolve.
    lookup: Option<ProviderLookup>,
}

/// Each spawn stands in for a broker child: a real process the authority
/// owns and kills, and a task speaking the child's side of its lease channel.
/// A real child resolves its provider addresses once, as it starts.
struct RenewalSpawner {
    started: std::time::Instant,
    store: SharedStore,
    /// Spawn attempts, by index, that fail.
    failing: BTreeSet<usize>,
    /// The provider hosts each child, by index, reports it has no address
    /// for; a child past the end reports none.
    unresolved: Vec<Vec<&'static str>>,
    /// An early replacement, told to get a host back, never starts: as a
    /// real child ends itself when no host it lacks resolves.
    no_host_comes_back: bool,
    /// What every attempt was told about hosts that do not resolve.
    lookups: StdMutex<Vec<ProviderLookup>>,
    /// Every child ends at its first step, as a broker whose runner speaks
    /// another protocol does: its lease channel closes at once, and a tenth
    /// of a second later it says why on stderr and exits 3.
    ends_at_its_first_step: bool,
    attempts: StdMutex<usize>,
    children: Arc<StdMutex<Vec<ChildRecord>>>,
    tasks: StdMutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl RenewalSpawner {
    fn new(failing: BTreeSet<usize>) -> Arc<Self> {
        Self::leaving(failing, Vec::new())
    }

    fn leaving(failing: BTreeSet<usize>, unresolved: Vec<Vec<&'static str>>) -> Arc<Self> {
        Arc::new(Self {
            started: std::time::Instant::now(),
            store: SharedStore::default(),
            failing,
            unresolved,
            no_host_comes_back: false,
            lookups: StdMutex::new(Vec::new()),
            ends_at_its_first_step: false,
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
    fn runner_protocol(&self) -> u32 {
        crate::broker_process::TEST_RUNNER_PROTOCOL
    }

    fn spawn(
        &self,
        config: &LocalBrokerProcessConfig,
        lookup: &ProviderLookup,
        authority_peer: std::os::unix::net::UnixStream,
        boot_secrets: &crate::BrokerBootSecrets,
    ) -> Result<tokio::process::Child, LocalBrokerSpawnError> {
        let attempt = {
            let mut attempts = self.attempts.lock().unwrap();
            *attempts += 1;
            *attempts - 1
        };
        self.lookups.lock().unwrap().push(lookup.clone());
        if self.failing.contains(&attempt)
            || (self.no_host_comes_back && matches!(lookup, ProviderLookup::FewerThan(_)))
        {
            return Err(LocalBrokerSpawnError::Spawn);
        }
        if self.ends_at_its_first_step {
            drop(authority_peer);
            return tokio::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("sleep 0.1; echo '{LAST_WORD}' >&2; exit 3"))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| LocalBrokerSpawnError::Spawn);
        }
        // The lifecycle counts a child's lifetime from just before it calls
        // the spawner, so the spawn time is taken before the process starts:
        // a fork and exec that a slow slot stalls would otherwise move the
        // lifetime end the test computes past the one the lifecycle keeps.
        let spawned = self.started.elapsed();
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
            // The lifecycle reaps a child it stops before it goes on, so an
            // earlier child counted here had not been stopped yet.
            let predecessors_alive = children
                .iter()
                .filter(|earlier| earlier.pid.is_some_and(|pid| !process_gone(pid)))
                .count();
            children.push(ChildRecord {
                pid: child.id(),
                config: Some(config.clone()),
                spawned: Some(spawned),
                predecessors_alive: Some(predecessors_alive),
                boot_secrets: Some(boot_secrets.clone()),
                lookup: Some(lookup.clone()),
                ..Default::default()
            });
            children.len() - 1
        };
        let unresolved: Vec<String> = self
            .unresolved
            .get(index)
            .map(|hosts| hosts.iter().map(|host| (*host).to_owned()).collect())
            .unwrap_or_default();
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
            if client.report_ready(ready, unresolved).await.is_err() {
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
    directory: tempfile::TempDir,
    spawner: Arc<RenewalSpawner>,
    shutdown: watch::Sender<bool>,
    /// Every state the lifecycle reported, in order.
    states: Arc<StdMutex<Vec<BrokerProcessState>>>,
    task: tokio::task::JoinHandle<()>,
    observer: tokio::task::JoinHandle<()>,
}

impl Lifecycle {
    fn start(spawner: Arc<RenewalSpawner>) -> Self {
        Self::start_with(spawner, RENEWAL)
    }

    fn start_with(spawner: Arc<RenewalSpawner>, renewal: BrokerRenewal) -> Self {
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
            network_policy_allows_github: true,
            network_policy_allowed_hosts: Default::default(),
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
                renewal,
                log: Arc::new(crate::broker_log::BrokerLog::in_root(directory.path())),
                boot_secrets: boot_secrets(),
            }),
            shutdown_rx,
            state,
        ));
        Self {
            directory,
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

    /// The first `count` states the lifecycle reported, once it has. The
    /// lifecycle goes on running until it is stopped, so a later state may
    /// follow before the test reads them; it is not among these.
    async fn until_states(&self, count: usize) -> Vec<BrokerProcessState> {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                {
                    let states = self.states.lock().unwrap();
                    if states.len() >= count {
                        return states[..count].to_vec();
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("broker lifecycle state")
    }

    /// Which start the lifecycle recorded for each spawned child, in order.
    fn spawned_as(&self) -> Vec<String> {
        let log = std::fs::read_to_string(self.directory.path().join("logs/brokers.log"))
            .unwrap_or_default();
        log.lines()
            .filter(|line| line.contains(" event=broker_spawned "))
            .filter_map(|line| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix("lookup="))
                    .map(str::to_owned)
            })
            .collect()
    }

    /// What the lifecycle recorded each ready child left unresolved, in order.
    fn ready_unresolved(&self) -> Vec<String> {
        let log = std::fs::read_to_string(self.directory.path().join("logs/brokers.log"))
            .unwrap_or_default();
        log.lines()
            .filter(|line| line.contains(" event=broker_ready "))
            .filter_map(|line| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix("unresolved="))
                    .map(str::to_owned)
            })
            .collect()
    }

    /// The reason the lifecycle recorded for ending the child `pid`.
    fn end_reason(&self, pid: u32) -> Option<String> {
        let log = std::fs::read_to_string(self.directory.path().join("logs/brokers.log")).ok()?;
        let pid = format!(" pid={pid} ");
        log.lines()
            .filter(|line| line.contains(" event=broker_ended ") && line.contains(&pid))
            .find_map(|line| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix("reason="))
                    .map(str::to_owned)
            })
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

/// A boot's secrets, as the harness's launch carries them: one byte, so any
/// copy of them is easy to find.
const SECRET_BYTE: u8 = 0xc7;

fn boot_secrets() -> crate::BrokerBootSecrets {
    crate::BrokerBootSecrets::new([(
        crate::BootSecretPurpose::FrontDoorPairing,
        vec![SECRET_BYTE; crate::BOOT_SECRET_BYTES],
    )])
    .unwrap()
}

/// Whether any file under `root` holds the secret's bytes.
fn secret_on_disk(root: &std::path::Path) -> bool {
    let needle = [SECRET_BYTE; crate::BOOT_SECRET_BYTES];
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if std::fs::read(&path)
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            {
                return true;
            }
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successor_runs_before_its_predecessor_stops_and_no_request_meets_a_gap() {
    let lifecycle = Lifecycle::start_with(RenewalSpawner::new(BTreeSet::new()), SLOW_SLOT_RENEWAL);
    // Two renewals: children 0 to 1 and 1 to 2, each predecessor stopped, and
    // the child after each of those spawned, which is the witness of the stop.
    lifecycle
        .until(|spawner| spawner.ready_count() >= 4 && spawner.closed(1))
        .await;
    // Every child, each renewal's successor included, got the boot's secrets
    // from memory, and nothing under the authority's root holds them (#3999).
    assert!(!secret_on_disk(lifecycle.directory.path()));
    let (children, states) = lifecycle.stop().await;
    assert!(
        children
            .iter()
            .all(|child| child.boot_secrets == Some(boot_secrets()))
    );

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
        // It drained until its lifetime ended.
        let lifetime_end = predecessor.spawned.unwrap() + SLOW_SLOT_RENEWAL.lifetime;
        assert!(
            closed + Duration::from_millis(100) >= lifetime_end,
            "child {index} stopped before its lifetime ended: {children:?}"
        );
        // And no longer: the lifecycle stops and reaps it before it spawns the
        // next child, so only that child's predecessor was still running then.
        // The probe's close time is no witness of that, as in the fail-closed
        // test below: it is late by however long the probe waited to run
        // (#3785).
        assert_eq!(
            children[index + 2].predecessors_alive,
            Some(1),
            "child {index} was still running when a later child spawned: {children:?}"
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
    // The four states up to the replacement's start. The replacement renews
    // on RENEWAL too: on a slow slot its own successor can miss the lead
    // before the test stops the lifecycle, and fail closed with a fifth state
    // (main run 23971). That is the replacement's renewal, not this test's.
    let states = lifecycle.until_states(4).await;
    // Why the lifecycle ended the first child, in its own broker log, written
    // before it stopped the child and before the replacement spawned.
    let first_pid = lifecycle.spawner.children()[0].pid.unwrap();
    let first_end = lifecycle.end_reason(first_pid);
    let (children, reported) = lifecycle.stop().await;

    let first = &children[0];
    let lifetime_end = first.spawned.unwrap() + RENEWAL.lifetime;
    // The probe sees the close no earlier than it happened.
    assert!(first.closed.unwrap() + Duration::from_millis(100) >= lifetime_end);
    assert!(process_gone(first.pid.unwrap()));
    // Its lifetime ending stopped it: the lifecycle ends a child for that
    // reason only when the child's lifetime timer fires, so it served no
    // longer than its lifetime. A wall-clock bound on how soon after the
    // lifetime end the stop came measures the slot instead: a CI slot that
    // stalls the test process for a second at that moment fails it, the
    // lifecycle unchanged.
    assert_eq!(
        first_end.as_deref(),
        Some("lifetime_ended"),
        "the first child ended for another reason: {children:?}"
    );
    // It failed closed: the replacement started afresh after it stopped. The
    // first child was already killed and reaped when the replacement spawned.
    // The probe's close time is no witness of that: it is late by however
    // long the probe waited to run, which on a slow CI slot exceeded the
    // replacement's spawn by more than 100 ms (#3239).
    let replacement = &children[1];
    assert_eq!(
        replacement.predecessors_alive,
        Some(0),
        "the replacement spawned while its predecessor ran: {children:?}"
    );
    assert_eq!(
        states,
        [
            BrokerProcessState::Starting,
            BrokerProcessState::Running,
            BrokerProcessState::Starting,
            BrokerProcessState::Running,
        ],
        "every state reported: {reported:?}"
    );
}

/// A generation's first child starts whatever resolves, and each replacement
/// is told exactly what the child it replaces left unresolved, so it can take
/// over with more providers and never with fewer (#5286). The broker log
/// says what each ready child left.
#[tokio::test]
async fn a_replacement_may_leave_unresolved_only_what_the_serving_child_does() {
    let spawner = RenewalSpawner::leaving(
        BTreeSet::new(),
        vec![vec!["platform.claude.com", "api.anthropic.com"], vec![]],
    );
    let lifecycle = Lifecycle::start_with(Arc::clone(&spawner), SLOW_SLOT_RENEWAL);
    lifecycle.until(|spawner| spawner.ready_count() >= 3).await;
    let recorded = lifecycle.ready_unresolved();
    let (children, _) = lifecycle.stop().await;

    let lookups: Vec<_> = children
        .iter()
        .take(3)
        .map(|child| child.lookup.clone().unwrap())
        .collect();
    let left = |hosts: &[&str]| {
        ProviderLookup::NoFewerThan(hosts.iter().map(|host| (*host).to_owned()).collect())
    };
    assert_eq!(
        lookups,
        [
            ProviderLookup::Available,
            left(&["api.anthropic.com", "platform.claude.com"]),
            left(&[]),
        ]
    );
    assert_eq!(
        recorded[..3],
        ["api.anthropic.com/platform.claude.com", "-", "-"]
    );
}

/// What a broker whose runner speaks another protocol says as it ends.
const LAST_WORD: &str =
    "CW_BROKER_EXIT stage=runner.connect kind=runner.protocol_mismatch broker=14 runner=13";

/// A broker that ends at its first step closes its lease channel before its
/// exit can be seen. Its `broker_not_ready` line still carries its exit
/// status and its own last word, with both protocol numbers, never
/// `status=running` with no error (#5238).
#[tokio::test]
async fn a_broker_that_ended_at_its_first_step_is_recorded_with_its_exit_and_its_word() {
    let spawner = Arc::new(RenewalSpawner {
        ends_at_its_first_step: true,
        ..Arc::into_inner(RenewalSpawner::new(BTreeSet::new())).unwrap()
    });
    let lifecycle = Lifecycle::start(Arc::clone(&spawner));
    let log = lifecycle.directory.path().join("logs/brokers.log");
    let not_ready = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let lines = std::fs::read_to_string(&log).unwrap_or_default();
            if let Some(line) = lines
                .lines()
                .find(|line| line.contains(" event=broker_not_ready "))
            {
                return line.to_owned();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first attempt is recorded");
    lifecycle.stop().await;

    assert!(not_ready.contains(" status=exit:3 "), "{not_ready}");
    assert!(
        not_ready.ends_with(
            " error=stage_runner.connect_kind_runner.protocol_mismatch_broker_14_runner_13"
        ),
        "{not_ready}"
    );
}

/// For the early replacements: they come after 100 ms and then at doubling
/// intervals up to 400 ms, long before the regular replacement.
const EARLY_RENEWAL: BrokerRenewal = BrokerRenewal {
    lifetime: Duration::from_secs(30),
    lead: Duration::from_secs(2),
    recovery_first: Duration::from_millis(100),
    recovery_max: Duration::from_millis(400),
};

fn left(hosts: &[&str]) -> BTreeSet<String> {
    hosts.iter().map(|host| (*host).to_owned()).collect()
}

/// A child that left a provider unresolved is replaced early, without
/// waiting for its regular replacement (#5286). Each early replacement is
/// told to get a host back; two that cannot start change nothing, and the
/// third, which resolves it, takes over. The child it replaced then drains
/// no longer than after a regular replacement, not to the end of the
/// lifetime it had left.
#[tokio::test]
async fn a_child_with_an_unserved_provider_is_replaced_early_by_one_that_serves_it() {
    let spawner = RenewalSpawner::leaving(
        BTreeSet::from([1, 2]),
        vec![vec!["api.anthropic.com"], vec![]],
    );
    let lifecycle = Lifecycle::start_with(Arc::clone(&spawner), EARLY_RENEWAL);
    lifecycle.until(|spawner| spawner.ready_count() >= 2).await;
    lifecycle.until(|spawner| spawner.closed(0)).await;
    let lookups = spawner.lookups.lock().unwrap().clone();
    let spawned_as = lifecycle.spawned_as();
    let (children, _) = lifecycle.stop().await;

    let early = ProviderLookup::FewerThan(left(&["api.anthropic.com"]));
    assert_eq!(
        lookups[..4],
        [
            ProviderLookup::Available,
            early.clone(),
            early.clone(),
            early
        ]
    );
    // The two that could not start left no `broker_spawned` line.
    assert_eq!(spawned_as[..2], ["first", "early"]);
    let regular = EARLY_RENEWAL.lifetime - EARLY_RENEWAL.lead;
    let took_over = children[1].ready.unwrap();
    assert!(took_over < regular / 2, "{took_over:?}");
    let drained = children[0].closed.unwrap();
    assert!(drained < regular / 2, "{drained:?}");
}

/// Early replacements that get no host back never take over, and the
/// regular replacement still comes: it may leave what the serving child
/// left, so the child is renewed with the same providers.
#[tokio::test]
async fn early_replacements_that_get_nothing_back_leave_the_regular_replacement_to_come() {
    let unresolved = vec!["api.anthropic.com"];
    let spawner = Arc::new(RenewalSpawner {
        no_host_comes_back: true,
        ..Arc::into_inner(RenewalSpawner::leaving(
            BTreeSet::new(),
            vec![unresolved.clone(), unresolved],
        ))
        .unwrap()
    });
    let renewal = BrokerRenewal {
        lifetime: Duration::from_millis(3000),
        lead: Duration::from_millis(2000),
        ..EARLY_RENEWAL
    };
    let lifecycle = Lifecycle::start_with(Arc::clone(&spawner), renewal);
    lifecycle.until(|spawner| spawner.ready_count() >= 2).await;
    let lookups = spawner.lookups.lock().unwrap().clone();
    let spawned_as = lifecycle.spawned_as();
    let (children, _) = lifecycle.stop().await;

    let hosts = left(&["api.anthropic.com"]);
    assert_eq!(
        children[1].lookup,
        Some(ProviderLookup::NoFewerThan(hosts.clone()))
    );
    // The broker log says which kind of start each spawned child was.
    assert_eq!(spawned_as[..2], ["first", "regular"]);
    let before_regular: Vec<_> = lookups
        .iter()
        .skip(1)
        .take_while(|lookup| **lookup != ProviderLookup::NoFewerThan(hosts.clone()))
        .collect();
    assert!(!before_regular.is_empty(), "{lookups:?}");
    assert!(
        before_regular
            .iter()
            .all(|lookup| **lookup == ProviderLookup::FewerThan(hosts.clone())),
        "{lookups:?}"
    );
}
