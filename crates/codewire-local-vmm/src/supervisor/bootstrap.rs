//! The broker's short launch budget starts after authenticated guest bootstrap
//! reaches the early daemon. VM preparation/root extraction uses the existing
//! boot budget; terminal install readiness must never be a prerequisite.

use super::*;
use tokio::sync::Notify;
use tokio_stream::StreamExt;

/// The runner's start beside the credential broker's wait for the guest's
/// bootstrap. A start the runner refuses ends that wait at once: the
/// bootstrap it waits for can no longer come, and the wait would otherwise
/// hold the start, and every operation queued behind it, for its full 20
/// minutes (#4953). Once the wait is over the broker's launch runs to its end
/// whatever the start does, so no broker starts after the cleanup that
/// follows a failed start. It holds all three futures at once, so a caller
/// that is itself a large future boxes it: unboxed in `ensure_vm_started`, it
/// overflowed the stack of the supervisor tests that start an environment.
pub(super) async fn start_beside_broker<T, U>(
    start: impl Future<Output = Result<T, Status>>,
    wait: Option<impl Future<Output = Result<(), SupervisorError>>>,
    launch: impl Future<Output = Result<U, SupervisorError>>,
) -> (Result<T, Status>, Result<U, SupervisorError>) {
    let refused = Notify::new();
    tokio::join!(
        async {
            let started = start.await;
            if started.is_err() {
                refused.notify_one();
            }
            started
        },
        async {
            if let Some(wait) = wait {
                tokio::select! {
                    waited = wait => waited?,
                    () = refused.notified() => return Err(SupervisorError::RunnerUnavailable),
                }
            }
            launch.await
        },
    )
}

pub(super) async fn wait_for_broker_bootstrap(
    mut events: impl Stream<Item = Result<v1::RunnerEvent, Status>> + Unpin,
    environment_id: Uuid,
    generation: u64,
    artifact_generation: &str,
) -> Result<(), SupervisorError> {
    tokio::time::timeout(Duration::from_secs(20 * 60), async {
        while let Some(event) = events.next().await {
            if broker_bootstrap_ready(
                &event.map_err(|_| SupervisorError::RunnerUnavailable)?,
                environment_id,
                generation,
                artifact_generation,
            )? {
                return Ok(());
            }
        }
        Err(SupervisorError::RunnerUnavailable)
    })
    .await
    .map_err(|_| SupervisorError::RunnerUnavailable)?
}

fn broker_bootstrap_ready(
    event: &v1::RunnerEvent,
    environment_id: Uuid,
    generation: u64,
    artifact_generation: &str,
) -> Result<bool, SupervisorError> {
    let runner = event
        .runner
        .as_ref()
        .ok_or(SupervisorError::InvalidRunnerResponse)?;
    if runner.environment_id != environment_id.to_string()
        || runner.artifact_generation != artifact_generation
        || runner.generation > generation
    {
        return Err(SupervisorError::InvalidRunnerResponse);
    }
    if runner.generation < generation {
        return Ok(false);
    }
    let state = StoredEnvironmentState::from_proto(runner.state)?;
    if matches!(
        state,
        StoredEnvironmentState::Error | StoredEnvironmentState::Stopped
    ) || !event.error_code.is_empty()
    {
        return Err(SupervisorError::RunnerUnavailable);
    }
    match v1::RunnerStage::try_from(event.stage) {
        Ok(v1::RunnerStage::DaemonReady) if state == StoredEnvironmentState::Running => Ok(true),
        Ok(v1::RunnerStage::GuestInit) if state == StoredEnvironmentState::Starting => {
            Ok(event.guest_sequence > 0
                && matches!(
                    v1::GuestBootStage::try_from(event.guest_stage),
                    Ok(v1::GuestBootStage::RuncLaunching
                        | v1::GuestBootStage::RuncRunning
                        | v1::GuestBootStage::WorkspaceRunning
                        | v1::GuestBootStage::DaemonStarted)
                ))
        }
        Ok(
            v1::RunnerStage::PreparingVm
            | v1::RunnerStage::StartingVmm
            | v1::RunnerStage::WaitingGuest,
        ) if state == StoredEnvironmentState::Starting => Ok(false),
        _ => Err(SupervisorError::InvalidRunnerResponse),
    }
}

/// Whether a runner event only restates the state before this start: the
/// prior generation, stopped or failed, with no guest progress.
pub(super) fn runner_event_is_prior_baseline(
    generation: u64,
    state: StoredEnvironmentState,
    stage: v1::RunnerStage,
    guest_sequence: u64,
    guest_stage: v1::GuestBootStage,
    error_code_valid: bool,
    prior: (u64, StoredEnvironmentState),
) -> bool {
    generation == prior.0
        && state == prior.1
        && guest_sequence == 0
        && guest_stage == v1::GuestBootStage::Unspecified
        && match state {
            StoredEnvironmentState::Stopped => {
                matches!(stage, v1::RunnerStage::Ready | v1::RunnerStage::Stopped)
                    && !error_code_valid
            }
            StoredEnvironmentState::Error => stage == v1::RunnerStage::Error && error_code_valid,
            StoredEnvironmentState::Starting
            | StoredEnvironmentState::Running
            | StoredEnvironmentState::Orphaned => false,
        }
}

/// How long a start waits for the guest's agent logins to settle, and how
/// often it asks: often enough that a settled login adds no visible delay
/// (#6123).
const AGENT_LOGINS_BOUND: Duration = Duration::from_secs(10);
const AGENT_LOGINS_POLL: Duration = Duration::from_millis(100);

/// What a start's wait for the guest's agent logins ended with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AgentLogins {
    /// Each login its profile delivers is written, the user's own was kept,
    /// or delivery was refused.
    Settled,
    /// The daemon doesn't report them, being from before #6123, or couldn't
    /// be asked: nothing to wait for.
    NotReported,
    /// Still arriving at the bound; they land when they come.
    StillArriving,
}

/// Reaches the guest daemon with `connect`, then asks `health` every
/// [`AGENT_LOGINS_POLL`] until it reports its agent logins settled, all
/// within `bound`: a runner or daemon that never answers holds a start no
/// longer than that.
pub(super) async fn wait_for_agent_logins<D, C, A, F>(
    connect: C,
    mut health: A,
    bound: Duration,
) -> AgentLogins
where
    D: Clone,
    C: Future<Output = Option<D>>,
    A: FnMut(D) -> F,
    F: Future<Output = Option<codewire_daemon_proto::daemon::v1::GetHealthResponse>>,
{
    use codewire_daemon::login_readiness::AGENT_LOGINS_DIAGNOSTIC;
    let deadline = tokio::time::Instant::now() + bound;
    let daemon = match tokio::time::timeout_at(deadline, connect).await {
        Err(_) => return AgentLogins::StillArriving,
        Ok(None) => return AgentLogins::NotReported,
        Ok(Some(daemon)) => daemon,
    };
    loop {
        let Ok(answer) = tokio::time::timeout_at(deadline, health(daemon.clone())).await else {
            return AgentLogins::StillArriving;
        };
        let Some(answer) = answer else {
            return AgentLogins::NotReported;
        };
        match answer
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.name == AGENT_LOGINS_DIAGNOSTIC)
        {
            None => return AgentLogins::NotReported,
            Some(diagnostic) if diagnostic.healthy => return AgentLogins::Settled,
            Some(_) => {}
        }
        if tokio::time::Instant::now() + AGENT_LOGINS_POLL >= deadline {
            return AgentLogins::StillArriving;
        }
        tokio::time::sleep(AGENT_LOGINS_POLL).await;
    }
}

impl Supervisor {
    /// The end of a VM start once the runner reports it running: the in-guest
    /// cw runtime's boot is confirmed, the guest's agent logins are waited
    /// for (#6123), and the environment records the runtime catalog it
    /// booted.
    pub(super) async fn finish_started_vm(
        &self,
        name: &str,
        generation: u64,
        operation_id: Uuid,
        environment: &EnvironmentRecord,
        mut client: RunnerClient,
        cw_runtime: Option<String>,
    ) -> Result<(), SupervisorError> {
        if cw_runtime.is_some() {
            let confirmation = match client.daemon_access().await {
                Ok(access) => runtime::confirm_boot(self, name, generation, access).await,
                Err(_) => Err(Status::unavailable("runtime startup endpoint unavailable")),
            };
            if let Err(status) = confirmation {
                let _ = client.stop().await;
                let mut failed_generation = environment.clone();
                failed_generation.generation = generation;
                self.stop_environment_broker_if_present(&failed_generation)
                    .await?;
                return Err(SupervisorError::VmStart(status.message().to_owned()));
            }
        }
        self.wait_for_started_agent_logins(&mut client, operation_id)
            .await;
        self.update_environment(name, |environment| {
            environment
                .runner
                .as_mut()
                .ok_or(SupervisorError::InvalidState)?
                .cw_runtime_catalog_generation = cw_runtime;
            Ok(())
        })
    }
}

impl Supervisor {
    /// A started VM's [`wait_for_agent_logins`], through its runner's daemon
    /// access, so the first agent command after the start finds its login.
    /// Logins still arriving at the bound are noted on `operation_id`, and
    /// `cw` says so.
    async fn wait_for_started_agent_logins(&self, client: &mut RunnerClient, operation_id: Uuid) {
        let connect = async {
            let access = client.daemon_access().await.ok()?;
            let capability = zeroize::Zeroizing::new(access.generation_capability);
            crate::hybrid_vsock::connect_daemon(
                std::path::Path::new(&access.hybrid_socket),
                access.guest_port,
                capability.as_str(),
            )
            .await
            .ok()
        };
        let waited = wait_for_agent_logins(
            connect,
            |daemon: codewire_daemon::client::SessionClient| async move {
                daemon.get_health().await.ok()
            },
            AGENT_LOGINS_BOUND,
        )
        .await;
        if waited == AgentLogins::StillArriving {
            self.core()
                .operation_notes
                .agent_logins_arriving(operation_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANG_GUARD: Duration = Duration::from_secs(30);

    fn health(logins: Option<bool>) -> codewire_daemon_proto::daemon::v1::GetHealthResponse {
        codewire_daemon_proto::daemon::v1::GetHealthResponse {
            diagnostics: logins
                .map(
                    |healthy| codewire_daemon_proto::daemon::v1::HealthDiagnostic {
                        name: codewire_daemon::login_readiness::AGENT_LOGINS_DIAGNOSTIC.to_owned(),
                        healthy,
                        message: String::new(),
                    },
                )
                .into_iter()
                .collect(),
            ..Default::default()
        }
    }

    /// #6123: a start waits for the guest's agent logins, asking every
    /// 100 ms, so a login that lands a moment later holds it only that long;
    /// one that never settles, or a daemon that never answers, holds it for
    /// the bound only; a daemon that doesn't report them, or can't answer,
    /// isn't waited for.
    #[tokio::test(start_paused = true)]
    async fn a_start_waits_for_the_agent_logins_at_most_its_bound() {
        let bound = Duration::from_secs(10);
        let reached = || std::future::ready(Some(()));
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let waited = wait_for_agent_logins(
            reached(),
            |()| {
                let call = asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { Some(health(Some(call >= 3))) }
            },
            bound,
        )
        .await;
        assert_eq!(waited, AgentLogins::Settled);
        assert_eq!(started.elapsed(), Duration::from_millis(300));

        let started = tokio::time::Instant::now();
        let waited =
            wait_for_agent_logins(reached(), |()| async { Some(health(Some(false))) }, bound).await;
        assert_eq!(waited, AgentLogins::StillArriving);
        assert!(started.elapsed() <= bound, "{:?}", started.elapsed());
        assert!(started.elapsed() >= bound - Duration::from_millis(100));

        let started = tokio::time::Instant::now();
        let waited = wait_for_agent_logins(reached(), |()| std::future::pending(), bound).await;
        assert_eq!(waited, AgentLogins::StillArriving);
        assert_eq!(started.elapsed(), bound);

        for answer in [Some(health(None)), None] {
            let started = tokio::time::Instant::now();
            let waited =
                wait_for_agent_logins(reached(), |()| std::future::ready(answer.clone()), bound)
                    .await;
            assert_eq!(waited, AgentLogins::NotReported);
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
    }

    /// A runner that never answers the daemon access, or a daemon that never
    /// accepts, holds the start for the bound only; one that refuses holds it
    /// not at all (#6123).
    #[tokio::test(start_paused = true)]
    async fn reaching_the_daemon_is_inside_the_bound() {
        let bound = Duration::from_secs(10);
        let never_asked = |()| async { unreachable!("the daemon was never reached") };
        let started = tokio::time::Instant::now();
        let waited =
            wait_for_agent_logins(std::future::pending::<Option<()>>(), never_asked, bound).await;
        assert_eq!(waited, AgentLogins::StillArriving);
        assert_eq!(started.elapsed(), bound);

        let started = tokio::time::Instant::now();
        let waited =
            wait_for_agent_logins(std::future::ready(None::<()>), never_asked, bound).await;
        assert_eq!(waited, AgentLogins::NotReported);
        assert_eq!(started.elapsed(), Duration::ZERO);

        // Reached late, the daemon has only what is left of the bound.
        let started = tokio::time::Instant::now();
        let waited = wait_for_agent_logins(
            async {
                tokio::time::sleep(Duration::from_secs(9)).await;
                Some(())
            },
            |()| async { Some(health(Some(false))) },
            bound,
        )
        .await;
        assert_eq!(waited, AgentLogins::StillArriving);
        assert!(started.elapsed() <= bound, "{:?}", started.elapsed());
    }

    /// #4953: a runner that refuses the start, as one still holding a failed
    /// VM does, ends a bootstrap wait that would otherwise never finish, and
    /// the refusal is what comes back. The broker is never launched.
    #[tokio::test]
    async fn a_refused_start_ends_the_brokers_wait() {
        let launched = std::sync::atomic::AtomicBool::new(false);
        let (start, broker) = tokio::time::timeout(
            HANG_GUARD,
            start_beside_broker(
                async { Err::<(), _>(Status::already_exists("environment is already running")) },
                Some(std::future::pending()),
                async {
                    launched.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            ),
        )
        .await
        .expect("the broker's wait held the refused start");
        assert_eq!(start.unwrap_err().code(), tonic::Code::AlreadyExists);
        assert!(matches!(broker, Err(SupervisorError::RunnerUnavailable)));
        assert!(!launched.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Once the guest's bootstrap has come, a start that fails later leaves
    /// the broker's launch to finish, so the cleanup after it finds the broker.
    #[tokio::test(start_paused = true)]
    async fn a_start_that_fails_after_the_wait_leaves_the_launch_to_finish() {
        let (start, broker) = start_beside_broker(
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Err::<(), _>(Status::unavailable("guest daemon never became ready"))
            },
            Some(std::future::ready(Ok(()))),
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(7)
            },
        )
        .await;
        assert!(start.is_err());
        assert_eq!(broker.unwrap(), 7);
    }

    /// The normal case: both finish, the broker only after its wait.
    #[tokio::test(start_paused = true)]
    async fn a_start_and_its_broker_both_finish() {
        let (start, broker) = start_beside_broker(
            async {
                tokio::time::sleep(Duration::from_secs(3)).await;
                Ok::<_, Status>("started")
            },
            Some(async {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(())
            }),
            async { Ok("launched") },
        )
        .await;
        assert_eq!(start.unwrap(), "started");
        assert_eq!(broker.unwrap(), "launched");
    }

    fn event(id: Uuid, generation: u64, guest: v1::GuestBootStage) -> v1::RunnerEvent {
        v1::RunnerEvent {
            runner: Some(v1::RunnerInfo {
                environment_id: id.to_string(),
                generation,
                artifact_generation: "a".repeat(64),
                state: v1::EnvironmentState::Starting as i32,
                ..Default::default()
            }),
            stage: v1::RunnerStage::GuestInit as i32,
            guest_sequence: 1,
            guest_stage: guest as i32,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn broker_bootstrap_waits_through_root_setup_but_not_install_completion() {
        let id = Uuid::new_v4();
        let events = tokio_stream::iter([
            Ok(event(id, 1, v1::GuestBootStage::DaemonStarted)),
            Ok(event(id, 2, v1::GuestBootStage::RootLayersReady)),
            Ok(event(id, 2, v1::GuestBootStage::PersistentLayoutReady)),
            Ok(event(id, 2, v1::GuestBootStage::RuncLaunching)),
        ]);
        wait_for_broker_bootstrap(events, id, 2, &"a".repeat(64))
            .await
            .unwrap();
    }

    #[test]
    fn broker_bootstrap_rejects_wrong_identity_generation_and_failed_boot() {
        let id = Uuid::new_v4();
        let good = event(id, 2, v1::GuestBootStage::RuncLaunching);
        assert!(broker_bootstrap_ready(&good, id, 2, &"a".repeat(64)).unwrap());
        for field in 0..4 {
            let mut invalid = good.clone();
            let runner = invalid.runner.as_mut().unwrap();
            match field {
                0 => runner.environment_id = Uuid::new_v4().to_string(),
                1 => runner.generation = 3,
                2 => runner.artifact_generation = "b".repeat(64),
                _ => runner.state = v1::EnvironmentState::Error as i32,
            }
            assert!(broker_bootstrap_ready(&invalid, id, 2, &"a".repeat(64)).is_err());
        }
    }
}
