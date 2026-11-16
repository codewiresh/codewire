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

#[cfg(test)]
mod tests {
    use super::*;

    const HANG_GUARD: Duration = Duration::from_secs(30);

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
