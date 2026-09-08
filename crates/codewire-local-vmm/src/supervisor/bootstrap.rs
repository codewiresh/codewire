//! The broker's short launch budget starts after authenticated guest bootstrap
//! reaches the early daemon. VM preparation/root extraction uses the existing
//! boot budget; terminal install readiness must never be a prerequisite.

use super::*;
use tokio_stream::StreamExt;

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
