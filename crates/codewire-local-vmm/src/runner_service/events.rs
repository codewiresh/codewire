//! The runner's event stream: one sequence, the latest event to every
//! subscriber.

use super::*;

pub(super) struct RunnerEvents {
    pub(super) environment_id: Uuid,
    artifact_generation: String,
    pub(super) sequence: AtomicU64,
    pub(super) sender: watch::Sender<v1::RunnerEvent>,
}

impl RunnerEvents {
    pub(super) fn new(environment_id: Uuid, artifact_generation: String, generation: u64) -> Self {
        let runner = v1::RunnerInfo {
            environment_id: environment_id.to_string(),
            state: v1::EnvironmentState::Stopped as i32,
            generation,
            artifact_generation: artifact_generation.clone(),
            error_code: String::new(),
            cw_runtime_catalog_generation: String::new(),
            ..Default::default()
        };
        let initial = v1::RunnerEvent {
            sequence: 1,
            runner: Some(runner),
            stage: v1::RunnerStage::WaitingAdoption as i32,
            guest_sequence: 0,
            guest_stage: v1::GuestBootStage::Unspecified as i32,
            error_code: String::new(),
            error_observed: String::new(),
        };
        Self {
            environment_id,
            artifact_generation,
            sequence: AtomicU64::new(1),
            sender: watch::channel(initial).0,
        }
    }

    pub(super) fn publish(
        &self,
        state: v1::EnvironmentState,
        generation: u64,
        stage: v1::RunnerStage,
        guest: Option<GuestProgressUpdate>,
        error_code: Option<&str>,
        cw_runtime_catalog_generation: Option<&str>,
    ) -> Result<v1::RunnerEvent, Status> {
        let event = self.next(
            state,
            generation,
            stage,
            guest,
            error_code,
            cw_runtime_catalog_generation,
        )?;
        self.sender.send_replace(event.clone());
        Ok(event)
    }

    /// The error event of a start that failed in the guest, with what the
    /// runner saw beside an error code that names a cause it inferred.
    pub(super) fn publish_start_failure(
        &self,
        generation: u64,
        failure: &GuestStartFailure,
        cw_runtime_catalog_generation: Option<&str>,
    ) -> Result<v1::RunnerEvent, Status> {
        let mut event = self.next(
            v1::EnvironmentState::Error,
            generation,
            v1::RunnerStage::Error,
            None,
            Some(failure.error_code),
            cw_runtime_catalog_generation,
        )?;
        event.error_observed = failure.observed().unwrap_or_default().to_owned();
        self.sender.send_replace(event.clone());
        Ok(event)
    }

    /// The next event in the sequence, not yet sent.
    fn next(
        &self,
        state: v1::EnvironmentState,
        generation: u64,
        stage: v1::RunnerStage,
        guest: Option<GuestProgressUpdate>,
        error_code: Option<&str>,
        cw_runtime_catalog_generation: Option<&str>,
    ) -> Result<v1::RunnerEvent, Status> {
        if cw_runtime_catalog_generation
            .is_some_and(|generation| !crate::state::valid_root_generation(generation))
        {
            return Err(Status::internal("runner runtime attachment is invalid"));
        }
        if error_code.is_some_and(|code| {
            code.is_empty()
                || code.len() > 64
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        }) {
            return Err(Status::internal("runner event error code is invalid"));
        }
        let sequence = self
            .sequence
            .try_update(Ordering::AcqRel, Ordering::Acquire, |sequence| {
                sequence.checked_add(1)
            })
            .map_err(|_| Status::internal("runner event sequence overflow"))?
            + 1;
        let event = v1::RunnerEvent {
            sequence,
            runner: Some(v1::RunnerInfo {
                environment_id: self.environment_id.to_string(),
                state: state as i32,
                generation,
                artifact_generation: self.artifact_generation.clone(),
                error_code: error_code.unwrap_or_default().to_owned(),
                cw_runtime_catalog_generation: cw_runtime_catalog_generation
                    .unwrap_or_default()
                    .to_owned(),
                ..Default::default()
            }),
            stage: stage as i32,
            guest_sequence: guest.map_or(0, |update| update.sequence),
            guest_stage: guest
                .map(|update| guest_boot_stage_proto(update.stage) as i32)
                .unwrap_or(v1::GuestBootStage::Unspecified as i32),
            error_code: error_code.unwrap_or_default().to_owned(),
            error_observed: String::new(),
        };
        Ok(event)
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<v1::RunnerEvent> {
        self.sender.subscribe()
    }
}

fn guest_boot_stage_proto(stage: GuestBootStage) -> v1::GuestBootStage {
    match stage {
        GuestBootStage::StateMounted => v1::GuestBootStage::StateMounted,
        GuestBootStage::CgroupsReady => v1::GuestBootStage::CgroupsReady,
        GuestBootStage::DisksAdmitted => v1::GuestBootStage::DisksAdmitted,
        GuestBootStage::RootMounted => v1::GuestBootStage::RootMounted,
        GuestBootStage::SetupHeaderReady => v1::GuestBootStage::SetupHeaderReady,
        GuestBootStage::SetupContentReady => v1::GuestBootStage::SetupContentReady,
        GuestBootStage::RootLayersReady => v1::GuestBootStage::RootLayersReady,
        GuestBootStage::WorkspacePlanReady => v1::GuestBootStage::WorkspacePlanReady,
        GuestBootStage::OwnershipReady => v1::GuestBootStage::OwnershipReady,
        GuestBootStage::ContainerControlReady => v1::GuestBootStage::ContainerControlReady,
        GuestBootStage::RootGenerationReady => v1::GuestBootStage::RootGenerationReady,
        GuestBootStage::PersistentLayoutReady => v1::GuestBootStage::PersistentLayoutReady,
        GuestBootStage::RuncLaunching => v1::GuestBootStage::RuncLaunching,
        GuestBootStage::RuncRunning => v1::GuestBootStage::RuncRunning,
        GuestBootStage::WorkspaceRunning => v1::GuestBootStage::WorkspaceRunning,
        GuestBootStage::DaemonStarted => v1::GuestBootStage::DaemonStarted,
        GuestBootStage::SetupFailed => v1::GuestBootStage::SetupFailed,
        GuestBootStage::WorkspaceFailed
        | GuestBootStage::DockerToolingMissing
        | GuestBootStage::WorkspaceLaunchRefused => v1::GuestBootStage::WorkspaceFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(error_code: &'static str) -> GuestStartFailure {
        GuestStartFailure {
            error_code,
            status: Status::unavailable("what was seen"),
            detail: "egress_broker_exited",
            guest_stage: None,
            daemon_ready: true,
            helper_exit: None,
        }
    }

    /// What the runner saw goes out only beside the cause it inferred from
    /// it; every other failed start's event is as it was.
    #[test]
    fn a_failed_start_event_says_what_was_seen_beside_an_inferred_cause() {
        let events = RunnerEvents::new(Uuid::new_v4(), "a".repeat(64), 1);
        let mut watch = events.subscribe();
        let inferred = events
            .publish_start_failure(2, &failure(CREDENTIAL_BROKER_UNAVAILABLE), None)
            .unwrap();
        assert_eq!(
            (
                inferred.error_code.as_str(),
                inferred.error_observed.as_str()
            ),
            ("credential_broker_unavailable", "egress_broker_exited")
        );
        assert_eq!(inferred.stage, v1::RunnerStage::Error as i32);
        assert_eq!(*watch.borrow_and_update(), inferred);
        let plain = events
            .publish_start_failure(2, &failure("guest_start_failed"), None)
            .unwrap();
        assert_eq!(
            (plain.error_code.as_str(), plain.error_observed.as_str()),
            ("guest_start_failed", "")
        );
        assert_eq!(plain.sequence, inferred.sequence + 1);
    }
}
