//! Waiting for a started guest's daemon, and why one never became ready.

use super::*;

/// The error code of a start that failed because the credential broker
/// started for its generation never came (#5238).
pub(crate) const CREDENTIAL_BROKER_UNAVAILABLE: &str = "credential_broker_unavailable";

/// Why a started guest never became ready. `detail` and `guest_stage` are
/// closed names for the runner log (#2595); the status keeps its existing text.
pub(super) struct GuestStartFailure {
    /// The start's error code: `guest_start_failed`, the front door's own
    /// when it stopped first, or `credential_broker_unavailable`.
    pub(super) error_code: &'static str,
    pub(super) status: Status,
    pub(super) detail: &'static str,
    pub(super) guest_stage: Option<GuestBootStage>,
    pub(super) daemon_ready: bool,
    /// The VMM or helper process whose exit ended the wait.
    pub(super) helper_exit: Option<exit_cause::ObservedExit>,
}

impl GuestStartFailure {
    /// What the runner's `vm_start_failed` line says of the guest's start.
    pub(super) fn log_fields(&self, fields: &mut Vec<(&'static str, LogField<'_>)>) {
        fields.push(("detail", LogField::Name(self.detail)));
        fields.push((
            "guest_stage",
            LogField::Name(self.guest_stage.map_or("none", guest_stage_name)),
        ));
        fields.push((
            "daemon_ready",
            LogField::Count(u64::from(self.daemon_ready)),
        ));
        if let Some(exit) = self.helper_exit {
            fields.push(("helper_exit", exit.log_field()));
        }
    }

    /// What the runner saw, when the error code names a cause it inferred
    /// from that and not the thing itself.
    pub(super) fn observed(&self) -> Option<&'static str> {
        (self.error_code == CREDENTIAL_BROKER_UNAVAILABLE).then_some(self.detail)
    }
}

/// How long a start whose guest progress stopped waits for the VMM's exit.
/// The stream breaks as the process carrying it goes, a moment before that
/// process's exit can be read, and the exit is what the start reports.
const PROGRESS_STOP_EXIT_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// What ended the wait: its closed name, the status `cw` shows, and the
/// process whose exit it was.
struct Seen {
    detail: &'static str,
    status: Status,
    helper_exit: Option<exit_cause::ObservedExit>,
}

fn seen(detail: &'static str, status: Status) -> Seen {
    Seen {
        detail,
        status,
        helper_exit: None,
    }
}

pub(super) async fn wait_for_guest_daemon(
    running: &mut RunningVm,
    timeout: std::time::Duration,
    events: &RunnerEvents,
    access: &GenerationAccessCell,
) -> Result<(), GuestStartFailure> {
    let target = GuestProgressTarget::from_running(running);
    let generation = running.generation();
    let (progress_tx, mut progress_rx) = mpsc::channel(RUNNER_WATCH_BUFFER);
    let mut progress_task = tokio::spawn(stream_guest_progress(target, progress_tx));
    let mut progress_joined = false;
    let mut guest_stage = None;
    let mut daemon_ready = false;
    let result = tokio::time::timeout(timeout, async {
        let mut progress_open = true;
        let mut progress_ready = false;
        loop {
            tokio::select! {
                progress = progress_rx.recv(), if progress_open => match progress {
                    Some(progress) => {
                        events.publish(
                            v1::EnvironmentState::Starting,
                            generation,
                            v1::RunnerStage::GuestInit,
                            Some(progress),
                            None,
                        running.cw_runtime_catalog_generation(),
                        ).map_err(|status| seen("event_publish", status))?;
                        guest_stage = Some(progress.stage);
                        running.stage_times_mut().record(progress.stage);
                        if progress.stage.is_failure() {
                            return Err(seen(
                                guest_failure_detail(progress.stage),
                                Status::failed_precondition(
                                    "authenticated guest initialization failed",
                                ),
                            ));
                        }
                        progress_ready |= progress.stage == GuestBootStage::DaemonStarted;
                    }
                    None => {
                        progress_open = false;
                        progress_joined = true;
                        match (&mut progress_task).await {
                            Ok(Ok(())) if progress_ready => {}
                            stopped => {
                                let exit = running
                                    .wait_for_exit(PROGRESS_STOP_EXIT_WAIT)
                                    .await
                                    .map_err(|error| seen("vm_observe_failed", Status::internal(error.to_string())))?;
                                return Err(progress_stopped(exit, matches!(stopped, Ok(Ok(())))));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(DAEMON_RETRY_DELAY) => {
                    // A front door that stopped fails the start now; the
                    // guest's own exit, which follows when its broker cannot
                    // pair, comes tens of seconds later.
                    if running.front_door_stopped().is_some() {
                        return Err(seen(
                            "front_door_stopped",
                            Status::unavailable("front door stopped before daemon readiness"),
                        ));
                    }
                    let exit = running
                        .observe_exit()
                        .await
                        .map_err(|error| seen("vm_observe_failed", Status::internal(error.to_string())))?;
                    if let Some(ended) = ended_before_readiness(exit) {
                        return Err(ended);
                    }
                    if !daemon_ready
                        && let Ok(client) = running.daemon_client().await
                        && client.require_ready().await.is_ok()
                    {
                        daemon_ready = true;
                    }
                }
            }
            if daemon_ready && progress_ready {
                return Ok(());
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(seen(
            "readiness_timeout",
            Status::unavailable("guest daemon readiness timed out"),
        ))
    });
    if !progress_joined {
        progress_task.abort();
        let _ = progress_task.await;
    }
    let stopped = running.front_door_stopped();
    result.map_err(|seen| {
        let waited = (daemon_ready, access.broker_seen(generation));
        let (error_code, status) = start_failure(stopped, waited, seen.detail, seen.status);
        GuestStartFailure {
            error_code,
            status,
            detail: seen.detail,
            guest_stage,
            daemon_ready,
            helper_exit: seen.helper_exit,
        }
    })
}

/// What a start saw when the guest's progress stopped short of its daemon:
/// the exit of the process that took it down, when one had ended.
fn progress_stopped(exit: ExitClass, ended_cleanly: bool) -> Seen {
    ended_before_readiness(exit).unwrap_or_else(|| {
        if ended_cleanly {
            seen(
                "guest_progress_ended",
                Status::unavailable("guest progress ended before daemon startup"),
            )
        } else {
            seen(
                "guest_progress_invalid",
                Status::failed_precondition("guest progress validation failed"),
            )
        }
    })
}

/// What a start saw when the guest or one of its processes ended before the
/// guest's daemon was ready; `None` while they all run.
fn ended_before_readiness(exit: ExitClass) -> Option<Seen> {
    let helper = |detail, name: &str, end: crate::process_end::ProcessEnd| {
        let status = end.code();
        (
            detail,
            Status::unavailable(format!(
                "{name} exited before guest daemon readiness with status {status:?}"
            )),
        )
    };
    let (detail, status) = match exit {
        ExitClass::StillRunning => return None,
        ExitClass::GuestShutdown => (
            "guest_shutdown",
            Status::unavailable("guest shut down before daemon readiness"),
        ),
        ExitClass::VmmFailure(end) => helper("vmm_exited", "Cloud Hypervisor", end),
        ExitClass::DirectShareFailure(end) => {
            helper("direct_share_exited", "isolated direct-share server", end)
        }
        ExitClass::NetworkWorkerFailure(end) => {
            helper("network_worker_exited", "isolated network worker", end)
        }
        ExitClass::EgressBrokerFailure(end) => {
            helper("egress_broker_exited", "isolated egress broker", end)
        }
        ExitClass::IngressForwarderFailure => (
            "ingress_forwarder_exited",
            Status::unavailable("ingress forwarder exited before guest daemon readiness"),
        ),
        ExitClass::MeshTransportFailure(end) => {
            helper("mesh_transport_exited", "isolated Mesh transport", end)
        }
        ExitClass::MeshIngressReceiverFailure => (
            "mesh_ingress_receiver_exited",
            Status::unavailable("Mesh ingress receiver exited before guest daemon readiness"),
        ),
    };
    Some(Seen {
        detail,
        status,
        helper_exit: exit_cause::observed_exit(exit),
    })
}

/// The error code and the status a failed start reports. A front door that
/// stopped is the cause of whatever the start then saw (the guest shutting
/// down, its progress ending, the wait running out), however it was seen.
/// So is a credential broker that never came once the guest's daemon had
/// answered (`waited`), which is where the guest starts waiting for it: the guest gives
/// up, and the other processes end as it goes down. Only a failure the guest
/// reported itself stays the guest's; a workspace launch its daemon refused
/// before it ran is not one, since the launch waits for the broker (#6281).
fn start_failure(
    stopped: Option<crate::runner::InterceptRefusal>,
    waited: (bool, BrokerSeen),
    detail: &'static str,
    status: Status,
) -> (&'static str, Status) {
    let guest_reported = [
        GUEST_SETUP_FAILED,
        GUEST_DOCKER_TOOLING_MISSING,
        GUEST_WORKSPACE_FAILED,
    ]
    .contains(&detail);
    match stopped {
        Some(stopped) if !guest_reported => {
            (stopped.code(), Status::unavailable(stopped.to_string()))
        }
        None if waited == (true, BrokerSeen::Never) && !guest_reported => {
            (CREDENTIAL_BROKER_UNAVAILABLE, status)
        }
        _ => ("guest_start_failed", status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{FrontDoorStop, InterceptRefusal};
    use crate::runner_service::start_error::GUEST_WORKSPACE_LAUNCH_REFUSED;

    /// The guest's daemon answered and the broker started for it never came.
    const NEVER_CAME: (bool, BrokerSeen) = (true, BrokerSeen::Never);

    /// Each process that can end a start keeps its own detail, the words
    /// `cw` shows and how it ended, and a start whose processes all run is
    /// not ended.
    #[test]
    fn a_process_that_ended_before_readiness_is_named() {
        use crate::process_end::ProcessEnd;
        assert!(ended_before_readiness(ExitClass::StillRunning).is_none());
        for (exit, detail, message) in [
            (
                ExitClass::GuestShutdown,
                "guest_shutdown",
                "guest shut down before daemon readiness",
            ),
            (
                ExitClass::VmmFailure(ProcessEnd::Code(1)),
                "vmm_exited",
                "Cloud Hypervisor exited before guest daemon readiness with status Some(1)",
            ),
            (
                ExitClass::EgressBrokerFailure(ProcessEnd::Code(72)),
                "egress_broker_exited",
                "isolated egress broker exited before guest daemon readiness with status Some(72)",
            ),
            (
                ExitClass::NetworkWorkerFailure(ProcessEnd::Signal(9)),
                "network_worker_exited",
                "isolated network worker exited before guest daemon readiness with status None",
            ),
            (
                ExitClass::DirectShareFailure(ProcessEnd::Code(2)),
                "direct_share_exited",
                "isolated direct-share server exited before guest daemon readiness with status Some(2)",
            ),
            (
                ExitClass::MeshTransportFailure(ProcessEnd::Code(3)),
                "mesh_transport_exited",
                "isolated Mesh transport exited before guest daemon readiness with status Some(3)",
            ),
            (
                ExitClass::IngressForwarderFailure,
                "ingress_forwarder_exited",
                "ingress forwarder exited before guest daemon readiness",
            ),
            (
                ExitClass::MeshIngressReceiverFailure,
                "mesh_ingress_receiver_exited",
                "Mesh ingress receiver exited before guest daemon readiness",
            ),
        ] {
            let seen = ended_before_readiness(exit).unwrap();
            assert_eq!((seen.detail, seen.status.message()), (detail, message));
            // The process that ended travels with what was seen.
            assert_eq!(seen.helper_exit, exit_cause::observed_exit(exit));
        }
    }

    /// A VMM that is killed breaks the guest's progress stream first; the
    /// start reports the VMM's exit, not the broken stream.
    #[test]
    fn progress_that_stopped_because_a_process_went_is_that_process_exit() {
        use crate::process_end::ProcessEnd;
        let killed = ExitClass::VmmFailure(ProcessEnd::Signal(9));
        for ended_cleanly in [true, false] {
            let seen = progress_stopped(killed, ended_cleanly);
            assert_eq!(seen.detail, "vmm_exited");
            assert_eq!(seen.helper_exit, exit_cause::observed_exit(killed));
        }
        assert_eq!(
            progress_stopped(ExitClass::GuestShutdown, true).detail,
            "guest_shutdown"
        );
        // With every process still running, the stream is what was seen.
        let ended = progress_stopped(ExitClass::StillRunning, true);
        assert_eq!(
            (ended.detail, ended.status.message(), ended.helper_exit),
            (
                "guest_progress_ended",
                "guest progress ended before daemon startup",
                None
            )
        );
        let invalid = progress_stopped(ExitClass::StillRunning, false);
        assert_eq!(
            (
                invalid.detail,
                invalid.status.message(),
                invalid.helper_exit
            ),
            (
                "guest_progress_invalid",
                "guest progress validation failed",
                None
            )
        );
    }

    #[test]
    fn a_front_door_that_stopped_is_the_cause_of_what_followed_it() {
        let stopped = InterceptRefusal::FrontDoorStopped(FrontDoorStop::ReceivedDead);
        for followed in [
            "guest_shutdown",
            "guest_progress_ended",
            "readiness_timeout",
            "front_door_stopped",
        ] {
            // The front door's stop comes before a broker that never came.
            let (error_code, status) = start_failure(
                Some(stopped),
                NEVER_CAME,
                followed,
                Status::unavailable("what followed"),
            );
            assert_eq!(error_code, "front_door_received_dead", "{followed}");
            assert_eq!(
                status.message(),
                "the environment's interception front door stopped while it started (received_dead); start the environment again"
            );
        }
        // What the guest reported of itself is not the front door's doing.
        let (error_code, status) = start_failure(
            Some(stopped),
            (false, BrokerSeen::None),
            GUEST_SETUP_FAILED,
            Status::failed_precondition("the guest's own"),
        );
        assert_eq!(
            (error_code, status.message()),
            ("guest_start_failed", "the guest's own")
        );
        // With no front door stopped, a failure is as it was.
        let (error_code, status) = start_failure(
            None,
            (false, BrokerSeen::None),
            "guest_shutdown",
            Status::unavailable("as before"),
        );
        assert_eq!(
            (error_code, status.message()),
            ("guest_start_failed", "as before")
        );
    }

    /// A broker that never came is the cause of what the start then saw,
    /// which keeps its words; what the guest reported of itself is not.
    #[test]
    fn a_broker_that_never_came_is_the_cause_of_what_followed_it() {
        for followed in [
            "egress_broker_exited",
            "guest_shutdown",
            "readiness_timeout",
        ] {
            let (error_code, status) = start_failure(
                None,
                NEVER_CAME,
                followed,
                Status::unavailable("what was seen"),
            );
            assert_eq!(error_code, CREDENTIAL_BROKER_UNAVAILABLE, "{followed}");
            assert_eq!(status.message(), "what was seen");
            // Before the guest's daemon answered, the guest was not yet
            // waiting for a broker; a broker that came, or none to come,
            // is no cause either.
            for waited in [
                (false, BrokerSeen::Never),
                (true, BrokerSeen::Connected),
                (true, BrokerSeen::None),
            ] {
                let (error_code, _) =
                    start_failure(None, waited, followed, Status::unavailable("what was seen"));
                assert_eq!(error_code, "guest_start_failed", "{followed} {waited:?}");
            }
        }
        for reported in [
            GUEST_SETUP_FAILED,
            GUEST_DOCKER_TOOLING_MISSING,
            GUEST_WORKSPACE_FAILED,
        ] {
            let (error_code, _) = start_failure(
                None,
                NEVER_CAME,
                reported,
                Status::unavailable("the guest's own"),
            );
            assert_eq!(error_code, "guest_start_failed", "{reported}");
        }
    }

    /// A workspace launch the guest's daemon refused before it ran names the
    /// broker only when the broker never came; a launched command that failed
    /// stays the guest's whatever the broker did (#6281).
    #[test]
    fn a_refused_launch_names_the_broker_only_when_it_never_came() {
        for (waited, expected) in [
            (NEVER_CAME, CREDENTIAL_BROKER_UNAVAILABLE),
            ((false, BrokerSeen::Never), "guest_start_failed"),
            ((true, BrokerSeen::Connected), "guest_start_failed"),
            ((true, BrokerSeen::None), "guest_start_failed"),
        ] {
            let (error_code, status) = start_failure(
                None,
                waited,
                GUEST_WORKSPACE_LAUNCH_REFUSED,
                Status::failed_precondition("refused"),
            );
            assert_eq!(
                (error_code, status.message()),
                (expected, "refused"),
                "{waited:?}"
            );
            let (error_code, _) = start_failure(
                None,
                waited,
                GUEST_WORKSPACE_FAILED,
                Status::failed_precondition("ran and failed"),
            );
            assert_eq!(error_code, "guest_start_failed", "{waited:?}");
        }
        assert_eq!(
            guest_failure_detail(GuestBootStage::WorkspaceLaunchRefused),
            GUEST_WORKSPACE_LAUNCH_REFUSED
        );
        assert_eq!(
            guest_failure_detail(GuestBootStage::WorkspaceFailed),
            GUEST_WORKSPACE_FAILED
        );
    }
}
