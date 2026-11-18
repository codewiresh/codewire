//! Waiting for a started guest's daemon, and why one never became ready.

use super::*;

/// Why a started guest never became ready. `detail` and `guest_stage` are
/// closed names for the runner log (#2595); the status keeps its existing text.
pub(super) struct GuestStartFailure {
    /// The start's error code: `guest_start_failed`, or the front door's own
    /// when it stopped first.
    pub(super) error_code: &'static str,
    pub(super) status: Status,
    pub(super) detail: &'static str,
    pub(super) guest_stage: Option<GuestBootStage>,
    pub(super) daemon_ready: bool,
}

pub(super) async fn wait_for_guest_daemon(
    running: &mut RunningVm,
    timeout: std::time::Duration,
    events: &RunnerEvents,
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
                        ).map_err(|status| ("event_publish", status))?;
                        guest_stage = Some(progress.stage);
                        running.stage_times_mut().record(progress.stage);
                        if progress.stage.is_failure() {
                            return Err((
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
                            Ok(Ok(())) => {
                                return Err((
                                    "guest_progress_ended",
                                    Status::unavailable(
                                        "guest progress ended before daemon startup",
                                    ),
                                ));
                            }
                            Ok(Err(_)) | Err(_) => {
                                return Err((
                                    "guest_progress_invalid",
                                    Status::failed_precondition("guest progress validation failed"),
                                ));
                            }
                        }
                    }
                },
                _ = tokio::time::sleep(DAEMON_RETRY_DELAY) => {
                    // A front door that stopped fails the start now; the
                    // guest's own exit, which follows when its broker cannot
                    // pair, comes tens of seconds later.
                    if running.front_door_stopped().is_some() {
                        return Err((
                            "front_door_stopped",
                            Status::unavailable("front door stopped before daemon readiness"),
                        ));
                    }
                    match running
                        .observe_exit()
                        .await
                        .map_err(|error| ("vm_observe_failed", Status::internal(error.to_string())))?
                    {
                        ExitClass::StillRunning => {}
                        ExitClass::GuestShutdown => {
                            return Err((
                                "guest_shutdown",
                                Status::unavailable("guest shut down before daemon readiness"),
                            ));
                        }
                        ExitClass::VmmFailure(code) => {
                            return Err(("vmm_exited", Status::unavailable(format!(
                                "Cloud Hypervisor exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::DirectShareFailure(code) => {
                            return Err(("direct_share_exited", Status::unavailable(format!(
                                "isolated direct-share server exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::NetworkWorkerFailure(code) => {
                            return Err(("network_worker_exited", Status::unavailable(format!(
                                "isolated network worker exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::EgressBrokerFailure(code) => {
                            return Err(("egress_broker_exited", Status::unavailable(format!(
                                "isolated egress broker exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::IngressForwarderFailure => {
                            return Err((
                                "ingress_forwarder_exited",
                                Status::unavailable(
                                    "ingress forwarder exited before guest daemon readiness",
                                ),
                            ));
                        }
                        ExitClass::MeshTransportFailure(code) => {
                            return Err(("mesh_transport_exited", Status::unavailable(format!(
                                "isolated Mesh transport exited before guest daemon readiness with status {code:?}"
                            ))));
                        }
                        ExitClass::MeshIngressReceiverFailure => {
                            return Err((
                                "mesh_ingress_receiver_exited",
                                Status::unavailable(
                                    "Mesh ingress receiver exited before guest daemon readiness",
                                ),
                            ));
                        }
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
        Err((
            "readiness_timeout",
            Status::unavailable("guest daemon readiness timed out"),
        ))
    });
    if !progress_joined {
        progress_task.abort();
        let _ = progress_task.await;
    }
    let stopped = running.front_door_stopped();
    result.map_err(|(detail, status)| {
        let (error_code, status) = start_failure(stopped, detail, status);
        GuestStartFailure {
            error_code,
            status,
            detail,
            guest_stage,
            daemon_ready,
        }
    })
}

/// The error code and the status a failed start reports. A front door that
/// stopped is the cause of whatever the start then saw (the guest shutting
/// down, its progress ending, the wait running out), however it was seen.
/// Only a failure the guest reported itself stays the guest's.
fn start_failure(
    stopped: Option<crate::runner::InterceptRefusal>,
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
        _ => ("guest_start_failed", status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::{FrontDoorStop, InterceptRefusal};

    #[test]
    fn a_front_door_that_stopped_is_the_cause_of_what_followed_it() {
        let stopped = InterceptRefusal::FrontDoorStopped(FrontDoorStop::ReceivedDead);
        for followed in [
            "guest_shutdown",
            "guest_progress_ended",
            "readiness_timeout",
            "front_door_stopped",
        ] {
            let (error_code, status) = start_failure(
                Some(stopped),
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
            GUEST_SETUP_FAILED,
            Status::failed_precondition("the guest's own"),
        );
        assert_eq!(
            (error_code, status.message()),
            ("guest_start_failed", "the guest's own")
        );
        // With no front door stopped, a failure is as it was.
        let (error_code, status) =
            start_failure(None, "guest_shutdown", Status::unavailable("as before"));
        assert_eq!(
            (error_code, status.message()),
            ("guest_start_failed", "as before")
        );
    }
}
