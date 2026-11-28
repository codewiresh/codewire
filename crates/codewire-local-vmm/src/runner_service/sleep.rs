//! Runner-side suspend and resume for a running Linux VM (#5529,
//! `docs/dev/LOCAL-VM-SLEEP.md`).
//!
//! Keeps `RunningVm` owned while paused in memory (`vm.pause` + guest workload
//! frozen) and resumes it cleanly on `ResumeVm`, `GetDaemonAccess`, `StopVm`,
//! `CheckpointVm`, or an inbound host-port connection (`WakeHook`).

#[cfg(target_os = "linux")]
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::*;

/// Live suspend state held on `RunnerState` while a Linux VM is paused.
#[derive(Debug, Clone)]
pub(super) struct SuspendedVm {
    #[cfg(target_os = "linux")]
    pub(super) operation_id: Uuid,
    #[cfg(target_os = "linux")]
    pub(super) abi: u32,
    pub(super) suspended_at_unix_ms: i64,
    pub(super) reason: String,
}

#[cfg(target_os = "linux")]
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", test))]
fn normalize_suspend_reason(reason: &str) -> Result<String, Status> {
    match reason.trim() {
        "" | "user" => Ok("user".to_owned()),
        "idle" => Ok("idle".to_owned()),
        other => Err(Status::invalid_argument(format!(
            "unsupported suspend reason: {other}"
        ))),
    }
}

impl RunnerClient {
    pub async fn suspend_vm(
        &mut self,
        environment_id: Uuid,
        generation: u64,
        operation_id: Uuid,
        reason: &str,
    ) -> Result<v1::SuspendVmResponse, Status> {
        Ok(self
            .inner
            .suspend_vm(v1::SuspendVmRequest {
                environment_id: environment_id.to_string(),
                generation,
                operation_id: operation_id.to_string(),
                reason: reason.to_owned(),
            })
            .await?
            .into_inner())
    }

    pub async fn resume_vm(
        &mut self,
        environment_id: Uuid,
        generation: u64,
    ) -> Result<v1::ResumeVmResponse, Status> {
        Ok(self
            .inner
            .resume_vm(v1::ResumeVmRequest {
                environment_id: environment_id.to_string(),
                generation,
            })
            .await?
            .into_inner())
    }

    pub async fn hibernate_vm(
        &mut self,
        environment_id: Uuid,
        generation: u64,
        operation_id: Uuid,
    ) -> Result<v1::HibernateVmResponse, Status> {
        Ok(self
            .inner
            .hibernate_vm(v1::HibernateVmRequest {
                environment_id: environment_id.to_string(),
                generation,
                operation_id: operation_id.to_string(),
            })
            .await?
            .into_inner())
    }
}

impl RunnerState {
    pub(super) fn clear_suspended(&mut self) {
        self.suspended = None;
        self.wake_hook.set_suspended(false);
    }

    /// Resumes a suspended Linux VM in place under the state lock. Returns
    /// `Ok(Some(wake_duration_ms))` if it resumed from suspend, or `Ok(None)`
    /// if the VM was already awake.
    pub(super) async fn resume_if_suspended(
        &mut self,
        log: Option<&DiagnosticLog>,
    ) -> Result<Option<u64>, Status> {
        let Some(suspended) = self.suspended.clone() else {
            return Ok(None);
        };
        #[cfg(target_os = "linux")]
        {
            let running = self
                .running
                .as_mut()
                .ok_or_else(|| Status::failed_precondition("environment is not running"))?;
            let started = Instant::now();
            running
                .resume_suspended(suspended.operation_id, suspended.abi)
                .await
                .map_err(map_sleep_error)?;
            let wake_ms = elapsed_ms(started);
            self.clear_suspended();
            self.last_wake_duration_ms = Some(wake_ms);
            diagnostic_log::record(
                log,
                "vm_resumed",
                &[
                    ("environment", LogField::Id(self.environment_id)),
                    ("generation", LogField::Count(self.generation)),
                    ("wake_ms", LogField::Count(wake_ms)),
                ],
            );
            Ok(Some(wake_ms))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (suspended, log);
            self.clear_suspended();
            Err(Status::unimplemented(
                "local VM resume is supported only on Linux",
            ))
        }
    }
}

impl RunnerRpc {
    pub(super) async fn suspend_vm_inner(
        &self,
        request: v1::SuspendVmRequest,
    ) -> Result<v1::SuspendVmResponse, Status> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(Status::unimplemented(
                "local VM suspend is supported only on Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let environment_id = parse_environment_id(&request.environment_id)?;
            let operation_id = Uuid::parse_str(&request.operation_id)
                .ok()
                .filter(|id| !id.is_nil() && id.to_string() == request.operation_id)
                .ok_or_else(|| Status::invalid_argument("suspend operation id is invalid"))?;
            let reason = normalize_suspend_reason(&request.reason)?;
            let state = Arc::clone(&self.state);
            let log = self.log.clone();
            // Run on a dedicated task so a dropped client RPC never leaves the
            // VM half-frozen or half-paused.
            tokio::spawn(async move {
                let mut state = state.lock_owned().await;
                state.retirement.require_active()?;
                state.require_adopted(environment_id)?;
                state
                    .observe_exit()
                    .await
                    .map_err(|_| Status::internal("observe VMM state failed"))?;
                if state.generation != request.generation
                    || state.state != v1::EnvironmentState::Running
                {
                    return Err(Status::failed_precondition(
                        "only a running VM generation can be suspended",
                    ));
                }
                if state.suspended.is_some() {
                    return Ok(v1::SuspendVmResponse {
                        runner: Some(state.info()),
                        already_suspended: true,
                    });
                }
                let abi = state
                    .runner
                    .guest_checkpoint_request_abi()
                    .map_err(map_sleep_error)?;
                let running = state.running.as_mut().ok_or_else(|| {
                    Status::failed_precondition("only a running VM can be suspended")
                })?;
                let started = Instant::now();
                let timings = running
                    .suspend(operation_id, abi)
                    .await
                    .map_err(map_sleep_error)?;
                let suspended_at_unix_ms = now_unix_ms();
                state.suspended = Some(SuspendedVm {
                    operation_id,
                    abi,
                    suspended_at_unix_ms,
                    reason: reason.clone(),
                });
                state.wake_hook.set_suspended(true);
                diagnostic_log::record(
                    log.as_deref(),
                    "vm_suspended",
                    &[
                        ("environment", LogField::Id(environment_id)),
                        ("generation", LogField::Count(state.generation)),
                        ("reason", LogField::Name(reason_label(&reason))),
                        ("freeze_ms", LogField::Count(elapsed_ms(started))),
                        (
                            "guest_freeze_us",
                            LogField::Count(
                                u64::try_from(timings.guest_freeze.as_micros()).unwrap_or(u64::MAX),
                            ),
                        ),
                    ],
                );
                Ok(v1::SuspendVmResponse {
                    runner: Some(state.info()),
                    already_suspended: false,
                })
            })
            .await
            .map_err(|_| Status::internal("VM suspend task failed"))?
        }
    }

    pub(super) async fn resume_vm_inner(
        &self,
        request: v1::ResumeVmRequest,
    ) -> Result<v1::ResumeVmResponse, Status> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(Status::unimplemented(
                "local VM resume is supported only on Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let environment_id = parse_environment_id(&request.environment_id)?;
            let state = Arc::clone(&self.state);
            let log = self.log.clone();
            tokio::spawn(async move {
                let mut state = state.lock_owned().await;
                state.retirement.require_active()?;
                state.require_adopted(environment_id)?;
                state
                    .observe_exit()
                    .await
                    .map_err(|_| Status::internal("observe VMM state failed"))?;
                if state.generation != request.generation
                    || state.state != v1::EnvironmentState::Running
                {
                    return Err(Status::failed_precondition(
                        "only a running or suspended VM generation can be resumed",
                    ));
                }
                match state.resume_if_suspended(log.as_deref()).await? {
                    Some(wake_duration_ms) => Ok(v1::ResumeVmResponse {
                        runner: Some(state.info()),
                        already_running: false,
                        wake_duration_ms,
                    }),
                    None => Ok(v1::ResumeVmResponse {
                        runner: Some(state.info()),
                        already_running: true,
                        wake_duration_ms: 0,
                    }),
                }
            })
            .await
            .map_err(|_| Status::internal("VM resume task failed"))?
        }
    }

    pub(super) async fn hibernate_vm_inner(
        &self,
        request: v1::HibernateVmRequest,
    ) -> Result<v1::HibernateVmResponse, Status> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(Status::unimplemented(
                "local VM hibernate is supported only on Linux",
            ))
        }
        #[cfg(target_os = "linux")]
        {
            let environment_id = parse_environment_id(&request.environment_id)?;
            let operation_id = Uuid::parse_str(&request.operation_id)
                .ok()
                .filter(|id| !id.is_nil() && id.to_string() == request.operation_id)
                .ok_or_else(|| Status::invalid_argument("hibernate operation id is invalid"))?;
            let state = Arc::clone(&self.state);
            let events = Arc::clone(&self.events);
            let log = self.log.clone();
            tokio::spawn(async move {
                let mut state = state.lock_owned().await;
                state.retirement.require_active()?;
                state.require_adopted(environment_id)?;
                state
                    .observe_exit()
                    .await
                    .map_err(|_| Status::internal("observe VMM state failed"))?;
                if state.generation != request.generation
                    || state.state != v1::EnvironmentState::Running
                {
                    return Err(Status::failed_precondition(
                        "only a running or suspended VM generation can be hibernated",
                    ));
                }
                let already_suspended = state.suspended.is_some();
                let mut running = state.running.take().ok_or_else(|| {
                    Status::failed_precondition("only a running or suspended VM can be hibernated")
                })?;
                let boot = running.boot_bindings().clone();
                let has_docker = running.has_docker_disk();
                let started = Instant::now();
                let result = state
                    .runner
                    .hibernate_with_state(&mut running, operation_id, already_suspended)
                    .await;
                let hibernation = match result {
                    Ok(hibernation) => hibernation,
                    Err(error) => {
                        if matches!(running.try_exit(), Ok(ExitClass::StillRunning)) {
                            state.running = Some(running);
                        } else {
                            state.generation_access = None;
                            state.clear_suspended();
                            state.state = v1::EnvironmentState::Error;
                            state.error_code = Some("hibernate_failed");
                        }
                        return Err(map_sleep_error(error));
                    }
                };
                state.generation_access = None;
                state.clear_suspended();
                state.state = v1::EnvironmentState::Stopped;
                state.error_code = None;
                let _ = events.publish(
                    v1::EnvironmentState::Stopped,
                    state.generation,
                    v1::RunnerStage::Stopped,
                    None,
                    None,
                    state.cw_runtime_catalog_generation(),
                );
                let total_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                let micros =
                    |d: std::time::Duration| u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
                diagnostic_log::record(
                    log.as_deref(),
                    "vm_hibernated",
                    &[
                        ("environment", LogField::Id(environment_id)),
                        ("generation", LogField::Count(state.generation)),
                        (
                            "memory_bytes",
                            LogField::Count(hibernation.restore.memory_bytes),
                        ),
                        ("total_ms", LogField::Count(elapsed_ms(started))),
                    ],
                );
                Ok(v1::HibernateVmResponse {
                    timings: Some(v1::CheckpointTimings {
                        guest_freeze_us: micros(hibernation.timings.guest_freeze),
                        workload_frozen_us: micros(hibernation.timings.workload_frozen),
                        vm_paused_us: micros(hibernation.timings.vm_paused),
                        memory_write_us: micros(hibernation.timings.memory_write),
                        disk_clone_us: 0,
                        total_us,
                    }),
                    memory_bytes: hibernation.restore.memory_bytes,
                    config_sha256: hibernation.restore.config_sha256,
                    state_sha256: hibernation.restore.state_sha256,
                    vmm_sha256: hibernation.restore.vmm_sha256,
                    vsock_cid: boot.vsock_cid,
                    root_generation: boot.root_generation,
                    setup_disk_bytes: hibernation.restore.setup_disk_bytes.unwrap_or_default(),
                    boot: Some(v1::CheckpointBootBindings {
                        skill_snapshot_sha256: boot
                            .skill_snapshot_sha256
                            .map(|digest| digest.to_string())
                            .unwrap_or_default(),
                        environment_projection_sha256: boot
                            .environment_projection_sha256
                            .map(|digest| digest.to_string())
                            .unwrap_or_default(),
                        managed_credential_clients: boot
                            .managed_credential_clients
                            .encode()
                            .to_owned(),
                        docker: has_docker,
                        cw_runtime_catalog_generation: boot
                            .cw_runtime_catalog_generation
                            .unwrap_or_default(),
                        daemon_vsock_port: boot.daemon_vsock_port,
                        intercept: !boot.intercepts.is_empty(),
                        bound_secrets: crate::runner::records_to_proto(boot.bound_secrets.clone()),
                    }),
                })
            })
            .await
            .map_err(|_| Status::internal("VM hibernate task failed"))?
        }
    }
}

/// Consumes inbound host-port wake requests and resumes the suspended VM under
/// `RunnerState`'s mutex, coalescing concurrent connections onto one resume.
pub(super) fn spawn_ingress_wake_loop(
    state: Arc<Mutex<RunnerState>>,
    log: Option<Arc<DiagnosticLog>>,
    mut wake_rx: mpsc::UnboundedReceiver<oneshot::Sender<Result<(), ()>>>,
) {
    drop(tokio::spawn(async move {
        while let Some(reply) = wake_rx.recv().await {
            let outcome = {
                let mut guard = state.lock().await;
                if guard.state != v1::EnvironmentState::Running {
                    Err(())
                } else {
                    guard
                        .resume_if_suspended(log.as_deref())
                        .await
                        .map(|_| ())
                        .map_err(|_| ())
                }
            };
            let _ = reply.send(outcome);
        }
    }));
}

#[cfg(target_os = "linux")]
fn reason_label(reason: &str) -> &'static str {
    if reason == "idle" { "idle" } else { "user" }
}

#[cfg(target_os = "linux")]
fn map_sleep_error(error: RunnerError) -> Status {
    match error {
        RunnerError::Checkpoint(message) => Status::failed_precondition(message),
        other => Status::internal(format!("VM sleep operation failed: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_reason_accepts_empty_user_and_idle_only() {
        assert_eq!(normalize_suspend_reason("").unwrap(), "user");
        assert_eq!(normalize_suspend_reason("user").unwrap(), "user");
        assert_eq!(normalize_suspend_reason("idle").unwrap(), "idle");
        assert!(normalize_suspend_reason("bogus").is_err());
    }
}
