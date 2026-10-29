//! The runner's `CheckpointVm` (#3046 R4), a child of `runner_service`.

use super::*;

/// The error code of a VM whose checkpoint completed but which did not
/// resume: it stays owned, paused, until an explicit stop reaps it.
const CHECKPOINT_RESUME_FAILED: &str = "checkpoint_resume_failed";

impl RunnerClient {
    pub async fn checkpoint_vm(
        &mut self,
        environment_id: Uuid,
        generation: u64,
        operation_id: Uuid,
    ) -> Result<v1::CheckpointVmResponse, Status> {
        Ok(self
            .inner
            .checkpoint_vm(v1::CheckpointVmRequest {
                environment_id: environment_id.to_string(),
                generation,
                operation_id: operation_id.to_string(),
            })
            .await?
            .into_inner())
    }
}

impl RunnerRpc {
    pub(super) async fn checkpoint(
        &self,
        request: v1::CheckpointVmRequest,
    ) -> Result<v1::CheckpointVmResponse, Status> {
        let environment_id = parse_environment_id(&request.environment_id)?;
        let operation_id = Uuid::parse_str(&request.operation_id)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == request.operation_id)
            .ok_or_else(|| Status::invalid_argument("checkpoint operation id is invalid"))?;
        let state = Arc::clone(&self.state);
        let events = Arc::clone(&self.events);
        // In a task of its own, holding the state lock throughout: a dropped
        // request never leaves the VM paused or its workload frozen, and no
        // start, stop or host-port change interleaves.
        tokio::spawn(async move {
            let mut state = state.lock_owned().await;
            state.retirement.require_active()?;
            if !state.adopted {
                return Err(Status::failed_precondition("runner is not adopted"));
            }
            if environment_id != state.environment_id {
                return Err(Status::permission_denied("runner identity mismatch"));
            }
            state
                .observe_exit()
                .await
                .map_err(|_| Status::internal("observe VMM state failed"))?;
            if state.generation != request.generation
                || state.state != v1::EnvironmentState::Running
            {
                return Err(Status::failed_precondition(
                    "a VM checkpoint is taken only of the running generation",
                ));
            }
            let (vmm_version, vmm_sha256) = state.runner.vmm_identity();
            let running = state.running.as_mut().ok_or_else(|| {
                Status::failed_precondition("a VM checkpoint is taken only of a running VM")
            })?;
            let started = std::time::Instant::now();
            let capture = running
                .checkpoint(operation_id)
                .await
                .map_err(map_checkpoint_error)?;
            let boot = running.boot_bindings();
            let response = v1::CheckpointVmResponse {
                timings: Some(v1::CheckpointTimings {
                    guest_freeze_us: micros(capture.timings.guest_freeze),
                    workload_frozen_us: micros(capture.timings.workload_frozen),
                    vm_paused_us: micros(capture.timings.vm_paused),
                    memory_write_us: micros(capture.timings.memory_write),
                    disk_clone_us: micros(capture.timings.disk_clone),
                    total_us: micros(started.elapsed()),
                }),
                memory_bytes: capture.memory_bytes,
                guest_checkpoint_abi: capture.guest_abi,
                vmm_version: vmm_version.to_owned(),
                vmm_sha256,
                vsock_cid: boot.vsock_cid,
                root_generation: boot.root_generation.clone(),
                setup_disk_bytes: capture.setup_disk_bytes.unwrap_or_default(),
                boot: Some(v1::CheckpointBootBindings {
                    skill_snapshot_sha256: boot
                        .skill_snapshot_sha256
                        .map(|digest| digest.to_string())
                        .unwrap_or_default(),
                    environment_projection_sha256: boot
                        .environment_projection_sha256
                        .map(|digest| digest.to_string())
                        .unwrap_or_default(),
                    managed_credential_clients: boot.managed_credential_clients.encode().to_owned(),
                    docker: running.has_docker_disk(),
                    cw_runtime_catalog_generation: boot
                        .cw_runtime_catalog_generation
                        .clone()
                        .unwrap_or_default(),
                    daemon_vsock_port: boot.daemon_vsock_port,
                }),
                resume_failed: capture.resume_failed,
            };
            if capture.resume_failed {
                state.state = v1::EnvironmentState::Error;
                state.error_code = Some(CHECKPOINT_RESUME_FAILED);
                let generation = state.generation;
                let catalog = state.cw_runtime_catalog_generation().map(str::to_owned);
                events.publish(
                    v1::EnvironmentState::Error,
                    generation,
                    v1::RunnerStage::Ready,
                    None,
                    Some(CHECKPOINT_RESUME_FAILED),
                    catalog.as_deref(),
                )?;
            }
            Ok(response)
        })
        .await
        .map_err(|_| Status::internal("VM checkpoint task failed"))?
    }
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn map_checkpoint_error(error: RunnerError) -> Status {
    match error {
        RunnerError::Checkpoint(message) => Status::failed_precondition(message),
        other => Status::internal(format!("VM checkpoint failed: {other}")),
    }
}
