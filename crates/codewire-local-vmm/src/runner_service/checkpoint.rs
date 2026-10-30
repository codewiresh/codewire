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

/// `StartVmRequest.checkpoint`, parsed and validated, or none.
pub(super) fn parse_checkpoint_boot(
    request: &v1::StartVmRequest,
) -> Result<Option<crate::runner::RestoreBoot>, Status> {
    let Some(boot) = request.checkpoint.as_ref() else {
        return Ok(None);
    };
    let invalid = || Status::invalid_argument("invalid VM checkpoint boot");
    let id = |value: &str| {
        Uuid::parse_str(value)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == value)
            .ok_or_else(invalid)
    };
    let digest = |value: &str| {
        crate::supervisor_metadata::valid_sha256(value)
            .then(|| value.to_owned())
            .ok_or_else(invalid)
    };
    let optional_digest = |value: &str| {
        if value.is_empty() {
            Ok(None)
        } else {
            Sha256Value::parse_hex(value)
                .map(Some)
                .map_err(|_| invalid())
        }
    };
    let bindings = boot.boot.as_ref().ok_or_else(invalid)?;
    if boot.memory_bytes == 0 || boot.source_generation == 0 {
        return Err(invalid());
    }
    Ok(Some(crate::runner::RestoreBoot {
        checkpoint_id: id(&boot.checkpoint_id)?,
        source_environment_id: id(&boot.source_environment_id)?,
        config_sha256: digest(&boot.config_sha256)?,
        state_sha256: digest(&boot.state_sha256)?,
        memory_bytes: boot.memory_bytes,
        setup_disk_bytes: (boot.setup_disk_bytes != 0).then_some(boot.setup_disk_bytes),
        vmm_sha256: digest(&boot.vmm_sha256)?,
        source_generation: boot.source_generation,
        skill_snapshot_sha256: optional_digest(&bindings.skill_snapshot_sha256)?,
        environment_projection_sha256: optional_digest(&bindings.environment_projection_sha256)?,
        managed_credential_clients: codewire_access::ManagedCredentialClients::decode(
            &bindings.managed_credential_clients,
        )
        .map_err(|_| invalid())?,
        docker: bindings.docker,
        cw_runtime_catalog_generation: (!bindings.cw_runtime_catalog_generation.is_empty())
            .then(|| digest(&bindings.cw_runtime_catalog_generation))
            .transpose()?,
        daemon_vsock_port: bindings.daemon_vsock_port,
    }))
}

impl RunnerRpc {
    /// Record how a restored boot resumed: the guest reseeded before the
    /// workload thawed.
    pub(super) fn log_restore(&self, environment_id: Uuid, generation: u64, running: &RunningVm) {
        let Some(report) = running.restore_report() else {
            return;
        };
        if let Some(log) = &self.log {
            log.record(
                "vm_restored",
                &[
                    ("environment", LogField::Id(environment_id)),
                    ("generation", LogField::Count(generation)),
                    ("reseeded", LogField::Name(bool_text(report.reseeded))),
                    (
                        "vmgenid_driver",
                        LogField::Name(bool_text(report.vmgenid_driver)),
                    ),
                    (
                        "removed_logins",
                        LogField::Name(bool_text(report.removed_logins)),
                    ),
                    ("admit_ms", LogField::Count(report.admit.as_millis() as u64)),
                    (
                        "shares_ms",
                        LogField::Count(report.shares.as_millis() as u64),
                    ),
                    ("vmm_ms", LogField::Count(report.vmm.as_millis() as u64)),
                    (
                        "resume_ms",
                        LogField::Count(report.resume.as_millis() as u64),
                    ),
                    ("thaw_ms", LogField::Count(report.thaw.as_millis() as u64)),
                ],
            );
        }
    }
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> v1::CheckpointBoot {
        v1::CheckpointBoot {
            checkpoint_id: Uuid::new_v4().to_string(),
            source_environment_id: Uuid::new_v4().to_string(),
            config_sha256: "a".repeat(64),
            state_sha256: "b".repeat(64),
            memory_bytes: 512 * 1024 * 1024,
            setup_disk_bytes: 0,
            vmm_sha256: "c".repeat(64),
            boot: Some(v1::CheckpointBootBindings {
                managed_credential_clients: codewire_access::ManagedCredentialClients::default()
                    .encode()
                    .to_owned(),
                daemon_vsock_port: 7777,
                ..Default::default()
            }),
            source_generation: 3,
        }
    }

    #[test]
    fn a_checkpoint_boot_parses_exactly() {
        let request = |checkpoint| v1::StartVmRequest {
            checkpoint,
            ..Default::default()
        };
        assert_eq!(parse_checkpoint_boot(&request(None)).unwrap(), None);
        let parsed = parse_checkpoint_boot(&request(Some(boot())))
            .unwrap()
            .unwrap();
        assert_eq!(parsed.source_generation, 3);
        assert_eq!(parsed.setup_disk_bytes, None);
        assert_eq!(parsed.cw_runtime_catalog_generation, None);
        let broken: [fn(&mut v1::CheckpointBoot); 6] = [
            |boot| boot.checkpoint_id = "nope".into(),
            |boot| boot.config_sha256 = "short".into(),
            |boot| boot.memory_bytes = 0,
            |boot| boot.source_generation = 0,
            |boot| boot.boot = None,
            |boot| boot.boot.as_mut().unwrap().managed_credential_clients = "bogus".into(),
        ];
        for change in broken {
            let mut boot = boot();
            change(&mut boot);
            assert!(parse_checkpoint_boot(&request(Some(boot))).is_err());
        }
    }
}
