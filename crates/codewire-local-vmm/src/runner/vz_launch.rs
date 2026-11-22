//! Darwin's launch: the signed Virtualization.framework helper as the VM's
//! VMM, apart from `runner.rs` so the schema 3 setup (#4654) grows neither.

use super::*;

impl CloudHypervisorRunner {
    /// Launch the signed Virtualization.framework helper as this VM's VMM.
    /// The helper inherits the open `vm.lock`, and stops its VM when this
    /// runner exits. Readiness is its hybrid-vsock socket plus a live helper.
    pub(super) async fn launch(&self, prepared: PreparedVm) -> Result<RunningVm, RunnerError> {
        let (restore_input, restore_admit) = admit_restore_input(&prepared)?;
        let checkpointing = self
            .write_configuration(&prepared, restore_input.as_ref())
            .await?;
        let executable = self.artifacts.vz_runner.path();
        let spawning = std::time::Instant::now();
        // Arm cancellation cleanup in the same synchronous span as spawn.
        let vmm = crate::vz::spawn(
            executable,
            &prepared.paths.vm_dir.join(crate::vz::CONFIG_NAME),
            &prepared.paths.vm_dir,
            &prepared.lock,
            checkpointing.as_ref().map(crate::vz::Checkpointing::helper),
        )?;
        let mut startup = StartupOwnership::new(vmm);
        let pid = startup.child_mut().id().ok_or(RunnerError::Spawn)?;
        let process = match LiveProcess::capture_child(pid, executable) {
            Ok(process) => process,
            Err(error) => {
                startup.terminate_unadmitted(pid).await?;
                return Err(error.into());
            }
        };
        startup.admit(process);
        // This process's copy of the helper's end closes here; the runner's
        // end lives as long as the VM.
        let started = checkpointing.map(crate::vz::Checkpointing::into_started);
        // A restored VM answers on its vsock only once the helper has
        // restored and resumed it, which its `started` reports, and the
        // guest's Resume connects once; so a restore reads it first (#4654).
        let (started, restored_control) = match (started, restore_input.is_some()) {
            (Some(started), true) => (
                None,
                Some(
                    started
                        .keep_identifier(&prepared.paths.vm_dir, prepared.request.vm_id)
                        .await,
                ),
            ),
            (started, _) => (started, None),
        };

        // As on Linux, persist the helper's identity before any guest wait.
        let mut state = PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id: prepared.request.vm_id,
            generation: prepared.request.generation,
            intercept: !prepared.request.intercepts.is_empty(),
            vsock_cid: prepared.request.vsock_cid,
            daemon_vsock_port: prepared.request.daemon_vsock_port,
            phase: VmPhase::Starting,
            process: startup.process().identity().clone(),
            state_disk: prepared.state_disk.clone(),
            docker_disk: prepared.docker_disk.clone(),
            root_generation: Some(prepared.request.root_generation.clone()),
            root_disk: Some(prepared.root_disk.clone()),
            cw_runtime_disk: prepared.cw_runtime_disk.clone(),
            api_socket: None,
            vsock_socket: None,
        };
        if let Err(error) = state.write_atomic(&prepared.paths.state_file) {
            startup.terminate_admitted().await?;
            return Err(error.into());
        }

        let finalized = async {
            let (hybrid, vsock_socket) = wait_for_vsock_endpoint(
                &prepared.paths,
                startup.process(),
                prepared.request.daemon_vsock_port,
            )
            .await?;
            prepared.paths.validate_diagnostics()?;
            state.phase = VmPhase::Running;
            state.vsock_socket = Some(vsock_socket);
            state.write_atomic(&prepared.paths.state_file)?;
            let restored = match &restore_input {
                Some(_) => Some(
                    self.resume_restored(&prepared, restore_admit, spawning.elapsed())
                        .await?,
                ),
                None => None,
            };
            Ok::<_, RunnerError>((hybrid, restored))
        }
        .await;
        let (hybrid, restored) = match finalized {
            Ok(finalized) => finalized,
            Err(error) => {
                startup.terminate_admitted().await?;
                return Err(error);
            }
        };
        let control = match started {
            Some(started) => Some(
                started
                    .keep_identifier(&prepared.paths.vm_dir, prepared.request.vm_id)
                    .await,
            ),
            None => restored_control,
        };
        let (child, process) = startup.disarm();
        Ok(RunningVm {
            // Evaluated before the request moves.
            host_ports: prepared.request.host_ports.clone(),
            request: prepared.request,
            paths: prepared.paths,
            state_disk: prepared.state_disk,
            docker_disk: prepared.docker_disk,
            root_disk: prepared.root_disk,
            setup_disk: prepared.setup_disk,
            cw_runtime_disk: prepared.cw_runtime_disk,
            token: prepared.token,
            child,
            process,
            hybrid,
            network_worker: None,
            host_port_listeners: prepared.host_port_listeners,
            stage_times: GuestStageTimes::default(),
            front_door: prepared.front_door,
            restored,
            control,
            _lock: prepared.lock,
        })
    }
}

impl CloudHypervisorRunner {
    /// Write this boot's helper configuration as the VM's `vz.json`, a
    /// restore's included, and return the control channel and checkpoint
    /// files a schema 3 helper also gets (#4654).
    async fn write_configuration(
        &self,
        prepared: &PreparedVm,
        restore_input: Option<&checkpoint::RestoreInput>,
    ) -> Result<Option<crate::vz::Checkpointing>, RunnerError> {
        let root_disk = root_disk_path(&prepared.paths, &prepared.request.root_generation)?;
        let configuration = crate::vz::VzConfiguration::new(
            self.artifacts.kernel.path(),
            self.artifacts.initramfs.path(),
            prepared.request.vcpus,
            prepared.request.memory_mib,
            crate::vz::VzDisks {
                state: &prepared.paths.state_disk,
                docker: prepared
                    .docker_disk
                    .as_ref()
                    .map(|_| prepared.paths.docker_disk.as_path()),
                root: &root_disk,
                seed: &prepared.paths.seed_disk,
                setup: setup_disk(prepared, restore_input),
                cw_runtime: prepared
                    .cw_runtime_disk
                    .as_ref()
                    .map(|disk| disk.path.as_path()),
            },
            admitted_shares(&prepared.direct_shares)?,
            &prepared.paths.vsock_socket,
        );
        let (configuration, mut checkpointing) = crate::vz::Checkpointing::configure(
            &self.vz_protocol,
            self.artifacts.vz_runner.path(),
            &prepared.paths,
            configuration,
        )
        .await?;
        let configuration = restoring(
            configuration.encode()?,
            restore_input,
            checkpointing.as_mut(),
        )?;
        prepared.paths.open_vm_root()?.atomic_replace(
            Path::new(crate::vz::CONFIG_NAME),
            &configuration,
            0o600,
        )?;
        Ok(checkpointing)
    }
}

impl CloudHypervisorRunner {
    /// A restored VM runs with its workload frozen: it moves to this boot's
    /// identity and thaws before anything else reaches it, its clock stepped
    /// past the time it spent saved (#3046 R4, #4654).
    async fn resume_restored(
        &self,
        prepared: &PreparedVm,
        admit: std::time::Duration,
        vmm: std::time::Duration,
    ) -> Result<RestoreReport, RunnerError> {
        let mut report = checkpoint::resume_restored(
            &prepared.paths.vsock_socket,
            &prepared.token,
            prepared.request.vm_id,
            prepared.request.generation,
            self.guest_checkpoint_request_abi()?,
        )
        .await?;
        report.admit = admit;
        report.vmm = vmm;
        Ok(report)
    }
}

/// A restore admits what the supervisor placed before anything starts
/// (#4654 M4c): the checkpoint's configuration and saved state as recorded,
/// and a stand-in for its setup disk. With how long that took.
fn admit_restore_input(
    prepared: &PreparedVm,
) -> Result<(Option<checkpoint::RestoreInput>, std::time::Duration), RunnerError> {
    let admitting = std::time::Instant::now();
    let input = prepared
        .request
        .checkpoint
        .as_ref()
        .map(|restore| checkpoint::restore_input(&prepared.paths, restore))
        .transpose()?;
    Ok((input, admitting.elapsed()))
}

/// The setup disk this boot attaches: a restore's stand-in for the captured
/// boot's, or this boot's own.
fn setup_disk<'a>(
    prepared: &'a PreparedVm,
    restore_input: Option<&'a checkpoint::RestoreInput>,
) -> Option<&'a Path> {
    restore_input
        .and_then(|input| input.setup.as_deref())
        .or_else(|| {
            prepared
                .setup_disk
                .as_ref()
                .map(|setup| setup.path.as_path())
        })
}

/// This boot's encoded configuration, or for a restore the same made to
/// restore the checkpoint: it runs only if its devices are the checkpoint's,
/// with the checkpoint's identity and saved state, and only on a helper with
/// the control channel.
fn restoring(
    configuration: Vec<u8>,
    restore_input: Option<&checkpoint::RestoreInput>,
    checkpointing: Option<&mut crate::vz::Checkpointing>,
) -> Result<Vec<u8>, RunnerError> {
    match (restore_input, checkpointing) {
        (None, _) => Ok(configuration),
        (Some(_), None) => Err(RunnerError::Checkpoint(
            "this VM's helper cannot restore a VM checkpoint",
        )),
        (Some(input), Some(checkpointing)) => checkpointing.restoring(
            checkpoint::restore_configuration(&input.captured, &configuration, &input.state)?,
        ),
    }
}

/// The VM's direct shares for the helper. As Linux does before starting
/// virtiofsd, each must be the admitted directory once more; the helper
/// checks it again before and after VM start.
fn admitted_shares(shares: &[PreparedDirectShare]) -> Result<Vec<crate::vz::VzShare>, RunnerError> {
    shares
        .iter()
        .map(|share| {
            let current = share
                .request
                .reopen(&[])
                .map_err(|_| RunnerError::DirectShareChanged)?;
            if current.identity() != share.admitted.identity()
                || current.path() != share.admitted.path()
            {
                return Err(RunnerError::DirectShareChanged);
            }
            Ok(crate::vz::VzShare::new(
                share.request.mount.tag(),
                share.admitted.path(),
                share.request.mount.read_only(),
                share.admitted.identity(),
            ))
        })
        .collect()
}
