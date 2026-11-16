//! Darwin's launch: the signed Virtualization.framework helper as the VM's
//! VMM, apart from `runner.rs` so the schema 3 setup (#4654) grows neither.

use super::*;

impl CloudHypervisorRunner {
    /// Launch the signed Virtualization.framework helper as this VM's VMM.
    /// The helper inherits the open `vm.lock`, and stops its VM when this
    /// runner exits. Readiness is its hybrid-vsock socket plus a live helper.
    pub(super) async fn launch(&self, prepared: PreparedVm) -> Result<RunningVm, RunnerError> {
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
                setup: prepared
                    .setup_disk
                    .as_ref()
                    .map(|setup| setup.path.as_path()),
                cw_runtime: prepared
                    .cw_runtime_disk
                    .as_ref()
                    .map(|disk| disk.path.as_path()),
            },
            admitted_shares(&prepared.direct_shares)?,
            &prepared.paths.vsock_socket,
        );
        let executable = self.artifacts.vz_runner.path();
        // A schema 3 helper also gets the control channel and the checkpoint
        // files (#4654).
        let (configuration, checkpointing) = crate::vz::Checkpointing::configure(
            &self.vz_protocol,
            executable,
            &prepared.paths,
            configuration,
        )
        .await?;
        prepared.paths.open_vm_root()?.atomic_replace(
            Path::new(crate::vz::CONFIG_NAME),
            &configuration.encode()?,
            0o600,
        )?;
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
            Ok::<_, RunnerError>(hybrid)
        }
        .await;
        let hybrid = match finalized {
            Ok(hybrid) => hybrid,
            Err(error) => {
                startup.terminate_admitted().await?;
                return Err(error);
            }
        };
        let control = match started {
            Some(started) => Some(started.keep_identifier(&prepared.paths.vm_dir).await),
            None => None,
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
            _control: control,
            _lock: prepared.lock,
        })
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
