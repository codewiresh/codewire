//! Sleep for a running VM (#5484, #6647, `docs/dev/SANDBOX-SLEEP.md`): a
//! lasting pause with the workload frozen, and a hibernate that writes the
//! VM's memory and device state and ends the VMM, copying no disk, so the
//! next boot on the same disks restores it. A child of `runner::checkpoint`.

use super::*;

/// What a hibernate left: its VMM files in `checkpoints/in`, and the restore
/// that repeats its boot exactly.
#[derive(Debug, Clone)]
pub struct Hibernation {
    pub restore: RestoreBoot,
    pub timings: CaptureTimings,
}

impl RunningVm {
    /// Freeze the workload and pause the VM until [`Self::resume_suspended`].
    /// On a failed pause the workload is thawed again.
    pub async fn suspend(
        &mut self,
        operation_id: Uuid,
        abi: u32,
    ) -> Result<CaptureTimings, RunnerError> {
        if !matches!(self.try_exit()?, ExitClass::StillRunning) {
            return Err(RunnerError::Checkpoint("the VM is not running"));
        }
        let mut timings = CaptureTimings::default();
        let started = Instant::now();
        let freeze = self
            .hook(CheckpointAction::Freeze, operation_id, abi)
            .await?;
        if freeze.status != CheckpointStatus::Done {
            return Err(RunnerError::Checkpoint(
                "the guest could not freeze its workload; a process may be stuck in I/O, so try again",
            ));
        }
        timings.guest_freeze = Duration::from_micros(freeze.elapsed_us);
        if let Err(error) = self.api.pause().await {
            // Best effort: the pause is what failed, and the caller gets it.
            let _ = self.hook(CheckpointAction::Thaw, operation_id, abi).await;
            return Err(error.into());
        }
        timings.workload_frozen = started.elapsed();
        Ok(timings)
    }

    /// Resume a VM [`Self::suspend`] paused and thaw its workload.
    pub async fn resume_suspended(
        &mut self,
        operation_id: Uuid,
        abi: u32,
    ) -> Result<(), RunnerError> {
        self.api.resume().await?;
        let thawed = self.hook(CheckpointAction::Thaw, operation_id, abi).await?;
        if thawed.status != CheckpointStatus::Done {
            return Err(RunnerError::Checkpoint(
                "the guest did not thaw its workload after the suspend",
            ));
        }
        Ok(())
    }

    /// Freeze, pause and write the VMM's state into `vmm`. On failure the VM
    /// is resumed and thawed again.
    async fn pause_and_snapshot(
        &mut self,
        vmm: &Path,
        operation_id: Uuid,
        abi: u32,
    ) -> Result<CaptureTimings, RunnerError> {
        let mut timings = self.suspend(operation_id, abi).await?;
        let paused = Instant::now();
        let written = self
            .api
            .snapshot(vmm, snapshot_timeout(self.request.memory_mib))
            .await;
        timings.memory_write = paused.elapsed();
        timings.vm_paused = timings.memory_write;
        if let Err(error) = written {
            // Best effort: the snapshot is what failed, and the caller gets it.
            let _ = self.resume_suspended(operation_id, abi).await;
            return Err(error.into());
        }
        Ok(timings)
    }
    /// Snapshot a VM that [`Self::suspend`] already froze and paused. On
    /// failure the VM remains suspended rather than waking.
    async fn snapshot_already_suspended(
        &mut self,
        vmm: &Path,
    ) -> Result<CaptureTimings, RunnerError> {
        let paused = Instant::now();
        self.api
            .snapshot(vmm, snapshot_timeout(self.request.memory_mib))
            .await?;
        let memory_write = paused.elapsed();
        Ok(CaptureTimings {
            memory_write,
            vm_paused: memory_write,
            ..CaptureTimings::default()
        })
    }
}

impl CloudHypervisorRunner {
    /// Hibernate `running`: freeze its workload, pause it, have the VMM write
    /// its memory and device state, and end the VMM without a guest poweroff.
    /// The disks stay where they are, exactly as the memory saw them, so
    /// nothing is copied and no reflink is needed. The VMM files end in
    /// `checkpoints/in`, where the runner's restore reads them.
    ///
    /// The caller records the returned restore outside the VM's checkpoint
    /// directory, which the VMM writes, and restores from it once
    /// (`docs/dev/SANDBOX-SLEEP.md`, "After a restore"); a later boot that is
    /// not that restore removes the files. On any failure before the VMM
    /// ends, the VM runs on, thawed, and nothing is left.
    pub async fn hibernate(
        &self,
        running: &mut RunningVm,
        operation_id: Uuid,
    ) -> Result<Hibernation, RunnerError> {
        self.hibernate_with_state(running, operation_id, false)
            .await
    }

    /// Hibernate a VM that is either running (`already_suspended == false`) or
    /// already frozen and paused (`already_suspended == true`).
    pub async fn hibernate_with_state(
        &self,
        running: &mut RunningVm,
        operation_id: Uuid,
        already_suspended: bool,
    ) -> Result<Hibernation, RunnerError> {
        if !matches!(running.try_exit()?, ExitClass::StillRunning) {
            return Err(RunnerError::Checkpoint("the VM is not running"));
        }
        let abi = self.guest_checkpoint_request_abi()?;
        let checkpoints = PrivateRoot::open(&running.paths.checkpoints_dir)?;
        for name in checkpoint_tree_names(&checkpoints)? {
            remove_checkpoint_tree(&checkpoints, &name)?;
        }
        let out_name = format!("{CHECKPOINT_OUT_PREFIX}{operation_id}");
        let out = checkpoints.create_dir(Path::new(&out_name), 0o700)?;
        let vmm = PrivateRoot::open(&out)?.create_dir(Path::new("vmm"), 0o700)?;
        let captured = if already_suspended {
            running.snapshot_already_suspended(&vmm).await
        } else {
            running.pause_and_snapshot(&vmm, operation_id, abi).await
        };
        let mut timings = match captured {
            Ok(timings) => timings,
            Err(error) => {
                // Best effort: the VM stays in its previous state, and the next
                // capture or boot removes a tree left here.
                let _ = remove_checkpoint_tree(&checkpoints, &out_name);
                return Err(error);
            }
        };
        let stopping = Instant::now();
        running.stop_discarding_guest_state().await?;
        timings.vm_paused += stopping.elapsed();
        let memory_bytes = seal_vmm_files(&vmm, running.request.memory_mib)?;
        PrivateRoot::open(&out)?.move_private_directory_to(
            Path::new("vmm"),
            &checkpoints,
            Path::new(CHECKPOINT_IN),
        )?;
        remove_checkpoint_tree(&checkpoints, &out_name)?;
        let input = checkpoints.path().join(CHECKPOINT_IN);
        let setup_disk_bytes = running
            .setup_disk
            .as_ref()
            .map(|setup| setup.file.size)
            .or_else(|| {
                running
                    .request
                    .checkpoint
                    .as_ref()
                    .and_then(|checkpoint| checkpoint.setup_disk_bytes)
            });
        let restore = build_hibernate_restore(
            &input,
            &running.request,
            operation_id,
            memory_bytes,
            setup_disk_bytes,
            running.docker_disk.is_some(),
            self.vmm_identity().1,
        )?;
        Ok(Hibernation { restore, timings })
    }
}

fn build_hibernate_restore(
    input: &Path,
    request: &CreateVmRequest,
    operation_id: Uuid,
    memory_bytes: u64,
    setup_disk_bytes: Option<u64>,
    docker: bool,
    vmm_sha256: String,
) -> Result<RestoreBoot, RunnerError> {
    let digest = |name: &str| -> Result<String, RunnerError> {
        let path = input.join(name);
        let bytes = std::fs::read(&path).map_err(|source| PathError::Io { path, source })?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    };
    Ok(RestoreBoot {
        checkpoint_id: operation_id,
        source_environment_id: request.vm_id,
        config_sha256: digest("config.json")?,
        state_sha256: digest("state.json")?,
        memory_bytes,
        setup_disk_bytes,
        vmm_sha256,
        source_generation: request.generation,
        skill_snapshot_sha256: request.skill_snapshot_sha256,
        environment_projection_sha256: request.environment_projection_sha256,
        managed_credential_clients: request.managed_credential_clients,
        docker,
        cw_runtime_catalog_generation: request.cw_runtime_catalog_generation.clone(),
        daemon_vsock_port: request.daemon_vsock_port,
        intercept: !request.intercepts.is_empty(),
        image_disk: request.image_disk.as_ref().map(CheckpointImageDisk::from),
        bound_secrets: request.bound_secrets.clone(),
        state_identity: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_vmm_files_sets_readonly_and_measures_memory_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let vmm = dir.path().join("vmm");
        std::fs::create_dir(&vmm).unwrap();
        std::fs::write(vmm.join("config.json"), b"{\"ok\":true}").unwrap();
        std::fs::write(vmm.join("state.json"), b"{\"state\":1}").unwrap();
        std::fs::write(vmm.join("memory-ranges"), vec![0x5a_u8; 4096]).unwrap();

        let bytes = seal_vmm_files(&vmm, 512).unwrap();
        assert_eq!(bytes, 4096);
        for name in CHECKPOINT_VMM_FILES {
            let mode = std::fs::metadata(vmm.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o400, "{name} mode was {mode:o}");
        }

        // Missing any required VMM file fails sealing cleanly.
        let incomplete = dir.path().join("incomplete");
        std::fs::create_dir(&incomplete).unwrap();
        std::fs::write(incomplete.join("config.json"), b"{}").unwrap();
        assert!(seal_vmm_files(&incomplete, 512).is_err());
    }

    #[test]
    fn build_hibernate_restore_binds_vmm_digests_and_image_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), b"config-bytes").unwrap();
        std::fs::write(dir.path().join("state.json"), b"state-bytes").unwrap();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let image_disk_id = "a".repeat(64);
        let build_id = "b".repeat(32);
        let request = CreateVmRequest {
            vm_id,
            generation: 7,
            vsock_cid: 11,
            daemon_vsock_port: 7777,
            state_disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: Some(crate::state::MINIMUM_DOCKER_DISK_BYTES),
            root_generation: "c".repeat(64),
            root_disk_bytes: crate::runner::MINIMUM_ROOT_DISK_BYTES,
            vcpus: 2,
            memory_mib: 1024,
            setup: None,
            host_ports: Vec::new(),
            mesh: None,
            direct_shares: Vec::new(),
            skill_snapshot_sha256: None,
            environment_projection_sha256: None,
            managed_credential_clients: Default::default(),
            cw_runtime_catalog_generation: Some("d".repeat(64)),
            cw_runtime_moved_from_generation: None,
            image_disk: Some(ImageDiskAttachment::Published {
                directory: PathBuf::from("/image"),
                image_disk_id: image_disk_id.clone(),
                build_id: build_id.clone(),
            }),
            network_policy: codewire_egress_policy::CompiledPolicy::locked(),
            udp_peers: Vec::new(),
            intercepts: Default::default(),
            credential_placeholders: Default::default(),
            bound_secrets: None,
            checkpoint: None,
        };
        let restore = build_hibernate_restore(
            dir.path(),
            &request,
            operation_id,
            8192,
            None,
            true,
            "e".repeat(64),
        )
        .unwrap();
        assert_eq!(restore.checkpoint_id, operation_id);
        assert_eq!(restore.source_environment_id, vm_id);
        assert_eq!(restore.source_generation, 7);
        assert_eq!(restore.memory_bytes, 8192);
        assert_eq!(
            restore.config_sha256,
            format!("{:x}", Sha256::digest(b"config-bytes"))
        );
        assert_eq!(
            restore.state_sha256,
            format!("{:x}", Sha256::digest(b"state-bytes"))
        );
        assert_eq!(restore.vmm_sha256, "e".repeat(64));
        assert!(restore.docker);
        assert_eq!(
            restore.image_disk,
            Some(CheckpointImageDisk {
                image_disk_id,
                build_id,
            })
        );
        assert!(restore.state_identity.is_none());
    }
}
