use std::time::Instant;

use super::super::snapshots::{
    CAPTURE_STAGING_PREFIX, InFlight, delete_ready, find_ready, list_ready, now_unix_ms, publish,
    remove_snapshot_tree, settle, snapshot_proto, snapshots_root, store, store_status,
};
use super::*;
use crate::state::{CHECKPOINT_OUT_PREFIX, CHECKPOINT_VMM_FILES, CHECKPOINTS_DIRECTORY};

mod host;
mod proto;
use host::{CLONING_FILESYSTEMS, pinned_vmm, require_same_host, synced_store_warning};
pub(in crate::supervisor) use host::{host_identity, read_vmm_files};
pub(in crate::supervisor) use proto::{checkpoint_proto, earlier_runtime, unrestorable_after_move};

/// The seed bindings a runner reports for the boot it captured; an empty
/// field is unset.
fn boot_bindings(boot: &v1::CheckpointBootBindings) -> BootBindings {
    let optional = |value: &str| (!value.is_empty()).then(|| value.to_owned());
    BootBindings {
        skill_snapshot_sha256: optional(&boot.skill_snapshot_sha256),
        environment_projection_sha256: optional(&boot.environment_projection_sha256),
        managed_credential_clients: boot.managed_credential_clients.clone(),
        docker: boot.docker,
        cw_runtime_catalog_generation: optional(&boot.cw_runtime_catalog_generation),
        daemon_vsock_port: boot.daemon_vsock_port,
        intercept: boot.intercept,
    }
}

fn status(error: SupervisorError) -> Status {
    Status::from(error)
}

pub(super) async fn capture(
    supervisor: &Supervisor,
    request: v1::CreateCheckpointRequest,
) -> Result<v1::Checkpoint, Status> {
    let started = Instant::now();
    let environment_name = request.environment.clone();
    let name = checkpoint_name(&environment_name, &request.name)?;
    let account = PlatformAccount::from_proto(request.account.as_ref())?;
    let settling = supervisor.config.clone();
    let store = tokio::task::spawn_blocking(move || {
        let store = store(&settling)?;
        settle(&settling, &store)?;
        Ok::<_, SupervisorError>(store)
    })
    .await
    .map_err(|_| Status::internal("snapshot reconciliation task failed"))?
    .map_err(status)?;
    store.require_free(&name).map_err(store_status)?;
    // The name lease for the whole capture: no operation of the source
    // runs until it ends.
    let _lease = supervisor
        .quiet_lease(&environment_name)
        .await
        .map_err(status)?;
    let environment = admit_source(supervisor, &environment_name)?;
    if store
        .checkpoint_count(environment.id)
        .map_err(store_status)?
        >= MAX_CHECKPOINTS_PER_ENVIRONMENT
    {
        return Err(Status::resource_exhausted(format!(
            "{environment_name} already has {MAX_CHECKPOINTS_PER_ENVIRONMENT} VM checkpoints; remove one first (`cw checkpoint rm NAME`)"
        )));
    }
    let artifact_generation = artifact_generation_for_boot(&environment, false)
        .map_err(status)?
        .to_owned();
    let engine = PrivateRoot::open(&supervisor.config.engine_root())
        .map_err(|error| status(SupervisorError::from(error)))?;
    RuntimeArtifactStore::create(&engine)
        .map_err(artifact_store_error)
        .map_err(status)?
        .open_generation(&artifact_generation)
        .await
        .map_err(artifact_store_error)
        .map_err(status)?
        .require_guest_checkpoint_abi()
        .map_err(|_| {
            Status::failed_precondition(format!(
                "{environment_name} runs a guest without VM checkpoints; restart it once (`cw restart {environment_name}`) to enable them"
            ))
        })?;
    let space = supervisor.config.clone();
    let memory_bytes = u64::from(environment.memory_mib) * MIB;
    let synced = tokio::task::spawn_blocking(move || require_capture_space(&space, memory_bytes))
        .await
        .map_err(|_| Status::internal("VM checkpoint space check failed"))??;

    let operation_id = Uuid::new_v4();
    let checkpoint_id = Uuid::new_v4();
    let staging_name = format!("{CAPTURE_STAGING_PREFIX}{operation_id}");
    let _staging_in_flight = InFlight::new(staging_name.clone());
    let _checkpoint_in_flight = InFlight::new(checkpoint_id.to_string());
    let mut runner = supervisor
        .runner_client_for_artifact(&environment_name, &artifact_generation)
        .await
        .map_err(status)?;
    let captured = runner
        .checkpoint_vm(environment.id, environment.generation, operation_id)
        .await?;
    let config = supervisor.config.clone();
    let admitted = {
        let environment = environment.clone();
        let captured = captured.clone();
        let staging_name = staging_name.clone();
        tokio::task::spawn_blocking(move || {
            admit_capture(
                &config,
                &environment,
                operation_id,
                &captured,
                &staging_name,
            )
        })
        .await
        .map_err(|_| Status::internal("VM checkpoint admission task failed"))??
    };
    let mut cleanup = StagingCleanup(Some(
        snapshots_root(&supervisor.config.engine_root())
            .map_err(status)?
            .path()
            .join(&staging_name),
    ));
    let proto = supervisor
        .core()
        .environment_proto(&environment_name)
        .map_err(status)?;
    let discriminators = supervisor
        .core()
        .store
        .direct_share_discriminators(environment.id)
        .map_err(SupervisorError::from)
        .map_err(status)?;
    let boot = captured
        .boot
        .as_ref()
        .ok_or_else(|| Status::internal("the runner reported no boot bindings"))?;
    let optional = |value: &str| (!value.is_empty()).then(|| value.to_owned());
    let timings = captured.timings.unwrap_or_default();
    let manifest = Manifest {
        schema_version: super::super::snapshots::CHECKPOINT_MANIFEST_SCHEMA_VERSION,
        kind: "checkpoint".to_owned(),
        id: checkpoint_id,
        name: name.clone(),
        created_unix_ms: now_unix_ms(),
        source: ManifestSource {
            environment_id: environment.id,
            name: environment.name.clone(),
        },
        consistency: Consistency::Paired,
        locations: vec!["local".to_owned()],
        architecture: environment
            .active_workspace_generation
            .as_ref()
            .map(|generation| generation.image.architecture.as_str().to_owned())
            .ok_or_else(|| status(SupervisorError::InvalidState))?,
        resources: ManifestResources {
            vcpus: environment.vcpus,
            memory_mib: environment.memory_mib,
            disk_bytes: environment.disk_bytes,
            docker_disk_bytes: environment.docker_disk_bytes,
        },
        disks: admitted.disks,
        project_spec_json: String::from_utf8(
            environment
                .project_spec_json
                .clone()
                .ok_or_else(|| status(SupervisorError::InvalidState))?,
        )
        .map_err(|_| status(SupervisorError::InvalidState))?,
        project_spec_sha256: environment
            .project_spec_sha256
            .clone()
            .ok_or_else(|| status(SupervisorError::InvalidState))?,
        workspace_plan: environment.workspace_plan.clone(),
        root_generation: environment
            .active_workspace_generation
            .clone()
            .ok_or_else(|| status(SupervisorError::InvalidState))?,
        direct_share_discriminators: discriminators.encode(),
        source_inputs: super::super::snapshots::source_inputs(&environment).map_err(status)?,
        recorded: RecordedAuthority {
            platform_source_authority: environment.platform_source_authority.clone(),
            access_profile_reference: proto.access_profile.clone(),
            cw_runtime_catalog_generation: optional(&boot.cw_runtime_catalog_generation),
            host_ports: environment.host_ports.clone(),
            mesh: environment.mesh.clone(),
            network_policy: proto
                .network_policy
                .as_ref()
                .map(|policy| policy.reference.clone())
                .unwrap_or_default(),
        },
        platform_account: account,
        removed_logins: 0,
        capture_milliseconds: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        checkpoint: Some(CheckpointManifest {
            source_generation: environment.generation,
            vsock_cid: captured.vsock_cid,
            vmm: VmmPin {
                version: captured.vmm_version.clone(),
                sha256: captured.vmm_sha256.clone(),
            },
            guest_checkpoint_abi: captured.guest_checkpoint_abi,
            host: host_identity(),
            memory_bytes: admitted.memory_bytes,
            config_sha256: admitted.config_sha256,
            state_sha256: admitted.state_sha256,
            setup_disk_bytes: (captured.setup_disk_bytes != 0).then_some(captured.setup_disk_bytes),
            boot: boot_bindings(boot),
            timings: Timings {
                guest_freeze_us: timings.guest_freeze_us,
                workload_frozen_us: timings.workload_frozen_us,
                vm_paused_us: timings.vm_paused_us,
                memory_write_us: timings.memory_write_us,
                disk_clone_us: timings.disk_clone_us,
                total_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            },
        }),
    };
    let row = publish(
        &supervisor.config,
        &store,
        staging_name,
        &manifest,
        &mut || cleanup.0 = None,
    )
    .await?;
    let mut proto = checkpoint_proto(&supervisor.config.engine_root(), &row, &manifest, true)
        .map_err(status)?;
    proto.warnings.extend(synced);
    if captured.resume_failed {
        proto.warnings.push(format!(
            "the VM checkpoint is complete, but {environment_name} did not resume; restore it with `cw checkpoint restore {}`",
            row.name
        ));
    }
    Ok(proto)
}

/// The new checkpoint's name: the one asked for, or `ENV-<UTC time>`, as
/// environment names are spelled and never a UUID, which names one by id.
fn checkpoint_name(environment: &str, requested: &str) -> Result<String, Status> {
    if !valid_environment_name(environment) {
        return Err(Status::invalid_argument(
            "name the running environment to checkpoint",
        ));
    }
    let name = if requested.is_empty() {
        default_name(environment, now_unix_ms() / 1000)
    } else {
        requested.to_owned()
    };
    if !valid_environment_name(&name) {
        return Err(Status::invalid_argument(
            "a VM checkpoint name is 1 to 63 letters, digits, `-`, `_` or `.`, starting with a letter or digit",
        ));
    }
    if Uuid::parse_str(&name).is_ok() {
        return Err(Status::invalid_argument(
            "a VM checkpoint name cannot be a UUID, which names it by id; choose another name",
        ));
    }
    Ok(name)
}

/// `RestoreCheckpoint`: every refusable check, then a Start operation
/// whose payload names the checkpoint. The source must be stopped.
/// Everything a restore requires of a VM checkpoint and its source,
/// other than the source being stopped: the same workspace, resources,
/// host, platform account, runtime and VMM build, and stored
/// files that still match the manifest. A restore runs it, and so does a
/// Stop for a restore before it discards the guest's state (#3046).
#[allow(clippy::too_many_arguments)]
async fn admit_restorable(
    supervisor: &Supervisor,
    name: &str,
    environment: &EnvironmentRecord,
    row: &crate::snapshot_store::SnapshotRow,
    manifest: &Manifest,
    checkpoint: &CheckpointManifest,
    account: Option<&v1::PlatformAccount>,
) -> Result<(), Status> {
    // The checkpoint itself first: intact stored files, or nothing else
    // about it matters.
    let config = supervisor.config.clone();
    let (row_id, row_name, stored_manifest, stored_checkpoint) = (
        row.id,
        row.name.clone(),
        manifest.clone(),
        checkpoint.clone(),
    );
    tokio::task::spawn_blocking(move || {
        stored_files_intact(&config, row_id, &stored_manifest, &stored_checkpoint)
    })
        .await
        .map_err(|_| Status::internal("VM checkpoint check task failed"))?
        .map_err(|_| {
            Status::failed_precondition(format!(
                "VM checkpoint {row_name} is damaged: its stored files no longer match its manifest; it cannot be restored"
            ))
        })?;
    if let Some(reason) = earlier_runtime(&supervisor.config.engine_root(), manifest) {
        return Err(Status::failed_precondition(format!(
            "VM checkpoint {} cannot be restored: {reason}",
            row.name
        )));
    }
    let fork = || {
        format!(
            "fork it instead: `cw create --local --checkpoint {}`",
            row.name
        )
    };
    let artifact_generation = manifest
        .root_generation
        .artifact_generation()
        .map_err(|error| status(error.into()))?
        .to_owned();
    if environment.active_workspace_generation.as_ref() != Some(&manifest.root_generation)
        || environment.active_artifact_generation.as_deref() != Some(artifact_generation.as_str())
        || environment.staging_workspace_generation.is_some()
        || environment.staging_artifact_generation.is_some()
        || environment.workspace_plan != manifest.workspace_plan
        || environment.vcpus != manifest.resources.vcpus
        || environment.memory_mib != manifest.resources.memory_mib
        || environment.disk_bytes != manifest.resources.disk_bytes
        || environment.docker_disk_bytes != manifest.resources.docker_disk_bytes
    {
        return Err(Status::failed_precondition(format!(
            "{name}'s workspace, runtime or resources changed since VM checkpoint {}; {}",
            row.name,
            fork()
        )));
    }
    require_same_host(&row.name, &checkpoint.host)?;
    let fresh = PlatformAccount::from_proto(account)?;
    if let (Some(recorded), Some(fresh)) = (manifest.platform_account.as_ref(), fresh.as_ref())
        && recorded != fresh
    {
        return Err(Status::permission_denied(format!(
            "VM checkpoint {} was captured while signed in to another platform account; sign in as that account (`cw login`) to restore it",
            row.name
        )));
    }
    let engine = PrivateRoot::open(&supervisor.config.engine_root())
        .map_err(|error| status(SupervisorError::from(error)))?;
    let artifacts = RuntimeArtifactStore::create(&engine)
        .map_err(artifact_store_error)
        .map_err(status)?
        .open_generation(&artifact_generation)
        .await
        .map_err(|_| {
            Status::failed_precondition(format!(
                "VM checkpoint {} is unrestorable: the runtime it was taken with is gone",
                row.name
            ))
        })?;
    let (vmm_sha256, vmm_name) = pinned_vmm(&artifacts);
    if vmm_sha256 != checkpoint.vmm.sha256 {
        return Err(Status::failed_precondition(format!(
            "VM checkpoint {} is unrestorable: its {vmm_name} changed",
            row.name
        )));
    }
    artifacts.require_guest_checkpoint_abi().map_err(|_| {
        Status::failed_precondition(format!(
            "VM checkpoint {}'s guest has no checkpoint hook",
            row.name
        ))
    })?;
    Ok(())
}

/// The checkpoint's stored VMM files hash to the recorded digests, its
/// memory is the recorded size, and each stored disk keeps its recorded
/// size and filesystem.
pub(in crate::supervisor) fn stored_files_intact(
    config: &NativeRuntimeConfig,
    checkpoint_id: Uuid,
    manifest: &Manifest,
    checkpoint: &CheckpointManifest,
) -> Result<(), SupervisorError> {
    let snapshots = snapshots_root(&config.engine_root())?;
    let source = snapshots.open_private_directory(Path::new(&checkpoint_id.to_string()), 0o700)?;
    if !checkpoint.files_match(source.path()) {
        return Err(SupervisorError::InvalidState);
    }
    let storage = manifest.storage_generation()?;
    for disk in &manifest.disks {
        let stored = match disk.role {
            DiskRole::State => PathBuf::from("disks/state.raw"),
            DiskRole::Docker => PathBuf::from("disks/docker.raw"),
            DiskRole::Root => Path::new("root").join(&storage).join("root.raw"),
        };
        let identity = crate::state::StateDiskIdentity::capture(&source.path().join(stored))?;
        if identity.file.size != disk.bytes || identity.filesystem_uuid != disk.filesystem_uuid {
            return Err(SupervisorError::InvalidState);
        }
    }
    Ok(())
}

/// Stop a VM checkpoint's running source for a restore of it: a Stop
/// that discards the guest's state instead of powering it off. It is
/// admitted only after every check the restore makes, so that a restore
/// after it fails only where one after a graceful stop would (#3046).
pub(super) async fn stop_for_restore(
    rpc: &SupervisorRpc,
    request: v1::StopForRestoreRequest,
) -> Result<v1::Operation, Status> {
    let supervisor = &rpc.supervisor;
    let request_id = Uuid::parse_str(&request.request_id)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| Status::invalid_argument("a stop for a restore needs a request id"))?;
    let config = supervisor.config.clone();
    let selector = request.checkpoint.clone();
    let (row, manifest) = tokio::task::spawn_blocking(move || find_ready(&config, &selector, true))
        .await
        .map_err(|_| Status::internal("VM checkpoint lookup task failed"))??;
    let checkpoint = manifest
        .checkpoint
        .clone()
        .ok_or_else(|| status(SupervisorError::InvalidState))?;
    let name = supervisor
        .core()
        .state
        .environments
        .values()
        .find(|environment| environment.id == manifest.source.environment_id)
        .map(|environment| environment.name.clone())
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "VM checkpoint {}'s environment {} no longer exists",
                row.name, manifest.source.name
            ))
        })?;
    let lease = supervisor.quiet_lease(&name).await.map_err(status)?;
    supervisor.reconcile(&name).await.map_err(status)?;
    let environment = supervisor.environment(&name).map_err(status)?;
    if environment.state != StoredEnvironmentState::Running {
        return Err(Status::failed_precondition(format!(
            "{name} is {}, not running; restore it without stopping it",
            environment.state.as_str()
        )));
    }
    admit_restorable(
        supervisor,
        &name,
        &environment,
        &row,
        &manifest,
        &checkpoint,
        request.account.as_ref(),
    )
    .await?;
    let payload = serde_json::json!({
        "name": name,
        "discard_for_checkpoint": row.id.to_string(),
    });
    let recorded = supervisor
        .core()
        .store
        .operation_by_request(request_id)
        .map_err(SupervisorError::from)
        .map_err(status)?;
    let operation = match recorded {
        Some(operation) if operation.payload == payload => operation,
        Some(_) => return Err(Status::aborted("local lifecycle request ID collision")),
        None => supervisor
            .core()
            .store
            .begin_operation(
                request_id,
                Some(environment.id),
                OperationKind::Stop,
                &payload,
            )
            .map_err(SupervisorError::from)
            .map_err(status)?,
    };
    let response = operation_proto(&operation)?;
    if !operation.phase.terminal() {
        supervisor.admit(&operation);
    }
    drop(lease);
    if !operation.phase.terminal() {
        rpc.spawn_drain(&name);
    }
    Ok(response)
}

pub(super) async fn restore(
    rpc: &SupervisorRpc,
    request: v1::RestoreCheckpointRequest,
) -> Result<v1::Operation, Status> {
    let supervisor = &rpc.supervisor;
    let request_id = Uuid::parse_str(&request.request_id)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| Status::invalid_argument("a restore needs a request id"))?;
    let config = supervisor.config.clone();
    let selector = request.checkpoint.clone();
    let (row, manifest) = tokio::task::spawn_blocking(move || find_ready(&config, &selector, true))
        .await
        .map_err(|_| Status::internal("VM checkpoint lookup task failed"))??;
    let checkpoint = manifest
        .checkpoint
        .clone()
        .ok_or_else(|| status(SupervisorError::InvalidState))?;
    let name = supervisor
        .core()
        .state
        .environments
        .values()
        .find(|environment| environment.id == manifest.source.environment_id)
        .map(|environment| environment.name.clone())
        .ok_or_else(|| {
            Status::failed_precondition(format!(
                "VM checkpoint {}'s environment {} no longer exists",
                row.name, manifest.source.name
            ))
        })?;
    let lease = supervisor.quiet_lease(&name).await.map_err(status)?;
    supervisor.reconcile(&name).await.map_err(status)?;
    let environment = supervisor.environment(&name).map_err(status)?;
    if environment.state != StoredEnvironmentState::Stopped {
        return Err(Status::failed_precondition(format!(
            "{name} is {}; stop it first (`cw stop {name}`), or let `cw checkpoint restore` stop it",
            environment.state.as_str()
        )));
    }
    admit_restorable(
        supervisor,
        &name,
        &environment,
        &row,
        &manifest,
        &checkpoint,
        request.account.as_ref(),
    )
    .await?;
    let generation = environment
        .generation
        .checked_add(1)
        .ok_or_else(|| Status::internal("local generation overflow"))?;
    let payload = serde_json::json!({
        "name": name,
        "generation": generation,
        "checkpoint": row.id.to_string(),
    });
    // Bind the lookup first: a `match` on `core()` would hold the core
    // lock through its arms, and `None` takes it again.
    let recorded = supervisor
        .core()
        .store
        .operation_by_request(request_id)
        .map_err(SupervisorError::from)
        .map_err(status)?;
    let operation = match recorded {
        Some(operation) if operation.payload == payload => operation,
        Some(_) => return Err(Status::aborted("local lifecycle request ID collision")),
        None => supervisor
            .core()
            .store
            .begin_operation(
                request_id,
                Some(environment.id),
                OperationKind::Start,
                &payload,
            )
            .map_err(SupervisorError::from)
            .map_err(status)?,
    };
    let response = operation_proto(&operation)?;
    if !operation.phase.terminal() {
        supervisor.admit(&operation);
    }
    drop(lease);
    if !operation.phase.terminal() {
        rpc.spawn_drain(&name);
    }
    Ok(response)
}

/// Place VM checkpoint `checkpoint_id` for its stopped source: its disks
/// over the environment's, its VMM files in `checkpoints/in`, and the
/// persisted VM state's disk identities updated to them. Under the VM's
/// lock with its VMM proven dead, and the checkpoint's shared lock, so
/// the checkpoint is not removed meanwhile. A replay places it again.
pub(super) fn place(
    config: &NativeRuntimeConfig,
    environment: &EnvironmentRecord,
    checkpoint_id: Uuid,
    operation_id: Uuid,
) -> Result<(), SupervisorError> {
    let engine_root = config.engine_root();
    let engine = PrivateRoot::open(&engine_root)?;
    let paths = VmPaths::create(&engine, environment.id)?;
    let _lock = paths.lock().map_err(|_| SupervisorError::InvalidState)?;
    super::super::snapshots::require_vmm_dead(&paths, environment.id)
        .map_err(|_| SupervisorError::InvalidState)?;
    let snapshots = snapshots_root(&engine_root)?;
    let source = snapshots.open_private_directory(Path::new(&checkpoint_id.to_string()), 0o700)?;
    let held = fs::File::open(source.path()).map_err(|error| SupervisorError::Io {
        path: source.path().to_owned(),
        source: error,
    })?;
    let held =
        crate::state::HeldFlock::try_lock(held, rustix::fs::FlockOperation::NonBlockingLockShared)
            .map_err(|_| SupervisorError::InvalidState)?;
    let (_, manifest) = find_ready(config, &checkpoint_id.to_string(), true)
        .map_err(|_| SupervisorError::NotFound(checkpoint_id.to_string()))?;
    if manifest.source.environment_id != environment.id {
        return Err(SupervisorError::InvalidState);
    }
    let storage = manifest.storage_generation()?;
    let checkpoints = PrivateRoot::open(&paths.checkpoints_dir)?;
    for name in crate::state::checkpoint_tree_names(&checkpoints)? {
        crate::state::remove_checkpoint_tree(&checkpoints, &name)?;
    }
    let out_name = format!("{CHECKPOINT_OUT_PREFIX}{operation_id}");
    let out_path = checkpoints.create_dir(Path::new(&out_name), 0o700)?;
    let result = (|| {
        let out = PrivateRoot::open(&out_path)?;
        out.create_dir(Path::new("vmm"), 0o700)?;
        out.create_dir(Path::new("disks"), 0o700)?;
        PrivateRoot::open(&out.create_dir(Path::new("root"), 0o700)?)?
            .create_dir(Path::new(&storage), 0o700)?;
        for name in CHECKPOINT_VMM_FILES {
            let relative = format!("vmm/{name}");
            clone_file(
                &source.path().join(&relative),
                &out_path.join(&relative),
                0o400,
            )?;
        }
        let mut disks = vec![("disks/state.raw", paths.state_disk.clone())];
        if environment.docker_disk_bytes != 0 {
            disks.push(("disks/docker.raw", paths.docker_disk.clone()));
        }
        let root = format!("root/{storage}/root.raw");
        let root_target = crate::state::RootGenerationPaths::create(&paths, &storage)?.root_disk;
        disks.push((root.as_str(), root_target));
        for (relative, _) in &disks {
            clone_file(
                &source.path().join(relative),
                &out_path.join(relative),
                0o600,
            )?;
        }
        for disk in &manifest.disks {
            let relative = match disk.role {
                DiskRole::State => "disks/state.raw".to_owned(),
                DiskRole::Docker => "disks/docker.raw".to_owned(),
                DiskRole::Root => root.clone(),
            };
            let identity = crate::state::StateDiskIdentity::capture(&out_path.join(&relative))?;
            if identity.file.size != disk.bytes || identity.filesystem_uuid != disk.filesystem_uuid
            {
                return Err(SupervisorError::InvalidState);
            }
        }
        // The VMM files first: a crash after it leaves an `in` the next
        // boot of any kind removes.
        out.move_private_directory_to(
            Path::new("vmm"),
            &checkpoints,
            Path::new(crate::state::CHECKPOINT_IN),
        )?;
        for (relative, target) in &disks {
            fs::rename(out_path.join(relative), target).map_err(|error| SupervisorError::Io {
                path: target.clone(),
                source: error,
            })?;
            if let Some(parent) = target.parent() {
                fs::File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| SupervisorError::Io {
                        path: parent.to_owned(),
                        source: error,
                    })?;
            }
        }
        // The runner admits disks against the persisted VM state.
        match crate::state::PersistedVmState::read(&paths.state_file) {
            Ok(mut persisted) => {
                persisted.state_disk = crate::state::StateDiskIdentity::capture(&paths.state_disk)?;
                if persisted.docker_disk.is_some() {
                    persisted.docker_disk = Some(crate::state::StateDiskIdentity::capture(
                        &paths.docker_disk,
                    )?);
                }
                if persisted.root_generation.as_deref() == Some(storage.as_str()) {
                    persisted.root_disk = Some(crate::state::StateDiskIdentity::capture(
                        &crate::state::RootGenerationPaths::create(&paths, &storage)?.root_disk,
                    )?);
                }
                persisted.write_atomic(&paths.state_file)?;
            }
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })();
    let _ = crate::state::remove_checkpoint_tree(&checkpoints, &out_name);
    drop(held);
    result
}

/// Clone `source` into the new `destination` with `mode`.
fn clone_file(source: &Path, destination: &Path, mode: u32) -> Result<(), SupervisorError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let io_error = |path: &Path, error: io::Error| SupervisorError::Io {
        path: path.to_owned(),
        source: error,
    };
    let from = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| io_error(source, error))?;
    let to = crate::fs_clone::clone_new(&from, destination)
        .map_err(|error| io_error(destination, error))?;
    to.sync_all()
        .map_err(|error| io_error(destination, error))?;
    to.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| io_error(destination, error))
}

/// Removes a staging tree unless its path was taken.
struct StagingCleanup(Option<PathBuf>);

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = remove_snapshot_tree(&path);
        }
    }
}

/// The running source, with nothing staged and no direct mounts. The
/// caller holds its lease.
fn admit_source(supervisor: &Supervisor, name: &str) -> Result<EnvironmentRecord, Status> {
    let environment = supervisor.environment(name).map_err(|_| {
        Status::not_found(format!(
            "no local environment is named {name}; list them with `cw ls --local`"
        ))
    })?;
    match environment.state {
        StoredEnvironmentState::Running => {}
        StoredEnvironmentState::Stopped => {
            return Err(Status::failed_precondition(format!(
                "{name} is stopped; a VM checkpoint needs it running (`cw start {name}`), or take a disk snapshot of it (`cw snapshot create {name}`)"
            )));
        }
        state => {
            return Err(Status::failed_precondition(format!(
                "{name} is {}; a VM checkpoint needs it running",
                state.as_str()
            )));
        }
    }
    if environment.staging_workspace_generation.is_some()
        || environment.staging_artifact_generation.is_some()
        || environment
            .cw_runtime
            .as_ref()
            .is_some_and(|binding| binding.staging_catalog_generation.is_some())
    {
        return Err(Status::failed_precondition(format!(
            "{name} has an unfinished workspace or runtime change; restart it so it completes (`cw restart {name}`), then checkpoint it"
        )));
    }
    if environment.active_workspace_generation.is_none() || environment.generation == 0 {
        return Err(Status::failed_precondition(format!(
            "{name} has never finished starting"
        )));
    }
    Ok(environment)
}

/// The snapshot store's filesystem shares blocks, holds the memory file,
/// written densely, with room to spare, and is not one a sync service
/// copies off the host; with the warning for one it might.
fn require_capture_space(
    config: &NativeRuntimeConfig,
    memory_bytes: u64,
) -> Result<Option<String>, Status> {
    let synced = synced_store_warning(&config.engine_root())?;
    let snapshots = snapshots_root(&config.engine_root()).map_err(status)?;
    let reflink = crate::fs_clone::reflink_works(snapshots.path())
        .map_err(|error| Status::internal(format!("checking the filesystem failed: {error}")))?;
    if !reflink {
        return Err(Status::failed_precondition(format!(
            "VM checkpoints need a filesystem that shares blocks between files ({CLONING_FILESYSTEMS}) under the local VM state root",
        )));
    }
    let free = crate::fs_clone::free_bytes(snapshots.path())
        .map_err(|error| Status::internal(format!("checking free space failed: {error}")))?;
    let needed = memory_bytes.saturating_add(SPACE_HEADROOM_BYTES);
    if free < needed {
        return Err(Status::resource_exhausted(format!(
            "a VM checkpoint writes the VM's whole memory: it needs {} free and {} are",
            bytes_text(needed),
            bytes_text(free)
        )));
    }
    Ok(synced)
}

fn bytes_text(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// What capture admitted from the runner's tree.
struct Admitted {
    disks: Vec<ManifestDisk>,
    memory_bytes: u64,
    config_sha256: String,
    state_sha256: String,
}

/// Admit `vms/<id>/checkpoints/out-<operation>` as untrusted input, then
/// move it to `snapshots/<staging_name>`: exact names, regular files
/// only, each the size its role has, never following a link.
fn admit_capture(
    config: &NativeRuntimeConfig,
    environment: &EnvironmentRecord,
    operation_id: Uuid,
    captured: &v1::CheckpointVmResponse,
    staging_name: &str,
) -> Result<Admitted, Status> {
    let engine_root = config.engine_root();
    let checkpoints_path = engine_root
        .join("vms")
        .join(environment.id.to_string())
        .join(CHECKPOINTS_DIRECTORY);
    let checkpoints = PrivateRoot::open(&checkpoints_path)
        .map_err(|error| status(SupervisorError::from(error)))?;
    let out_name = format!("{CHECKPOINT_OUT_PREFIX}{operation_id}");
    let result = (|| {
        let out = checkpoints
            .open_private_directory(Path::new(&out_name), 0o700)
            .map_err(SupervisorError::from)?;
        only_entries(out.path(), &["vmm", "disks", "root"])?;
        let root_generation = environment
            .active_workspace_generation
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let storage = workspace_storage_generation(root_generation)?;
        if captured.root_generation != storage {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let memory_bytes = u64::from(environment.memory_mib) * MIB;
        if captured.memory_bytes != memory_bytes {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let files = read_vmm_files(&out.path().join("vmm"), memory_bytes)?;
        let mut disks = vec![admit_disk(
            &out,
            "disks/state.raw",
            DiskRole::State,
            environment.disk_bytes,
        )?];
        let mut names = vec!["state.raw"];
        if environment.docker_disk_bytes != 0 {
            disks.push(admit_disk(
                &out,
                "disks/docker.raw",
                DiskRole::Docker,
                environment.docker_disk_bytes,
            )?);
            names.push("docker.raw");
        }
        only_entries(&out.path().join("disks"), &names)?;
        only_entries(&out.path().join("root"), &[storage.as_str()])?;
        only_entries(&out.path().join("root").join(&storage), &["root.raw"])?;
        disks.push(admit_disk(
            &out,
            &format!("root/{storage}/root.raw"),
            DiskRole::Root,
            root_generation.root_disk_bytes,
        )?);
        Ok(Admitted {
            disks,
            memory_bytes,
            config_sha256: files.config_sha256,
            state_sha256: files.state_sha256,
        })
    })();
    let admitted = match result {
        Ok(admitted) => admitted,
        Err(error) => {
            let _ = crate::state::remove_checkpoint_tree(&checkpoints, &out_name);
            return Err(status(error));
        }
    };
    let snapshots = snapshots_root(&engine_root).map_err(status)?;
    checkpoints
        .move_private_directory_to(Path::new(&out_name), &snapshots, Path::new(staging_name))
        .map_err(|error| status(SupervisorError::from(error)))?;
    Ok(admitted)
}

fn only_entries(directory: &Path, allowed: &[&str]) -> Result<(), SupervisorError> {
    let entries = fs::read_dir(directory).map_err(|source| SupervisorError::Io {
        path: directory.to_owned(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| SupervisorError::Io {
            path: directory.to_owned(),
            source,
        })?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|name| allowed.contains(&name))
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
    }
    Ok(())
}

/// One cloned disk: a private regular file of exactly `bytes`, with an
/// ext4 superblock.
fn admit_disk(
    out: &PrivateRoot,
    relative: &str,
    role: DiskRole,
    bytes: u64,
) -> Result<ManifestDisk, SupervisorError> {
    let path = out.path().join(relative);
    let parent = PrivateRoot::open(path.parent().ok_or(SupervisorError::InvalidState)?)?;
    let leaf = path.file_name().ok_or(SupervisorError::InvalidState)?;
    let opened = parent
        .open_regular(Path::new(leaf), false, Some(bytes), false, Some(0o600))
        .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
    let superblock = crate::state::read_ext4_superblock(opened.file(), &path)?;
    Ok(ManifestDisk {
        role,
        bytes,
        mode: "reflink".to_owned(),
        filesystem_uuid: superblock.uuid,
    })
}

pub(super) fn list(
    config: &NativeRuntimeConfig,
    source: Option<Uuid>,
) -> Result<Vec<v1::Checkpoint>, Status> {
    let engine_root = config.engine_root();
    list_ready(config, true)?
        .iter()
        .filter(|(_, manifest)| source.is_none_or(|id| manifest.source.environment_id == id))
        .map(|(row, manifest)| checkpoint_proto(&engine_root, row, manifest, false).map_err(status))
        .collect()
}

pub(super) fn get(config: &NativeRuntimeConfig, selector: &str) -> Result<v1::Checkpoint, Status> {
    let (row, manifest) = find_ready(config, selector, true)?;
    checkpoint_proto(&config.engine_root(), &row, &manifest, true).map_err(status)
}

pub(super) fn delete(
    config: &NativeRuntimeConfig,
    selector: &str,
) -> Result<v1::Checkpoint, Status> {
    let engine_root = config.engine_root();
    delete_ready(config, selector, true, |row, manifest| {
        checkpoint_proto(&engine_root, row, manifest, false).map_err(status)
    })
}

/// Delete every VM checkpoint of `environment_id`.
pub(super) fn retire(
    config: &NativeRuntimeConfig,
    environment_id: Uuid,
) -> Result<(), SupervisorError> {
    let store = store(config)?;
    settle(config, &store)?;
    for row in store.list().map_err(super::super::snapshots::store_error)? {
        if row.kind
            != (crate::snapshot_store::SnapshotKind::Checkpoint {
                source_environment_id: environment_id,
            })
        {
            continue;
        }
        match delete_ready(config, &row.id.to_string(), true, |_, _| Ok(())) {
            Ok(()) => {}
            Err(error) if error.code() == tonic::Code::NotFound => {}
            Err(_) => return Err(SupervisorError::InvalidState),
        }
    }
    Ok(())
}
