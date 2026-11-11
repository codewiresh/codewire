//! VM checkpoints of running local VMs (#3046 R4, private-docs:
//! designs/2026-10-25-local-vm-checkpoints.md).
//!
//! A VM checkpoint is a disk snapshot (`supervisor::snapshots`) plus the
//! VMM's memory and device state at the same instant, a row of kind
//! `checkpoint` in the same store. Capture asks the source's runner to freeze
//! the workload, pause the VM, write its state, clone its disks, resume and
//! thaw (`runner::checkpoint`); the supervisor then takes the runner's tree
//! over, admits every file in it as untrusted input, and publishes it as R1
//! publishes a snapshot. A VM checkpoint stays on this host and holds what
//! the guest's memory held, the creator's delivered sign-ins included (owner,
//! 2026-10-25, Q1); it is never exported.

// VM checkpoints are Linux only, so most of this module is unused on other
// targets.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use super::snapshots::{
    Consistency, DiskRole, Manifest, ManifestDisk, ManifestResources, ManifestSource,
    PlatformAccount, RecordedAuthority,
};
use super::*;
use crate::control::v1::local_checkpoint_service_server::LocalCheckpointService;

/// The most VM checkpoints one environment keeps.
pub(super) const MAX_CHECKPOINTS_PER_ENVIRONMENT: usize = 8;
/// Free space a capture leaves beyond the memory file it writes densely.
const SPACE_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const MAXIMUM_VMM_CONFIG_BYTES: u64 = 1024 * 1024;
const MAXIMUM_VMM_STATE_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(not(target_os = "linux"))]
const LINUX_ONLY: &str = "VM checkpoints need a Linux host for now";

/// The pinned VMM a VM checkpoint restores only into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct VmmPin {
    pub(in crate::supervisor) version: String,
    pub(in crate::supervisor) sha256: String,
}

/// The host a VM checkpoint was taken on: a restore on another CPU is
/// refused; another host kernel is allowed and shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct HostIdentity {
    /// `vendor:family:model:stepping` from the first processor.
    pub(in crate::supervisor) cpu: String,
    pub(in crate::supervisor) kernel_release: String,
}

/// The seed bindings the captured guest applied, which a restore's seed
/// repeats exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct BootBindings {
    pub(in crate::supervisor) skill_snapshot_sha256: Option<String>,
    pub(in crate::supervisor) environment_projection_sha256: Option<String>,
    pub(in crate::supervisor) managed_credential_clients: String,
    pub(in crate::supervisor) docker: bool,
    pub(in crate::supervisor) cw_runtime_catalog_generation: Option<String>,
    pub(in crate::supervisor) daemon_vsock_port: u32,
}

/// How long each part of the capture took, in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct Timings {
    pub(in crate::supervisor) guest_freeze_us: u64,
    pub(in crate::supervisor) workload_frozen_us: u64,
    pub(in crate::supervisor) vm_paused_us: u64,
    pub(in crate::supervisor) memory_write_us: u64,
    pub(in crate::supervisor) disk_clone_us: u64,
    pub(in crate::supervisor) total_us: u64,
}

impl Timings {
    fn proto(self) -> v1::CheckpointTimings {
        v1::CheckpointTimings {
            guest_freeze_us: self.guest_freeze_us,
            workload_frozen_us: self.workload_frozen_us,
            vm_paused_us: self.vm_paused_us,
            memory_write_us: self.memory_write_us,
            disk_clone_us: self.disk_clone_us,
            total_us: self.total_us,
        }
    }
}

/// A manifest's `checkpoint` object: what makes a disk snapshot a VM
/// checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct CheckpointManifest {
    /// The source's boot generation at capture.
    pub(in crate::supervisor) source_generation: u64,
    /// The captured boot's vsock CID, which the guest cached at probe.
    pub(in crate::supervisor) vsock_cid: u32,
    pub(in crate::supervisor) vmm: VmmPin,
    pub(in crate::supervisor) guest_checkpoint_abi: u32,
    pub(in crate::supervisor) host: HostIdentity,
    /// `vmm/memory-ranges`, written densely: the guest's whole memory.
    pub(in crate::supervisor) memory_bytes: u64,
    pub(in crate::supervisor) config_sha256: String,
    pub(in crate::supervisor) state_sha256: String,
    /// The captured boot's one-boot setup disk, when it had one.
    pub(in crate::supervisor) setup_disk_bytes: Option<u64>,
    pub(in crate::supervisor) boot: BootBindings,
    pub(in crate::supervisor) timings: Timings,
}

impl CheckpointManifest {
    pub(in crate::supervisor) fn validate(&self, memory_mib: u32) -> Result<(), SupervisorError> {
        let digest = |value: &str| valid_sha256(value);
        if self.source_generation == 0
            || self.vsock_cid < 3
            || self.vsock_cid == u32::MAX
            || self.vmm.version.is_empty()
            || self.vmm.version.len() > 32
            || !digest(&self.vmm.sha256)
            || self.guest_checkpoint_abi != codewire_vmm_guest_probe::GUEST_CHECKPOINT_ABI
            || self.host.cpu.is_empty()
            || self.host.cpu.len() > 256
            || self.host.kernel_release.len() > 256
            || self.memory_bytes != u64::from(memory_mib) * MIB
            || !digest(&self.config_sha256)
            || !digest(&self.state_sha256)
            || self.setup_disk_bytes == Some(0)
            || self
                .boot
                .skill_snapshot_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .boot
                .environment_projection_sha256
                .as_deref()
                .is_some_and(|value| !digest(value))
            || self
                .boot
                .cw_runtime_catalog_generation
                .as_deref()
                .is_some_and(|value| !digest(value))
            || codewire_access::ManagedCredentialClients::decode(
                &self.boot.managed_credential_clients,
            )
            .is_err()
        {
            return Err(SupervisorError::InvalidState);
        }
        Ok(())
    }

    /// Whether a VM tree's `checkpoints/in` files are this checkpoint's.
    pub(in crate::supervisor) fn files_match_in(&self, vm: &Path) -> bool {
        #[cfg(target_os = "linux")]
        {
            linux::read_vmm_files(
                &vm.join(crate::state::CHECKPOINTS_DIRECTORY)
                    .join(crate::state::CHECKPOINT_IN),
                self.memory_bytes,
            )
            .is_ok_and(|files| {
                files.config_sha256 == self.config_sha256 && files.state_sha256 == self.state_sha256
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = vm;
            false
        }
    }

    /// Whether `directory`'s `vmm/` files are the ones this manifest names.
    pub(in crate::supervisor) fn files_match(&self, directory: &Path) -> bool {
        #[cfg(target_os = "linux")]
        {
            linux::read_vmm_files(&directory.join("vmm"), self.memory_bytes).is_ok_and(|files| {
                files.config_sha256 == self.config_sha256 && files.state_sha256 == self.state_sha256
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            false
        }
    }
}

/// The default name of a VM checkpoint of `environment`: the name and the
/// UTC time, `<env>-<yyyymmddThhmmssZ>`, the name shortened to fit.
fn default_name(environment: &str, unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    // Days since the epoch to a civil date (Howard Hinnant's algorithm).
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let suffix = format!(
        "-{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    );
    let room = 63 - suffix.len();
    let mut base = environment
        .get(..environment.len().min(room))
        .unwrap_or(environment)
        .to_owned();
    while base.ends_with(['-', '_', '.']) {
        base.pop();
    }
    format!("{base}{suffix}")
}

/// Delete every VM checkpoint of `environment_id`: a deleted environment's
/// checkpoints go with it (DELETE's PrepareDelete). Idempotent on replay.
pub(super) async fn retire_for_environment(
    supervisor: &Supervisor,
    environment_id: Uuid,
) -> Result<(), SupervisorError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (supervisor, environment_id);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        let config = supervisor.config.clone();
        tokio::task::spawn_blocking(move || linux::retire(&config, environment_id))
            .await
            .map_err(|_| SupervisorError::InvalidState)?
    }
}

// ---------------------------------------------------------------------------
// Supervisor hooks for an in-place restore: a Start whose payload names the
// VM checkpoint (supervisor.rs calls each once).

/// The VM checkpoint a Start operation restores, if any: its payload's
/// optional third key.
pub(super) fn start_payload_checkpoint(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<Uuid>, SupervisorError> {
    match fields.get("checkpoint") {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .and_then(super::snapshots::canonical_id)
            .map(Some)
            .ok_or(SupervisorError::InvalidState),
    }
}

/// A restoring Start's StageWorkspaceGeneration: place the checkpoint's
/// disks and VMM files for the stopped source. Nothing is staged.
pub(super) async fn place_in_place(
    supervisor: &Supervisor,
    name: &str,
    checkpoint_id: Uuid,
    operation_id: Uuid,
) -> Result<Option<WorkspaceGenerationRecord>, SupervisorError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (supervisor, name, checkpoint_id, operation_id);
        Err(SupervisorError::InvalidRequest)
    }
    #[cfg(target_os = "linux")]
    {
        let environment = supervisor.environment(name)?;
        let config = supervisor.config.clone();
        tokio::task::spawn_blocking(move || {
            linux::place(&config, &environment, checkpoint_id, operation_id)
        })
        .await
        .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
        Ok(None)
    }
}

/// A restoring Start's StartVm request: the checkpoint to restore, and its
/// vsock CID, which the restored guest cached at probe.
pub(super) fn attach_boot(
    supervisor: &Supervisor,
    operation_id: Uuid,
    request: v1::StartVmRequest,
) -> Result<v1::StartVmRequest, SupervisorError> {
    // The Start being applied is pending until it completes.
    let operation = supervisor
        .core()
        .store
        .pending_operations()?
        .into_iter()
        .find(|operation| operation.operation_id == operation_id)
        .ok_or(SupervisorError::InvalidState)?;
    let fields = operation
        .payload
        .as_object()
        .ok_or(SupervisorError::InvalidState)?;
    let checkpoint_id = match operation.kind {
        OperationKind::Start => start_payload_checkpoint(fields)?,
        // A create from a VM checkpoint's id is a live fork; one from a disk
        // snapshot boots.
        OperationKind::Create => match super::snapshots::from_payload(fields)? {
            Some(restore) => super::snapshots::canonical_id(&restore.snapshot_id).filter(|id| {
                super::snapshots::store(&supervisor.config)
                    .ok()
                    .and_then(|store| store.find(&id.to_string()).ok().flatten())
                    .is_some_and(|row| row.kind.is_checkpoint())
            }),
            None => None,
        },
        _ => None,
    };
    let Some(checkpoint_id) = checkpoint_id else {
        return Ok(request);
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = checkpoint_id;
        Err(SupervisorError::InvalidRequest)
    }
    #[cfg(target_os = "linux")]
    {
        let mut request = request;
        let (_, manifest) =
            super::snapshots::find_ready(&supervisor.config, &checkpoint_id.to_string(), true)
                .map_err(|_| SupervisorError::NotFound(checkpoint_id.to_string()))?;
        let checkpoint = manifest
            .checkpoint
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        request.vsock_cid = checkpoint.vsock_cid;
        request.checkpoint = Some(v1::CheckpointBoot {
            checkpoint_id: checkpoint_id.to_string(),
            source_environment_id: manifest.source.environment_id.to_string(),
            config_sha256: checkpoint.config_sha256.clone(),
            state_sha256: checkpoint.state_sha256.clone(),
            memory_bytes: checkpoint.memory_bytes,
            setup_disk_bytes: checkpoint.setup_disk_bytes.unwrap_or_default(),
            vmm_sha256: checkpoint.vmm.sha256.clone(),
            boot: Some(v1::CheckpointBootBindings {
                skill_snapshot_sha256: checkpoint
                    .boot
                    .skill_snapshot_sha256
                    .clone()
                    .unwrap_or_default(),
                environment_projection_sha256: checkpoint
                    .boot
                    .environment_projection_sha256
                    .clone()
                    .unwrap_or_default(),
                managed_credential_clients: checkpoint.boot.managed_credential_clients.clone(),
                docker: checkpoint.boot.docker,
                cw_runtime_catalog_generation: checkpoint
                    .boot
                    .cw_runtime_catalog_generation
                    .clone()
                    .unwrap_or_default(),
                daemon_vsock_port: checkpoint.boot.daemon_vsock_port,
            }),
            source_generation: checkpoint.source_generation,
        });
        Ok(request)
    }
}

// ---------------------------------------------------------------------------
// The VM checkpoint RPCs.

#[tonic::async_trait]
impl LocalCheckpointService for SupervisorRpc {
    async fn create_checkpoint(
        &self,
        request: Request<v1::CreateCheckpointRequest>,
    ) -> Result<Response<v1::Checkpoint>, Status> {
        self.start_drains()?;
        let request = request.into_inner();
        let supervisor = Arc::clone(&self.supervisor);
        // In a task of its own: a dropped request never cuts a capture short
        // while it holds the source's lease.
        tokio::spawn(async move { capture(&supervisor, request).await })
            .await
            .map_err(|_| Status::internal("VM checkpoint capture task failed"))?
            .map(Response::new)
    }

    async fn list_checkpoints(
        &self,
        request: Request<v1::ListCheckpointsRequest>,
    ) -> Result<Response<v1::ListCheckpointsResponse>, Status> {
        let environment = request.into_inner().environment;
        let config = self.supervisor.config.clone();
        let source = if environment.is_empty() {
            None
        } else {
            Some(
                self.supervisor
                    .environment(&environment)
                    .map_err(|_| {
                        Status::not_found(format!(
                            "no local environment is named {environment}; list them with `cw ls --local`"
                        ))
                    })?
                    .id,
            )
        };
        let checkpoints = tokio::task::spawn_blocking(move || list(&config, source))
            .await
            .map_err(|_| Status::internal("VM checkpoint listing task failed"))??;
        Ok(Response::new(v1::ListCheckpointsResponse { checkpoints }))
    }

    async fn get_checkpoint(
        &self,
        request: Request<v1::CheckpointSelector>,
    ) -> Result<Response<v1::Checkpoint>, Status> {
        let selector = request.into_inner().checkpoint;
        let config = self.supervisor.config.clone();
        tokio::task::spawn_blocking(move || get(&config, &selector))
            .await
            .map_err(|_| Status::internal("VM checkpoint inspection task failed"))?
            .map(Response::new)
    }

    async fn stop_for_restore(
        &self,
        request: Request<v1::StopForRestoreRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(Status::unimplemented(LINUX_ONLY))
        }
        #[cfg(target_os = "linux")]
        {
            self.start_drains()?;
            linux::stop_for_restore(self, request.into_inner())
                .await
                .map(Response::new)
        }
    }

    async fn restore_checkpoint(
        &self,
        request: Request<v1::RestoreCheckpointRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = request;
            Err(Status::unimplemented(LINUX_ONLY))
        }
        #[cfg(target_os = "linux")]
        {
            self.start_drains()?;
            linux::restore(self, request.into_inner())
                .await
                .map(Response::new)
        }
    }

    async fn delete_checkpoint(
        &self,
        request: Request<v1::CheckpointSelector>,
    ) -> Result<Response<v1::Checkpoint>, Status> {
        let selector = request.into_inner().checkpoint;
        let config = self.supervisor.config.clone();
        tokio::task::spawn_blocking(move || delete(&config, &selector))
            .await
            .map_err(|_| Status::internal("VM checkpoint deletion task failed"))?
            .map(Response::new)
    }
}

#[cfg(not(target_os = "linux"))]
async fn capture(
    _supervisor: &Supervisor,
    _request: v1::CreateCheckpointRequest,
) -> Result<v1::Checkpoint, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn list(
    _config: &NativeRuntimeConfig,
    _source: Option<Uuid>,
) -> Result<Vec<v1::Checkpoint>, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn get(_config: &NativeRuntimeConfig, _selector: &str) -> Result<v1::Checkpoint, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(not(target_os = "linux"))]
fn delete(_config: &NativeRuntimeConfig, _selector: &str) -> Result<v1::Checkpoint, Status> {
    Err(Status::unimplemented(LINUX_ONLY))
}

#[cfg(target_os = "linux")]
pub(in crate::supervisor) mod linux {
    use std::io::Read as _;
    use std::time::Instant;

    use sha2::Digest as _;

    use super::super::snapshots::{
        CAPTURE_STAGING_PREFIX, InFlight, delete_ready, find_ready, list_ready, now_unix_ms,
        publish, remove_snapshot_tree, settle, snapshot_proto, snapshots_root, store, store_status,
    };
    use super::*;
    use crate::state::{CHECKPOINT_OUT_PREFIX, CHECKPOINT_VMM_FILES, CHECKPOINTS_DIRECTORY};

    fn status(error: SupervisorError) -> Status {
        Status::from(error)
    }

    pub(super) async fn capture(
        supervisor: &Supervisor,
        request: v1::CreateCheckpointRequest,
    ) -> Result<v1::Checkpoint, Status> {
        let started = Instant::now();
        let environment_name = request.environment.clone();
        if !valid_environment_name(&environment_name) {
            return Err(Status::invalid_argument(
                "name the running environment to checkpoint",
            ));
        }
        let name = if request.name.is_empty() {
            default_name(&environment_name, now_unix_ms() / 1000)
        } else {
            request.name.clone()
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
        tokio::task::spawn_blocking(move || require_capture_space(&space, memory_bytes))
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
                host: linux::host_identity(),
                memory_bytes: admitted.memory_bytes,
                config_sha256: admitted.config_sha256,
                state_sha256: admitted.state_sha256,
                setup_disk_bytes: (captured.setup_disk_bytes != 0)
                    .then_some(captured.setup_disk_bytes),
                boot: BootBindings {
                    skill_snapshot_sha256: optional(&boot.skill_snapshot_sha256),
                    environment_projection_sha256: optional(&boot.environment_projection_sha256),
                    managed_credential_clients: boot.managed_credential_clients.clone(),
                    docker: boot.docker,
                    cw_runtime_catalog_generation: optional(&boot.cw_runtime_catalog_generation),
                    daemon_vsock_port: boot.daemon_vsock_port,
                },
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
        if captured.resume_failed {
            proto.warnings.push(format!(
                "the VM checkpoint is complete, but {environment_name} did not resume; restore it with `cw checkpoint restore {}`",
                row.name
            ));
        }
        Ok(proto)
    }

    /// `RestoreCheckpoint`: every refusable check, then a Start operation
    /// whose payload names the checkpoint. The source must be stopped.
    /// Everything a restore requires of a VM checkpoint and its source,
    /// other than the source being stopped: the same workspace, resources,
    /// CPU, platform account, runtime and Cloud Hypervisor build, and stored
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
            || environment.active_artifact_generation.as_deref()
                != Some(artifact_generation.as_str())
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
        let host = host_identity();
        if host.cpu != checkpoint.host.cpu {
            return Err(Status::failed_precondition(format!(
                "VM checkpoint {} was taken on another CPU ({}; this host has {}); it cannot be restored here",
                row.name, checkpoint.host.cpu, host.cpu
            )));
        }
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
        if artifacts.cloud_hypervisor.sha256() != checkpoint.vmm.sha256 {
            return Err(Status::failed_precondition(format!(
                "VM checkpoint {} is unrestorable: its Cloud Hypervisor build changed",
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
        let source =
            snapshots.open_private_directory(Path::new(&checkpoint_id.to_string()), 0o700)?;
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
            if identity.file.size != disk.bytes || identity.filesystem_uuid != disk.filesystem_uuid
            {
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
        let (row, manifest) =
            tokio::task::spawn_blocking(move || find_ready(&config, &selector, true))
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
        let (row, manifest) =
            tokio::task::spawn_blocking(move || find_ready(&config, &selector, true))
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
        let source =
            snapshots.open_private_directory(Path::new(&checkpoint_id.to_string()), 0o700)?;
        let held = fs::File::open(source.path()).map_err(|error| SupervisorError::Io {
            path: source.path().to_owned(),
            source: error,
        })?;
        let held = crate::state::HeldFlock::try_lock(
            held,
            rustix::fs::FlockOperation::NonBlockingLockShared,
        )
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
            let root_target =
                crate::state::RootGenerationPaths::create(&paths, &storage)?.root_disk;
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
                if identity.file.size != disk.bytes
                    || identity.filesystem_uuid != disk.filesystem_uuid
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
                fs::rename(out_path.join(relative), target).map_err(|error| {
                    SupervisorError::Io {
                        path: target.clone(),
                        source: error,
                    }
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
                    persisted.state_disk =
                        crate::state::StateDiskIdentity::capture(&paths.state_disk)?;
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

    /// Reflink `source` into the new `destination` with `mode`.
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
        let to = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(destination)
            .map_err(|error| io_error(destination, error))?;
        crate::fs_clone::reflink(&from, &to).map_err(|error| io_error(destination, error))?;
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

    /// The snapshot store's filesystem shares blocks, and holds the memory
    /// file, written densely, with room to spare.
    fn require_capture_space(
        config: &NativeRuntimeConfig,
        memory_bytes: u64,
    ) -> Result<(), Status> {
        let snapshots = snapshots_root(&config.engine_root()).map_err(status)?;
        let reflink = crate::fs_clone::reflink_works(snapshots.path()).map_err(|error| {
            Status::internal(format!("checking the filesystem failed: {error}"))
        })?;
        if !reflink {
            return Err(Status::failed_precondition(
                "VM checkpoints need a filesystem that shares blocks between files (btrfs or XFS) under the local VM state root",
            ));
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
        Ok(())
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

    pub(super) struct VmmFiles {
        pub(super) config_sha256: String,
        pub(super) state_sha256: String,
    }

    /// Read `vmm/` as the VMM must have written it: exactly its three files,
    /// sealed 0400, the memory file exactly `memory_bytes`, the configuration
    /// a JSON object.
    pub(super) fn read_vmm_files(
        vmm: &Path,
        memory_bytes: u64,
    ) -> Result<VmmFiles, SupervisorError> {
        only_entries(vmm, &CHECKPOINT_VMM_FILES)?;
        let root = PrivateRoot::open(vmm)?;
        let digest = |name: &str, limit: u64| -> Result<(String, Vec<u8>), SupervisorError> {
            let opened = root
                .open_regular(Path::new(name), false, None, false, Some(0o400))
                .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
            let mut bytes = Vec::new();
            opened
                .file()
                .take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(|source| SupervisorError::Io {
                    path: vmm.join(name),
                    source,
                })?;
            if bytes.len() as u64 > limit {
                return Err(SupervisorError::InvalidRunnerResponse);
            }
            Ok((format!("{:x}", Sha256::digest(&bytes)), bytes))
        };
        let (config_sha256, config) = digest("config.json", MAXIMUM_VMM_CONFIG_BYTES)?;
        if !serde_json::from_slice::<serde_json::Value>(&config)
            .is_ok_and(|value| value.is_object())
        {
            return Err(SupervisorError::InvalidRunnerResponse);
        }
        let (state_sha256, _) = digest("state.json", MAXIMUM_VMM_STATE_BYTES)?;
        root.open_regular(
            Path::new("memory-ranges"),
            false,
            Some(memory_bytes),
            false,
            Some(0o400),
        )
        .map_err(|_| SupervisorError::InvalidRunnerResponse)?;
        Ok(VmmFiles {
            config_sha256,
            state_sha256,
        })
    }

    /// The first processor's vendor, family, model and stepping, and the
    /// kernel release.
    pub(super) fn host_identity() -> HostIdentity {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let field = |key: &str| {
            cpuinfo
                .lines()
                .take_while(|line| !line.trim().is_empty())
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    (name.trim() == key).then(|| value.trim().to_owned())
                })
                .unwrap_or_default()
        };
        // x86_64 names these; aarch64 names its implementer and part.
        let cpu = [
            field("vendor_id"),
            field("cpu family"),
            field("model"),
            field("stepping"),
            field("CPU implementer"),
            field("CPU part"),
            field("CPU variant"),
            field("CPU revision"),
        ]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(":");
        HostIdentity {
            cpu: if cpu.is_empty() {
                "unknown".to_owned()
            } else {
                cpu
            },
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|release| release.trim().to_owned())
                .unwrap_or_default(),
        }
    }

    pub(super) fn list(
        config: &NativeRuntimeConfig,
        source: Option<Uuid>,
    ) -> Result<Vec<v1::Checkpoint>, Status> {
        let engine_root = config.engine_root();
        list_ready(config, true)?
            .iter()
            .filter(|(_, manifest)| source.is_none_or(|id| manifest.source.environment_id == id))
            .map(|(row, manifest)| {
                checkpoint_proto(&engine_root, row, manifest, false).map_err(status)
            })
            .collect()
    }

    pub(super) fn get(
        config: &NativeRuntimeConfig,
        selector: &str,
    ) -> Result<v1::Checkpoint, Status> {
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

    pub(super) fn checkpoint_proto(
        engine_root: &Path,
        row: &crate::snapshot_store::SnapshotRow,
        manifest: &Manifest,
        measure_sharing: bool,
    ) -> Result<v1::Checkpoint, SupervisorError> {
        let checkpoint = manifest
            .checkpoint
            .as_ref()
            .ok_or(SupervisorError::InvalidState)?;
        let snapshot = snapshot_proto(engine_root, row, manifest, measure_sharing)?;
        let described = snapshot.clone();
        let memory = snapshots_root(engine_root)?
            .path()
            .join(row.id.to_string())
            .join("vmm/memory-ranges");
        let memory_allocated_bytes = fs::File::open(&memory)
            .and_then(|file| crate::fs_clone::allocated_bytes(&file))
            .unwrap_or(0);
        let host = host_identity();
        let unrestorable_reason = if host.cpu != checkpoint.host.cpu {
            format!(
                "it was taken on another CPU ({}; this host has {})",
                checkpoint.host.cpu, host.cpu
            )
        } else {
            String::new()
        };
        let mut warnings = vec![
            "a VM checkpoint holds everything the VM's memory held, delivered sign-ins included, until they expire; it stays on this host and is never exported".to_owned(),
        ];
        if host.kernel_release != checkpoint.host.kernel_release {
            warnings.push(format!(
                "taken under host kernel {}; this host runs {}",
                checkpoint.host.kernel_release, host.kernel_release
            ));
        }
        Ok(v1::Checkpoint {
            id: snapshot.id,
            name: snapshot.name,
            created_unix_ms: snapshot.created_unix_ms,
            source_environment_id: snapshot.source_environment_id,
            source_name: snapshot.source_name,
            consistency: snapshot.consistency,
            locations: snapshot.locations,
            architecture: snapshot.architecture,
            vcpus: snapshot.vcpus,
            memory_mib: snapshot.memory_mib,
            disk_bytes: snapshot.disk_bytes,
            docker_disk_bytes: snapshot.docker_disk_bytes,
            image: snapshot.image,
            disks: snapshot.disks,
            memory_bytes: checkpoint.memory_bytes,
            memory_allocated_bytes,
            vmm_version: checkpoint.vmm.version.clone(),
            vmm_sha256: checkpoint.vmm.sha256.clone(),
            guest_checkpoint_abi: checkpoint.guest_checkpoint_abi,
            timings: Some(checkpoint.timings.proto()),
            unrestorable_reason,
            warnings,
            account: snapshot.account,
            source_generation: checkpoint.source_generation,
            snapshot: Some(described),
        })
    }
}

#[cfg(target_os = "linux")]
use linux::{capture, delete, get, list};

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn a_start_names_at_most_one_canonical_checkpoint() {
        let fields = |value: serde_json::Value| value.as_object().unwrap().clone();
        let id = Uuid::new_v4();
        assert_eq!(
            start_payload_checkpoint(&fields(serde_json::json!({"name": "app"}))).unwrap(),
            None
        );
        assert_eq!(
            start_payload_checkpoint(&fields(serde_json::json!({"checkpoint": id.to_string()})))
                .unwrap(),
            Some(id)
        );
        for invalid in [
            serde_json::json!({"checkpoint": "c1"}),
            serde_json::json!({"checkpoint": Uuid::nil().to_string()}),
            serde_json::json!({"checkpoint": 7}),
            serde_json::json!({"checkpoint": id.to_string().to_uppercase()}),
        ] {
            assert!(start_payload_checkpoint(&fields(invalid)).is_err());
        }
    }

    #[test]
    fn default_names_take_the_utc_time_and_fit() {
        // 2026-10-28T12:34:56Z.
        assert_eq!(default_name("app", 1_793_190_896), "app-20261028T123456Z");
        assert_eq!(default_name("app", 0), "app-19700101T000000Z");
        let long = "a".repeat(63);
        let name = default_name(&long, 1_793_190_896);
        assert_eq!(name.len(), 63);
        assert!(name.ends_with("-20261028T123456Z"));
        assert!(valid_environment_name(&name));
        // A cut never leaves a separator before the time.
        let cut = format!("{}-b", "a".repeat(45));
        assert!(!default_name(&cut, 0).contains("--"));
    }
}
