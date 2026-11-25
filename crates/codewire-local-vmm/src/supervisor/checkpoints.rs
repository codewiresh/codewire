//! VM checkpoints of running local VMs (#3046 R4).
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
    /// The captured boot intercepted agent hosts (#3999). A checkpoint taken
    /// before the switch existed has none: off.
    #[serde(default)]
    pub(in crate::supervisor) intercept: bool,
    /// The VM's state disk was recorded as cleared when it was taken (#6277):
    /// absent on a checkpoint taken before the record existed, false after a
    /// start with the override. Absent or false flags the checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in crate::supervisor) state_disk_cleared: Option<bool>,
}

impl BootBindings {
    /// What a restore or fork's state disk settling reads of it.
    pub(in crate::supervisor) fn disk(&self) -> super::state_disk_clear::CheckpointDisk {
        super::state_disk_clear::CheckpointDisk {
            intercepted: self.intercept,
            cleared: self.state_disk_cleared == Some(true),
        }
    }
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
            // Linux sends ABI 1; a Mac sends 2 to a guest that steps its
            // clock on Thaw (#4654).
            || !matches!(
                self.guest_checkpoint_abi,
                codewire_vmm_guest_probe::GUEST_CHECKPOINT_ABI
                    | codewire_vmm_guest_probe::GUEST_CHECKPOINT_THAW_CLOCK_ABI
            )
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
        self.vmm_files_match(
            &vm.join(crate::state::CHECKPOINTS_DIRECTORY)
                .join(crate::state::CHECKPOINT_IN),
        )
    }

    /// Whether `directory`'s `vmm/` files are the ones this manifest names.
    pub(in crate::supervisor) fn files_match(&self, directory: &Path) -> bool {
        self.vmm_files_match(&directory.join("vmm"))
    }

    /// A Mac's saved state is digested only when its pin doesn't hold
    /// (#6124).
    fn vmm_files_match(&self, vmm: &Path) -> bool {
        local::vmm_files_match(
            vmm,
            self.memory_bytes,
            &self.config_sha256,
            &self.state_sha256,
        )
    }
}

/// A fork's `checkpoints/in` in its staged VM `tree`: its own sealed
/// reflinks of the VMM files in the checkpoint directory `source`, checked
/// against `checkpoint`. The source is checked first, so a Mac can pin the
/// saved state's clone from its descriptor and skip digesting it (#6124).
pub(in crate::supervisor) fn place_fork_input(
    tree_root: &PrivateRoot,
    tree: &Path,
    source: &Path,
    checkpoint: &CheckpointManifest,
) -> Result<(), SupervisorError> {
    let checkpoints =
        tree_root.create_dir(Path::new(crate::state::CHECKPOINTS_DIRECTORY), 0o700)?;
    let input = PrivateRoot::open(&checkpoints)?
        .create_dir(Path::new(crate::state::CHECKPOINT_IN), 0o700)?;
    if !checkpoint.files_match(source) {
        return Err(SupervisorError::InvalidState);
    }
    for name in crate::state::CHECKPOINT_VMM_FILES {
        let clone = clone_sealed(&source.join("vmm").join(name), &input.join(name))?;
        local::pin_clone(name, &clone, &input, &checkpoint.state_sha256)?;
    }
    if !checkpoint.files_match_in(tree) {
        return Err(SupervisorError::InvalidState);
    }
    for directory in [&input, &checkpoints] {
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| SupervisorError::Io {
                path: directory.clone(),
                source,
            })?;
    }
    Ok(())
}

/// Clone `source` into the new `destination`, sealed 0400, open.
fn clone_sealed(source: &Path, destination: &Path) -> Result<File, SupervisorError> {
    use std::os::unix::fs::OpenOptionsExt as _;
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
        .and_then(|()| to.set_permissions(fs::Permissions::from_mode(0o400)))
        .map_err(|error| io_error(destination, error))?;
    Ok(to)
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
    let config = supervisor.config.clone();
    tokio::task::spawn_blocking(move || local::retire(&config, environment_id))
        .await
        .map_err(|_| SupervisorError::InvalidState)?
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
    let environment = supervisor.environment(name)?;
    let config = supervisor.config.clone();
    tokio::task::spawn_blocking(move || {
        local::place(&config, &environment, checkpoint_id, operation_id)
    })
    .await
    .map_err(|_| SupervisorError::WorkspaceProvisionTask)??;
    Ok(None)
}

/// A restoring Start's StartVm request: the checkpoint to restore, and its
/// vsock CID, which the restored guest cached at probe.
/// The key a Start or a checkpoint restore journals, only when set, for the
/// one-start override of an uncleared state disk (#6277).
pub(super) const START_WITH_UNCLEARED_DISK: &str = "start_with_uncleared_disk";

/// Whether a journaled Start's payload carries the override: absent, or
/// exactly `true`.
pub(super) fn start_payload_override(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<bool, SupervisorError> {
    match fields.get(START_WITH_UNCLEARED_DISK) {
        None => Ok(false),
        Some(serde_json::Value::Bool(true)) => Ok(true),
        Some(_) => Err(SupervisorError::InvalidState),
    }
}

/// What a boot's state disk starts from (#6277).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BootOrigin {
    /// The VM's disk as its last boot left it.
    Existing,
    /// A create's new disk, or one placed from a disk snapshot, which
    /// capture cleared.
    New,
    /// A restore or fork of this VM checkpoint.
    Checkpoint(Uuid),
}

/// What a boot starts from, and whether its operation passed the override
/// of an uncleared state disk.
pub(super) fn boot_source(
    supervisor: &Supervisor,
    operation_id: Uuid,
) -> Result<(BootOrigin, bool), SupervisorError> {
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
    Ok(match operation.kind {
        OperationKind::Start => (
            start_payload_checkpoint(fields)?.map_or(BootOrigin::Existing, BootOrigin::Checkpoint),
            start_payload_override(fields)?,
        ),
        // A create from a VM checkpoint's id is a live fork; one from a disk
        // snapshot boots.
        OperationKind::Create => match super::snapshots::from_payload(fields)? {
            Some(restore) => (
                super::snapshots::canonical_id(&restore.snapshot_id)
                    .filter(|id| {
                        super::snapshots::store(&supervisor.config)
                            .ok()
                            .and_then(|store| store.find(&id.to_string()).ok().flatten())
                            .is_some_and(|row| row.kind.is_checkpoint())
                    })
                    .map_or(BootOrigin::New, BootOrigin::Checkpoint),
                restore.start_with_uncleared_disk,
            ),
            None => (BootOrigin::New, false),
        },
        _ => (BootOrigin::Existing, false),
    })
}

/// What the VM checkpoint `checkpoint_id` recorded about its state disk.
pub(super) fn checkpoint_disk(
    supervisor: &Supervisor,
    checkpoint_id: Uuid,
) -> Result<super::state_disk_clear::CheckpointDisk, SupervisorError> {
    let (_, manifest) =
        super::snapshots::find_ready(&supervisor.config, &checkpoint_id.to_string(), true)
            .map_err(|_| SupervisorError::NotFound(checkpoint_id.to_string()))?;
    manifest
        .checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.boot.disk())
        .ok_or(SupervisorError::InvalidState)
}

pub(super) fn attach_boot(
    supervisor: &Supervisor,
    operation_id: Uuid,
    request: v1::StartVmRequest,
) -> Result<v1::StartVmRequest, SupervisorError> {
    let (BootOrigin::Checkpoint(checkpoint_id), _) = boot_source(supervisor, operation_id)? else {
        return Ok(request);
    };
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
            intercept: checkpoint.boot.intercept,
        }),
        source_generation: checkpoint.source_generation,
        state_identity: placed_state_identity(supervisor, &request.environment_id),
    });
    Ok(request)
}

/// The pin the supervisor recorded for the saved state it cloned into the
/// VM's `checkpoints/in`, for the runner to compare (#6124); `None` when
/// there is none, and the runner then digests.
fn placed_state_identity(
    supervisor: &Supervisor,
    environment_id: &str,
) -> Option<v1::CheckpointStateIdentity> {
    let input = supervisor
        .config
        .engine_root()
        .join("vms")
        .join(Uuid::parse_str(environment_id).ok()?.to_string())
        .join(crate::state::CHECKPOINTS_DIRECTORY)
        .join(crate::state::CHECKPOINT_IN);
    let pin = crate::checkpoint_pin::read(&input)?;
    Some(v1::CheckpointStateIdentity {
        device: pin.device,
        inode: pin.inode,
        size: pin.size,
        birth_seconds: pin.birth_seconds,
        birth_nanoseconds: pin.birth_nanoseconds,
        change_seconds: pin.change_seconds,
        change_nanoseconds: pin.change_nanoseconds,
        mode: pin.mode,
        sha256: pin.sha256,
    })
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
        self.start_drains()?;
        local::stop_for_restore(self, request.into_inner())
            .await
            .map(Response::new)
    }

    async fn restore_checkpoint(
        &self,
        request: Request<v1::RestoreCheckpointRequest>,
    ) -> Result<Response<v1::Operation>, Status> {
        self.start_drains()?;
        local::restore(self, request.into_inner())
            .await
            .map(Response::new)
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

pub(in crate::supervisor) mod local;

use local::{capture, delete, get, list};

/// The closed cause class of a failed lifecycle effect (#2595). Like
/// [`create_failure_code`], it names the error, never its Display, Debug or
/// source chain, so no path, upstream text or secret value reaches the journal
/// or the log. Every cause is a `[a-z_]` token of at most
/// [`MAXIMUM_LIFECYCLE_CAUSE_BYTES`], so `<operation prefix>_<cause>` stays a
/// valid journal error code. The match is exhaustive: a new error variant must
/// be named here.
/// A Stop payload is exactly `{"name"}`, or `{"name", "discard_for_checkpoint"}`
/// for one the checkpoint service admitted for a restore (#3046): `Some` with
/// whether the guest's state is discarded, `None` for any other shape.
pub(super) fn stop_payload_checkpoint(payload: &serde_json::Value, name: &str) -> Option<bool> {
    let fields = payload.as_object()?;
    if fields.get("name").and_then(serde_json::Value::as_str) != Some(name) {
        return None;
    }
    match fields.len() {
        1 => Some(false),
        2 => fields
            .get("discard_for_checkpoint")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
            .filter(|id| !id.is_nil())
            .map(|_| true),
        _ => None,
    }
}

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
