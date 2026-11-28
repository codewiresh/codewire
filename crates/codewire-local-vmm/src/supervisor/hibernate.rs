//! Host-side hibernate metadata, one-shot restore admission, and fallback
//! recording for local Linux VMs (#5529, `docs/dev/LOCAL-VM-SLEEP.md`).
//!
//! Layout under `engine_root/vms/<id>/`:
//! - `checkpoints/in/{config.json,state.json,memory-ranges}`: sealed (0400)
//!   memory and device state written by `CloudHypervisorRunner::hibernate_with_state`.
//! - `hibernate/record.json` (0600 inside 0700): sibling metadata outside the
//!   VMM's Landlock write directory.
//! - `hibernate/generation` (0600): external one-shot guard consumed and deleted
//!   BEFORE starting the restoring VMM, guaranteeing restore-at-most-once.
//! - `hibernate/fallback.json` (0600): recorded when restore cannot proceed and
//!   the supervisor falls back to a clean cold boot from persistent disks;
//!   cleared on the next start, stop, or hibernate.

use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(all(test, target_os = "linux"))]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tonic::Status;
use uuid::Uuid;

use crate::control::v1;
use crate::host::path::PrivateRoot;
use crate::state::{
    CHECKPOINT_IN, CHECKPOINT_VMM_FILES, CHECKPOINTS_DIRECTORY, HIBERNATE_DIRECTORY,
};
use crate::supervisor::EnvironmentRecord;

const RECORD_FILE: &str = "record.json";
const GENERATION_FILE: &str = "generation";
const FALLBACK_FILE: &str = "fallback.json";
const SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 128 * 1024;
const MIB: u64 = 1024 * 1024;
/// Free space required beyond the VM's memory size before writing a hibernate
/// image (`docs/dev/LOCAL-VM-SLEEP.md`, "Disk space").
const HIBERNATE_SPACE_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::supervisor) struct LocalHibernateRecord {
    pub schema_version: u32,
    pub restore_generation: u64,
    pub operation_id: Uuid,
    pub environment_id: Uuid,
    pub vsock_cid: u32,
    pub vmm_sha256: String,
    pub artifact_generation: String,
    pub root_generation: String,
    pub config_sha256: String,
    pub state_sha256: String,
    pub memory_bytes: u64,
    pub setup_disk_bytes: Option<u64>,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_bytes: u64,
    pub docker_disk_bytes: u64,
    pub skill_snapshot_sha256: Option<String>,
    pub environment_projection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub docker: bool,
    pub cw_runtime_catalog_generation: Option<String>,
    pub daemon_vsock_port: u32,
    pub intercept: bool,
    pub host_cpu: String,
    pub hibernated_at_unix_ms: i64,
    pub hibernate_reason: String,
}

impl LocalHibernateRecord {
    pub(in crate::supervisor) fn to_checkpoint_boot(&self) -> v1::CheckpointBoot {
        v1::CheckpointBoot {
            checkpoint_id: self.operation_id.to_string(),
            source_environment_id: self.environment_id.to_string(),
            config_sha256: self.config_sha256.clone(),
            state_sha256: self.state_sha256.clone(),
            memory_bytes: self.memory_bytes,
            setup_disk_bytes: self.setup_disk_bytes.unwrap_or_default(),
            vmm_sha256: self.vmm_sha256.clone(),
            boot: Some(v1::CheckpointBootBindings {
                skill_snapshot_sha256: self.skill_snapshot_sha256.clone().unwrap_or_default(),
                environment_projection_sha256: self
                    .environment_projection_sha256
                    .clone()
                    .unwrap_or_default(),
                managed_credential_clients: self.managed_credential_clients.clone(),
                docker: self.docker,
                cw_runtime_catalog_generation: self
                    .cw_runtime_catalog_generation
                    .clone()
                    .unwrap_or_default(),
                daemon_vsock_port: self.daemon_vsock_port,
                intercept: self.intercept,
            }),
            source_generation: self.restore_generation,
            state_identity: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::supervisor) struct HibernateSummary {
    pub hibernated_at_unix_ms: i64,
    pub reason: String,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FallbackRecord {
    reason: String,
    at_unix_ms: i64,
}

/// Canonical fallback reason codes shared with cloud `standard` hibernate
/// (`docs/dev/LOCAL-VM-SLEEP.md` & `crates/codewire-cli/.../idle_hibernate.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::supervisor) enum FallbackReason {
    GenerationConsumed,
    GenerationMismatch,
    VmmDigestMismatch,
    RuntimeImageDigestMismatch,
    VmConfigMismatch,
    DamagedMemoryFile,
    RestoreFailed,
}

impl FallbackReason {
    pub(in crate::supervisor) const fn as_str(self) -> &'static str {
        match self {
            Self::GenerationConsumed => "generation-consumed",
            Self::GenerationMismatch => "generation-mismatch",
            Self::VmmDigestMismatch => "vmm-digest-mismatch",
            Self::RuntimeImageDigestMismatch => "runtime-image-digest-mismatch",
            Self::VmConfigMismatch => "vm-config-mismatch",
            Self::DamagedMemoryFile => "damaged-memory-file",
            Self::RestoreFailed => "restore-failed",
        }
    }

    /// Underscore-formatted name for structured diagnostic logs (`LogField::Name`).
    pub(in crate::supervisor) const fn log_name(self) -> &'static str {
        match self {
            Self::GenerationConsumed => "generation_consumed",
            Self::GenerationMismatch => "generation_mismatch",
            Self::VmmDigestMismatch => "vmm_digest_mismatch",
            Self::RuntimeImageDigestMismatch => "runtime_image_digest_mismatch",
            Self::VmConfigMismatch => "vm_config_mismatch",
            Self::DamagedMemoryFile => "damaged_memory_file",
            Self::RestoreFailed => "restore_failed",
        }
    }
}

fn vm_dir(engine_root: &Path, environment_id: Uuid) -> PathBuf {
    engine_root.join("vms").join(environment_id.to_string())
}

pub(in crate::supervisor) fn hibernate_dir(engine_root: &Path, environment_id: Uuid) -> PathBuf {
    vm_dir(engine_root, environment_id).join(HIBERNATE_DIRECTORY)
}

fn checkpoints_in_dir(engine_root: &Path, environment_id: Uuid) -> PathBuf {
    vm_dir(engine_root, environment_id)
        .join(CHECKPOINTS_DIRECTORY)
        .join(CHECKPOINT_IN)
}

pub(in crate::supervisor) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_millis()).ok())
        .unwrap_or_default()
}

/// Verifies the state root has room for the VM's memory image plus 2 GiB
/// headroom before writing anything (`docs/dev/LOCAL-VM-SLEEP.md`, "Disk space").
pub(in crate::supervisor) fn require_hibernate_space(
    engine_root: &Path,
    memory_mib: u32,
) -> Result<(), Status> {
    let free = crate::fs_clone::free_bytes(engine_root)
        .map_err(|error| Status::internal(format!("checking free space failed: {error}")))?;
    let needed = (u64::from(memory_mib) * MIB).saturating_add(HIBERNATE_SPACE_HEADROOM_BYTES);
    if free < needed {
        return Err(Status::resource_exhausted(format!(
            "hibernating this VM needs {:.1} GiB free on the local state root and only {:.1} GiB are available",
            needed as f64 / (1024.0 * 1024.0 * 1024.0),
            free as f64 / (1024.0 * 1024.0 * 1024.0),
        )));
    }
    Ok(())
}

/// Persists `record.json` and the external one-shot `generation` guard under
/// `vms/<id>/hibernate/` (0700 dir, 0600 files), clearing any stale fallback.
pub(in crate::supervisor) fn write_record(
    engine_root: &Path,
    record: &LocalHibernateRecord,
) -> io::Result<()> {
    let vm = vm_dir(engine_root, record.environment_id);
    let vm_root = PrivateRoot::open(&vm).map_err(path_io)?;
    let dir = vm_root
        .ensure_dir(Path::new(HIBERNATE_DIRECTORY), 0o700)
        .map_err(path_io)?;
    let hib_root = PrivateRoot::open(&dir).map_err(path_io)?;

    let bytes = serde_json::to_vec(record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_private_atomic(hib_root.path(), RECORD_FILE, &bytes)?;
    write_private_atomic(
        hib_root.path(),
        GENERATION_FILE,
        format!("{}\n", record.restore_generation).as_bytes(),
    )?;
    let _ = fs::remove_file(hib_root.path().join(FALLBACK_FILE));
    sync_dir(hib_root.path())?;
    sync_dir(vm_root.path())?;
    Ok(())
}

/// Records the reason a hibernated VM fell back to a cold boot from disks.
pub(in crate::supervisor) fn write_fallback(
    engine_root: &Path,
    environment_id: Uuid,
    reason: FallbackReason,
) {
    let vm = vm_dir(engine_root, environment_id);
    let Ok(vm_root) = PrivateRoot::open(&vm) else {
        return;
    };
    let Ok(dir) = vm_root.ensure_dir(Path::new(HIBERNATE_DIRECTORY), 0o700) else {
        return;
    };
    let Ok(hib_root) = PrivateRoot::open(&dir) else {
        return;
    };
    let payload = FallbackRecord {
        reason: reason.as_str().to_owned(),
        at_unix_ms: now_unix_ms(),
    };
    if let Ok(bytes) = serde_json::to_vec(&payload) {
        let _ = write_private_atomic(hib_root.path(), FALLBACK_FILE, &bytes);
        let _ = sync_dir(hib_root.path());
    }
}

/// Reads the last hibernate fallback reason for `environment_id`, if any.
pub(in crate::supervisor) fn read_fallback(
    engine_root: &Path,
    environment_id: Uuid,
) -> Option<String> {
    let hib = hibernate_dir(engine_root, environment_id);
    let hib_root = PrivateRoot::open(&hib).ok()?;
    let bytes = read_regular_nofollow(&hib_root.path().join(FALLBACK_FILE), 4096).ok()?;
    let record: FallbackRecord = serde_json::from_slice(&bytes).ok()?;
    (!record.reason.trim().is_empty()).then_some(record.reason)
}

/// Clears any stored fallback notice (called on the next start or stop).
pub(in crate::supervisor) fn clear_fallback(engine_root: &Path, environment_id: Uuid) {
    let hib = hibernate_dir(engine_root, environment_id);
    if let Ok(hib_root) = PrivateRoot::open(&hib) {
        let _ = fs::remove_file(hib_root.path().join(FALLBACK_FILE));
        let _ = sync_dir(hib_root.path());
        remove_dir_if_empty(&hib);
    }
}

/// Returns hibernate summary metadata when both `record.json` and the unconsumed
/// `generation` guard exist and parse cleanly.
pub(in crate::supervisor) fn read_summary(
    engine_root: &Path,
    environment_id: Uuid,
) -> Option<HibernateSummary> {
    let hib = hibernate_dir(engine_root, environment_id);
    let hib_root = PrivateRoot::open(&hib).ok()?;
    let gen_meta = fs::symlink_metadata(hib_root.path().join(GENERATION_FILE)).ok()?;
    if !gen_meta.file_type().is_file() {
        return None;
    }
    let bytes = read_regular_nofollow(&hib_root.path().join(RECORD_FILE), MAX_RECORD_BYTES).ok()?;
    let record: LocalHibernateRecord = serde_json::from_slice(&bytes).ok()?;
    if record.schema_version != SCHEMA_VERSION || record.environment_id != environment_id {
        return None;
    }
    Some(HibernateSummary {
        hibernated_at_unix_ms: record.hibernated_at_unix_ms,
        reason: record.hibernate_reason,
        memory_bytes: record.memory_bytes,
    })
}

/// True when `environment_id` currently has a valid hibernate image on disk.
pub(in crate::supervisor) fn is_hibernated(engine_root: &Path, environment_id: Uuid) -> bool {
    read_summary(engine_root, environment_id).is_some()
}

/// True when any hibernate record or generation guard exists on disk (even if
/// damaged or consumed), so a start runs admission and surfaces a clear
/// fallback notice instead of silently ignoring leftover files.
pub(in crate::supervisor) fn has_pending_hibernate(
    engine_root: &Path,
    environment_id: Uuid,
) -> bool {
    let hib = hibernate_dir(engine_root, environment_id);
    fs::symlink_metadata(hib.join(RECORD_FILE)).is_ok()
        || fs::symlink_metadata(hib.join(GENERATION_FILE)).is_ok()
}

/// Removes `checkpoints/in` and `hibernate/{record.json,generation}`, preserving
/// any `fallback.json`.
pub(in crate::supervisor) fn clear_hibernate_image(engine_root: &Path, environment_id: Uuid) {
    let ckpt_dir = vm_dir(engine_root, environment_id).join(CHECKPOINTS_DIRECTORY);
    if let Ok(checkpoints) = PrivateRoot::open(&ckpt_dir) {
        let _ = crate::state::remove_checkpoint_tree(&checkpoints, CHECKPOINT_IN);
    }
    let hib = hibernate_dir(engine_root, environment_id);
    if let Ok(hib_root) = PrivateRoot::open(&hib) {
        let _ = fs::remove_file(hib_root.path().join(RECORD_FILE));
        let _ = fs::remove_file(hib_root.path().join(GENERATION_FILE));
        let _ = sync_dir(hib_root.path());
        remove_dir_if_empty(&hib);
    }
}

/// Removes all hibernate files including `fallback.json` and `checkpoints/in`.
pub(in crate::supervisor) fn clear_all(engine_root: &Path, environment_id: Uuid) {
    clear_hibernate_image(engine_root, environment_id);
    clear_fallback(engine_root, environment_id);
}

/// Populates `hibernated_at_unix_ms`, `hibernate_reason`,
/// `hibernate_memory_bytes`, `hibernate_fallback_reason`, and idle sleep
/// policy fields on `environment`.
pub(in crate::supervisor) fn apply_to_environment(
    engine_root: &Path,
    environment: &mut v1::Environment,
) {
    super::idle_sleep::apply_to_environment(engine_root, environment);
    let Ok(id) = Uuid::parse_str(&environment.id) else {
        return;
    };
    if environment.state == v1::EnvironmentState::Stopped as i32 {
        if let Some(summary) = read_summary(engine_root, id) {
            environment.hibernated_at_unix_ms = summary.hibernated_at_unix_ms;
            environment.hibernate_reason = summary.reason;
            environment.hibernate_memory_bytes = summary.memory_bytes;
        }
        environment.hibernate_fallback_reason.clear();
    } else {
        environment.hibernated_at_unix_ms = 0;
        environment.hibernate_reason.clear();
        environment.hibernate_memory_bytes = 0;
        if environment.state == v1::EnvironmentState::Running as i32 {
            environment.hibernate_fallback_reason =
                read_fallback(engine_root, id).unwrap_or_default();
        } else {
            environment.hibernate_fallback_reason.clear();
        }
    }
}

/// Validates and consumes a pending hibernate restore BEFORE the VMM starts.
///
/// Always unlinks and fsyncs `hibernate/generation` first so a memory image is
/// restored at most once. On any mismatch, missing file, or digest failure,
/// clears the unusable hibernate image and returns `Err(FallbackReason)` so the
/// caller falls back to a clean cold boot from persistent disks.
#[allow(clippy::too_many_arguments)]
pub(in crate::supervisor) fn admit_restore(
    engine_root: &Path,
    environment: &EnvironmentRecord,
    expected_restore_generation: u64,
    current_vmm_sha256: &str,
    current_host_cpu: &str,
    expected_artifact_generation: &str,
    start_request: &v1::StartVmRequest,
) -> Result<LocalHibernateRecord, FallbackReason> {
    let result = admit_restore_inner(
        engine_root,
        environment,
        expected_restore_generation,
        current_vmm_sha256,
        current_host_cpu,
        expected_artifact_generation,
        start_request,
    );
    if result.is_err() {
        clear_hibernate_image(engine_root, environment.id);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn admit_restore_inner(
    engine_root: &Path,
    environment: &EnvironmentRecord,
    expected_restore_generation: u64,
    current_vmm_sha256: &str,
    current_host_cpu: &str,
    expected_artifact_generation: &str,
    start_request: &v1::StartVmRequest,
) -> Result<LocalHibernateRecord, FallbackReason> {
    let hib = hibernate_dir(engine_root, environment.id);
    let Ok(hib_root) = PrivateRoot::open(&hib) else {
        return Err(FallbackReason::GenerationConsumed);
    };

    // Consume the external generation guard BEFORE touching the VMM so a memory
    // image can never be restored twice, even across a mid-restore crash.
    let gen_path = hib_root.path().join(GENERATION_FILE);
    let external_gen = match read_regular_nofollow(&gen_path, 64) {
        Ok(bytes) => {
            fs::remove_file(&gen_path).map_err(|_| FallbackReason::DamagedMemoryFile)?;
            sync_dir(hib_root.path()).map_err(|_| FallbackReason::DamagedMemoryFile)?;
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or(FallbackReason::DamagedMemoryFile)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(FallbackReason::GenerationConsumed);
        }
        Err(_) => {
            let _ = fs::remove_file(&gen_path);
            let _ = sync_dir(hib_root.path());
            return Err(FallbackReason::DamagedMemoryFile);
        }
    };
    if external_gen != expected_restore_generation {
        return Err(FallbackReason::GenerationMismatch);
    }

    let record_bytes = read_regular_nofollow(&hib_root.path().join(RECORD_FILE), MAX_RECORD_BYTES)
        .map_err(|_| FallbackReason::DamagedMemoryFile)?;
    let record: LocalHibernateRecord =
        serde_json::from_slice(&record_bytes).map_err(|_| FallbackReason::DamagedMemoryFile)?;

    if record.schema_version != SCHEMA_VERSION || record.environment_id != environment.id {
        return Err(FallbackReason::DamagedMemoryFile);
    }
    if record.restore_generation != expected_restore_generation {
        return Err(FallbackReason::GenerationMismatch);
    }
    if record.vmm_sha256 != current_vmm_sha256 {
        return Err(FallbackReason::VmmDigestMismatch);
    }
    if record.artifact_generation != expected_artifact_generation {
        return Err(FallbackReason::RuntimeImageDigestMismatch);
    }
    let opt = |value: &str| (!value.is_empty()).then(|| value.to_owned());
    if record.host_cpu != current_host_cpu
        || record.root_generation != start_request.root_generation
        || record.vcpus != environment.vcpus
        || record.memory_mib != environment.memory_mib
        || record.disk_bytes != environment.disk_bytes
        || record.docker_disk_bytes != environment.docker_disk_bytes
        || record.docker != (start_request.docker_disk_bytes != 0)
        || record.cw_runtime_catalog_generation != opt(&start_request.cw_runtime_catalog_generation)
        || record.daemon_vsock_port != start_request.daemon_vsock_port
        || record.intercept != start_request.intercept
        || record.skill_snapshot_sha256 != opt(&start_request.skill_snapshot_sha256)
        || record.environment_projection_sha256 != opt(&start_request.environment_projection_sha256)
        || record.managed_credential_clients != start_request.managed_credential_clients
        || start_request.setup_total_bytes != 0
    {
        return Err(FallbackReason::VmConfigMismatch);
    }

    // Verify checkpoints/in files exist as regular files (not symlinks), match
    // recorded memory size, and match recorded config.json / state.json SHA-256.
    let ckpt_in = checkpoints_in_dir(engine_root, environment.id);
    let Ok(ckpt_root) = PrivateRoot::open(&ckpt_in) else {
        return Err(FallbackReason::DamagedMemoryFile);
    };
    for name in CHECKPOINT_VMM_FILES {
        let path = ckpt_root.path().join(name);
        let meta = fs::symlink_metadata(&path).map_err(|_| FallbackReason::DamagedMemoryFile)?;
        if !meta.file_type().is_file() {
            return Err(FallbackReason::DamagedMemoryFile);
        }
        if name == "memory-ranges" && meta.len() != record.memory_bytes {
            return Err(FallbackReason::DamagedMemoryFile);
        }
    }
    let config_sha = sha256_regular_file(&ckpt_root.path().join("config.json"))
        .map_err(|_| FallbackReason::DamagedMemoryFile)?;
    let state_sha = sha256_regular_file(&ckpt_root.path().join("state.json"))
        .map_err(|_| FallbackReason::DamagedMemoryFile)?;
    if config_sha != record.config_sha256 || state_sha != record.state_sha256 {
        return Err(FallbackReason::DamagedMemoryFile);
    }

    Ok(record)
}

pub(in crate::supervisor) fn write_private_atomic(
    dir: &Path,
    name: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let staged = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&staged);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&staged, dir.join(name))?;
    Ok(())
}

pub(in crate::supervisor) fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub(in crate::supervisor) fn remove_dir_if_empty(path: &Path) {
    let _ = fs::remove_dir(path);
}

pub(in crate::supervisor) fn path_io(error: crate::host::path::PathError) -> io::Error {
    io::Error::other(error.to_string())
}

pub(in crate::supervisor) fn read_regular_nofollow(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.is_empty() || (bytes.len() as u64) > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file size out of bounds",
        ));
    }
    Ok(bytes)
}

fn sha256_regular_file(path: &Path) -> io::Result<String> {
    let bytes = read_regular_nofollow(path, 64 * 1024 * 1024)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::supervisor::StoredEnvironmentState;
    use crate::workspace_plan::WorkspacePlan;

    fn sample_env(id: Uuid) -> EnvironmentRecord {
        EnvironmentRecord {
            id,
            name: "nap".to_owned(),
            state: StoredEnvironmentState::Stopped,
            vcpus: 2,
            memory_mib: 1024,
            disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: 0,
            generation: 3,
            host_ports: Vec::new(),
            mesh: None,
            workspace_plan: WorkspacePlan {
                schema_version: 1,
                inputs: Vec::new(),
            },
            project_spec_json: None,
            project_spec_sha256: None,
            access_profile: None,
            access_binding: None,
            platform_source_authority: None,
            cw_runtime: None,
            runner: None,
            active_artifact_generation: Some("a".repeat(64)),
            staging_artifact_generation: None,
            active_workspace_generation: None,
            staging_workspace_generation: None,
            rollback_workspace_generation: None,
        }
    }

    fn sample_start_request(id: Uuid) -> v1::StartVmRequest {
        v1::StartVmRequest {
            environment_id: id.to_string(),
            generation: 4,
            vsock_cid: 11,
            daemon_vsock_port: 7777,
            state_disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: 0,
            vcpus: 2,
            memory_mib: 1024,
            root_generation: "b".repeat(64),
            managed_credential_clients: "v1:none".to_owned(),
            ..Default::default()
        }
    }

    fn setup_hibernated(
        id: Uuid,
        vmm_sha: &str,
        artifact_gen: &str,
        host_cpu: &str,
    ) -> tempfile::TempDir {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let vm = vm_dir(engine.path(), id);
        fs::create_dir_all(&vm).unwrap();
        fs::set_permissions(&vm, fs::Permissions::from_mode(0o700)).unwrap();
        let ckpt_in = checkpoints_in_dir(engine.path(), id);
        fs::create_dir_all(&ckpt_in).unwrap();
        fs::set_permissions(
            vm.join(CHECKPOINTS_DIRECTORY),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&ckpt_in, fs::Permissions::from_mode(0o700)).unwrap();
        let config_bytes = b"{\"vmm\":\"config\"}";
        let state_bytes = b"{\"vmm\":\"state\"}";
        let memory_bytes = vec![0xab_u8; 4096];
        fs::write(ckpt_in.join("config.json"), config_bytes).unwrap();
        fs::write(ckpt_in.join("state.json"), state_bytes).unwrap();
        fs::write(ckpt_in.join("memory-ranges"), &memory_bytes).unwrap();
        for name in CHECKPOINT_VMM_FILES {
            fs::set_permissions(ckpt_in.join(name), fs::Permissions::from_mode(0o400)).unwrap();
        }
        let record = LocalHibernateRecord {
            schema_version: SCHEMA_VERSION,
            restore_generation: 3,
            operation_id: Uuid::new_v4(),
            environment_id: id,
            vsock_cid: 11,
            vmm_sha256: vmm_sha.to_owned(),
            artifact_generation: artifact_gen.to_owned(),
            root_generation: "b".repeat(64),
            config_sha256: format!("{:x}", Sha256::digest(config_bytes)),
            state_sha256: format!("{:x}", Sha256::digest(state_bytes)),
            memory_bytes: memory_bytes.len() as u64,
            setup_disk_bytes: None,
            vcpus: 2,
            memory_mib: 1024,
            disk_bytes: crate::state::MINIMUM_STATE_DISK_BYTES,
            docker_disk_bytes: 0,
            skill_snapshot_sha256: None,
            environment_projection_sha256: None,
            managed_credential_clients: "v1:none".to_owned(),
            docker: false,
            cw_runtime_catalog_generation: None,
            daemon_vsock_port: 7777,
            intercept: false,
            host_cpu: host_cpu.to_owned(),
            hibernated_at_unix_ms: 1_764_300_000_000,
            hibernate_reason: "user".to_owned(),
        };
        write_record(engine.path(), &record).unwrap();
        engine
    }

    #[test]
    fn restore_admits_once_and_rejects_second_attempt() {
        let id = Uuid::new_v4();
        let env = sample_env(id);
        let req = sample_start_request(id);
        let vmm_sha = "c".repeat(64);
        let artifact = "a".repeat(64);
        let engine = setup_hibernated(id, &vmm_sha, &artifact, "AuthenticAMD:25:97:2");

        assert!(is_hibernated(engine.path(), id));
        let admitted = admit_restore(
            engine.path(),
            &env,
            3,
            &vmm_sha,
            "AuthenticAMD:25:97:2",
            &artifact,
            &req,
        )
        .unwrap();
        assert_eq!(admitted.restore_generation, 3);
        assert!(!is_hibernated(engine.path(), id));
        assert!(has_pending_hibernate(engine.path(), id));

        // Second admission sees GenerationConsumed and cleans up files.
        let err = admit_restore(
            engine.path(),
            &env,
            3,
            &vmm_sha,
            "AuthenticAMD:25:97:2",
            &artifact,
            &req,
        )
        .unwrap_err();
        assert_eq!(err, FallbackReason::GenerationConsumed);
        assert!(!checkpoints_in_dir(engine.path(), id).exists());
        assert!(!has_pending_hibernate(engine.path(), id));
    }

    #[test]
    fn mismatches_and_corruption_return_canonical_fallback_reasons_and_clean_up() {
        let id = Uuid::new_v4();
        let env = sample_env(id);
        let req = sample_start_request(id);
        let vmm_sha = "c".repeat(64);
        let other_vmm = "d".repeat(64);
        let artifact = "a".repeat(64);
        let other_artifact = "e".repeat(64);

        // VMM digest mismatch
        let engine = setup_hibernated(id, &vmm_sha, &artifact, "cpu-a");
        assert_eq!(
            admit_restore(engine.path(), &env, 3, &other_vmm, "cpu-a", &artifact, &req)
                .unwrap_err(),
            FallbackReason::VmmDigestMismatch
        );
        assert!(!checkpoints_in_dir(engine.path(), id).exists());

        // Runtime artifact generation mismatch
        let engine = setup_hibernated(id, &vmm_sha, &artifact, "cpu-a");
        assert_eq!(
            admit_restore(
                engine.path(),
                &env,
                3,
                &vmm_sha,
                "cpu-a",
                &other_artifact,
                &req
            )
            .unwrap_err(),
            FallbackReason::RuntimeImageDigestMismatch
        );

        // VM config mismatch
        let engine = setup_hibernated(id, &vmm_sha, &artifact, "cpu-a");
        let mut resized = env.clone();
        resized.memory_mib = 2048;
        assert_eq!(
            admit_restore(
                engine.path(),
                &resized,
                3,
                &vmm_sha,
                "cpu-a",
                &artifact,
                &req
            )
            .unwrap_err(),
            FallbackReason::VmConfigMismatch
        );

        // Truncated memory-ranges
        let engine = setup_hibernated(id, &vmm_sha, &artifact, "cpu-a");
        let mem = checkpoints_in_dir(engine.path(), id).join("memory-ranges");
        fs::set_permissions(&mem, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&mem, b"short").unwrap();
        assert_eq!(
            admit_restore(engine.path(), &env, 3, &vmm_sha, "cpu-a", &artifact, &req).unwrap_err(),
            FallbackReason::DamagedMemoryFile
        );
        assert!(!checkpoints_in_dir(engine.path(), id).exists());

        // Fallback notice persists and clears cleanly.
        write_fallback(engine.path(), id, FallbackReason::DamagedMemoryFile);
        assert_eq!(
            read_fallback(engine.path(), id).as_deref(),
            Some("damaged-memory-file")
        );
        clear_fallback(engine.path(), id);
        assert_eq!(read_fallback(engine.path(), id), None);
    }
}
