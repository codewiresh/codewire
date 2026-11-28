//! Hibernate and restore for a `standard` Pod's VM (#6647,
//! `docs/dev/SANDBOX-SLEEP.md`).
//!
//! Layout on the Sandbox's encrypted volume under `/state/runtime/`:
//! - `vms/<POD_VM_ID>/checkpoints/in/{config.json,state.json,memory-ranges}`:
//!   the VMM's sealed (0400) memory and device state written by
//!   [`crate::CloudHypervisorRunner::hibernate`].
//! - `hibernate/record.json` (0600 inside 0700 `hibernate/`): sibling metadata
//!   binding the memory file to `restore_generation`, `vmm_sha256`,
//!   `runtime_image_digest`, `image_disk_id`, `build_id`, VM shape, and
//!   [`RestoreBoot`].
//! - `hibernate/generation` (0600): external one-shot generation guard consumed
//!   and deleted BEFORE the VMM starts restoring, so a memory file can never be
//!   restored twice even if a Pod crashes mid-restore.
//!
//! Security & lifecycle invariants enforced here:
//! 1. **Restore at most once:** `admit_hibernate_restore` deletes
//!    `hibernate/generation` before attempting restore.
//! 2. **Strict digest/config match:** VMM digest, runtime image digest, image
//!    disk id/build id, VM config, and `config.json`/`state.json` digests must
//!    all match; otherwise artifacts are deleted, a host-observed `fallback`
//!    record is written, and the Pod cold-boots cleanly from disks.
//! 3. **Ports closed until `rebind-ok`:** On a restored boot, `pod-runtime`
//!    keeps Pod ports `7777` and `2222` closed and `daemon/ready` absent until
//!    the restored daemon sends `rebind-ok\n` over vsock `7784`.
//! 4. **One-shot `rebind-ok`:** `HibernateControl` accepts `rebind-ok\n` at
//!    most once and ONLY while actively restoring (never on a normal boot,
//!    never re-armable).
//! 5. **Delete memory file only after re-bind:** `checkpoints/in` and
//!    `hibernate/` stay on disk until `rebind-ok\n` arrives (or a fallback/cold
//!    boot discards them).

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Notify;

use super::{EgressMode, POD_VM_ID, PodRuntimeError, PodSettings};
use crate::host::path::PrivateRoot;
use crate::runner::{CheckpointImageDisk, RestoreBoot};
use crate::state::{CHECKPOINT_IN, CHECKPOINT_VMM_FILES};

/// Host-observed Pod log marker for hibernate, restore, and fallback events.
/// Guest output reaches the Pod log only escaped and prefixed with
/// [`super::guest_log::PREFIX`], so a line starting with this was written here
/// and nowhere else.
pub(super) const HIBERNATE_RECORD_MARKER: &str = "standard runtime: vm-hibernate-record ";

/// Sibling directory under `/state/runtime` holding `record.json` and the
/// one-shot `generation` guard. Kept outside `checkpoints/in` so the VMM never
/// touches it and `cw __snapshot-clear --standard-vm` strips it alongside
/// `checkpoints/`.
pub(super) const HIBERNATE_DIR_NAME: &str = "hibernate";
const RECORD_FILE_NAME: &str = "record.json";
const GENERATION_FILE_NAME: &str = "generation";
const HIBERNATE_RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 128 * 1024;

/// Persisted beside `checkpoints/in` after `CloudHypervisorRunner::hibernate`
/// completes cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct HibernateRecord {
    pub schema_version: u32,
    pub restore_generation: u64,
    pub checkpoint_id: uuid::Uuid,
    pub source_generation: u64,
    pub config_sha256: String,
    pub state_sha256: String,
    pub setup_disk_bytes: Option<u64>,
    pub cw_runtime_catalog_generation: Option<String>,
    pub daemon_vsock_port: u32,
    pub vmm_sha256: String,
    pub runtime_image_digest: String,
    pub workspace_image: String,
    pub image_disk_id: String,
    pub build_id: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub egress_mode: String,
    pub docker: bool,
    pub memory_bytes: u64,
}

impl HibernateRecord {
    pub(super) fn to_restore_boot(&self) -> RestoreBoot {
        RestoreBoot {
            checkpoint_id: self.checkpoint_id,
            source_environment_id: POD_VM_ID,
            config_sha256: self.config_sha256.clone(),
            state_sha256: self.state_sha256.clone(),
            memory_bytes: self.memory_bytes,
            setup_disk_bytes: self.setup_disk_bytes,
            vmm_sha256: self.vmm_sha256.clone(),
            source_generation: self.source_generation,
            skill_snapshot_sha256: None,
            environment_projection_sha256: None,
            managed_credential_clients: Default::default(),
            docker: self.docker,
            cw_runtime_catalog_generation: self.cw_runtime_catalog_generation.clone(),
            daemon_vsock_port: self.daemon_vsock_port,
            intercept: false,
            image_disk: Some(CheckpointImageDisk {
                image_disk_id: self.image_disk_id.clone(),
                build_id: self.build_id.clone(),
            }),
            bound_secrets: Default::default(),
            state_identity: None,
        }
    }
}

fn vm_checkpoints_dir(engine_root: &Path) -> PathBuf {
    engine_root
        .join("vms")
        .join(POD_VM_ID.to_string())
        .join("checkpoints")
}

/// Why a restore could not proceed and fell back to a clean cold boot from disks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FallbackReason {
    GenerationConsumed,
    GenerationMismatch,
    VmmDigestMismatch,
    RuntimeImageDigestMismatch,
    ImageDiskMismatch,
    VmConfigMismatch,
    DamagedMemoryFile,
    RestoreFailed,
    RebindFailed,
}

impl FallbackReason {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::GenerationConsumed => "generation-consumed",
            Self::GenerationMismatch => "generation-mismatch",
            Self::VmmDigestMismatch => "vmm-digest-mismatch",
            Self::RuntimeImageDigestMismatch => "runtime-image-digest-mismatch",
            Self::ImageDiskMismatch => "image-disk-mismatch",
            Self::VmConfigMismatch => "vm-config-mismatch",
            Self::DamagedMemoryFile => "damaged-memory-file",
            Self::RestoreFailed => "restore-failed",
            Self::RebindFailed => "rebind-failed",
        }
    }
}

/// Host-observed log lines read by orchestration and billing.
pub(super) fn format_hibernated_line(record: &HibernateRecord) -> String {
    let payload = serde_json::json!({
        "event": "hibernated",
        "restore_generation": record.restore_generation,
        "vmm_sha256": record.vmm_sha256,
        "runtime_image_digest": record.runtime_image_digest,
        "image_disk_id": record.image_disk_id,
        "build_id": record.build_id,
        "memory_bytes": record.memory_bytes,
        "at_unix_ms": now_unix_ms(),
    });
    format!("{HIBERNATE_RECORD_MARKER}{payload}")
}

pub(super) fn format_restored_line(restore_generation: u64) -> String {
    let payload = serde_json::json!({
        "event": "restored",
        "restore_generation": restore_generation,
        "at_unix_ms": now_unix_ms(),
    });
    format!("{HIBERNATE_RECORD_MARKER}{payload}")
}

pub(super) fn format_fallback_line(restore_generation: u64, reason: FallbackReason) -> String {
    let payload = serde_json::json!({
        "event": "fallback",
        "restore_generation": restore_generation,
        "reason": reason.as_str(),
        "at_unix_ms": now_unix_ms(),
    });
    format!("{HIBERNATE_RECORD_MARKER}{payload}")
}

pub(super) fn format_hibernate_failed_line(reason: &str) -> String {
    let payload = serde_json::json!({
        "event": "hibernate-failed",
        "reason": reason,
        "at_unix_ms": now_unix_ms(),
    });
    format!("{HIBERNATE_RECORD_MARKER}{payload}")
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

fn egress_mode_str(mode: EgressMode) -> &'static str {
    match mode {
        EgressMode::GuestCarried => codewire_daemon_proto::POD_RUNTIME_EGRESS_MODE_GUEST_CARRIED,
        EgressMode::Broker => codewire_daemon_proto::POD_RUNTIME_EGRESS_MODE_BROKER,
    }
}

/// Validates a `sha256:<64 lowercase hex>` runtime image digest.
pub(super) fn is_valid_runtime_image_digest(digest: &str) -> bool {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Writes `record.json` and the external `generation` guard durably under
/// `engine_root/hibernate/` (0700 directory, 0600 files).
pub(super) fn write_hibernate_record(
    engine_root: &Path,
    record: &HibernateRecord,
) -> Result<(), PodRuntimeError> {
    let root = PrivateRoot::open(engine_root)?;
    let dir = root.path().join(HIBERNATE_DIR_NAME);
    match fs::create_dir(&dir) {
        Ok(()) => fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let hib_root = PrivateRoot::open(&dir)?;

    let bytes = serde_json::to_vec(record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_private_atomic(hib_root.path(), RECORD_FILE_NAME, &bytes)?;
    write_private_atomic(
        hib_root.path(),
        GENERATION_FILE_NAME,
        format!("{}\n", record.restore_generation).as_bytes(),
    )?;
    sync_dir(hib_root.path())?;
    sync_dir(root.path())?;
    Ok(())
}

fn write_private_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
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

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Removes all host-side hibernate artifacts (`engine_root/hibernate/` and every
/// entry inside `engine_root/vms/<POD_VM_ID>/checkpoints/`), refusing to
/// traverse symlinks.
///
/// The `checkpoints/` directory itself is preserved in place (same inode): on a
/// restored boot this runs after `CloudHypervisorRunner::start_hosted_restored`
/// has already launched Cloud Hypervisor with Landlock bound to
/// `paths.checkpoints_dir`, so deleting the directory itself would break any
/// subsequent hibernate on the restored VM.
pub(super) fn clear_hibernate_artifacts(engine_root: &Path) {
    let hib_dir = engine_root.join(HIBERNATE_DIR_NAME);
    match fs::symlink_metadata(&hib_dir) {
        Ok(meta) if meta.file_type().is_dir() => {
            if let Err(error) = fs::remove_dir_all(&hib_dir) {
                eprintln!(
                    "standard runtime: could not clear hibernate directory {}: {error}",
                    hib_dir.display()
                );
            }
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            eprintln!(
                "standard runtime: refusing to follow symlink at {}",
                hib_dir.display()
            );
        }
        Ok(_) => {
            if let Err(error) = fs::remove_file(&hib_dir) {
                eprintln!(
                    "standard runtime: could not remove unexpected hibernate file {}: {error}",
                    hib_dir.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            eprintln!(
                "standard runtime: could not inspect {}: {error}",
                hib_dir.display()
            );
        }
    }

    let vm_checkpoints = vm_checkpoints_dir(engine_root);
    match fs::symlink_metadata(&vm_checkpoints) {
        Ok(meta) if meta.file_type().is_dir() => match fs::read_dir(&vm_checkpoints) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            eprintln!(
                                "standard runtime: could not read entry in {}: {error}",
                                vm_checkpoints.display()
                            );
                            continue;
                        }
                    };
                    let path = entry.path();
                    match fs::symlink_metadata(&path) {
                        Ok(child_meta) if child_meta.file_type().is_dir() => {
                            if let Err(error) = fs::remove_dir_all(&path) {
                                eprintln!(
                                    "standard runtime: could not clear checkpoint tree {}: {error}",
                                    path.display()
                                );
                            }
                        }
                        Ok(_) => {
                            if let Err(error) = fs::remove_file(&path) {
                                eprintln!(
                                    "standard runtime: could not remove checkpoint file {}: {error}",
                                    path.display()
                                );
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            eprintln!(
                                "standard runtime: could not inspect {}: {error}",
                                path.display()
                            );
                        }
                    }
                }
                if let Err(error) = sync_dir(&vm_checkpoints) {
                    eprintln!(
                        "standard runtime: could not sync checkpoint directory {}: {error}",
                        vm_checkpoints.display()
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "standard runtime: could not list checkpoint directory {}: {error}",
                    vm_checkpoints.display()
                );
            }
        },
        Ok(meta) if meta.file_type().is_symlink() => {
            eprintln!(
                "standard runtime: refusing to follow symlink at {}",
                vm_checkpoints.display()
            );
        }
        Ok(_) => {
            if let Err(error) = fs::remove_file(&vm_checkpoints) {
                eprintln!(
                    "standard runtime: could not remove unexpected checkpoint file {}: {error}",
                    vm_checkpoints.display()
                );
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            eprintln!(
                "standard runtime: could not inspect {}: {error}",
                vm_checkpoints.display()
            );
        }
    }
}

/// Validates and consumes a pending hibernate restore for `expected_generation`
/// BEFORE the VMM starts (`docs/dev/SANDBOX-SLEEP.md`, "After a restore").
///
/// Always consumes `hibernate/generation` immediately so a memory file is
/// restored at most once. On any mismatch or corruption, clears all hibernate
/// artifacts and returns `Err(FallbackReason)` so the caller falls back to a
/// clean cold boot from disks.
pub(super) fn admit_hibernate_restore(
    engine_root: &Path,
    settings: &PodSettings,
    expected_generation: u64,
    current_vmm_sha256: &str,
) -> Result<HibernateRecord, FallbackReason> {
    let result = admit_hibernate_restore_inner(
        engine_root,
        settings,
        expected_generation,
        current_vmm_sha256,
    );
    if result.is_err() {
        clear_hibernate_artifacts(engine_root);
    }
    result
}

fn consume_generation_guard_with(
    dir: &Path,
    gen_path: &Path,
    remove: impl FnOnce(&Path) -> io::Result<()>,
    sync: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<u64, FallbackReason> {
    match read_regular_nofollow(gen_path, 64) {
        Ok(bytes) => {
            remove(gen_path).map_err(|_| FallbackReason::DamagedMemoryFile)?;
            sync(dir).map_err(|_| FallbackReason::DamagedMemoryFile)?;
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or(FallbackReason::DamagedMemoryFile)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(FallbackReason::GenerationConsumed)
        }
        Err(_) => {
            let _ = remove(gen_path);
            let _ = sync(dir);
            Err(FallbackReason::DamagedMemoryFile)
        }
    }
}

fn admit_hibernate_restore_inner(
    engine_root: &Path,
    settings: &PodSettings,
    expected_generation: u64,
    current_vmm_sha256: &str,
) -> Result<HibernateRecord, FallbackReason> {
    let hib_dir = engine_root.join(HIBERNATE_DIR_NAME);
    let Ok(hib_root) = PrivateRoot::open(&hib_dir) else {
        return Err(FallbackReason::GenerationConsumed);
    };

    // Read and immediately consume the external generation guard BEFORE
    // touching the VMM, enforcing restore-at-most-once even across crashes.
    // Fail closed if unlinking or fsyncing the guard fails so a memory file
    // can never be restored while its generation guard remains on disk.
    let gen_path = hib_root.path().join(GENERATION_FILE_NAME);
    let external_gen = consume_generation_guard_with(
        hib_root.path(),
        &gen_path,
        |path| fs::remove_file(path),
        sync_dir,
    )?;

    if external_gen != expected_generation {
        return Err(FallbackReason::GenerationMismatch);
    }

    let record_bytes =
        read_regular_nofollow(&hib_root.path().join(RECORD_FILE_NAME), MAX_RECORD_BYTES)
            .map_err(|_| FallbackReason::DamagedMemoryFile)?;
    let record: HibernateRecord =
        serde_json::from_slice(&record_bytes).map_err(|_| FallbackReason::DamagedMemoryFile)?;

    if record.schema_version != HIBERNATE_RECORD_SCHEMA_VERSION {
        return Err(FallbackReason::DamagedMemoryFile);
    }
    if record.restore_generation != expected_generation {
        return Err(FallbackReason::GenerationMismatch);
    }
    if record.vmm_sha256 != current_vmm_sha256 {
        return Err(FallbackReason::VmmDigestMismatch);
    }
    if settings.runtime_image_digest.as_deref() != Some(record.runtime_image_digest.as_str()) {
        return Err(FallbackReason::RuntimeImageDigestMismatch);
    }
    if record.image_disk_id != settings.image_disk_id || record.build_id != settings.build_id {
        return Err(FallbackReason::ImageDiskMismatch);
    }
    if record.vcpus != settings.vcpus
        || record.memory_mib != settings.memory_mib
        || record.egress_mode != egress_mode_str(settings.egress_mode)
        || record.docker != settings.docker_disk_bytes.is_some()
    {
        return Err(FallbackReason::VmConfigMismatch);
    }

    // Verify the VMM checkpoint files under checkpoints/in exist as regular
    // files (not symlinks), match recorded config/state SHA-256 and memory size.
    let ckpt_in = vm_checkpoints_dir(engine_root).join(CHECKPOINT_IN);
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

fn read_regular_nofollow(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
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
    let bytes = read_regular_nofollow(path, 16 * 1024 * 1024)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// Builds a [`HibernateRecord`] from a completed [`crate::runner::Hibernation`].
pub(super) fn build_record(
    settings: &PodSettings,
    restore_generation: u64,
    vmm_sha256: String,
    runtime_image_digest: String,
    restore: RestoreBoot,
) -> HibernateRecord {
    HibernateRecord {
        schema_version: HIBERNATE_RECORD_SCHEMA_VERSION,
        restore_generation,
        checkpoint_id: restore.checkpoint_id,
        source_generation: restore.source_generation,
        config_sha256: restore.config_sha256,
        state_sha256: restore.state_sha256,
        setup_disk_bytes: restore.setup_disk_bytes,
        cw_runtime_catalog_generation: restore.cw_runtime_catalog_generation,
        daemon_vsock_port: restore.daemon_vsock_port,
        vmm_sha256,
        runtime_image_digest,
        workspace_image: settings.workspace_image.clone(),
        image_disk_id: settings.image_disk_id.clone(),
        build_id: settings.build_id.clone(),
        vcpus: settings.vcpus,
        memory_mib: settings.memory_mib,
        egress_mode: egress_mode_str(settings.egress_mode).to_owned(),
        docker: settings.docker_disk_bytes.is_some(),
        memory_bytes: restore.memory_bytes,
    }
}

/// Re-bind gate state for `rebind-ok\n` over vsock `7784` (cw-security #6652):
/// accepted at most once, ONLY while actively restoring, never on a normal
/// boot, and never re-armable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RebindState {
    Normal,
    AwaitingRebind,
    Rebound,
}

/// Maximum window between `hibernate\n` arming and Kubernetes SIGTERM
/// (`docs/dev/SANDBOX-SLEEP.md`, "Hibernating a Sandbox"). An unused arm
/// expires automatically so an unsolicited guest `hibernate\n` cannot turn a
/// much later ordinary `cw stop` into a wasted memory write.
const HIBERNATE_ARM_TTL: Duration = Duration::from_secs(120);

/// Per-boot hibernate arming and post-restore re-bind gate shared between the
/// vsock `7784` listener (`pod_runtime::suspend`) and `pod_runtime`'s boot/stop
/// loop.
pub(super) struct HibernateControl {
    armed_at: Mutex<Option<Instant>>,
    rebind: Mutex<RebindState>,
    rebind_notify: Notify,
}

impl HibernateControl {
    /// Normal cold boot: `rebind-ok\n` is always refused.
    pub(super) fn normal() -> Self {
        Self {
            armed_at: Mutex::new(None),
            rebind: Mutex::new(RebindState::Normal),
            rebind_notify: Notify::new(),
        }
    }

    /// Restored boot: accepts `rebind-ok\n` exactly once before Pod ports open
    /// and the memory file is deleted.
    pub(super) fn awaiting_rebind() -> Self {
        Self {
            armed_at: Mutex::new(None),
            rebind: Mutex::new(RebindState::AwaitingRebind),
            rebind_notify: Notify::new(),
        }
    }

    /// Handles `hibernate\n` from the guest daemon: arms hibernate for the
    /// next Kubernetes SIGTERM within [`HIBERNATE_ARM_TTL`] and never triggers
    /// immediate hibernation on its own (`docs/dev/SANDBOX-SLEEP.md`, steps
    /// 2–5). Refused while awaiting restore re-bind or while already armed.
    pub(super) fn arm(&self) -> bool {
        self.arm_at(Instant::now())
    }

    fn arm_at(&self, now: Instant) -> bool {
        let state = *self
            .rebind
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state == RebindState::AwaitingRebind {
            return false;
        }
        let mut armed_at = self
            .armed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if armed_at.is_some_and(|at| now.saturating_duration_since(at) <= HIBERNATE_ARM_TTL) {
            return false;
        }
        *armed_at = Some(now);
        eprintln!("standard runtime: hibernate armed for next SIGTERM");
        true
    }

    pub(super) fn is_armed(&self) -> bool {
        self.is_armed_at(Instant::now())
    }

    fn is_armed_at(&self, now: Instant) -> bool {
        self.armed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|at| now.saturating_duration_since(at) <= HIBERNATE_ARM_TTL)
    }

    /// Handles `rebind-ok\n` from the restored guest daemon. Returns `true` at
    /// most once while in `AwaitingRebind`; returns `false` on normal boots and
    /// on any duplicate call.
    pub(super) fn signal_rebind_ok(&self) -> bool {
        let mut state = self
            .rebind
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *state != RebindState::AwaitingRebind {
            return false;
        }
        *state = RebindState::Rebound;
        drop(state);
        self.rebind_notify.notify_waiters();
        true
    }

    pub(super) fn is_rebound(&self) -> bool {
        *self
            .rebind
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == RebindState::Rebound
    }

    /// Resolves once `rebind-ok\n` has been accepted.
    pub(super) async fn wait_for_rebind(&self) {
        loop {
            let notified = self.rebind_notify.notified();
            if self.is_rebound() {
                return;
            }
            notified.await;
        }
    }
}

/// Checks whether a published port listener should be opened yet. Exposed for
/// tests alongside `HibernateControl`.
#[cfg(test)]
pub(super) fn should_open_ports(control: &HibernateControl) -> bool {
    let state = *control
        .rebind
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state != RebindState::AwaitingRebind
}

/// Location of the VM's `checkpoints/in` directory for tests and diagnostics.
#[cfg(test)]
pub(super) fn checkpoints_in_dir(engine_root: &Path) -> PathBuf {
    vm_checkpoints_dir(engine_root).join(CHECKPOINT_IN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::CheckpointImageDisk;

    fn sample_settings(runtime_digest: Option<&str>) -> PodSettings {
        PodSettings {
            vcpus: 2,
            memory_mib: 4096,
            state_disk_bytes: 20 * 1024 * 1024 * 1024,
            docker_disk_bytes: None,
            workspace_image: format!("registry.example/workspace@sha256:{}", "a".repeat(64)),
            image_disk_id: "1".repeat(64),
            build_id: "2".repeat(32),
            platform_peers: Vec::new(),
            udp_peers: Vec::new(),
            vm_state: super::super::VmState::Existing,
            egress_mode: EgressMode::GuestCarried,
            workspace_init: codewire_vmm_guest_probe::hosted_control::HostedWorkspaceInit::Image,
            restore_generation: Some(5),
            runtime_image_digest: runtime_digest.map(str::to_owned),
        }
    }

    fn setup_hibernated_engine(
        settings: &PodSettings,
        vmm_sha256: &str,
        runtime_digest: &str,
        restore_generation: u64,
    ) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let ckpt_in = checkpoints_in_dir(temp.path());
        fs::create_dir_all(&ckpt_in).unwrap();
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
        let restore = RestoreBoot {
            checkpoint_id: uuid::Uuid::new_v4(),
            source_environment_id: POD_VM_ID,
            config_sha256: format!("{:x}", Sha256::digest(config_bytes)),
            state_sha256: format!("{:x}", Sha256::digest(state_bytes)),
            memory_bytes: memory_bytes.len() as u64,
            setup_disk_bytes: None,
            vmm_sha256: vmm_sha256.to_owned(),
            source_generation: restore_generation,
            skill_snapshot_sha256: None,
            environment_projection_sha256: None,
            managed_credential_clients: Default::default(),
            docker: settings.docker_disk_bytes.is_some(),
            cw_runtime_catalog_generation: Some("3".repeat(64)),
            daemon_vsock_port: 7777,
            intercept: false,
            image_disk: Some(CheckpointImageDisk {
                image_disk_id: settings.image_disk_id.clone(),
                build_id: settings.build_id.clone(),
            }),
            bound_secrets: Default::default(),
            state_identity: None,
        };
        let record = build_record(
            settings,
            restore_generation,
            vmm_sha256.to_owned(),
            runtime_digest.to_owned(),
            restore,
        );
        write_hibernate_record(temp.path(), &record).unwrap();
        temp
    }

    #[test]
    fn restore_admits_once_and_refuses_second_attempt_with_generation_consumed() {
        let runtime_digest = format!("sha256:{}", "c".repeat(64));
        let vmm_sha = "d".repeat(64);
        let settings = sample_settings(Some(&runtime_digest));
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);

        // First admission succeeds and consumes the external generation guard.
        let admitted = admit_hibernate_restore(engine.path(), &settings, 5, &vmm_sha).unwrap();
        assert_eq!(admitted.restore_generation, 5);
        assert!(
            !engine
                .path()
                .join(HIBERNATE_DIR_NAME)
                .join(GENERATION_FILE_NAME)
                .exists()
        );
        // Memory file stays on disk until rebind-ok completes.
        assert!(
            checkpoints_in_dir(engine.path())
                .join("memory-ranges")
                .exists()
        );

        // Second attempt (e.g. Pod restarted with same restore generation) is
        // refused with GenerationConsumed and cleans up artifacts.
        let second = admit_hibernate_restore(engine.path(), &settings, 5, &vmm_sha).unwrap_err();
        assert_eq!(second, FallbackReason::GenerationConsumed);
        assert!(!checkpoints_in_dir(engine.path()).exists());
        assert!(!engine.path().join(HIBERNATE_DIR_NAME).exists());
    }

    #[test]
    fn digest_image_disk_config_and_corruption_mismatches_fall_back_and_clean_up() {
        let runtime_digest = format!("sha256:{}", "c".repeat(64));
        let other_runtime = format!("sha256:{}", "e".repeat(64));
        let vmm_sha = "d".repeat(64);
        let other_vmm = "f".repeat(64);
        let settings = sample_settings(Some(&runtime_digest));

        // 1. VMM digest mismatch
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        assert_eq!(
            admit_hibernate_restore(engine.path(), &settings, 5, &other_vmm).unwrap_err(),
            FallbackReason::VmmDigestMismatch
        );
        assert!(!checkpoints_in_dir(engine.path()).exists());

        // 2. Runtime image digest mismatch
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        let mismatched_runtime = sample_settings(Some(&other_runtime));
        assert_eq!(
            admit_hibernate_restore(engine.path(), &mismatched_runtime, 5, &vmm_sha).unwrap_err(),
            FallbackReason::RuntimeImageDigestMismatch
        );
        assert!(!checkpoints_in_dir(engine.path()).exists());

        // 3. Rebuilt image disk mismatch
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        let mut rebuilt = settings.clone();
        rebuilt.build_id = "9".repeat(32);
        assert_eq!(
            admit_hibernate_restore(engine.path(), &rebuilt, 5, &vmm_sha).unwrap_err(),
            FallbackReason::ImageDiskMismatch
        );

        // 4. VM config mismatch (e.g. memory changed)
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        let mut resized = settings.clone();
        resized.memory_mib = 8192;
        assert_eq!(
            admit_hibernate_restore(engine.path(), &resized, 5, &vmm_sha).unwrap_err(),
            FallbackReason::VmConfigMismatch
        );

        // 5. Damaged / tampered config.json
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        let cfg = checkpoints_in_dir(engine.path()).join("config.json");
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&cfg, b"corrupted").unwrap();
        assert_eq!(
            admit_hibernate_restore(engine.path(), &settings, 5, &vmm_sha).unwrap_err(),
            FallbackReason::DamagedMemoryFile
        );
        assert!(!checkpoints_in_dir(engine.path()).exists());

        // 6. Wrong expected generation
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        assert_eq!(
            admit_hibernate_restore(engine.path(), &settings, 6, &vmm_sha).unwrap_err(),
            FallbackReason::GenerationMismatch
        );
    }

    /// cw-security (#6652): `rebind-ok` is accepted at most once and only while
    /// actively restoring — never on a normal boot, never re-armable — and
    /// `should_open_ports` stays false until `rebind-ok` arrives.
    #[test]
    fn rebind_ok_is_one_shot_restore_only_and_gates_port_opening() {
        let normal = HibernateControl::normal();
        assert!(should_open_ports(&normal));
        assert!(!normal.signal_rebind_ok());
        assert!(normal.arm());
        assert!(!normal.arm()); // already armed

        let restoring = HibernateControl::awaiting_rebind();
        assert!(!should_open_ports(&restoring));
        // Cannot arm a new hibernate while still awaiting restore re-bind.
        assert!(!restoring.arm());
        // First rebind-ok succeeds and opens the port gate.
        assert!(restoring.signal_rebind_ok());
        assert!(should_open_ports(&restoring));
        // Second rebind-ok is refused (one-shot, never re-armable).
        assert!(!restoring.signal_rebind_ok());
        // After re-bind completes, a future hibernate can be armed.
        assert!(restoring.arm());
    }

    #[test]
    fn admit_restore_fails_closed_when_generation_guard_cannot_be_removed() {
        let vmm_sha = "c".repeat(64);
        let runtime_digest = format!("sha256:{}", "d".repeat(64));
        let settings = sample_settings(Some(&runtime_digest));
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        let hib_dir = engine.path().join(HIBERNATE_DIR_NAME);
        let gen_path = hib_dir.join(GENERATION_FILE_NAME);

        // Failing unlink (e.g. read-only mount / EROFS / EACCES) fails closed.
        let remove_err = consume_generation_guard_with(
            &hib_dir,
            &gen_path,
            |_| Err(io::Error::from_raw_os_error(libc::EROFS)),
            sync_dir,
        );
        assert_eq!(remove_err.unwrap_err(), FallbackReason::DamagedMemoryFile);
        assert!(gen_path.exists());

        // Failing directory fsync (e.g. EIO) also fails closed.
        let sync_err = consume_generation_guard_with(
            &hib_dir,
            &gen_path,
            |_| Ok(()),
            |_| Err(io::Error::from_raw_os_error(libc::EIO)),
        );
        assert_eq!(sync_err.unwrap_err(), FallbackReason::DamagedMemoryFile);

        // Read-only hibernate/ directory fails closed on non-root runs (root
        // bypasses DAC write checks on 0o500 directories).
        if unsafe { libc::geteuid() } != 0 {
            fs::set_permissions(&hib_dir, fs::Permissions::from_mode(0o500)).unwrap();
            let outcome = admit_hibernate_restore(engine.path(), &settings, 5, &vmm_sha);
            fs::set_permissions(&hib_dir, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(outcome.is_err());
        }
    }

    #[test]
    fn hibernate_arm_expires_after_ttl() {
        let control = HibernateControl::normal();
        let t0 = Instant::now();
        assert!(control.arm_at(t0));
        assert!(control.is_armed_at(t0 + Duration::from_secs(60)));
        assert!(!control.arm_at(t0 + Duration::from_secs(60)));
        // Past HIBERNATE_ARM_TTL, the arm expires so a later ordinary stop
        // never triggers an unintended hibernate.
        let expired = t0 + HIBERNATE_ARM_TTL + Duration::from_secs(1);
        assert!(!control.is_armed_at(expired));
        // Once expired, a fresh legitimate hibernate can arm again.
        assert!(control.arm_at(expired));
        assert!(control.is_armed_at(expired));
    }

    #[test]
    fn clear_hibernate_artifacts_removes_entries_while_preserving_checkpoints_dir_inode() {
        use std::os::unix::fs::MetadataExt as _;

        let runtime_digest = format!("sha256:{}", "c".repeat(64));
        let vmm_sha = "d".repeat(64);
        let settings = sample_settings(Some(&runtime_digest));
        let engine = setup_hibernated_engine(&settings, &vmm_sha, &runtime_digest, 5);
        let vm_checkpoints = vm_checkpoints_dir(engine.path());
        fs::set_permissions(&vm_checkpoints, fs::Permissions::from_mode(0o700)).unwrap();
        let stale_out = vm_checkpoints.join("out-stale");
        fs::create_dir(&stale_out).unwrap();
        fs::write(stale_out.join("state.json"), b"{}").unwrap();

        let before = fs::symlink_metadata(&vm_checkpoints).unwrap();

        clear_hibernate_artifacts(engine.path());

        assert!(!engine.path().join(HIBERNATE_DIR_NAME).exists());
        assert!(!checkpoints_in_dir(engine.path()).exists());
        assert!(!stale_out.exists());
        assert!(vm_checkpoints.is_dir());
        assert!(fs::read_dir(&vm_checkpoints).unwrap().next().is_none());

        let after = fs::symlink_metadata(&vm_checkpoints).unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(PrivateRoot::open(&vm_checkpoints).is_ok());
    }
}
