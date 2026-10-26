use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use uuid::Uuid;

use crate::cw_runtime::AdmittedCwRuntimeDisk;
use codewire_vmm_guest_probe::MAX_DIRECT_SHARES;

use crate::host::path::{FileIdentity, PathError, PrivateRoot, SocketIdentity};
use crate::host::process::ProcessIdentity;

pub const PERSISTED_STATE_SCHEMA_VERSION: u32 = 1;
pub use crate::supervisor_metadata::legacy::{
    MINIMUM_DOCKER_DISK_BYTES, MINIMUM_ROOT_DISK_BYTES, MINIMUM_STATE_DISK_BYTES,
};
pub const DEFAULT_ROOT_DISK_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_DOCKER_DISK_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub(crate) const MAXIMUM_ROOT_GENERATIONS: usize = 64;
/// The hybrid-vsock socket inside `vsock/`. Darwin's `sun_path` holds 103
/// bytes, so macOS uses a one-byte name; see `max_socket_path_bytes`.
#[cfg(target_os = "linux")]
pub(crate) const VSOCK_SOCKET_NAME: &str = "vsock.sock";
#[cfg(target_os = "macos")]
pub(crate) const VSOCK_SOCKET_NAME: &str = "v";
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_BYTES: usize = 0x78;
const EXT4_MAGIC_OFFSET: usize = 0x38;
const EXT4_UUID_OFFSET: usize = 0x68;

/// A VM's paths. State, disks and logs live in `vm_dir` under the state
/// root; its sockets live in a short private per-user directory
/// (`sockets_dir`, see [`crate::socket_dir`]) so their paths fit the kernel's
/// limit whatever the length of HOME (#2735).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmPaths {
    pub vm_dir: PathBuf,
    pub sockets_dir: PathBuf,
    pub api_dir: PathBuf,
    pub api_socket: PathBuf,
    pub vsock_dir: PathBuf,
    pub vsock_socket: PathBuf,
    /// Direct-share daemons' sockets, and the pid files virtiofsd writes
    /// beside them.
    pub virtiofs_dir: PathBuf,
    pub disks_dir: PathBuf,
    pub state_disk: PathBuf,
    pub docker_disk: PathBuf,
    pub generations_dir: PathBuf,
    pub seed_dir: PathBuf,
    pub seed_disk: PathBuf,
    pub diagnostics_dir: PathBuf,
    pub serial_log: PathBuf,
    pub vmm_log: PathBuf,
    pub event_monitor: PathBuf,
    pub lock_file: PathBuf,
    pub state_file: PathBuf,
}

impl VmPaths {
    pub fn create(state_root: &PrivateRoot, vm_id: Uuid) -> Result<Self, StateError> {
        let vms_path = state_root.ensure_dir(Path::new("vms"), 0o700)?;
        let vms_root = PrivateRoot::open(&vms_path)?;
        let vm_name = vm_id.to_string();
        let vm_dir = vms_root.ensure_dir(Path::new(&vm_name), 0o700)?;
        let vm_root = PrivateRoot::open(&vm_dir)?;
        let sockets = crate::socket_dir::prepare(state_root.path())?;
        let sockets_dir = crate::socket_dir::ensure_subdirectory(&sockets, &["vms", &vm_name])?;
        let sockets_root = PrivateRoot::open(&sockets_dir)?;
        let api_dir = sockets_root.ensure_dir(Path::new("api"), 0o700)?;
        let vsock_dir = sockets_root.ensure_dir(Path::new("vsock"), 0o700)?;
        let virtiofs_dir = sockets_root.ensure_dir(Path::new("fs"), 0o700)?;
        let disks_dir = vm_root.ensure_dir(Path::new("disks"), 0o700)?;
        let generations_dir = vm_root.ensure_dir(Path::new("generations"), 0o700)?;
        let seed_dir = vm_root.ensure_dir(Path::new("seed"), 0o700)?;
        let diagnostics_dir = vm_root.ensure_dir(Path::new("diagnostics"), 0o700)?;
        let api_socket = api_dir.join("api.sock");
        let vsock_socket = vsock_dir.join(VSOCK_SOCKET_NAME);
        for socket in [
            &api_socket,
            &vsock_socket,
            &virtiofs_dir.join(direct_share_pid_file_name(MAX_DIRECT_SHARES - 1)),
        ] {
            crate::socket_dir::check_length(socket)?;
        }
        Ok(Self {
            api_socket,
            vsock_socket,
            virtiofs_dir,
            sockets_dir,
            state_disk: disks_dir.join("state.raw"),
            docker_disk: disks_dir.join("docker.raw"),
            seed_disk: seed_dir.join("seed.raw"),
            serial_log: diagnostics_dir.join("serial.log"),
            vmm_log: diagnostics_dir.join("vmm.log"),
            event_monitor: diagnostics_dir.join("events.json"),
            lock_file: vm_dir.join("vm.lock"),
            state_file: vm_dir.join("state.json"),
            vm_dir,
            api_dir,
            vsock_dir,
            disks_dir,
            generations_dir,
            seed_dir,
            diagnostics_dir,
        })
    }

    pub fn open_vm_root(&self) -> Result<PrivateRoot, StateError> {
        PrivateRoot::open(&self.vm_dir).map_err(StateError::from)
    }

    pub fn lock(&self) -> Result<VmLock, StateError> {
        let root = self.open_vm_root()?;
        let opened = root
            .create_regular(Path::new("vm.lock"), 0o600, false)
            .map_err(StateError::from)?;
        flock(opened.file(), FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| StateError::AlreadyLocked)?;
        Ok(VmLock(opened.into_file()))
    }

    /// Removes endpoints a previous run left; the caller holds the VM lock,
    /// so nothing serves them. Socket directories under the state root that
    /// releases before #2735 used are removed with their stale sockets.
    pub fn clear_stale_runtime_endpoints(&self) -> Result<(), StateError> {
        let api = PrivateRoot::open(&self.api_dir)?;
        api.remove_private_socket(Path::new("api.sock"))?;
        api.remove_private_regular(Path::new("api.sock.lock"), 0o600)?;
        PrivateRoot::open(&self.vsock_dir)?.remove_private_socket(Path::new(VSOCK_SOCKET_NAME))?;
        let virtiofs = PrivateRoot::open(&self.virtiofs_dir)?;
        for index in 0..MAX_DIRECT_SHARES {
            virtiofs.remove_private_socket_with_permissions(
                Path::new(&direct_share_socket_name(index)),
                &[0o600, 0o700],
            )?;
            virtiofs
                .remove_private_regular(Path::new(&direct_share_pid_file_name(index)), 0o600)?;
        }
        let vm = self.open_vm_root()?;
        if let Some(api) = optional_private_directory(&vm, Path::new("api"))? {
            api.remove_private_socket(Path::new("api.sock"))?;
            api.remove_private_regular(Path::new("api.sock.lock"), 0o600)?;
            vm.remove_empty_private_directory(Path::new("api"))?;
        }
        if let Some(vsock) = optional_private_directory(&vm, Path::new("vsock"))? {
            vsock.remove_private_socket(Path::new("vsock.sock"))?;
            vsock.remove_private_socket(Path::new("v"))?;
            vm.remove_empty_private_directory(Path::new("vsock"))?;
        }
        if let Some(virtiofs) = optional_private_directory(&vm, Path::new("fs"))? {
            for index in 0..MAX_DIRECT_SHARES {
                virtiofs.remove_private_socket_with_permissions(
                    Path::new(&direct_share_socket_name(index)),
                    &[0o600, 0o700],
                )?;
                virtiofs
                    .remove_private_regular(Path::new(&direct_share_pid_file_name(index)), 0o600)?;
            }
            vm.remove_empty_private_directory(Path::new("fs"))?;
        }
        Ok(())
    }

    pub fn direct_share_socket(&self, index: usize) -> Result<PathBuf, StateError> {
        if index >= MAX_DIRECT_SHARES {
            return Err(StateError::InvalidDirectShareIndex(index));
        }
        Ok(self.virtiofs_dir.join(direct_share_socket_name(index)))
    }

    pub fn prepare_diagnostics(&self) -> Result<(), StateError> {
        let root = PrivateRoot::open(&self.diagnostics_dir)?;
        for name in ["serial.log", "vmm.log", "events.json"] {
            let opened = root.create_regular(Path::new(name), 0o600, false)?;
            opened.file().set_len(0).map_err(|source| StateError::Io {
                path: self.diagnostics_dir.join(name),
                source,
            })?;
            opened.file().sync_all().map_err(|source| StateError::Io {
                path: self.diagnostics_dir.join(name),
                source,
            })?;
        }
        Ok(())
    }

    pub fn validate_diagnostics(&self) -> Result<(), StateError> {
        let root = PrivateRoot::open(&self.diagnostics_dir)?;
        for name in ["serial.log", "vmm.log", "events.json"] {
            root.open_regular(Path::new(name), true, None, false, Some(0o600))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootGenerationPaths {
    pub generation: String,
    pub generation_dir: PathBuf,
    pub root_disk: PathBuf,
    pub setup_disk: PathBuf,
}

impl RootGenerationPaths {
    pub fn create(paths: &VmPaths, generation: &str) -> Result<Self, StateError> {
        if !valid_root_generation(generation) {
            return Err(StateError::InvalidRootGeneration);
        }
        let generations = PrivateRoot::open(&paths.generations_dir)?;
        let generation_dir = generations.ensure_dir(Path::new(generation), 0o700)?;
        Ok(Self {
            generation: generation.to_owned(),
            root_disk: generation_dir.join("root.raw"),
            setup_disk: generation_dir.join("setup.raw"),
            generation_dir,
        })
    }
}

pub fn valid_root_generation(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub struct VmLock(File);

impl std::fmt::Debug for VmLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("VmLock").finish_non_exhaustive()
    }
}

impl VmLock {
    pub fn file(&self) -> &File {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDiskIdentity {
    pub file: FileIdentity,
    pub filesystem_uuid: Uuid,
}

impl StateDiskIdentity {
    pub fn capture(path: &Path) -> Result<Self, StateError> {
        let root_path = path
            .parent()
            .ok_or_else(|| StateError::InvalidStateDisk(path.to_owned()))?;
        let file_name = path
            .file_name()
            .map(Path::new)
            .ok_or_else(|| StateError::InvalidStateDisk(path.to_owned()))?;
        let root = PrivateRoot::open(root_path)?;
        let opened = root.open_regular(file_name, true, None, false, Some(0o600))?;
        let filesystem_uuid = read_ext4_uuid(opened.file(), path)?;
        Ok(Self {
            file: opened.identity().clone(),
            filesystem_uuid,
        })
    }

    pub fn revalidate(&self, path: &Path) -> Result<(), StateError> {
        if &Self::capture(path)? != self {
            return Err(StateError::StateDiskIdentityChanged(path.to_owned()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum VmPhase {
    Starting,
    Running,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedVmState {
    pub schema_version: u32,
    pub vm_id: Uuid,
    pub generation: u64,
    pub vsock_cid: u32,
    pub daemon_vsock_port: u32,
    pub phase: VmPhase,
    pub process: ProcessIdentity,
    pub state_disk: StateDiskIdentity,
    #[serde(default)]
    pub docker_disk: Option<StateDiskIdentity>,
    #[serde(default)]
    pub root_generation: Option<String>,
    #[serde(default)]
    pub root_disk: Option<StateDiskIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cw_runtime_disk: Option<AdmittedCwRuntimeDisk>,
    pub api_socket: Option<SocketIdentity>,
    pub vsock_socket: Option<SocketIdentity>,
}

impl PersistedVmState {
    pub fn read(path: &Path) -> Result<Self, StateError> {
        let parent = PrivateRoot::open(path.parent().ok_or(StateError::InvalidPersistedState)?)?;
        let name = path
            .file_name()
            .map(Path::new)
            .ok_or(StateError::InvalidPersistedState)?;
        let opened = parent.open_regular(name, false, None, false, Some(0o600))?;
        let mut bytes = Vec::new();
        opened
            .file()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| StateError::Io {
                path: path.to_owned(),
                source,
            })?;
        if bytes.len() > 1024 * 1024 {
            return Err(StateError::InvalidPersistedState);
        }
        let state: Self = serde_json::from_slice(&bytes).map_err(StateError::Decode)?;
        state.validate()?;
        Ok(state)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), StateError> {
        self.validate()?;
        let parent = path.parent().ok_or(StateError::InvalidPersistedState)?;
        let file_name = path
            .file_name()
            .map(Path::new)
            .ok_or(StateError::InvalidPersistedState)?;
        let bytes = serde_json::to_vec(self).map_err(StateError::Encode)?;
        PrivateRoot::open(parent)?
            .atomic_replace(file_name, &bytes, 0o600)
            .map_err(StateError::from)
    }

    fn validate(&self) -> Result<(), StateError> {
        // Darwin's helper has no API socket; Cloud Hypervisor's always has.
        #[cfg(target_os = "linux")]
        let valid_phase = matches!(
            (self.phase, &self.api_socket, &self.vsock_socket),
            (VmPhase::Starting, None, None) | (VmPhase::Running, Some(_), Some(_))
        );
        #[cfg(target_os = "macos")]
        let valid_phase = matches!(
            (self.phase, &self.api_socket, &self.vsock_socket),
            (VmPhase::Starting, None, None) | (VmPhase::Running, None, Some(_))
        );
        let valid_root = match (&self.root_generation, &self.root_disk) {
            (None, None) => true,
            (Some(generation), Some(disk)) => {
                valid_root_generation(generation) && !disk.filesystem_uuid.is_nil()
            }
            _ => false,
        };
        if self.schema_version != PERSISTED_STATE_SCHEMA_VERSION
            || self.vm_id.is_nil()
            || self.generation == 0
            || self.vsock_cid < 3
            || self.vsock_cid == u32::MAX
            || self.daemon_vsock_port == 0
            || self.daemon_vsock_port == u32::MAX
            || self.state_disk.filesystem_uuid.is_nil()
            || self
                .docker_disk
                .as_ref()
                .is_some_and(|disk| disk.filesystem_uuid.is_nil())
            || !valid_root
            || !valid_phase
        {
            return Err(StateError::InvalidPersistedState);
        }
        if self
            .cw_runtime_disk
            .as_ref()
            .is_some_and(|disk| disk.validate_metadata().is_err())
        {
            return Err(StateError::InvalidPersistedState);
        }
        Ok(())
    }
}

pub fn publish_seed(path: &Path, seed: &[u8]) -> Result<(), StateError> {
    let parent = path
        .parent()
        .ok_or_else(|| StateError::InvalidStateDisk(path.to_owned()))?;
    let file_name = path
        .file_name()
        .map(Path::new)
        .ok_or_else(|| StateError::InvalidStateDisk(path.to_owned()))?;
    PrivateRoot::open(parent)?
        .atomic_replace(file_name, seed, 0o400)
        .map_err(StateError::from)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionTreeLocation {
    Active(PathBuf),
    Trash(PathBuf),
    Missing,
}

pub fn deletion_tree_location(
    state_root: &Path,
    vm_id: Uuid,
    operation_id: Uuid,
) -> Result<DeletionTreeLocation, StateError> {
    if vm_id.is_nil() || operation_id.is_nil() {
        return Err(StateError::InvalidTrashIdentity);
    }
    let state_root = PrivateRoot::open(state_root)?;
    let vms_path = state_root.ensure_dir(Path::new("vms"), 0o700)?;
    let trash_path = state_root.ensure_dir(Path::new("trash"), 0o700)?;
    let vms = PrivateRoot::open(&vms_path)?;
    let trash = PrivateRoot::open(&trash_path)?;
    let source = vm_id.to_string();
    let destination = trash_name(vm_id, operation_id);
    let active = optional_private_directory(&vms, Path::new(&source))?;
    let trashed = optional_private_directory(&trash, Path::new(&destination))?;
    match (active, trashed) {
        (Some(_), Some(_)) => Err(StateError::TrashConflict(trash.path().join(destination))),
        (Some(_), None) => Ok(DeletionTreeLocation::Active(vms.path().join(source))),
        (None, Some(_)) => Ok(DeletionTreeLocation::Trash(trash.path().join(destination))),
        (None, None) => Ok(DeletionTreeLocation::Missing),
    }
}

pub fn move_stopped_vm_to_trash(
    state_root: &Path,
    vm_id: Uuid,
    operation_id: Uuid,
) -> Result<PathBuf, StateError> {
    if vm_id.is_nil() || operation_id.is_nil() {
        return Err(StateError::InvalidTrashIdentity);
    }
    let state_root = PrivateRoot::open(state_root)?;
    let vms_path = state_root.ensure_dir(Path::new("vms"), 0o700)?;
    let trash_path = state_root.ensure_dir(Path::new("trash"), 0o700)?;
    let vms = PrivateRoot::open(&vms_path)?;
    let trash = PrivateRoot::open(&trash_path)?;
    let source = vm_id.to_string();
    let destination = trash_name(vm_id, operation_id);
    let destination_path = trash.path().join(&destination);
    if optional_private_directory(&trash, Path::new(&destination))?.is_some() {
        if optional_private_directory(&vms, Path::new(&source))?.is_some() {
            return Err(StateError::TrashConflict(destination_path));
        }
        return Ok(destination_path);
    }
    if optional_private_directory(&vms, Path::new(&source))?.is_none() {
        return Err(StateError::MissingTrashSource(vms.path().join(source)));
    }
    if let Err(error) =
        vms.move_private_directory_to(Path::new(&source), &trash, Path::new(&destination))
    {
        #[cfg(target_os = "linux")]
        let conflict = matches!(
            error,
            PathError::Openat2 {
                source: rustix::io::Errno::EXIST,
                ..
            }
        );
        #[cfg(target_os = "macos")]
        let conflict = matches!(
            &error,
            PathError::Io { source, .. } if source.raw_os_error() == Some(libc::EEXIST)
        );
        if conflict {
            return Err(StateError::TrashConflict(destination_path));
        }
        return Err(error.into());
    }
    Ok(destination_path)
}

pub fn cleanup_trashed_vm(
    state_root: &Path,
    vm_id: Uuid,
    operation_id: Uuid,
) -> Result<(), StateError> {
    if vm_id.is_nil() || operation_id.is_nil() {
        return Err(StateError::InvalidTrashIdentity);
    }
    let state_root = PrivateRoot::open(state_root)?;
    let trash_path = state_root.ensure_dir(Path::new("trash"), 0o700)?;
    let trash = PrivateRoot::open(&trash_path)?;
    let name = trash_name(vm_id, operation_id);
    let vm = match optional_private_directory(&trash, Path::new(&name))? {
        Some(vm) => vm,
        None => return Ok(()),
    };

    validate_owned_vm_tree(&vm)?;
    if let Some(api) = optional_private_directory(&vm, Path::new("api"))? {
        api.remove_private_socket(Path::new("api.sock"))?;
        api.remove_private_regular(Path::new("api.sock.lock"), 0o600)?;
        vm.remove_empty_private_directory(Path::new("api"))?;
    }
    if let Some(vsock) = optional_private_directory(&vm, Path::new("vsock"))? {
        vsock.remove_private_socket(Path::new(VSOCK_SOCKET_NAME))?;
        vm.remove_empty_private_directory(Path::new("vsock"))?;
    }
    if let Some(virtiofs) = optional_private_directory(&vm, Path::new("fs"))? {
        for index in 0..MAX_DIRECT_SHARES {
            virtiofs.remove_private_socket_with_permissions(
                Path::new(&direct_share_socket_name(index)),
                &[0o600, 0o700],
            )?;
            virtiofs
                .remove_private_regular(Path::new(&direct_share_pid_file_name(index)), 0o600)?;
        }
        vm.remove_empty_private_directory(Path::new("fs"))?;
    }
    if let Some(disks) = optional_private_directory(&vm, Path::new("disks"))? {
        disks.remove_private_regular(Path::new("state.raw"), 0o600)?;
        disks.remove_private_regular(Path::new("docker.raw"), 0o600)?;
        disks.remove_private_regular(Path::new("docker.raw.staging"), 0o600)?;
        vm.remove_empty_private_directory(Path::new("disks"))?;
    }
    if let Some(seed) = optional_private_directory(&vm, Path::new("seed"))? {
        seed.remove_private_regular(Path::new("seed.raw"), 0o400)?;
        vm.remove_empty_private_directory(Path::new("seed"))?;
    }
    if let Some(diagnostics) = optional_private_directory(&vm, Path::new("diagnostics"))? {
        for file in ["serial.log", "vmm.log", "events.json"] {
            diagnostics.remove_private_regular(Path::new(file), 0o600)?;
        }
        vm.remove_empty_private_directory(Path::new("diagnostics"))?;
    }
    if let Some(generations) = optional_private_directory(&vm, Path::new("generations"))? {
        for name in admitted_generation_names(&generations)? {
            let generation = generations.open_private_directory(Path::new(&name), 0o700)?;
            generation.remove_private_regular(Path::new("setup.raw"), 0o400)?;
            generation.remove_private_regular(Path::new("root.raw"), 0o600)?;
            drop(generation);
            generations.remove_empty_private_directory(Path::new(&name))?;
        }
        vm.remove_empty_private_directory(Path::new("generations"))?;
    }
    #[cfg(target_os = "macos")]
    vm.remove_private_regular(Path::new(crate::vz::CONFIG_NAME), 0o600)?;
    vm.remove_private_regular(Path::new("state.json"), 0o600)?;
    vm.remove_private_regular(Path::new("vm.lock"), 0o600)?;
    drop(vm);
    trash.remove_empty_private_directory(Path::new(&name))?;
    remove_vm_sockets(state_root.path(), vm_id)?;
    Ok(())
}

/// Removes a deleted VM's socket directory (#2735), if it is still there.
fn remove_vm_sockets(state_root: &Path, vm_id: Uuid) -> Result<(), StateError> {
    let vms_path = crate::socket_dir::predicted(state_root).join("vms");
    let vms = match PrivateRoot::open(&vms_path) {
        Ok(vms) => vms,
        Err(error) if path_error_is_not_found(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let name = vm_id.to_string();
    let Some(sockets) = optional_private_directory(&vms, Path::new(&name))? else {
        return Ok(());
    };
    if let Some(api) = optional_private_directory(&sockets, Path::new("api"))? {
        api.remove_private_socket(Path::new("api.sock"))?;
        api.remove_private_regular(Path::new("api.sock.lock"), 0o600)?;
        sockets.remove_empty_private_directory(Path::new("api"))?;
    }
    if let Some(vsock) = optional_private_directory(&sockets, Path::new("vsock"))? {
        vsock.remove_private_socket(Path::new(VSOCK_SOCKET_NAME))?;
        sockets.remove_empty_private_directory(Path::new("vsock"))?;
    }
    if let Some(virtiofs) = optional_private_directory(&sockets, Path::new("fs"))? {
        for index in 0..MAX_DIRECT_SHARES {
            virtiofs.remove_private_socket_with_permissions(
                Path::new(&direct_share_socket_name(index)),
                &[0o600, 0o700],
            )?;
            virtiofs
                .remove_private_regular(Path::new(&direct_share_pid_file_name(index)), 0o600)?;
        }
        sockets.remove_empty_private_directory(Path::new("fs"))?;
    }
    drop(sockets);
    vms.remove_empty_private_directory(Path::new(&name))?;
    Ok(())
}

/// Removes only root-generation trees that are absent from the supervisor's
/// durable active/staging/rollback set.
///
/// Every generation tree is admitted before the first unlink so an unknown or
/// unsafe object leaves the complete directory unchanged for orphan diagnosis.
/// A filesystem failure after admission may leave a partially collected,
/// unreferenced tree; replay is safe and idempotent.
pub(crate) fn cleanup_unreferenced_root_generations(
    paths: &VmPaths,
    retained: &BTreeSet<String>,
) -> Result<Vec<String>, StateError> {
    if retained
        .iter()
        .any(|generation| !valid_root_generation(generation))
    {
        return Err(StateError::InvalidRootGeneration);
    }

    let generations = PrivateRoot::open(&paths.generations_dir)?;
    let admitted = admitted_generation_names(&generations)?;
    for name in &admitted {
        validate_root_generation_tree(&generations, name)?;
    }

    let mut removed = Vec::new();
    for name in admitted {
        if retained.contains(&name) {
            continue;
        }
        let generation = generations.open_private_directory(Path::new(&name), 0o700)?;
        generation.remove_private_regular(Path::new("setup.raw"), 0o400)?;
        generation.remove_private_regular(Path::new("root.raw"), 0o600)?;
        drop(generation);
        generations.remove_empty_private_directory(Path::new(&name))?;
        removed.push(name);
    }
    Ok(removed)
}

fn validate_root_generation_tree(generations: &PrivateRoot, name: &str) -> Result<(), StateError> {
    let generation = generations.open_private_directory(Path::new(name), 0o700)?;
    ensure_only_entries(generation.path(), &["root.raw", "setup.raw"])?;
    for (file, mode) in [("root.raw", 0o600), ("setup.raw", 0o400)] {
        match generation.open_regular(Path::new(file), false, None, false, Some(mode)) {
            Ok(_) => {}
            Err(error) if path_error_is_not_found(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn trash_name(vm_id: Uuid, operation_id: Uuid) -> String {
    format!("delete-{operation_id}-{vm_id}")
}

pub(crate) fn direct_share_socket_name(index: usize) -> String {
    format!("{index:02}.sock")
}

fn direct_share_pid_file_name(index: usize) -> String {
    format!("{}.pid", direct_share_socket_name(index))
}

fn optional_private_directory(
    root: &PrivateRoot,
    relative: &Path,
) -> Result<Option<PrivateRoot>, StateError> {
    match root.open_private_directory(relative, 0o700) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if path_error_is_not_found(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn validate_owned_vm_tree(vm: &PrivateRoot) -> Result<(), StateError> {
    const ENTRIES: [&str; 9] = [
        "api",
        "vsock",
        "fs",
        "disks",
        "seed",
        "diagnostics",
        "generations",
        "vm.lock",
        "state.json",
    ];
    #[cfg(target_os = "linux")]
    ensure_only_entries(vm.path(), &ENTRIES)?;
    // Darwin also keeps the helper's configuration beside the state.
    #[cfg(target_os = "macos")]
    {
        let mut entries = ENTRIES.to_vec();
        entries.push(crate::vz::CONFIG_NAME);
        ensure_only_entries(vm.path(), &entries)?;
    }
    if let Some(virtiofs) = optional_private_directory(vm, Path::new("fs"))? {
        for entry in fs::read_dir(virtiofs.path()).map_err(|source| StateError::Io {
            path: virtiofs.path().to_owned(),
            source,
        })? {
            let entry = entry.map_err(|source| StateError::Io {
                path: virtiofs.path().to_owned(),
                source,
            })?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|name| StateError::UnexpectedOwnedObject(virtiofs.path().join(name)))?;
            let socket =
                (0..MAX_DIRECT_SHARES).any(|index| name == direct_share_socket_name(index));
            let pid_file =
                (0..MAX_DIRECT_SHARES).any(|index| name == direct_share_pid_file_name(index));
            if !socket && !pid_file {
                return Err(StateError::UnexpectedOwnedObject(entry.path()));
            }
            if socket {
                match SocketIdentity::capture_with_permissions(&entry.path(), &[0o600, 0o700]) {
                    Ok(_) => {}
                    Err(error) if path_error_is_not_found(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            } else {
                match virtiofs.open_regular(Path::new(&name), false, None, false, Some(0o600)) {
                    Ok(_) => {}
                    Err(error) if path_error_is_not_found(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    for (directory, files) in [
        (
            "api",
            &[(&"api.sock", 0o600, true), (&"api.sock.lock", 0o600, false)][..],
        ),
        ("vsock", &[(&VSOCK_SOCKET_NAME, 0o600, true)][..]),
        (
            "disks",
            &[
                (&"state.raw", 0o600, false),
                (&"docker.raw", 0o600, false),
                (&"docker.raw.staging", 0o600, false),
            ][..],
        ),
        ("seed", &[(&"seed.raw", 0o400, false)][..]),
        (
            "diagnostics",
            &[
                (&"serial.log", 0o600, false),
                (&"vmm.log", 0o600, false),
                (&"events.json", 0o600, false),
            ][..],
        ),
    ] {
        let Some(root) = optional_private_directory(vm, Path::new(directory))? else {
            continue;
        };
        let allowed = files.iter().map(|(name, _, _)| **name).collect::<Vec<_>>();
        ensure_only_entries(root.path(), &allowed)?;
        for (name, mode, socket) in files {
            let relative = Path::new(name);
            if *socket {
                match SocketIdentity::capture(&root.path().join(relative)) {
                    Ok(_) => {}
                    Err(error) if path_error_is_not_found(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            } else {
                match root.open_regular(relative, false, None, false, Some(*mode)) {
                    Ok(_) => {}
                    Err(error) if path_error_is_not_found(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    for (name, mode) in [("state.json", 0o600), ("vm.lock", 0o600)] {
        match vm.open_regular(Path::new(name), false, None, false, Some(mode)) {
            Ok(_) => {}
            Err(error) if path_error_is_not_found(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(generations) = optional_private_directory(vm, Path::new("generations"))? {
        for name in admitted_generation_names(&generations)? {
            let generation = generations.open_private_directory(Path::new(&name), 0o700)?;
            ensure_only_entries(generation.path(), &["root.raw", "setup.raw"])?;
            match generation.open_regular(Path::new("root.raw"), false, None, false, Some(0o600)) {
                Ok(_) => {}
                Err(error) if path_error_is_not_found(&error) => {}
                Err(error) => return Err(error.into()),
            }
            match generation.open_regular(Path::new("setup.raw"), false, None, false, Some(0o400)) {
                Ok(_) => {}
                Err(error) if path_error_is_not_found(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

pub(crate) fn admitted_generation_names(root: &PrivateRoot) -> Result<Vec<String>, StateError> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root.path()).map_err(|source| StateError::Io {
        path: root.path().to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| StateError::Io {
            path: root.path().to_owned(),
            source,
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| StateError::UnexpectedOwnedObject(entry.path()))?;
        if !valid_root_generation(&name) {
            return Err(StateError::UnexpectedOwnedObject(entry.path()));
        }
        names.push(name);
        if names.len() > MAXIMUM_ROOT_GENERATIONS {
            return Err(StateError::UnexpectedOwnedObject(root.path().to_owned()));
        }
    }
    names.sort();
    Ok(names)
}

fn ensure_only_entries(path: &Path, allowed: &[&str]) -> Result<(), StateError> {
    for entry in fs::read_dir(path).map_err(|source| StateError::Io {
        path: path.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| StateError::Io {
            path: path.to_owned(),
            source,
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| StateError::UnexpectedOwnedObject(path.join(name)))?;
        if !allowed.contains(&name.as_str()) {
            return Err(StateError::UnexpectedOwnedObject(path.join(name)));
        }
    }
    Ok(())
}

fn path_error_is_not_found(error: &PathError) -> bool {
    match error {
        #[cfg(target_os = "linux")]
        PathError::Openat2 { source, .. } => *source == rustix::io::Errno::NOENT,
        PathError::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

/// How an ext4 superblock says its filesystem was left: whether it was
/// unmounted cleanly, whether its journal still needs replaying, and its
/// block size.
// Only Linux takes disk snapshots, which read these.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ext4Superblock {
    pub(crate) uuid: Uuid,
    /// The valid-filesystem state bit is set and the error bit is not.
    pub(crate) valid: bool,
    /// The journal holds transactions a mount or fsck must replay.
    pub(crate) needs_recovery: bool,
    pub(crate) block_size: u64,
    /// The filesystem may hold fs-verity files, whose Merkle trees lie past
    /// their end.
    pub(crate) verity: bool,
}

impl Ext4Superblock {
    /// What a cleanly shut-down guest leaves: valid, nothing to replay.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn clean(&self) -> bool {
        self.valid && !self.needs_recovery
    }
}

/// Read `file`'s ext4 superblock.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn read_ext4_superblock(file: &File, path: &Path) -> Result<Ext4Superblock, StateError> {
    const EXT4_STATE_OFFSET: usize = 0x3a;
    const EXT4_LOG_BLOCK_SIZE_OFFSET: usize = 0x18;
    const EXT4_FEATURE_INCOMPAT_OFFSET: usize = 0x60;
    const EXT4_FEATURE_RO_COMPAT_OFFSET: usize = 0x64;
    const EXT4_FEATURE_RO_COMPAT_VERITY: u32 = 0x8000;
    const EXT4_STATE_VALID: u16 = 0x0001;
    const EXT4_STATE_ERROR: u16 = 0x0002;
    const EXT4_FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;

    let superblock = read_ext4_superblock_bytes(file, path)?;
    let state = u16::from_le_bytes([
        superblock[EXT4_STATE_OFFSET],
        superblock[EXT4_STATE_OFFSET + 1],
    ]);
    let incompat = u32::from_le_bytes(
        superblock[EXT4_FEATURE_INCOMPAT_OFFSET..EXT4_FEATURE_INCOMPAT_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    let ro_compat = u32::from_le_bytes(
        superblock[EXT4_FEATURE_RO_COMPAT_OFFSET..EXT4_FEATURE_RO_COMPAT_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    let log_block_size = u32::from_le_bytes(
        superblock[EXT4_LOG_BLOCK_SIZE_OFFSET..EXT4_LOG_BLOCK_SIZE_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    if log_block_size > 6 {
        return Err(StateError::InvalidExt4(path.to_owned()));
    }
    Ok(Ext4Superblock {
        uuid: ext4_uuid(&superblock, path)?,
        valid: state & EXT4_STATE_VALID != 0 && state & EXT4_STATE_ERROR == 0,
        needs_recovery: incompat & EXT4_FEATURE_INCOMPAT_RECOVER != 0,
        block_size: 1024 << log_block_size,
        verity: ro_compat & EXT4_FEATURE_RO_COMPAT_VERITY != 0,
    })
}

pub(crate) fn read_ext4_uuid(file: &File, path: &Path) -> Result<Uuid, StateError> {
    ext4_uuid(&read_ext4_superblock_bytes(file, path)?, path)
}

fn ext4_uuid(superblock: &[u8; EXT4_SUPERBLOCK_BYTES], path: &Path) -> Result<Uuid, StateError> {
    let uuid = Uuid::from_slice(&superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + 16])
        .map_err(|_| StateError::InvalidExt4(path.to_owned()))?;
    if uuid.is_nil() {
        return Err(StateError::InvalidExt4(path.to_owned()));
    }
    Ok(uuid)
}

fn read_ext4_superblock_bytes(
    file: &File,
    path: &Path,
) -> Result<[u8; EXT4_SUPERBLOCK_BYTES], StateError> {
    let mut file = file.try_clone().map_err(|source| StateError::Io {
        path: path.to_owned(),
        source,
    })?;
    file.seek(SeekFrom::Start(EXT4_SUPERBLOCK_OFFSET))
        .map_err(|source| StateError::Io {
            path: path.to_owned(),
            source,
        })?;
    let mut superblock = [0_u8; EXT4_SUPERBLOCK_BYTES];
    file.read_exact(&mut superblock)
        .map_err(|_| StateError::InvalidExt4(path.to_owned()))?;
    if superblock[EXT4_MAGIC_OFFSET..EXT4_MAGIC_OFFSET + 2] != [0x53, 0xef] {
        return Err(StateError::InvalidExt4(path.to_owned()));
    }
    Ok(superblock)
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error(transparent)]
    SocketDir(#[from] crate::socket_dir::SocketDirError),
    #[error("VM is already owned by another supervisor process")]
    AlreadyLocked,
    #[error("unsafe existing runtime endpoint: {0}")]
    UnsafeExistingEndpoint(PathBuf),
    #[error("invalid state disk path: {0}")]
    InvalidStateDisk(PathBuf),
    #[error("root generation identity must be a lowercase SHA-256 digest")]
    InvalidRootGeneration,
    #[error("invalid state disk size {0}")]
    InvalidDiskSize(u64),
    #[error("state disk is not a valid ext4 filesystem: {0}")]
    InvalidExt4(PathBuf),
    #[error("state disk identity changed: {0}")]
    StateDiskIdentityChanged(PathBuf),
    #[error("invalid persisted VM state")]
    InvalidPersistedState,
    #[error("invalid VM trash identity")]
    InvalidTrashIdentity,
    #[error("invalid direct-share socket index {0}")]
    InvalidDirectShareIndex(usize),
    #[error("VM trash destination conflicts with a live environment tree: {0}")]
    TrashConflict(PathBuf),
    #[error("VM tree is absent from both active and trash state: {0}")]
    MissingTrashSource(PathBuf),
    #[error("VM trash contains an unowned or unexpected object: {0}")]
    UnexpectedOwnedObject(PathBuf),
    #[error("decode persisted VM state failed")]
    Decode(serde_json::Error),
    #[error("encode persisted VM state failed")]
    Encode(serde_json::Error),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

impl StateError {
    pub(crate) fn is_not_found(&self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::Path(PathError::Openat2 { source, .. }) => *source == rustix::io::Errno::NOENT,
            Self::Path(PathError::Io { source, .. }) | Self::Io { source, .. } => {
                source.kind() == io::ErrorKind::NotFound
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    fn private_root() -> (tempfile::TempDir, PrivateRoot) {
        let parent = tempfile::tempdir().unwrap();
        let state_path = parent.path().join("state");
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = PrivateRoot::open(&state_path).unwrap();
        (parent, root)
    }

    fn write_minimal_ext4(path: &Path, filesystem_uuid: Uuid) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.set_len(EXT4_SUPERBLOCK_OFFSET + EXT4_SUPERBLOCK_BYTES as u64)
            .unwrap();
        file.seek(SeekFrom::Start(
            EXT4_SUPERBLOCK_OFFSET + EXT4_MAGIC_OFFSET as u64,
        ))
        .unwrap();
        file.write_all(&[0x53, 0xef]).unwrap();
        file.seek(SeekFrom::Start(
            EXT4_SUPERBLOCK_OFFSET + EXT4_UUID_OFFSET as u64,
        ))
        .unwrap();
        file.write_all(filesystem_uuid.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    fn persisted(phase: VmPhase) -> PersistedVmState {
        PersistedVmState {
            schema_version: PERSISTED_STATE_SCHEMA_VERSION,
            vm_id: Uuid::new_v4(),
            generation: 1,
            vsock_cid: 7,
            daemon_vsock_port: 7777,
            phase,
            process: ProcessIdentity {
                pid: 123,
                boot_id: Uuid::new_v4().to_string(),
                start_time_ticks: 456,
                executable: "/private/cloud-hypervisor".into(),
                executable_file: FileIdentity {
                    device: 1,
                    inode: 2,
                    size: 3,
                    uid: crate::host::path::current_uid(),
                    mode: 0o100500,
                    links: 1,
                    pin: Default::default(),
                },
                executable_sha256: "a".repeat(64),
            },
            state_disk: StateDiskIdentity {
                file: FileIdentity {
                    device: 1,
                    inode: 3,
                    size: MINIMUM_STATE_DISK_BYTES,
                    uid: crate::host::path::current_uid(),
                    mode: 0o100600,
                    links: 1,
                    pin: Default::default(),
                },
                filesystem_uuid: Uuid::new_v4(),
            },
            docker_disk: None,
            root_generation: None,
            root_disk: None,
            cw_runtime_disk: None,
            api_socket: None,
            vsock_socket: None,
        }
    }

    #[test]
    fn missing_persisted_state_has_one_stable_absence_classification() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = PersistedVmState::read(&parent.path().join("missing.json")).unwrap_err();
        assert!(error.is_not_found());
    }

    #[test]
    fn vm_layout_separates_api_vsock_disk_seed_and_diagnostic_authority() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::nil()).unwrap();
        let directories = [
            &paths.api_dir,
            &paths.vsock_dir,
            &paths.virtiofs_dir,
            &paths.disks_dir,
            &paths.seed_dir,
            &paths.diagnostics_dir,
        ];
        for (index, directory) in directories.iter().enumerate() {
            // Sockets live in the short per-user directory, everything else
            // under the state root (#2735).
            let parent = if index < 3 {
                &paths.sockets_dir
            } else {
                &paths.vm_dir
            };
            assert_eq!(directory.parent(), Some(parent.as_path()));
            assert_eq!(fs::metadata(directory).unwrap().mode() & 0o777, 0o700);
            for other in directories.iter().skip(index + 1) {
                assert_ne!(directory, other);
            }
        }
        assert_eq!(
            paths.sockets_dir,
            crate::socket_dir::predicted(root.path()).join(format!("vms/{}", Uuid::nil()))
        );
        assert!(
            paths.vsock_socket.as_os_str().len() <= crate::socket_dir::MAXIMUM_SOCKET_PATH_BYTES
        );
        assert_eq!(paths.state_disk.parent(), Some(paths.disks_dir.as_path()));
        assert_eq!(paths.docker_disk.parent(), Some(paths.disks_dir.as_path()));
        assert_ne!(paths.docker_disk, paths.state_disk);
        assert_eq!(paths.seed_disk.parent(), Some(paths.seed_dir.as_path()));
        assert_eq!(fs::metadata(&paths.vm_dir).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn direct_share_runtime_endpoints_are_private_validated_and_replay_cleaned() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();
        let socket = paths.direct_share_socket(0).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        // virtiofsd publishes its socket as 0700 before the runner normalizes
        // a healthy endpoint to the steady-state 0600 mode.
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
        let pid_file = PathBuf::from(format!("{}.pid", socket.display()));
        fs::write(&pid_file, std::process::id().to_string()).unwrap();
        fs::set_permissions(&pid_file, fs::Permissions::from_mode(0o600)).unwrap();

        validate_owned_vm_tree(&paths.open_vm_root().unwrap()).unwrap();
        paths.clear_stale_runtime_endpoints().unwrap();
        assert!(!socket.exists());
        assert!(!pid_file.exists());
        drop(listener);

        assert!(matches!(
            paths.direct_share_socket(MAX_DIRECT_SHARES),
            Err(StateError::InvalidDirectShareIndex(MAX_DIRECT_SHARES))
        ));
    }

    #[test]
    fn vm_lock_excludes_a_second_owner_until_released() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();

        let first = paths.lock().unwrap();
        assert!(matches!(paths.lock(), Err(StateError::AlreadyLocked)));

        drop(first);
        // A concurrent test's forked child can hold an inherited copy of the
        // released lock until it execs (#2678); a holder past the bound fails.
        crate::host_port::tests::once_released(|| paths.lock());
    }

    #[test]
    fn state_disk_revalidation_rejects_same_path_inode_replacement() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();
        let filesystem_uuid = Uuid::new_v4();
        write_minimal_ext4(&paths.state_disk, filesystem_uuid);
        let admitted = StateDiskIdentity::capture(&paths.state_disk).unwrap();

        let replacement = paths.disks_dir.join("replacement.raw");
        write_minimal_ext4(&replacement, filesystem_uuid);
        fs::rename(&replacement, &paths.state_disk).unwrap();

        assert!(matches!(
            admitted.revalidate(&paths.state_disk),
            Err(StateError::StateDiskIdentityChanged(path)) if path == paths.state_disk
        ));
    }

    #[test]
    fn seed_is_published_read_only_and_exact() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("seed.raw");
        publish_seed(&path, b"seed").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"seed");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o400);
    }

    #[test]
    fn serialized_state_has_no_token_or_credential_field() {
        let names = serde_json::to_string(&persisted(VmPhase::Starting)).unwrap();
        assert!(!names.to_ascii_lowercase().contains("token"));
        assert!(!names.to_ascii_lowercase().contains("credential"));
    }

    #[test]
    fn legacy_persisted_state_defaults_to_no_cw_runtime_attachment() {
        let original = persisted(VmPhase::Starting);
        let json = serde_json::to_value(&original).unwrap();
        assert!(json.get("cw_runtime_disk").is_none());
        let restored: PersistedVmState = serde_json::from_value(json).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored, original);
        assert!(restored.cw_runtime_disk.is_none());
    }

    #[test]
    fn persisted_phase_requires_an_exact_socket_identity_shape() {
        let mut state = persisted(VmPhase::Starting);
        assert!(state.validate().is_ok());

        let socket = SocketIdentity {
            device: 1,
            inode: 4,
            uid: crate::host::path::current_uid(),
            mode: 0o140600,
            pin: Default::default(),
        };
        state.api_socket = Some(socket.clone());
        assert!(matches!(
            state.validate(),
            Err(StateError::InvalidPersistedState)
        ));

        state.phase = VmPhase::Running;
        assert!(matches!(
            state.validate(),
            Err(StateError::InvalidPersistedState)
        ));
        state.vsock_socket = Some(socket);
        #[cfg(target_os = "linux")]
        assert!(state.validate().is_ok());
        // The Darwin VMM has no API socket: a running VM records only vsock.
        #[cfg(target_os = "macos")]
        {
            assert!(matches!(
                state.validate(),
                Err(StateError::InvalidPersistedState)
            ));
            state.api_socket = None;
            assert!(state.validate().is_ok());
        }
    }

    #[test]
    fn persisted_root_generation_requires_an_exact_identity_pair() {
        let mut state = persisted(VmPhase::Starting);
        let root_disk = state.state_disk.clone();

        state.root_generation = Some("a".repeat(64));
        assert!(matches!(
            state.validate(),
            Err(StateError::InvalidPersistedState)
        ));

        state.root_generation = None;
        state.root_disk = Some(root_disk.clone());
        assert!(matches!(
            state.validate(),
            Err(StateError::InvalidPersistedState)
        ));

        state.root_generation = Some("not-a-generation".to_owned());
        assert!(matches!(
            state.validate(),
            Err(StateError::InvalidPersistedState)
        ));

        state.root_generation = Some("a".repeat(64));
        assert!(state.validate().is_ok());

        state.root_disk.as_mut().unwrap().filesystem_uuid = Uuid::nil();
        assert!(matches!(
            state.validate(),
            Err(StateError::InvalidPersistedState)
        ));
    }

    #[test]
    fn stopped_vm_tree_moves_to_operation_trash_and_cleans_known_layout() {
        let (_parent, root) = private_root();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let paths = VmPaths::create(&root, vm_id).unwrap();
        write_minimal_ext4(&paths.state_disk, Uuid::new_v4());
        write_minimal_ext4(&paths.docker_disk, Uuid::new_v4());
        fs::write(paths.disks_dir.join("docker.raw.staging"), b"staging").unwrap();
        fs::set_permissions(
            paths.disks_dir.join("docker.raw.staging"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let trash = move_stopped_vm_to_trash(root.path(), vm_id, operation_id).unwrap();
        assert!(!paths.vm_dir.exists());
        assert!(trash.is_dir());
        assert_eq!(
            move_stopped_vm_to_trash(root.path(), vm_id, operation_id).unwrap(),
            trash
        );

        cleanup_trashed_vm(root.path(), vm_id, operation_id).unwrap();
        assert!(!trash.exists());
        cleanup_trashed_vm(root.path(), vm_id, operation_id).unwrap();
    }

    #[test]
    fn trash_cleanup_removes_all_admitted_root_generations() {
        let (_parent, root) = private_root();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let paths = VmPaths::create(&root, vm_id).unwrap();
        for generation in ["a".repeat(64), "b".repeat(64)] {
            let generation = RootGenerationPaths::create(&paths, &generation).unwrap();
            write_minimal_ext4(&generation.root_disk, Uuid::new_v4());
            fs::write(&generation.setup_disk, b"setup").unwrap();
            fs::set_permissions(&generation.setup_disk, fs::Permissions::from_mode(0o400)).unwrap();
        }

        let trash = move_stopped_vm_to_trash(root.path(), vm_id, operation_id).unwrap();
        assert!(trash.join("generations").is_dir());
        cleanup_trashed_vm(root.path(), vm_id, operation_id).unwrap();
        assert!(!trash.exists());
    }

    #[test]
    fn root_generation_collection_retains_only_durable_references() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();
        let active = "a".repeat(64);
        let rollback = "b".repeat(64);
        let stale = "c".repeat(64);
        let interrupted = "d".repeat(64);

        for name in [&active, &rollback, &stale] {
            let generation = RootGenerationPaths::create(&paths, name).unwrap();
            write_minimal_ext4(&generation.root_disk, Uuid::new_v4());
            fs::write(&generation.setup_disk, b"setup").unwrap();
            fs::set_permissions(&generation.setup_disk, fs::Permissions::from_mode(0o400)).unwrap();
        }
        RootGenerationPaths::create(&paths, &interrupted).unwrap();

        let removed = cleanup_unreferenced_root_generations(
            &paths,
            &BTreeSet::from([active.clone(), rollback.clone()]),
        )
        .unwrap();

        assert_eq!(removed, vec![stale.clone(), interrupted.clone()]);
        assert!(paths.generations_dir.join(active).is_dir());
        assert!(paths.generations_dir.join(rollback).is_dir());
        assert!(!paths.generations_dir.join(stale).exists());
        assert!(!paths.generations_dir.join(interrupted).exists());
    }

    #[test]
    fn root_generation_collection_rejects_unknown_objects_before_unlink() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();
        let first = "a".repeat(64);
        let unsafe_generation = "b".repeat(64);
        for name in [&first, &unsafe_generation] {
            let generation = RootGenerationPaths::create(&paths, name).unwrap();
            write_minimal_ext4(&generation.root_disk, Uuid::new_v4());
        }
        let unknown = paths
            .generations_dir
            .join(&unsafe_generation)
            .join("unknown");
        fs::write(&unknown, b"leave me").unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            cleanup_unreferenced_root_generations(&paths, &BTreeSet::new()),
            Err(StateError::UnexpectedOwnedObject(path)) if path == unknown
        ));
        assert!(paths.generations_dir.join(first).join("root.raw").is_file());
        assert!(
            paths
                .generations_dir
                .join(unsafe_generation)
                .join("root.raw")
                .is_file()
        );
    }

    #[test]
    fn root_generation_collection_rejects_invalid_retained_identity() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();

        assert!(matches!(
            cleanup_unreferenced_root_generations(
                &paths,
                &BTreeSet::from(["../generation".to_owned()]),
            ),
            Err(StateError::InvalidRootGeneration)
        ));
    }

    #[test]
    fn trash_cleanup_refuses_unknown_objects_without_partial_removal() {
        let (_parent, root) = private_root();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let paths = VmPaths::create(&root, vm_id).unwrap();
        fs::write(paths.vm_dir.join("unknown"), b"leave me").unwrap();
        fs::set_permissions(
            paths.vm_dir.join("unknown"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let trash = move_stopped_vm_to_trash(root.path(), vm_id, operation_id).unwrap();
        assert!(matches!(
            cleanup_trashed_vm(root.path(), vm_id, operation_id),
            Err(StateError::UnexpectedOwnedObject(path)) if path == trash.join("unknown")
        ));
        assert!(trash.join("unknown").is_file());
        assert!(trash.join("disks").is_dir());
    }

    #[test]
    fn trash_cleanup_refuses_unknown_generation_without_partial_removal() {
        let (_parent, root) = private_root();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let paths = VmPaths::create(&root, vm_id).unwrap();
        let admitted = RootGenerationPaths::create(&paths, &"a".repeat(64)).unwrap();
        write_minimal_ext4(&admitted.root_disk, Uuid::new_v4());
        let unknown = paths.generations_dir.join("not-a-generation");
        fs::create_dir(&unknown).unwrap();
        fs::set_permissions(&unknown, fs::Permissions::from_mode(0o700)).unwrap();

        let trash = move_stopped_vm_to_trash(root.path(), vm_id, operation_id).unwrap();
        let admitted_root = trash
            .join("generations")
            .join("a".repeat(64))
            .join("root.raw");
        assert!(matches!(
            cleanup_trashed_vm(root.path(), vm_id, operation_id),
            Err(StateError::UnexpectedOwnedObject(path))
                if path == trash.join("generations").join("not-a-generation")
        ));
        assert!(admitted_root.is_file());
        assert!(trash.join("disks").is_dir());
    }

    #[test]
    fn trash_move_never_replaces_an_existing_generation() {
        let (_parent, root) = private_root();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let paths = VmPaths::create(&root, vm_id).unwrap();
        let trash = root.ensure_dir(Path::new("trash"), 0o700).unwrap();
        let trash = PrivateRoot::open(&trash).unwrap();
        let destination = trash_name(vm_id, operation_id);
        trash.create_dir(Path::new(&destination), 0o700).unwrap();

        assert!(matches!(
            move_stopped_vm_to_trash(root.path(), vm_id, operation_id),
            Err(StateError::TrashConflict(path)) if path == trash.path().join(destination)
        ));
        assert!(paths.vm_dir.is_dir());
    }

    #[test]
    fn deletion_tree_location_rejects_split_brain() {
        let (_parent, root) = private_root();
        let vm_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        VmPaths::create(&root, vm_id).unwrap();
        let trash = root.ensure_dir(Path::new("trash"), 0o700).unwrap();
        PrivateRoot::open(&trash)
            .unwrap()
            .create_dir(Path::new(&trash_name(vm_id, operation_id)), 0o700)
            .unwrap();

        assert!(matches!(
            deletion_tree_location(root.path(), vm_id, operation_id),
            Err(StateError::TrashConflict(_))
        ));
    }
}
