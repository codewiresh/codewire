use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use uuid::Uuid;

use super::path::{FileIdentity, PathError, PrivateRoot, SocketIdentity};
use super::process::ProcessIdentity;

pub const PERSISTED_STATE_SCHEMA_VERSION: u32 = 1;
pub const MINIMUM_STATE_DISK_BYTES: u64 = 256 * 1024 * 1024;
const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_BYTES: usize = 0x78;
const EXT4_MAGIC_OFFSET: usize = 0x38;
const EXT4_UUID_OFFSET: usize = 0x68;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmPaths {
    pub vm_dir: PathBuf,
    pub api_dir: PathBuf,
    pub api_socket: PathBuf,
    pub vsock_dir: PathBuf,
    pub vsock_socket: PathBuf,
    pub disks_dir: PathBuf,
    pub state_disk: PathBuf,
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
        let api_dir = vm_root.ensure_dir(Path::new("api"), 0o700)?;
        let vsock_dir = vm_root.ensure_dir(Path::new("vsock"), 0o700)?;
        let disks_dir = vm_root.ensure_dir(Path::new("disks"), 0o700)?;
        let seed_dir = vm_root.ensure_dir(Path::new("seed"), 0o700)?;
        let diagnostics_dir = vm_root.ensure_dir(Path::new("diagnostics"), 0o700)?;
        Ok(Self {
            api_socket: api_dir.join("api.sock"),
            vsock_socket: vsock_dir.join("vsock.sock"),
            state_disk: disks_dir.join("state.raw"),
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

    pub fn clear_stale_runtime_endpoints(&self) -> Result<(), StateError> {
        PrivateRoot::open(&self.api_dir)?.remove_private_socket(Path::new("api.sock"))?;
        PrivateRoot::open(&self.vsock_dir)?.remove_private_socket(Path::new("vsock.sock"))?;
        Ok(())
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
        let valid_phase = matches!(
            (self.phase, &self.api_socket, &self.vsock_socket),
            (VmPhase::Starting, None, None) | (VmPhase::Running, Some(_), Some(_))
        );
        if self.schema_version != PERSISTED_STATE_SCHEMA_VERSION
            || self.vm_id.is_nil()
            || self.generation == 0
            || self.vsock_cid < 3
            || self.vsock_cid == u32::MAX
            || self.daemon_vsock_port == 0
            || self.daemon_vsock_port == u32::MAX
            || self.state_disk.filesystem_uuid.is_nil()
            || !valid_phase
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

fn read_ext4_uuid(file: &File, path: &Path) -> Result<Uuid, StateError> {
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
    let uuid = Uuid::from_slice(&superblock[EXT4_UUID_OFFSET..EXT4_UUID_OFFSET + 16])
        .map_err(|_| StateError::InvalidExt4(path.to_owned()))?;
    if uuid.is_nil() {
        return Err(StateError::InvalidExt4(path.to_owned()));
    }
    Ok(uuid)
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("VM is already owned by another supervisor process")]
    AlreadyLocked,
    #[error("unsafe existing runtime endpoint: {0}")]
    UnsafeExistingEndpoint(PathBuf),
    #[error("invalid state disk path: {0}")]
    InvalidStateDisk(PathBuf),
    #[error("invalid state disk size {0}")]
    InvalidDiskSize(u64),
    #[error("state disk is not a valid ext4 filesystem: {0}")]
    InvalidExt4(PathBuf),
    #[error("state disk identity changed: {0}")]
    StateDiskIdentityChanged(PathBuf),
    #[error("invalid persisted VM state")]
    InvalidPersistedState,
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
                    uid: super::super::path::current_uid(),
                    mode: 0o100500,
                    links: 1,
                },
                executable_sha256: "a".repeat(64),
            },
            state_disk: StateDiskIdentity {
                file: FileIdentity {
                    device: 1,
                    inode: 3,
                    size: MINIMUM_STATE_DISK_BYTES,
                    uid: super::super::path::current_uid(),
                    mode: 0o100600,
                    links: 1,
                },
                filesystem_uuid: Uuid::new_v4(),
            },
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
            &paths.disks_dir,
            &paths.seed_dir,
            &paths.diagnostics_dir,
        ];
        for (index, directory) in directories.iter().enumerate() {
            assert_eq!(directory.parent(), Some(paths.vm_dir.as_path()));
            assert_eq!(fs::metadata(directory).unwrap().mode() & 0o777, 0o700);
            for other in directories.iter().skip(index + 1) {
                assert_ne!(directory, other);
            }
        }
        assert_eq!(paths.state_disk.parent(), Some(paths.disks_dir.as_path()));
        assert_eq!(paths.seed_disk.parent(), Some(paths.seed_dir.as_path()));
        assert_eq!(fs::metadata(&paths.vm_dir).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn vm_lock_excludes_a_second_owner_until_released() {
        let (_parent, root) = private_root();
        let paths = VmPaths::create(&root, Uuid::new_v4()).unwrap();

        let first = paths.lock().unwrap();
        assert!(matches!(paths.lock(), Err(StateError::AlreadyLocked)));

        drop(first);
        paths.lock().unwrap();
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
    fn persisted_phase_requires_an_exact_socket_identity_shape() {
        let mut state = persisted(VmPhase::Starting);
        assert!(state.validate().is_ok());

        let socket = SocketIdentity {
            device: 1,
            inode: 4,
            uid: super::super::path::current_uid(),
            mode: 0o140600,
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
        assert!(state.validate().is_ok());
    }
}
