//! Host-owned root-generation disk preparation.
//!
//! This module creates an empty ext4 filesystem or seeds it with an exact
//! host-prepared immutable skill snapshot. OCI descriptors and hostile layer
//! bytes are never extracted on the host; the authenticated guest setup path
//! owns their verification and application.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use uuid::Uuid;

use crate::host::path::PrivateRoot;
use crate::state::{
    MAXIMUM_ROOT_GENERATIONS, RootGenerationPaths, StateDiskIdentity, VmPaths,
    admitted_generation_names,
};
pub(crate) use crate::supervisor_metadata::legacy::valid_root_disk_bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootGenerationDisk {
    pub generation: String,
    pub path: PathBuf,
    pub identity: StateDiskIdentity,
    /// True only when this invocation published and formatted the disk.
    pub created: bool,
}

pub fn ensure_empty_root_generation(
    engine_state_root: &Path,
    vm_id: Uuid,
    generation: &str,
    disk_bytes: u64,
) -> Result<RootGenerationDisk, GenerationError> {
    ensure_root_generation(
        engine_state_root,
        vm_id,
        generation,
        disk_bytes,
        false,
        None,
    )
}

pub(crate) fn ensure_root_generation(
    engine_state_root: &Path,
    vm_id: Uuid,
    generation: &str,
    disk_bytes: u64,
    skill_snapshot_expected: bool,
    seed_directory: Option<&Path>,
) -> Result<RootGenerationDisk, GenerationError> {
    if !valid_root_disk_bytes(disk_bytes) {
        return Err(GenerationError::InvalidDiskSize(disk_bytes));
    }
    let engine = PrivateRoot::open(engine_state_root)?;
    let paths = VmPaths::create(&engine, vm_id)?;
    let generations = PrivateRoot::open(&paths.generations_dir)?;
    let admitted = admitted_generation_names(&generations)?;
    if !admitted.iter().any(|existing| existing == generation)
        && admitted.len() == MAXIMUM_ROOT_GENERATIONS
    {
        return Err(GenerationError::GenerationLimit);
    }
    let generation_paths = RootGenerationPaths::create(&paths, generation)?;
    match fs::symlink_metadata(&generation_paths.root_disk) {
        Ok(_) => {
            let identity = StateDiskIdentity::capture(&generation_paths.root_disk)?;
            if identity.file.size != disk_bytes {
                return Err(GenerationError::ExistingDiskSizeMismatch {
                    path: generation_paths.root_disk,
                    expected: disk_bytes,
                    actual: identity.file.size,
                });
            }
            return Ok(RootGenerationDisk {
                generation: generation.to_owned(),
                path: generation_paths.root_disk,
                identity,
                created: false,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(GenerationError::Io {
                path: generation_paths.root_disk,
                source,
            });
        }
    }
    if skill_snapshot_expected && seed_directory.is_none() {
        return Err(GenerationError::SkillSnapshotSeedRequired);
    }

    let mut cleanup = NewDiskCleanup::new(
        generation_paths.root_disk.clone(),
        generation_paths.generation_dir.clone(),
    );
    let disk = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&generation_paths.root_disk)
        .map_err(|source| GenerationError::Io {
            path: generation_paths.root_disk.clone(),
            source,
        })?;
    disk.set_len(disk_bytes)
        .and_then(|()| disk.sync_all())
        .map_err(|source| GenerationError::Io {
            path: generation_paths.root_disk.clone(),
            source,
        })?;
    drop(disk);
    format_ext4(&generation_paths.root_disk, seed_directory)?;
    File::open(&generation_paths.root_disk)
        .and_then(|file| file.sync_all())
        .and_then(|()| File::open(&generation_paths.generation_dir)?.sync_all())
        .map_err(|source| GenerationError::Io {
            path: generation_paths.root_disk.clone(),
            source,
        })?;
    let identity = StateDiskIdentity::capture(&generation_paths.root_disk)?;
    if identity.file.size != disk_bytes {
        return Err(GenerationError::ExistingDiskSizeMismatch {
            path: generation_paths.root_disk,
            expected: disk_bytes,
            actual: identity.file.size,
        });
    }
    cleanup.disarm();
    Ok(RootGenerationDisk {
        generation: generation.to_owned(),
        path: generation_paths.root_disk,
        identity,
        created: true,
    })
}

fn format_ext4(disk: &Path, seed_directory: Option<&Path>) -> Result<(), GenerationError> {
    let mkfs = crate::host::e2fsprogs("mkfs.ext4").ok_or(GenerationError::MkfsUnavailable)?;
    #[cfg(target_os = "macos")]
    let config = crate::host::mke2fs_config().ok_or(GenerationError::MkfsUnavailable)?;
    if let Some(seed) = seed_directory {
        let metadata = fs::symlink_metadata(seed).map_err(|source| GenerationError::Io {
            path: seed.to_owned(),
            source,
        })?;
        if !seed.is_absolute() || !metadata.is_dir() {
            return Err(GenerationError::InvalidSeedDirectory(seed.to_owned()));
        }
    }
    let mut command = Command::new(mkfs);
    command.args(crate::host::EXT4_FORMAT).args([
        OsStr::new("-q"),
        OsStr::new("-F"),
        OsStr::new("-m"),
        OsStr::new("0"),
        OsStr::new("-L"),
        OsStr::new("CWROOT"),
    ]);
    if let Some(seed) = seed_directory {
        command.arg("-d").arg(seed);
    }
    command.arg(disk).env_clear().env("LC_ALL", "C");
    #[cfg(target_os = "macos")]
    command.env("MKE2FS_CONFIG", config);
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| GenerationError::MkfsUnavailable)?;
    if !status.success() {
        return Err(GenerationError::MkfsFailed);
    }
    Ok(())
}

struct NewDiskCleanup {
    disk: Option<PathBuf>,
    generation_directory: PathBuf,
}

impl NewDiskCleanup {
    fn new(disk: PathBuf, generation_directory: PathBuf) -> Self {
        Self {
            disk: Some(disk),
            generation_directory,
        }
    }

    fn disarm(&mut self) {
        self.disk = None;
    }
}

impl Drop for NewDiskCleanup {
    fn drop(&mut self) {
        if let Some(disk) = self.disk.take() {
            let _ = fs::remove_file(disk);
            let _ = fs::remove_dir(&self.generation_directory);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("root generation disk size is invalid: {0}")]
    InvalidDiskSize(u64),
    #[error("root generation limit reached; garbage collection is required before staging")]
    GenerationLimit,
    #[error(
        "existing root generation disk has size {actual}, but the generation requires {expected}: {path}"
    )]
    ExistingDiskSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[cfg_attr(
        target_os = "linux",
        error(
            "mkfs.ext4 is required for root generation preparation; install your distribution's e2fsprogs package (cw looks in /usr/sbin and /usr/bin)"
        )
    )]
    #[cfg_attr(
        target_os = "macos",
        error(
            "the local VM runtime's mkfs.ext4 is missing or changed; reinstall the local VM runtime: cw setup --local --replace"
        )
    )]
    MkfsUnavailable,
    #[error("mkfs.ext4 failed to create the root generation disk")]
    MkfsFailed,
    #[error("skill snapshot material is required to create this root generation")]
    SkillSnapshotSeedRequired,
    #[error("root generation seed directory is invalid: {0}")]
    InvalidSeedDirectory(PathBuf),
    #[error(transparent)]
    Path(#[from] crate::host::path::PathError),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::PermissionsExt as _;

    use crate::supervisor_metadata::legacy::{MAXIMUM_ROOT_DISK_BYTES, MINIMUM_ROOT_DISK_BYTES};

    use super::*;

    #[test]
    fn replay_admits_only_the_exact_generation_disk() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine_root = PrivateRoot::open(engine.path()).unwrap();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&engine_root, vm_id).unwrap();
        let generation = "a".repeat(64);
        let root = RootGenerationPaths::create(&paths, &generation).unwrap();
        write_test_ext4(&root.root_disk, MINIMUM_ROOT_DISK_BYTES);

        let admitted = ensure_empty_root_generation(
            engine.path(),
            vm_id,
            &generation,
            MINIMUM_ROOT_DISK_BYTES,
        )
        .unwrap();
        assert_eq!(admitted.path, root.root_disk);
        assert_eq!(admitted.generation, generation);
        assert!(!admitted.created);
        assert!(matches!(
            ensure_empty_root_generation(
                engine.path(),
                vm_id,
                &admitted.generation,
                MINIMUM_ROOT_DISK_BYTES + 1024 * 1024,
            ),
            Err(GenerationError::ExistingDiskSizeMismatch { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn creation_is_reported_only_by_the_publishing_invocation() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let vm_id = Uuid::new_v4();
        let generation = "b".repeat(64);

        let created = ensure_empty_root_generation(
            engine.path(),
            vm_id,
            &generation,
            MINIMUM_ROOT_DISK_BYTES,
        )
        .unwrap();
        assert!(created.created);

        let replayed = ensure_empty_root_generation(
            engine.path(),
            vm_id,
            &generation,
            MINIMUM_ROOT_DISK_BYTES,
        )
        .unwrap();
        assert!(!replayed.created);
        assert_eq!(replayed.identity, created.identity);
    }

    #[test]
    fn generation_identity_rejects_traversal() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            ensure_empty_root_generation(
                engine.path(),
                Uuid::new_v4(),
                "../escape",
                MINIMUM_ROOT_DISK_BYTES,
            ),
            Err(GenerationError::State(
                crate::state::StateError::InvalidRootGeneration
            ))
        ));
    }

    #[test]
    fn generation_disk_size_is_bounded_and_megabyte_aligned() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for size in [
            MINIMUM_ROOT_DISK_BYTES - 1024 * 1024,
            MINIMUM_ROOT_DISK_BYTES + 1,
            MAXIMUM_ROOT_DISK_BYTES + 1024 * 1024,
        ] {
            assert!(matches!(
                ensure_empty_root_generation(
                    engine.path(),
                    Uuid::new_v4(),
                    &"a".repeat(64),
                    size,
                ),
                Err(GenerationError::InvalidDiskSize(rejected)) if rejected == size
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn skill_snapshot_generation_requires_explicit_seed_before_publication() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let seed = tempfile::tempdir().unwrap();
        fs::write(seed.path().join("skill-snapshot.json"), b"snapshot\n").unwrap();
        let vm_id = Uuid::new_v4();
        let generation = "c".repeat(64);

        assert!(matches!(
            ensure_root_generation(
                engine.path(),
                vm_id,
                &generation,
                MINIMUM_ROOT_DISK_BYTES,
                true,
                None,
            ),
            Err(GenerationError::SkillSnapshotSeedRequired)
        ));
        let created = ensure_root_generation(
            engine.path(),
            vm_id,
            &generation,
            MINIMUM_ROOT_DISK_BYTES,
            true,
            Some(seed.path()),
        )
        .unwrap();
        assert!(created.created);
    }

    #[test]
    fn existing_generation_disk_must_be_a_private_regular_file() {
        use std::os::unix::fs::symlink;

        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine_root = PrivateRoot::open(engine.path()).unwrap();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&engine_root, vm_id).unwrap();
        let generation = "a".repeat(64);
        let root = RootGenerationPaths::create(&paths, &generation).unwrap();
        let outside = engine.path().join("outside.raw");
        write_test_ext4(&outside, MINIMUM_ROOT_DISK_BYTES);
        symlink(&outside, &root.root_disk).unwrap();

        assert!(
            ensure_empty_root_generation(
                engine.path(),
                vm_id,
                &generation,
                MINIMUM_ROOT_DISK_BYTES,
            )
            .is_err()
        );
        assert!(outside.is_file());
    }

    #[test]
    fn a_new_generation_fails_before_formatting_at_the_owned_limit() {
        let engine = tempfile::tempdir().unwrap();
        fs::set_permissions(engine.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let engine_root = PrivateRoot::open(engine.path()).unwrap();
        let vm_id = Uuid::new_v4();
        let paths = VmPaths::create(&engine_root, vm_id).unwrap();
        for index in 0..MAXIMUM_ROOT_GENERATIONS {
            RootGenerationPaths::create(&paths, &format!("{index:064x}")).unwrap();
        }

        assert!(matches!(
            ensure_empty_root_generation(
                engine.path(),
                vm_id,
                &format!("{:064x}", MAXIMUM_ROOT_GENERATIONS),
                MINIMUM_ROOT_DISK_BYTES,
            ),
            Err(GenerationError::GenerationLimit)
        ));
    }

    fn write_test_ext4(path: &Path, size: u64) {
        let mut disk = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        disk.set_len(size).unwrap();
        let mut superblock = [0_u8; 0x78];
        superblock[0x38..0x3a].copy_from_slice(&[0x53, 0xef]);
        superblock[0x68..0x78].copy_from_slice(Uuid::new_v4().as_bytes());
        disk.seek(SeekFrom::Start(1024)).unwrap();
        disk.write_all(&superblock).unwrap();
        disk.sync_all().unwrap();
    }
}
