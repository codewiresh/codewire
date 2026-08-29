//! Host-owned root-generation disk preparation.
//!
//! This module creates only an empty ext4 filesystem. OCI descriptors and
//! hostile layer bytes are never extracted on the host; the authenticated
//! guest setup path owns their verification and application.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use uuid::Uuid;

use crate::linux::path::PrivateRoot;
use crate::linux::state::{
    MAXIMUM_ROOT_GENERATIONS, MINIMUM_ROOT_DISK_BYTES, RootGenerationPaths, StateDiskIdentity,
    VmPaths, admitted_generation_names,
};

const MAXIMUM_ROOT_DISK_BYTES: u64 = 128 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootGenerationDisk {
    pub generation: String,
    pub path: PathBuf,
    pub identity: StateDiskIdentity,
}

pub fn ensure_empty_root_generation(
    engine_state_root: &Path,
    vm_id: Uuid,
    generation: &str,
    disk_bytes: u64,
) -> Result<RootGenerationDisk, GenerationError> {
    if !(MINIMUM_ROOT_DISK_BYTES..=MAXIMUM_ROOT_DISK_BYTES).contains(&disk_bytes)
        || !disk_bytes.is_multiple_of(1024 * 1024)
    {
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
    format_empty_ext4(&generation_paths.root_disk)?;
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
    })
}

fn format_empty_ext4(disk: &Path) -> Result<(), GenerationError> {
    let mkfs = ["/usr/sbin/mkfs.ext4", "/usr/bin/mkfs.ext4"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or(GenerationError::MkfsUnavailable)?;
    let status = Command::new(mkfs)
        .args([
            OsStr::new("-q"),
            OsStr::new("-F"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-L"),
            OsStr::new("CWROOT"),
        ])
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C")
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
    #[error("mkfs.ext4 is required for root generation preparation")]
    MkfsUnavailable,
    #[error("mkfs.ext4 failed to create the root generation disk")]
    MkfsFailed,
    #[error(transparent)]
    Path(#[from] crate::linux::path::PathError),
    #[error(transparent)]
    State(#[from] crate::linux::state::StateError),
    #[error("filesystem operation failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::PermissionsExt as _;

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
                crate::linux::state::StateError::InvalidRootGeneration
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
