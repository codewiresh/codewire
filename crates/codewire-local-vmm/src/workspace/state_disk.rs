//! Formatting a VM's state disk: with a provisioned workspace, or empty for
//! a `standard` Pod (#5602).

use super::*;

/// The state disk of a VM that starts with an empty workspace, as the
/// `standard` Pod's does (#5602): made once with empty `workspace/` and
/// `home/`, then kept. An existing disk must be `disk_bytes`.
#[cfg(target_os = "linux")]
pub(crate) fn ensure_empty_state_disk(
    engine_state_root: &Path,
    vm_id: Uuid,
    disk_bytes: u64,
) -> Result<PathBuf, WorkspaceError> {
    if disk_bytes < MINIMUM_STATE_DISK_BYTES
        || !disk_bytes.is_multiple_of(1024 * 1024)
        || disk_bytes <= MINIMUM_EXT4_HEADROOM
    {
        return Err(WorkspaceError::InvalidDiskSize(disk_bytes));
    }
    let engine_root = PrivateRoot::open(engine_state_root)?;
    let paths = VmPaths::create(&engine_root, vm_id)?;
    cleanup_provisioning_staging(&engine_root, vm_id)?;
    match fs::symlink_metadata(&paths.state_disk) {
        Ok(_) => {
            let identity = StateDiskIdentity::capture(&paths.state_disk)?;
            if identity.file.size != disk_bytes {
                return Err(WorkspaceError::ExistingDiskSizeMismatch {
                    path: paths.state_disk,
                    expected: disk_bytes,
                    actual: identity.file.size,
                });
            }
            return Ok(paths.state_disk);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(WorkspaceError::Io {
                path: paths.state_disk,
                source,
            });
        }
    }
    let staging_dir =
        engine_root.create_dir(Path::new(&provisioning_staging_name(vm_id)), 0o700)?;
    let mut cleanup = ProvisionCleanup::new(staging_dir.clone(), paths.state_disk.clone());
    for (name, mode) in [("workspace", 0o755), ("home", 0o700)] {
        let directory = staging_dir.join(name);
        fs::create_dir(&directory)
            .and_then(|()| fs::set_permissions(&directory, fs::Permissions::from_mode(mode)))
            .map_err(|source| WorkspaceError::Io {
                path: directory,
                source,
            })?;
    }
    let disk = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&paths.state_disk)
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;
    disk.set_len(disk_bytes)
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;
    drop(disk);
    format_state_disk(&staging_dir, &paths.state_disk)?;
    File::open(&paths.state_disk)
        .and_then(|file| file.sync_all())
        .and_then(|()| File::open(&paths.disks_dir)?.sync_all())
        .map_err(|source| WorkspaceError::Io {
            path: paths.state_disk.clone(),
            source,
        })?;
    cleanup.remove_staging()?;
    cleanup.disarm_disk();
    Ok(paths.state_disk)
}

/// Format a new VM's state disk with the contents of `staging`. It alone has
/// the ext4 `verity` feature, so the guest can seal files on it; a kernel
/// without fs-verity mounts such a disk read-only.
pub(super) fn format_state_disk(staging: &Path, disk: &Path) -> Result<(), WorkspaceError> {
    let mkfs = crate::host::e2fsprogs("mkfs.ext4").ok_or(WorkspaceError::MkfsUnavailable)?;
    let mut command = crate::swept_command(mkfs, &[]);
    command
        .args(crate::host::EXT4_FORMAT)
        .args([
            OsStr::new("-O"),
            OsStr::new("verity"),
            OsStr::new("-q"),
            OsStr::new("-F"),
            OsStr::new("-m"),
            OsStr::new("0"),
        ])
        .arg("-d")
        .arg(staging)
        .arg(disk)
        .env_clear()
        .env("LC_ALL", "C");
    #[cfg(target_os = "macos")]
    command.env(
        "MKE2FS_CONFIG",
        crate::host::mke2fs_config().ok_or(WorkspaceError::MkfsUnavailable)?,
    );
    let status = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| WorkspaceError::MkfsUnavailable)?;
    if !status.success() {
        return Err(WorkspaceError::MkfsFailed);
    }
    Ok(())
}
