//! Clearing a restore that is a Block volume (#3718). Its fork's guest formats
//! and reads the disk block by block, so besides the files every block the
//! guest cannot read through the filesystem is wiped
//! (private-docs designs/2026-11-01-commodity-workspace-direct-io.md,
//! section 3). This runs as the only process of a clearing Sandbox, a VM with
//! no network, so the host never parses the guest's filesystem.
//!
//! 1. a settling `e2fsck -f -p`, which replays the journal and refuses a
//!    filesystem it cannot fix without asking;
//! 2. mount it on an empty directory and clear its files, as a Filesystem
//!    restore's are ([`super::clear_workspace_volume`]);
//! 3. unmount it and settle it again, so the block bitmaps are exact;
//! 4. wipe every free range and each file's unwritten extents and blocks past
//!    its end ([`codewire_ext4_scrub::wipe_unreadable_blocks`]).
//!
//! Any failure is an error, never retried with `e2fsck -y`, so a volume that
//! could not be cleared is never kept.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileTypeExt as _;
use std::path::Path;

use codewire_ext4_scrub::{SystemTools, WipeReport, e2fsck, wipe_unreadable_blocks};

use super::{ClearingReport, clear_workspace_volume};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockClearingReport {
    pub files: ClearingReport,
    pub wipe: WipeReport,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockClearingError {
    #[error("the restore is not a block device")]
    NotBlockDevice,
    #[error("the volume's filesystem could not be settled: {0}")]
    Check(codewire_ext4_scrub::Error),
    #[error("the volume could not be mounted: {0}")]
    Mount(io::Error),
    #[error("the volume's delivered sign-ins could not be cleared: {0}")]
    Files(io::Error),
    #[error("the volume could not be unmounted: {0}")]
    Unmount(io::Error),
    #[error("the volume's free blocks could not be wiped: {0}")]
    Wipe(codewire_ext4_scrub::Error),
}

/// Clear the ext4 filesystem on the block device `device`, mounting it on the
/// empty directory `mount_point` while its files are cleared.
pub async fn clear_block_volume(
    device: &Path,
    mount_point: &Path,
) -> Result<BlockClearingReport, BlockClearingError> {
    let is_block_device = std::fs::metadata(device)
        .map_err(|_| BlockClearingError::NotBlockDevice)?
        .file_type()
        .is_block_device();
    if !is_block_device {
        return Err(BlockClearingError::NotBlockDevice);
    }
    e2fsck(&SystemTools, device)
        .await
        .map_err(BlockClearingError::Check)?;
    mount(device, mount_point).map_err(BlockClearingError::Mount)?;
    let files = clear_workspace_volume(mount_point);
    // Unmounted whatever clearing said, so the device is never left mounted.
    let unmounted = unmount(mount_point);
    let files = files.map_err(BlockClearingError::Files)?;
    unmounted.map_err(BlockClearingError::Unmount)?;
    e2fsck(&SystemTools, device)
        .await
        .map_err(BlockClearingError::Check)?;
    let wipe = wipe_unreadable_blocks(&SystemTools, device)
        .await
        .map_err(BlockClearingError::Wipe)?;
    Ok(BlockClearingReport { files, wipe })
}

fn path_string(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path holds a NUL byte"))
}

/// Mount the ext4 filesystem on `device` at `target`, never executing,
/// honouring set-id bits or opening device nodes from it.
fn mount(device: &Path, target: &Path) -> io::Result<()> {
    let (source, target) = (path_string(device)?, path_string(target)?);
    let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    // SAFETY: every pointer is a live NUL-terminated string or null.
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            c"ext4".as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Unmount `target`, failing while anything holds it.
fn unmount(target: &Path) -> io::Result<()> {
    let target = path_string(target)?;
    // SAFETY: a live NUL-terminated string.
    let result = unsafe { libc::umount2(target.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn anything_but_a_block_device_is_refused_before_any_tool_runs() {
        let scratch = tempfile::tempdir().unwrap();
        let image = scratch.path().join("disk.raw");
        std::fs::write(&image, [0_u8; 4096]).unwrap();

        for device in [
            image.as_path(),
            &scratch.path().join("missing"),
            scratch.path(),
        ] {
            let error = clear_block_volume(device, scratch.path())
                .await
                .unwrap_err();
            assert!(
                matches!(error, BlockClearingError::NotBlockDevice),
                "{error}"
            );
        }
    }
}
