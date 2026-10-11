//! Persisted direct-share identity and its closed codec validation.
//!
//! The fields name Linux's statx/statfs identity. Darwin has no mount ID or
//! statfs magic, so a Darwin store records these Darwin values in the same
//! fields, and each platform admits only its own filesystems:
//!
//! - `device_major`/`device_minor`: `major()`/`minor()` of `st_dev` on both.
//! - `inode`, `owner_uid`: `st_ino`, `st_uid` on both.
//! - `mount_id`: Linux `stx_mnt_id`; Darwin the mounted filesystem's `f_fsid`,
//!   its two 32-bit words packed high then low.
//! - `filesystem_magic`: Linux `statfs.f_type`; Darwin the APFS volume
//!   superblock magic, the only filesystem it admits.
//!
//! Each platform's native store is private to it, and a record carrying the
//! other platform's filesystem fails validation rather than being reinterpreted.

use std::path::PathBuf;

use codewire_vmm_guest_probe::DirectSharePlanError;
use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "macos"))]
const EXT4_SUPER_MAGIC: i64 = 0x0000_ef53;
#[cfg(not(target_os = "macos"))]
const TMPFS_MAGIC: i64 = 0x0102_1994;
#[cfg(not(target_os = "macos"))]
const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
#[cfg(not(target_os = "macos"))]
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
#[cfg(not(target_os = "macos"))]
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c_7630;
#[cfg(not(target_os = "macos"))]
const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;
#[cfg(not(target_os = "macos"))]
const F2FS_SUPER_MAGIC: i64 = 0xf2f5_2010;
#[cfg(not(target_os = "macos"))]
const BCACHEFS_SUPER_MAGIC: i64 = 0xca45_1a4e;
/// The APFS volume superblock magic, `APSB` read as a little-endian `u32`.
#[cfg(target_os = "macos")]
pub(crate) const APFS_VOLUME_MAGIC: i64 = 0x4253_5041;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectShareIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount_id: u64,
    owner_uid: u32,
    filesystem_magic: i64,
}

impl DirectShareIdentity {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_captured_parts(
        device_major: u32,
        device_minor: u32,
        inode: u64,
        mount_id: u64,
        owner_uid: u32,
        filesystem_magic: i64,
    ) -> Self {
        Self {
            device_major,
            device_minor,
            inode,
            mount_id,
            owner_uid,
            filesystem_magic,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        device_major: u32,
        device_minor: u32,
        inode: u64,
        mount_id: u64,
        owner_uid: u32,
        filesystem_magic: i64,
    ) -> Result<Self, DirectShareError> {
        let identity = Self {
            device_major,
            device_minor,
            inode,
            mount_id,
            owner_uid,
            filesystem_magic,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn device_major(&self) -> u32 {
        self.device_major
    }

    pub(crate) fn device_minor(&self) -> u32 {
        self.device_minor
    }

    pub(crate) fn inode(&self) -> u64 {
        self.inode
    }

    pub(crate) fn mount_id(&self) -> u64 {
        self.mount_id
    }

    pub(crate) fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    pub(crate) fn filesystem_magic(&self) -> i64 {
        self.filesystem_magic
    }

    pub(crate) fn validate(&self) -> Result<(), DirectShareError> {
        if self.inode == 0
            || self.mount_id == 0
            || self.owner_uid != current_uid()
            || !allowed_filesystem(self.filesystem_magic)
        {
            return Err(DirectShareError::InvalidDirectory);
        }
        Ok(())
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and no memory effects.
    unsafe { libc::geteuid() }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn allowed_filesystem(magic: i64) -> bool {
    matches!(
        magic,
        EXT4_SUPER_MAGIC
            | TMPFS_MAGIC
            | XFS_SUPER_MAGIC
            | BTRFS_SUPER_MAGIC
            | OVERLAYFS_SUPER_MAGIC
            | ZFS_SUPER_MAGIC
            | F2FS_SUPER_MAGIC
            | BCACHEFS_SUPER_MAGIC
    )
}

/// Darwin shares only APFS directories through Virtualization.framework.
#[cfg(target_os = "macos")]
pub(crate) fn allowed_filesystem(magic: i64) -> bool {
    magic == APFS_VOLUME_MAGIC
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DirectShareError {
    #[error("direct-share source path is invalid: {0}")]
    InvalidPath(PathBuf),
    #[error("direct-share source path is not canonical: {0}")]
    NonCanonical(PathBuf),
    #[error("direct-share source overlaps protected or overly broad host state: {0}")]
    ForbiddenSource(PathBuf),
    #[error("direct-share source is not owned by the current user: {0}")]
    WrongOwner(PathBuf),
    #[error("direct-share source filesystem is unsupported: {0}")]
    UnsupportedFilesystem(PathBuf),
    #[error("direct-share source is a mount alias: {0}")]
    MountAlias(PathBuf),
    #[error("direct-share source contains a nested mount: {0}")]
    NestedMount(PathBuf),
    #[error("direct-share source changed after admission: {0}")]
    SourceChanged(PathBuf),
    #[error("direct-share source is not a valid directory")]
    InvalidDirectory,
    #[error("current user's home directory is unavailable for direct-share policy")]
    MissingHomeDirectory,
    #[error("host mount table is malformed")]
    InvalidMountTable,
    #[error(transparent)]
    GuestPlan(#[from] DirectSharePlanError),
    #[error("open direct-share source {path}: {source}")]
    Open {
        path: PathBuf,
        source: rustix::io::Errno,
    },
    #[error("inspect direct-share source: {0}")]
    Inspect(rustix::io::Errno),
    #[error("direct-share filesystem operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}
