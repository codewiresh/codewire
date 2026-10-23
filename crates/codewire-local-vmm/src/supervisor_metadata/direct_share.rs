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

use std::collections::BTreeMap;
use std::path::PathBuf;

use codewire_vmm_guest_probe::DirectSharePlanError;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

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

/// The most bytes a kernel file handle carries (`MAX_HANDLE_SZ`).
pub(crate) const MAXIMUM_FILE_HANDLE_BYTES: usize = 128;
/// The `supervisor_metadata` key prefix of an environment's discriminators;
/// the environment's UUID follows it.
pub(crate) const DIRECT_SHARE_DISCRIMINATORS_KEY_PREFIX: &str = "direct_share_discriminators:";

/// What tells an admitted directory apart from one recreated at its path
/// when the filesystem reuses inode numbers, as ext4 and overlay do (#3209).
/// The identity, which the plan records, cannot: a directory removed while
/// the VM is stopped frees its inode, and a new one can take its number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DirectShareDiscriminator {
    /// No file handle could be read, as on overlay: the identity's
    /// (device, inode) is all there is.
    Unsupported,
    /// The directory's kernel file handle. It embeds the inode generation,
    /// so a recreated directory has another handle even where its inode
    /// number is reused. `handle` is lowercase hex.
    Handle { handle_type: i32, handle: String },
}

impl DirectShareDiscriminator {
    #[cfg(target_os = "linux")]
    pub(crate) fn handle(handle_type: i32, bytes: &[u8]) -> Option<Self> {
        (!bytes.is_empty() && bytes.len() <= MAXIMUM_FILE_HANDLE_BYTES).then(|| Self::Handle {
            handle_type,
            handle: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        })
    }

    fn valid(&self) -> bool {
        match self {
            Self::Unsupported => true,
            Self::Handle { handle, .. } => {
                !handle.is_empty()
                    && handle.len() % 2 == 0
                    && handle.len() <= MAXIMUM_FILE_HANDLE_BYTES * 2
                    && handle
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
        }
    }

    /// What to record for a share admitted again with `current`, or `None`
    /// to refuse it. Nothing recorded accepts once; an unsupported record
    /// keeps the identity comparison until a handle can be read; a recorded
    /// handle must be read again, equal.
    pub(crate) fn admit(recorded: Option<&Self>, current: &Self) -> Option<Self> {
        match recorded {
            None | Some(Self::Unsupported) => Some(current.clone()),
            Some(handle) => (handle == current).then(|| handle.clone()),
        }
    }
}

/// The discriminators recorded for one environment's direct shares, keyed
/// by [`direct_share_identity_sha256`] of the plan entry each belongs to. An
/// entry whose digest no longer names a plan entry is ignored and dropped
/// on the next write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectShareDiscriminators(BTreeMap<String, DirectShareDiscriminator>);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectShareDiscriminatorEntry {
    identity_sha256: String,
    discriminator: DirectShareDiscriminator,
}

impl DirectShareDiscriminators {
    pub(crate) fn get(&self, identity_sha256: &str) -> Option<&DirectShareDiscriminator> {
        self.0.get(identity_sha256)
    }

    pub(crate) fn insert(
        &mut self,
        identity_sha256: String,
        discriminator: DirectShareDiscriminator,
    ) {
        self.0.insert(identity_sha256, discriminator);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The row value: a JSON list of `{identity_sha256, discriminator}`.
    pub(crate) fn encode(&self) -> String {
        let entries = self
            .0
            .iter()
            .map(
                |(identity_sha256, discriminator)| DirectShareDiscriminatorEntry {
                    identity_sha256: identity_sha256.clone(),
                    discriminator: discriminator.clone(),
                },
            )
            .collect::<Vec<_>>();
        serde_json::to_string(&entries).expect("discriminator entries encode")
    }

    /// Decode a row value. A malformed one reads as nothing recorded, the
    /// state a database written before #3209 is in.
    pub(crate) fn decode(value: &str) -> Self {
        let Ok(entries) = serde_json::from_str::<Vec<DirectShareDiscriminatorEntry>>(value) else {
            return Self::default();
        };
        if entries.len() > codewire_project::MAX_LOCAL_MOUNTS
            || !entries.iter().all(|entry| {
                valid_sha256_hex(&entry.identity_sha256) && entry.discriminator.valid()
            })
        {
            return Self::default();
        }
        Self(
            entries
                .into_iter()
                .map(|entry| (entry.identity_sha256, entry.discriminator))
                .collect(),
        )
    }
}

/// The digest binding a discriminator to one plan entry: the source path
/// and every identity field, so a changed plan entry never inherits it.
pub(crate) fn direct_share_identity_sha256(
    source_path: &[u8],
    identity: &DirectShareIdentity,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"codewire direct-share identity v1\0");
    digest.update((source_path.len() as u64).to_be_bytes());
    digest.update(source_path);
    digest.update(identity.device_major.to_be_bytes());
    digest.update(identity.device_minor.to_be_bytes());
    digest.update(identity.inode.to_be_bytes());
    digest.update(identity.mount_id.to_be_bytes());
    digest.update(identity.owner_uid.to_be_bytes());
    digest.update(identity.filesystem_magic.to_be_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
