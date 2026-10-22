//! Complete legacy Linux identities retained by the shared metadata codec.
//!
//! These records do not confer process, socket, or filesystem authority on a
//! non-Linux host. Platform stores admit or reject them separately from JSON
//! decoding and structural validation.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub uid: u32,
    pub mode: u32,
    pub links: u64,
    /// The file itself, held while this identity lives when it came from an
    /// open descriptor (#3214); see [`InodePin`].
    #[serde(skip)]
    pub pin: InodePin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    /// The socket inode itself, held while this identity lives (#3207).
    #[serde(skip)]
    pub pin: InodePin,
}

/// A reference that keeps a captured file's or socket's inode allocated.
///
/// A filesystem such as ext4, or overlay over it, hands a freed inode number
/// straight to the next file, so a file or socket removed and created again
/// at the same path can carry the same device and inode numbers. While a
/// capture's pin lives, the kernel cannot free that inode, and whatever is
/// created at the path afterwards must have another number: comparing with a
/// pinned identity detects replacement on every local filesystem (#3207,
/// #3214). Linux socket captures hold an `O_PATH` descriptor and Linux file
/// identities a duplicate of the descriptor they were read from; macOS (APFS
/// never reuses inode numbers) and identities read back from stored records
/// hold none, and compare exactly as before (#3209). The descriptor is private and close-on-exec; equality
/// ignores it. The guarantee covers local filesystems (ext4, XFS, overlay,
/// tmpfs, btrfs), where cw keeps its sockets; a network filesystem numbers
/// inodes on its server.
#[derive(Clone, Default)]
pub struct InodePin(Option<std::sync::Arc<std::os::fd::OwnedFd>>);

impl InodePin {
    /// Linux captures only: macOS identities hold nothing.
    #[cfg(target_os = "linux")]
    pub(crate) fn holding(descriptor: std::os::fd::OwnedFd) -> Self {
        Self(Some(std::sync::Arc::new(descriptor)))
    }

    /// Whether this identity holds its socket's inode.
    pub fn is_pinned(&self) -> bool {
        self.0.is_some()
    }
}

impl PartialEq for InodePin {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for InodePin {}

impl std::fmt::Debug for InodePin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(if self.is_pinned() {
            "pinned"
        } else {
            "unpinned"
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub boot_id: String,
    pub start_time_ticks: u64,
    pub executable: PathBuf,
    pub executable_file: FileIdentity,
    pub executable_sha256: String,
}

pub const MINIMUM_STATE_DISK_BYTES: u64 = 256 * 1024 * 1024;
pub const MINIMUM_ROOT_DISK_BYTES: u64 = 256 * 1024 * 1024;
pub const MINIMUM_DOCKER_DISK_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const MAXIMUM_ROOT_DISK_BYTES: u64 = 128 * 1024 * 1024 * 1024;

pub(crate) fn valid_root_disk_bytes(disk_bytes: u64) -> bool {
    (MINIMUM_ROOT_DISK_BYTES..=MAXIMUM_ROOT_DISK_BYTES).contains(&disk_bytes)
        && disk_bytes.is_multiple_of(1024 * 1024)
}
