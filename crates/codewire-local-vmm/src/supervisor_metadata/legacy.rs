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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
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
