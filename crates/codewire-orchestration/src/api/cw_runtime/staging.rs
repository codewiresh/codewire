//! Where a cw runtime upload is staged: one private directory the server
//! makes under its staging mount and holds open, so the server can run with
//! a read-only root filesystem (`docs/dev/CW-RUNTIME-JOURNAL.md`, "Where an
//! upload is staged").
use std::ffi::OsString;
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use codewire_server_core::AppResult;
use rustix::fs::{self as rfs, AtFlags, Mode, OFlags};
use rustix::io::Errno;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::model::unavailable;

/// Overrides the staging mount, for tests and local runs only.
pub const STAGING_ENV: &str = "CODEWIRE_CW_RUNTIME_STAGING";
/// Orchestration's Pod mounts a disk `emptyDir` here.
pub const DEFAULT_MOUNT: &str = "/var/lib/codewire-orchestration/staging";
// The mount's root is root-owned and group-writable under the Pod's fsGroup,
// so no upload is ever made in it directly.
const PRIVATE: &str = "cw-runtime";
// Three uploads of at most 512 MiB stay inside the mount's 2 GiB limit,
// over which the kubelet evicts the Pod.
const SLOTS: usize = 3;
const MIN_FREE: u64 = 512 * 1024 * 1024;
// An upload is two levels deep; anything deeper was not made by the intake.
const MAX_DEPTH: usize = 8;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// Why the server refused to start. Each case says only that staging is
/// unavailable; none echoes a path or an OS error.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StagingUnavailable {
    #[error("cw runtime staging unavailable")]
    Mount,
    #[error("cw runtime staging unavailable")]
    Private,
    #[error("cw runtime staging unavailable")]
    Owner,
    #[error("cw runtime staging unavailable")]
    Mode,
    #[error("cw runtime staging unavailable")]
    Leftovers,
}

/// The validated private directory, held open for the server's life, and
/// the slots uploads take from it. Each replica has its own `emptyDir`, so a
/// per-process count is exact for its mount.
#[derive(Clone)]
pub struct Staging {
    directory: Arc<File>,
    path: Arc<Path>,
    slots: Arc<Semaphore>,
    min_free: u64,
}

/// One upload's claim on the staging mount, released when it drops.
pub(super) struct Slot {
    _permit: OwnedSemaphorePermit,
}

impl Staging {
    /// Opens the mount named by [`STAGING_ENV`], or [`DEFAULT_MOUNT`].
    pub fn from_env() -> Result<Self, StagingUnavailable> {
        Self::open(&mount_path(std::env::var_os(STAGING_ENV)))
    }

    /// Makes `<mount>/cw-runtime` if it is absent, requires it to be this
    /// server's alone with mode exactly 0700, and empties it: an `emptyDir`
    /// survives a container restart, so an earlier run's uploads can remain.
    pub fn open(mount: &Path) -> Result<Self, StagingUnavailable> {
        Self::open_as(mount, rustix::process::geteuid().as_raw())
    }

    fn open_as(mount: &Path, uid: u32) -> Result<Self, StagingUnavailable> {
        let parent = rfs::open(
            mount,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StagingUnavailable::Mount)?;
        let created = match rfs::mkdirat(&parent, PRIVATE, Mode::from_raw_mode(0o700)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(_) => return Err(StagingUnavailable::Private),
        };
        let directory = File::from(
            rfs::openat(&parent, PRIVATE, DIRECTORY, Mode::empty())
                .map_err(|_| StagingUnavailable::Private)?,
        );
        let metadata = directory
            .metadata()
            .map_err(|_| StagingUnavailable::Private)?;
        if !metadata.is_dir() || metadata.uid() != uid {
            return Err(StagingUnavailable::Owner);
        }
        // A directory made below the mount's setgid root inherits setgid.
        // Only one this server just made is corrected; any other is refused.
        if created {
            rfs::fchmod(&directory, Mode::from_raw_mode(0o700))
                .map_err(|_| StagingUnavailable::Private)?;
        }
        let metadata = directory
            .metadata()
            .map_err(|_| StagingUnavailable::Private)?;
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(StagingUnavailable::Mode);
        }
        empty(&directory, 0).map_err(|_| StagingUnavailable::Leftovers)?;
        Ok(Self {
            directory: Arc::new(directory),
            path: mount.join(PRIVATE).into(),
            slots: Arc::new(Semaphore::new(SLOTS)),
            min_free: MIN_FREE,
        })
    }

    /// Admits one upload before its first chunk: a free slot, then, with it
    /// held, enough free space on the staging filesystem.
    pub(super) fn reserve(&self) -> AppResult<Slot> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable())?;
        let room = rfs::fstatvfs(&*self.directory).map_err(|_| unavailable())?;
        if room.f_bavail.saturating_mul(room.f_frsize) < self.min_free {
            return Err(unavailable());
        }
        Ok(Slot { _permit: permit })
    }

    /// The held private directory, where every upload's walk starts.
    pub(super) fn directory(&self) -> &File {
        &self.directory
    }

    /// The private directory's name, for diagnostics only; nothing opens it.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

fn mount_path(value: Option<OsString>) -> PathBuf {
    value.map_or_else(|| PathBuf::from(DEFAULT_MOUNT), PathBuf::from)
}

/// Removes every entry below `directory`, relative to the held descriptor.
/// A symlink is removed itself and never followed; a subdirectory is opened
/// only with `O_NOFOLLOW`.
fn empty(directory: &File, depth: usize) -> rustix::io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(Errno::LOOP);
    }
    let names = rfs::Dir::read_from(directory)?
        .map(|entry| entry.map(|entry| entry.file_name().to_owned()))
        .collect::<rustix::io::Result<Vec<_>>>()?;
    for name in names {
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        match rfs::openat(
            directory,
            &*name,
            DIRECTORY | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(child) => {
                empty(&File::from(child), depth + 1)?;
                rfs::unlinkat(directory, &*name, AtFlags::REMOVEDIR)?;
            }
            Err(Errno::NOTDIR | Errno::LOOP) => rfs::unlinkat(directory, &*name, AtFlags::empty())?,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
impl Staging {
    pub(crate) fn with_min_free(mut self, min_free: u64) -> Self {
        self.min_free = min_free;
        self
    }

    pub(crate) fn min_free(&self) -> u64 {
        self.min_free
    }

    /// A staging directory already removed from disk, for state that never
    /// uploads: an upload into it fails closed.
    pub(crate) fn removed() -> Self {
        let mount = tempfile::tempdir().expect("a temporary staging mount");
        Self::open(mount.path()).expect("a fresh mount stages")
    }
}

#[cfg(test)]
#[path = "staging_tests.rs"]
mod tests;
