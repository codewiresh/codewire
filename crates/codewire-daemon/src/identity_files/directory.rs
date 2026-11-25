//! The token files' directory, used only through one descriptor: no step
//! resolves a path through a symlink, and a symlink planted at a file's name
//! or its temporary name is replaced or removed, never followed.

use std::io;
use std::path::Path;

use super::IdentityFile;
use crate::private_files::PrivateDirectory;

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
/// The most leftover names removed at start.
const MAX_LEFTOVERS: usize = 4096;

/// Whether a directory is on a memory file system: the descriptor's
/// `fstatfs` in production, a test's answer otherwise.
pub(super) type MemoryCheck = fn(&PrivateDirectory) -> io::Result<bool>;

/// The directory, open, owner-only and on a memory file system.
pub(super) struct TokenDirectory(PrivateDirectory);

/// Why the daemon writes no token file, logged once.
pub(super) enum Unusable {
    /// `/codewire/run`, or the directory in it, is a symlink, not a
    /// directory, or not the daemon's.
    NotPrivate,
    /// It is on disk: a Sandbox rendered before `/codewire/run` was memory.
    OnDisk,
    Failed(io::Error),
}

impl From<io::Error> for Unusable {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}

/// The directory at `path` when it exists as the daemon's own, created by
/// nobody.
fn existing(path: &Path) -> io::Result<Option<PrivateDirectory>> {
    let (Some(parent), Some(name)) = (path.parent(), file_name(path)) else {
        return Ok(None);
    };
    match PrivateDirectory::open_home(parent)? {
        Some(parent) => match parent.open_child(name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            opened => opened,
        },
        None => Ok(None),
    }
}

fn file_name(path: &Path) -> Option<&str> {
    path.file_name().and_then(|name| name.to_str())
}

/// Remove every `*.jwt` and `.*.tmp` an earlier daemon in this Pod left in
/// the directory at `path`, if there is one. Nothing is created.
pub(super) fn remove_leftovers(path: &Path) -> io::Result<()> {
    let Some(directory) = existing(path)? else {
        return Ok(());
    };
    for name in directory.names_with_prefix("", MAX_LEFTOVERS)? {
        let leftover = name.ends_with(".jwt") || (name.starts_with('.') && name.ends_with(".tmp"));
        if leftover && let Err(error) = directory.unlink(&name) {
            tracing::warn!(file = %name, error = %error, "sandbox identity file left over");
        }
    }
    Ok(())
}

impl TokenDirectory {
    /// Open the directory at `path`, creating it at 0700 and tightening a
    /// wider mode through its descriptor, then check through the same
    /// descriptor that it is on a memory file system. `/codewire/run` may be
    /// root's (a volume's root) or the daemon's.
    pub(super) fn open(path: &Path, in_memory: MemoryCheck) -> Result<Self, Unusable> {
        let (Some(parent), Some(name)) = (path.parent(), file_name(path)) else {
            return Err(Unusable::NotPrivate);
        };
        let parent = PrivateDirectory::open_home(parent)?.ok_or(Unusable::NotPrivate)?;
        let directory = parent
            .open_or_create_child(name, DIRECTORY_MODE)?
            .ok_or(Unusable::NotPrivate)?;
        directory.set_mode(DIRECTORY_MODE)?;
        if !in_memory(&directory)? {
            return Err(Unusable::OnDisk);
        }
        Ok(Self(directory))
    }

    /// Replace `file` with `token`, 0600 and no newline: written to its
    /// temporary name with `O_CREAT|O_EXCL|O_NOFOLLOW`, then renamed into
    /// place, so a reader sees the old token or the new one. A temporary
    /// name already taken is unlinked once and tried again.
    pub(super) fn write(&self, file: &IdentityFile, token: &[u8]) -> io::Result<()> {
        let temporary = file.temporary_name();
        match self.0.write_new(&temporary, token, FILE_MODE) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.0.unlink(&temporary)?;
                self.0.write_new(&temporary, token, FILE_MODE)?;
            }
            written => written?,
        }
        self.0
            .rename(&temporary, &file.file_name())
            .inspect_err(|_| {
                // The rename's error is the one reported; an unlink that fails
                // too leaves a temporary file the next start removes.
                let _ = self.0.unlink(&temporary);
            })
    }

    /// Delete `file`. An absent file is not an error.
    pub(super) fn remove(&self, file: &IdentityFile) -> io::Result<()> {
        self.0.unlink(&file.file_name())
    }
}
