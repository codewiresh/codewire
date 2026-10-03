//! Owner-only files a hosted daemon writes: its state under `/codewire/run`
//! and Codewire's file in Codex's home. Every write goes through a temporary
//! file created exclusively in the target directory with its final mode, so a
//! reader never observes a partial file or a wider mode, and no write follows
//! a symlink.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Create the owner-only directory `path`, or tighten an existing one to
/// `mode`. A symlink or other non-directory is refused.
pub(crate) fn ensure_private_directory(path: &Path, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(not_a_directory()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            match fs::DirBuilder::new().mode(mode).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if !fs::symlink_metadata(path)?.is_dir() {
                        return Err(not_a_directory());
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn not_a_directory() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "hosted daemon state path is not a directory",
    )
}

/// Write `contents` to `path` with exactly `mode`, through an exclusive
/// temporary sibling and a rename.
pub(crate) fn write_atomically(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let temporary = temporary_sibling(path, &std::process::id().to_string())?;
    write_new(&temporary, contents, mode)?;
    fs::rename(&temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })
}

/// The hidden sibling `.<file name>.<tag>.tmp` of `path`.
pub(crate) fn temporary_sibling(path: &Path, tag: &str) -> io::Result<PathBuf> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    Ok(directory.join(format!(".{}.{tag}.tmp", name.to_string_lossy())))
}

/// Create `path` exclusively with exactly `mode`, then write and sync it. A
/// stale file or symlink of that name is unlinked first, never followed.
pub(crate) fn write_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let _ = fs::remove_file(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        // The umask may have narrowed the mode; never widen it past `mode`.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

/// Make the entries just created, renamed or removed in `directory` durable.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}
