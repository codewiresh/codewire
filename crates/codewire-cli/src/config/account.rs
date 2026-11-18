//! The account's own home directory, from the user database and never from
//! `$HOME`: what a process run with another HOME still belongs to.

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

/// This user's home directory from the user database.
pub(crate) fn home_directory() -> anyhow::Result<PathBuf> {
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain old data; zero is a valid value to overwrite.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    // SAFETY: every pointer refers to a live, writable value of the stated
    // size; on success `result` points at `entry`, whose strings live in
    // `buffer`, which outlives their use below.
    let status = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        )
    };
    anyhow::ensure!(
        status == 0 && !result.is_null() && !entry.pw_dir.is_null(),
        "resolve this user's home directory"
    );
    // SAFETY: pw_dir is a NUL-terminated string inside `buffer`.
    let home = unsafe { CStr::from_ptr(entry.pw_dir) };
    Ok(PathBuf::from(OsStr::from_bytes(home.to_bytes())))
}

/// Whether `path` is the account's own `~/.codewire/LEAF`, whatever `HOME`
/// says, seen through links. The leaf may not exist yet on a first run: what
/// does exist (the parent) is resolved and the name joined, so a link to the
/// account's own `.codewire` is still seen.
pub(crate) fn is_own_codewire_path(path: &Path, account_home: &Path, leaf: &str) -> bool {
    let resolved = |path: &Path| {
        std::fs::canonicalize(path).unwrap_or_else(|_| match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => std::fs::canonicalize(parent)
                .map_or_else(|_| path.to_owned(), |parent| parent.join(name)),
            _ => path.to_owned(),
        })
    };
    resolved(path) == resolved(&account_home.join(".codewire").join(leaf))
}
