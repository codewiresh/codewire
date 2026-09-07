//! Shared private staging and executable validation for explicit provider login.
//!
//! Callers supply trusted configuration. This module never reads ambient PATH,
//! HOME, provider credentials or the user's ordinary provider configuration.

use std::ffi::OsStr;
use std::fs::{DirBuilder, File};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use thiserror::Error;
use zeroize::Zeroizing;

/// Value-blind failures for private provider login staging.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("provider enrollment configuration or private staging is unavailable")]
pub struct ProviderEnrollmentError;

/// Resolve an executable using an explicitly supplied, trusted search path.
/// Neither the search path nor the executable is supplied by an API caller.
pub fn resolve_provider_executable(
    name: &str,
    search_path: &OsStr,
) -> Result<PathBuf, ProviderEnrollmentError> {
    if name.is_empty() || name.contains('/') {
        return Err(ProviderEnrollmentError);
    }
    for directory in std::env::split_paths(search_path) {
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(name);
        if let Ok(path) = validate_executable(&candidate) {
            return Ok(path);
        }
    }
    Err(ProviderEnrollmentError)
}

pub(crate) fn validate_executable(path: &Path) -> Result<PathBuf, ProviderEnrollmentError> {
    if !path.is_absolute() {
        return Err(ProviderEnrollmentError);
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| ProviderEnrollmentError)?;
    let metadata = std::fs::metadata(&canonical).map_err(|_| ProviderEnrollmentError)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(ProviderEnrollmentError);
    }
    Ok(canonical)
}

/// Require an absolute, canonical, non-symlink directory owned by this process's
/// effective user, with no group or other access.
pub fn validate_private_directory(path: &Path) -> Result<(), ProviderEnrollmentError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ProviderEnrollmentError)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| ProviderEnrollmentError)?;
    if !path.is_absolute()
        || canonical != path
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ProviderEnrollmentError);
    }
    Ok(())
}

/// Require private staging on Linux tmpfs, never persistent provider material.
pub fn validate_private_tmpfs_runtime(path: &Path) -> Result<(), ProviderEnrollmentError> {
    validate_private_directory(path)?;
    let directory = File::open(path).map_err(|_| ProviderEnrollmentError)?;
    let statistics = rustix::fs::fstatfs(&directory).map_err(|_| ProviderEnrollmentError)?;
    if statistics.f_type != 0x0102_1994 {
        return Err(ProviderEnrollmentError);
    }
    Ok(())
}

/// Private temporary login home, shared by Codex and GitHub enrollment.
///
/// A child-process owner must retain this value until its entire process group
/// has stopped. Drop is only a best-effort filesystem fallback, not child drain.
pub struct PrivateProviderHome {
    path: Option<PathBuf>,
}

impl PrivateProviderHome {
    /// Create an unpredictable, mode-0700 directory in a validated private tmpfs.
    pub fn create_in(runtime: &Path) -> Result<Self, ProviderEnrollmentError> {
        validate_private_tmpfs_runtime(runtime)?;
        let path = runtime.join(format!(".codewire-provider-login-{}", uuid::Uuid::new_v4()));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| ProviderEnrollmentError)?;
        validate_private_directory(&path)?;
        Ok(Self { path: Some(path) })
    }

    /// Private process-local staging path; never expose this through public RPC.
    pub fn path(&self) -> &Path {
        self.path.as_deref().expect("private home remains owned")
    }

    /// Remove all staging, including provider-created diagnostic files.
    pub fn remove(mut self) -> Result<(), ProviderEnrollmentError> {
        validate_private_directory(self.path())?;
        std::fs::remove_dir_all(self.path()).map_err(|_| ProviderEnrollmentError)?;
        self.path = None;
        Ok(())
    }

    // Failed process-group drain cannot authorize removal while a writer may
    // remain. Retention is exceptional and intentionally has no secret-bearing
    // path in its public error. A runtime crash has the same tmpfs-only limit.
    pub(crate) fn retain(mut self) {
        self.path = None;
    }
}

impl Drop for PrivateProviderHome {
    fn drop(&mut self) {
        if let Some(path) = &self.path
            && validate_private_directory(path).is_ok()
        {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

pub(crate) fn read_private_file(
    home: &PrivateProviderHome,
    name: &str,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ProviderEnrollmentError> {
    validate_private_directory(home.path())?;
    let directory = rustix::fs::open(
        home.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ProviderEnrollmentError)?;
    let descriptor = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ProviderEnrollmentError)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| ProviderEnrollmentError)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.len() == 0
        || metadata.len() > limit as u64
        || metadata.nlink() != 1
    {
        return Err(ProviderEnrollmentError);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderEnrollmentError)?;
    if bytes.len() != metadata.len() as usize || bytes.len() > limit {
        return Err(ProviderEnrollmentError);
    }
    Ok(bytes)
}
