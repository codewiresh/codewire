//! Private tmpfs staging and executable validation for the SSH agent helper.
//!
//! Callers supply trusted configuration. This module never reads ambient PATH,
//! HOME, provider credentials or the user's ordinary provider configuration.

use std::fs::{DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Value-blind failures for private provider login staging.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("provider enrollment configuration or private staging is unavailable")]
pub struct ProviderEnrollmentError;

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

    /// Create the selected-key SSH signer's staging on macOS, which has no
    /// per-user tmpfs. Only the signer stages here, and it writes no key or
    /// passphrase byte to a file: ssh-add reads the key on stdin and the
    /// passphrase through a FIFO, so the directory holds the agent socket and
    /// that FIFO only. The short name keeps the agent socket under Darwin's
    /// 104-byte socket path bound. Provider login staging keeps requiring
    /// [`validate_private_tmpfs_runtime`], which no macOS filesystem passes.
    #[cfg(all(feature = "ssh-agent", target_os = "macos"))]
    pub(crate) fn create_signer_staging_in(
        runtime: &Path,
    ) -> Result<Self, ProviderEnrollmentError> {
        validate_private_directory(runtime)?;
        let path = runtime.join(format!(".cw-{}", uuid::Uuid::new_v4().simple()));
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
