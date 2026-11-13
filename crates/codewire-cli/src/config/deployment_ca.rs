//! The deployment CA `cw login --ca-file` pins for the saved server (#4121).
//!
//! The CA is copied beside `config.json`, private to the user, and
//! `config.json` records each certificate's fingerprint. Every load reads the
//! copy again and refuses it unless it still holds exactly those
//! certificates, so a replaced file is never trusted silently. The host agent
//! keeps its own copy the same way beside its `host.json`.

use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use codewire_client::{DeploymentCa, DeploymentCaError};
use serde::{Deserialize, Serialize};

use super::sync_directory;

/// The copy's file name, beside `config.json` or the host agent's
/// `host.json`.
pub const DEPLOYMENT_CA_FILE: &str = "deployment-ca.pem";
/// Read one byte past `DeploymentCa`'s limit, so it reports the file as too
/// large rather than reading a truncated one.
const READ_LIMIT: u64 = 64 * 1024 + 1;

/// A pinned CA as its owner's record names it: each certificate's SHA-256
/// fingerprint, in file order.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinnedCa {
    pub fingerprints: Vec<String>,
}

impl PinnedCa {
    pub fn of(ca: &DeploymentCa) -> Self {
        Self {
            fingerprints: ca.fingerprints().to_vec(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeploymentCaFileError {
    #[error("read the CA file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the CA file {path}: {source}")]
    Invalid {
        path: PathBuf,
        source: DeploymentCaError,
    },
    #[error(
        "{path} is not the CA pinned at login: its fingerprints differ. Run `cw login --ca-file` again"
    )]
    Changed { path: PathBuf },
    #[error("save the CA to {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Read and check a CA file, returning the CA and the file's bytes, which are
/// what a pin copies.
pub fn read_ca_file(path: &Path) -> Result<(DeploymentCa, Vec<u8>), DeploymentCaFileError> {
    let read_error = |source: std::io::Error| DeploymentCaFileError::Read {
        path: path.to_path_buf(),
        source,
    };
    let mut pem = Vec::new();
    fs::File::open(path)
        .map_err(read_error)?
        .take(READ_LIMIT)
        .read_to_end(&mut pem)
        .map_err(read_error)?;
    let ca = DeploymentCa::from_pem(&pem).map_err(|source| DeploymentCaFileError::Invalid {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((ca, pem))
}

/// Copy a checked CA file's bytes into `dir`, made private (0700), as a
/// private file (0600) written atomically, and return the record that pins
/// it.
pub fn save_deployment_ca(
    dir: &Path,
    ca: &DeploymentCa,
    pem: &[u8],
) -> Result<PinnedCa, DeploymentCaFileError> {
    let path = dir.join(DEPLOYMENT_CA_FILE);
    let temporary = dir.join(format!(
        ".{DEPLOYMENT_CA_FILE}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let written = (|| -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(pem)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        sync_directory(dir)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary); // Best effort: the write already failed.
    }
    written.map_err(|source| DeploymentCaFileError::Write { path, source })?;
    Ok(PinnedCa::of(ca))
}

/// Load the CA pinned in `dir`, refusing it unless it is still a valid CA
/// with exactly the recorded fingerprints.
pub fn load_deployment_ca(
    dir: &Path,
    pinned: &PinnedCa,
) -> Result<DeploymentCa, DeploymentCaFileError> {
    let path = dir.join(DEPLOYMENT_CA_FILE);
    let (ca, _) = read_ca_file(&path)?;
    if ca.fingerprints() != pinned.fingerprints.as_slice() {
        return Err(DeploymentCaFileError::Changed { path });
    }
    Ok(ca)
}

/// Copy the CA pinned in `from` into `to`, checking it on the way.
pub fn copy_deployment_ca(
    from: &Path,
    to: &Path,
    pinned: &PinnedCa,
) -> Result<PinnedCa, DeploymentCaFileError> {
    let path = from.join(DEPLOYMENT_CA_FILE);
    let (ca, pem) = read_ca_file(&path)?;
    if ca.fingerprints() != pinned.fingerprints.as_slice() {
        return Err(DeploymentCaFileError::Changed { path });
    }
    save_deployment_ca(to, &ca, &pem)
}

/// Copy the CA `platform` pins, if any, from the config directory into a
/// host's directory for its agent, and return the record that pins it there.
pub fn pin_for_host(
    platform: &super::ResolvedPlatformConfig,
    platform_config_dir: &Path,
    host_dir: &Path,
) -> Result<Option<PinnedCa>, DeploymentCaFileError> {
    platform
        .deployment_ca()
        .map(|ca| copy_deployment_ca(platform_config_dir, host_dir, &PinnedCa::of(ca)))
        .transpose()
}

/// A host agent's connection settings for `server_url`, trusting the CA its
/// enrollment pinned, read again and checked from `host_dir`.
pub fn host_client_config(
    server_url: &str,
    host_dir: &Path,
    pinned: Option<&PinnedCa>,
) -> anyhow::Result<codewire_client::ClientConfig> {
    let config = codewire_client::ClientConfig::new(server_url)?;
    Ok(match pinned {
        Some(pinned) => config.with_deployment_ca(load_deployment_ca(host_dir, pinned)?)?,
        None => config,
    })
}

/// Remove the CA copy in `dir`; a missing one is already removed.
pub fn delete_deployment_ca(dir: &Path) -> Result<(), DeploymentCaFileError> {
    let path = dir.join(DEPLOYMENT_CA_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DeploymentCaFileError::Write { path, source }),
    }
}

#[cfg(test)]
mod tests;
