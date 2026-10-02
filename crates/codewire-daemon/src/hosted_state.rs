//! Owner-only files a hosted daemon keeps under the Pod's `/codewire/run`
//! (Program #2238 B2, design §8): the local readiness marker, the bound daemon
//! credential that the fixed-purpose hosted exec reads, and the stock Codex
//! configuration the daemon installs itself instead of an init container.
//!
//! Every write goes through a temporary file created exclusively in the target
//! directory with its final mode, then renamed, so a reader never observes a
//! partial file or a wider mode.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use codewire_access::{CODEX_CONFIG_FILE_NAME, CODEX_PLATFORM_HOME};

use crate::config::{
    HOSTED_DAEMON_CREDENTIAL_FILE, HOSTED_DAEMON_READY_FILE, HOSTED_DAEMON_STATE_DIRECTORY,
    WorkspaceBinding,
};

const STATE_DIRECTORY_MODE: u32 = 0o700;
const READY_MODE: u32 = 0o600;
const CREDENTIAL_MODE: u32 = 0o400;
const CODEX_HOME_MODE: u32 = 0o700;
const CODEX_CONFIG_MODE: u32 = 0o600;

/// Where one daemon keeps its state. Production uses the fixed Pod paths;
/// tests point it at a private temporary directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedStatePaths {
    pub state_directory: std::path::PathBuf,
    pub ready_file: std::path::PathBuf,
    pub credential_file: std::path::PathBuf,
    pub codex_home: std::path::PathBuf,
}

impl Default for HostedStatePaths {
    fn default() -> Self {
        Self {
            state_directory: HOSTED_DAEMON_STATE_DIRECTORY.into(),
            ready_file: HOSTED_DAEMON_READY_FILE.into(),
            credential_file: HOSTED_DAEMON_CREDENTIAL_FILE.into(),
            codex_home: CODEX_PLATFORM_HOME.into(),
        }
    }
}

impl HostedStatePaths {
    /// The same layout below `root`, for tests.
    pub fn under(root: &Path) -> Self {
        let state_directory = root.join("daemon");
        Self {
            ready_file: state_directory.join("ready"),
            credential_file: state_directory.join("credential"),
            codex_home: root.join("codex").join("home"),
            state_directory,
        }
    }

    /// Create the owner-only state directory, or tighten an existing one. A
    /// symlink or other non-directory is refused.
    pub fn prepare(&self) -> io::Result<()> {
        ensure_private_directory(&self.state_directory, STATE_DIRECTORY_MODE)
    }

    /// (Re)write the readiness marker. It is never removed: Pod readiness must
    /// not depend on binding, and a restarted daemon in the same Pod rebinds
    /// to the same answer.
    pub fn mark_ready(&self) -> io::Result<()> {
        self.prepare()?;
        write_atomically(&self.ready_file, b"", READY_MODE)
    }

    /// Install the bound state before the daemon listens: the Codex
    /// configuration when selected, then the credential file (0400).
    pub fn install_binding(&self, binding: &WorkspaceBinding) -> io::Result<()> {
        self.prepare()?;
        if let Some(config) = binding.codex_config_toml() {
            ensure_private_directory(&self.codex_home, CODEX_HOME_MODE)?;
            write_atomically(
                &self.codex_home.join(CODEX_CONFIG_FILE_NAME),
                config.as_bytes(),
                CODEX_CONFIG_MODE,
            )?;
        }
        write_atomically(
            &self.credential_file,
            binding.daemon_credential().expose_secret().as_bytes(),
            CREDENTIAL_MODE,
        )
    }
}

fn ensure_private_directory(path: &Path, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "hosted daemon state path is not a directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            match fs::DirBuilder::new().mode(mode).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if !fs::symlink_metadata(path)?.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "hosted daemon state path is not a directory",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// Write `contents` to `path` with exactly `mode`, through an exclusive
/// temporary sibling and a rename.
fn write_atomically(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let temporary = directory.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        // The umask may have narrowed the mode; never widen it past `mode`.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BindResponseFields, HostedDaemonMode, WORKSPACE_BINDING_URL_ENV};
    use crate::config::{WORKSPACE_POD_UID_ENV, WorkspaceBindingConfig};
    use std::ffi::OsString;

    const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
    const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SYNTHETIC_CREDENTIAL: &str = "synthetic-workspace-daemon-credential";

    fn binding_config() -> WorkspaceBindingConfig {
        let values = [
            (WORKSPACE_BINDING_URL_ENV, "http://binding.test:8087"),
            (WORKSPACE_POD_UID_ENV, POD),
        ];
        match HostedDaemonMode::from_lookup(|name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(*value))
        })
        .unwrap()
        {
            HostedDaemonMode::Binding(config) => config,
            HostedDaemonMode::EnvironmentToken(_) => panic!("binding mode expected"),
        }
    }

    fn binding(digest: &str, clients: &str) -> WorkspaceBinding {
        binding_config()
            .validate(&BindResponseFields {
                environment_id: ENVIRONMENT,
                pod_uid: POD,
                operation_generation: 3,
                daemon_credential: SYNTHETIC_CREDENTIAL,
                projection_selection_sha256: digest,
                managed_credential_clients: clients,
            })
            .unwrap()
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn marker_and_state_directory_are_owner_only_and_survive_rewrites() {
        let root = tempfile::tempdir().unwrap();
        let paths = HostedStatePaths::under(root.path());
        paths.mark_ready().unwrap();
        assert_eq!(mode(&paths.state_directory), 0o700);
        assert_eq!(mode(&paths.ready_file), 0o600);
        // A restarted daemon rewrites the marker in place.
        fs::set_permissions(&paths.state_directory, fs::Permissions::from_mode(0o755)).unwrap();
        paths.mark_ready().unwrap();
        assert_eq!(mode(&paths.state_directory), 0o700);
        assert!(paths.ready_file.is_file());
        // Installing a binding keeps the marker.
        paths.install_binding(&binding("", "v1:none")).unwrap();
        assert!(paths.ready_file.is_file());
        assert!(fs::read_dir(&paths.state_directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn credential_file_is_read_only_owner_and_replaced_atomically() {
        let root = tempfile::tempdir().unwrap();
        let paths = HostedStatePaths::under(root.path());
        paths.install_binding(&binding("", "v1:none")).unwrap();
        assert_eq!(mode(&paths.credential_file), 0o400);
        assert_eq!(
            fs::read_to_string(&paths.credential_file).unwrap(),
            SYNTHETIC_CREDENTIAL
        );
        // A rebind in the same Pod replaces the read-only file.
        paths.install_binding(&binding("", "v1:none")).unwrap();
        assert_eq!(mode(&paths.credential_file), 0o400);
        assert!(!paths.codex_home.exists());
    }

    #[test]
    fn codex_configuration_is_installed_only_when_selected() {
        let root = tempfile::tempdir().unwrap();
        let paths = HostedStatePaths::under(root.path());
        paths
            .install_binding(&binding(&"ab".repeat(32), "v1:openai"))
            .unwrap();
        assert!(!paths.codex_home.exists());
        paths
            .install_binding(&binding(&"ab".repeat(32), "v1:codex"))
            .unwrap();
        let config = paths.codex_home.join(CODEX_CONFIG_FILE_NAME);
        assert_eq!(mode(&paths.codex_home), 0o700);
        assert_eq!(mode(&config), 0o600);
        let expected = codewire_access::ManagedCredentialClients::decode("v1:codex")
            .unwrap()
            .for_placement(codewire_access::ManagedCredentialClientPlacement::Platform)
            .codex
            .unwrap();
        assert_eq!(fs::read_to_string(config).unwrap(), expected.config_toml());
    }

    #[test]
    fn a_symlinked_state_path_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let paths = HostedStatePaths::under(root.path());
        let elsewhere = root.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &paths.state_directory).unwrap();
        assert!(paths.mark_ready().is_err());
        assert!(paths.install_binding(&binding("", "v1:none")).is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn production_paths_are_the_shared_constants() {
        let paths = HostedStatePaths::default();
        assert_eq!(paths.state_directory, Path::new("/codewire/run/daemon"));
        assert_eq!(paths.ready_file, Path::new("/codewire/run/daemon/ready"));
        assert_eq!(
            paths.credential_file,
            Path::new("/codewire/run/daemon/credential")
        );
        assert_eq!(paths.codex_home, Path::new(CODEX_PLATFORM_HOME));
    }
}
