//! Owner-only files a hosted daemon keeps under the Pod's `/codewire/run`
//! (Program #2238 B2, design §8): the local readiness marker and the bound
//! daemon credential that the fixed-purpose hosted exec reads. Codex's home
//! is [`crate::codex_home`], which the daemon prepares in both identity modes.

use std::io;
use std::path::Path;

use crate::config::{
    HOSTED_DAEMON_CREDENTIAL_FILE, HOSTED_DAEMON_READY_FILE, HOSTED_DAEMON_STATE_DIRECTORY,
    WorkspaceBinding,
};
use crate::private_files::{ensure_private_directory, write_atomically};

const STATE_DIRECTORY_MODE: u32 = 0o700;
const READY_MODE: u32 = 0o600;
const CREDENTIAL_MODE: u32 = 0o400;

/// Where one daemon keeps its state. Production uses the fixed Pod paths;
/// tests point it at a private temporary directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedStatePaths {
    pub state_directory: std::path::PathBuf,
    pub ready_file: std::path::PathBuf,
    pub credential_file: std::path::PathBuf,
}

impl Default for HostedStatePaths {
    fn default() -> Self {
        Self {
            state_directory: HOSTED_DAEMON_STATE_DIRECTORY.into(),
            ready_file: HOSTED_DAEMON_READY_FILE.into(),
            credential_file: HOSTED_DAEMON_CREDENTIAL_FILE.into(),
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

    /// Install the bound credential (0400) before the daemon listens.
    pub fn install_binding(&self, binding: &WorkspaceBinding) -> io::Result<()> {
        self.prepare()?;
        write_atomically(
            &self.credential_file,
            binding.daemon_credential().expose_secret().as_bytes(),
            CREDENTIAL_MODE,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BindResponseFields, HostedDaemonMode, WORKSPACE_BINDING_URL_ENV};
    use crate::config::{WORKSPACE_POD_UID_ENV, WorkspaceBindingConfig};
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
    const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SYNTHETIC_CREDENTIAL: &str = "synthetic-workspace-daemon-credential";

    fn binding_config() -> WorkspaceBindingConfig {
        let values = [
            (WORKSPACE_BINDING_URL_ENV, "https://binding.test:8087"),
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
        // A binding installs only the daemon's own state; Codex's home is
        // prepared from the served configuration in both identity modes.
        paths
            .install_binding(&binding(&"ab".repeat(32), "v1:codex"))
            .unwrap();
        let mut names: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["daemon"]);
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
    }
}
