//! Codewire's `gh` configuration in a hosted Sandbox.
//!
//! While the GitHub client is selected, every session gets `GH_CONFIG_DIR`
//! naming this daemon's own directory beside its sockets, and the public
//! `GH_TOKEN` placeholder. The one file there, `config.yml`, tells stock `gh`
//! to reach `api.github.com` through the daemon's Unix ingress socket, where
//! the broker admits its closed GitHub operations and adds the owner's login
//! outside the Sandbox. The file names that socket and nothing else: no host,
//! account, token or helper.
//!
//! The daemon is the one writer, before it listens. The directory is `0700`
//! and the file `0600`, both the daemon's; nothing is followed through a
//! symlink, and the user's `~/.config/gh` is never read or written. When
//! GitHub is not selected the file and the directory are removed. A selection
//! change restarts the Sandbox, so one pass at daemon start covers it.
//!
//! Only [`GhConfigSync`] states are logged, never file contents.

use std::io;
use std::path::{Path, PathBuf};

use codewire_access::{
    GH_CONFIG_FILE_NAME, GH_PLATFORM_CONFIG_DIR, ManagedCredentialClientPlacement,
    ManagedCredentialClients,
};

use crate::private_files::{Entry, PrivateDirectory, ensure_private_directory};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
/// The generated file is two short lines; a larger one is not Codewire's.
const MAX_CONFIG_BYTES: u64 = 4096;

/// What one sync did. It names no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GhConfigSync {
    /// The GitHub client is not selected: Codewire's file is absent.
    NotSelected,
    /// The file was created or replaced with the generated configuration.
    Written,
    /// The file already held exactly the generated configuration.
    Current,
}

/// Codewire's `gh` configuration directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GhConfig {
    directory: PathBuf,
}

impl Default for GhConfig {
    /// The hosted workspace directory the shared projection names.
    fn default() -> Self {
        Self::new(GH_PLATFORM_CONFIG_DIR)
    }
}

impl GhConfig {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Converge the file for `clients` and log the outcome. A failure leaves
    /// `gh` without its route (its requests then fail); it never stops the
    /// daemon, and Git over the bridge and SSH are unaffected.
    pub fn prepare(&self, clients: ManagedCredentialClients) {
        match self.sync(clients) {
            Ok(state) => tracing::info!(gh_config = ?state, "hosted gh configuration"),
            Err(error) => {
                tracing::warn!(error = %error, "hosted gh configuration could not be written");
            }
        }
    }

    /// Write, keep or remove the generated configuration for `clients`.
    pub fn sync(&self, clients: ManagedCredentialClients) -> io::Result<GhConfigSync> {
        let Some(projection) = clients
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .gh
        else {
            self.remove()?;
            return Ok(GhConfigSync::NotSelected);
        };
        let contents = projection.config_yml().as_bytes();
        ensure_private_directory(&self.directory, DIRECTORY_MODE)?;
        let directory = PrivateDirectory::open(&self.directory)?.ok_or_else(foreign)?;
        if let Entry::Owned(current) = directory.read(GH_CONFIG_FILE_NAME, MAX_CONFIG_BYTES)?
            && current.mode == FILE_MODE
            && current.contents.as_slice() == contents
        {
            return Ok(GhConfigSync::Current);
        }
        // An exclusive temporary with the final mode, then a rename: a reader
        // never sees a partial file, and a symlink of that name is replaced,
        // not followed.
        let temporary = format!(".{GH_CONFIG_FILE_NAME}.{}.tmp", std::process::id());
        directory.unlink(&temporary)?;
        directory.write_new(&temporary, contents, FILE_MODE)?;
        if let Err(error) = directory.rename(&temporary, GH_CONFIG_FILE_NAME) {
            let _ = directory.unlink(&temporary);
            return Err(error);
        }
        directory.sync()?;
        Ok(GhConfigSync::Written)
    }

    /// Remove Codewire's file, then its directory when nothing else is in it.
    fn remove(&self) -> io::Result<()> {
        let directory = match PrivateDirectory::open(&self.directory) {
            Ok(Some(directory)) => directory,
            // Absent, a symlink or another owner's: there is nothing of
            // Codewire's to remove.
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        directory.unlink(GH_CONFIG_FILE_NAME)?;
        drop(directory);
        match std::fs::remove_dir(&self.directory) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// The file `gh` reads, for tests and diagnostics.
    pub fn path(&self) -> PathBuf {
        self.directory.join(GH_CONFIG_FILE_NAME)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

fn foreign() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "gh configuration directory is not the daemon's own directory",
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn selected_github_writes_exactly_the_generated_file_with_private_modes() {
        let temp = tempfile::tempdir().unwrap();
        let config = GhConfig::new(temp.path().join("run").join("gh"));
        let selected = clients(&["github", "codex"]);
        assert_eq!(config.sync(selected).unwrap(), GhConfigSync::Written);
        // The hosted daemon's ingress socket and nothing else.
        assert_eq!(
            std::fs::read_to_string(config.path()).unwrap(),
            "version: 1\nhttp_unix_socket: /codewire/run/credentials.sock\n"
        );
        assert_eq!(
            Path::new(codewire_access::MANAGED_HTTP_PLATFORM_SOCKET),
            Path::new(crate::config::HOSTED_CREDENTIAL_SOCKET)
        );
        assert_eq!(mode(config.directory()), 0o700);
        assert_eq!(mode(&config.path()), 0o600);
        assert_eq!(
            std::fs::read_dir(config.directory())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            [GH_CONFIG_FILE_NAME]
        );
        // A second pass changes nothing.
        let before = std::fs::symlink_metadata(config.path()).unwrap();
        assert_eq!(config.sync(selected).unwrap(), GhConfigSync::Current);
        let after = std::fs::symlink_metadata(config.path()).unwrap();
        assert_eq!(
            (before.ino(), before.mtime_nsec()),
            (after.ino(), after.mtime_nsec())
        );
    }

    #[test]
    fn a_changed_widened_or_linked_file_is_replaced_and_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        let config = GhConfig::new(temp.path().join("gh"));
        let selected = clients(&["github"]);
        config.sync(selected).unwrap();
        let generated = std::fs::read(config.path()).unwrap();

        std::fs::write(config.path(), b"http_unix_socket: /elsewhere\n").unwrap();
        assert_eq!(config.sync(selected).unwrap(), GhConfigSync::Written);
        assert_eq!(std::fs::read(config.path()).unwrap(), generated);

        std::fs::set_permissions(config.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(config.sync(selected).unwrap(), GhConfigSync::Written);
        assert_eq!(mode(&config.path()), 0o600);

        std::fs::set_permissions(config.directory(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert_eq!(config.sync(selected).unwrap(), GhConfigSync::Current);
        assert_eq!(mode(config.directory()), 0o700);

        // A symlink of the file's name is replaced; its target is untouched.
        let target = temp.path().join("users-own-config.yml");
        std::fs::write(&target, b"users own\n").unwrap();
        std::fs::remove_file(config.path()).unwrap();
        std::os::unix::fs::symlink(&target, config.path()).unwrap();
        assert_eq!(config.sync(selected).unwrap(), GhConfigSync::Written);
        assert!(
            std::fs::symlink_metadata(config.path())
                .unwrap()
                .file_type()
                .is_file()
        );
        assert_eq!(std::fs::read(config.path()).unwrap(), generated);
        assert_eq!(std::fs::read(&target).unwrap(), b"users own\n");
    }

    #[test]
    fn a_directory_that_is_a_symlink_is_refused_and_its_target_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let users = temp.path().join("users-gh");
        std::fs::create_dir(&users).unwrap();
        std::fs::write(users.join("hosts.yml"), b"users own\n").unwrap();
        let link = temp.path().join("gh");
        std::os::unix::fs::symlink(&users, &link).unwrap();
        let config = GhConfig::new(&link);
        assert!(config.sync(clients(&["github"])).is_err());
        assert!(!users.join(GH_CONFIG_FILE_NAME).exists());
        // Deselected: a symlinked directory is not Codewire's to clear.
        assert_eq!(
            config.sync(clients(&[])).unwrap(),
            GhConfigSync::NotSelected
        );
        assert_eq!(
            std::fs::read(users.join("hosts.yml")).unwrap(),
            b"users own\n"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn deselecting_github_removes_the_file_and_the_empty_directory_only() {
        let temp = tempfile::tempdir().unwrap();
        let config = GhConfig::new(temp.path().join("gh"));
        // Nothing was ever written: nothing to do.
        assert_eq!(
            config.sync(clients(&["codex", "ssh"])).unwrap(),
            GhConfigSync::NotSelected
        );
        assert!(!config.directory().exists());

        config.sync(clients(&["github"])).unwrap();
        assert_eq!(
            config.sync(clients(&["ssh"])).unwrap(),
            GhConfigSync::NotSelected
        );
        assert!(!config.directory().exists());

        // Something `gh` or the user left beside the file stays.
        config.sync(clients(&["github"])).unwrap();
        std::fs::write(config.directory().join("state.yml"), b"users own\n").unwrap();
        assert_eq!(
            config.sync(clients(&[])).unwrap(),
            GhConfigSync::NotSelected
        );
        assert!(!config.path().exists());
        assert_eq!(
            std::fs::read(config.directory().join("state.yml")).unwrap(),
            b"users own\n"
        );
    }

    #[test]
    fn the_default_directory_is_the_one_every_hosted_session_is_given() {
        let projection =
            clients(&["github"]).for_placement(ManagedCredentialClientPlacement::Platform);
        assert_eq!(
            GhConfig::default().directory(),
            Path::new(&projection.environment["GH_CONFIG_DIR"])
        );
        // Beside the daemon's sockets, in its own runtime directory.
        assert_eq!(
            GhConfig::default().directory().parent(),
            Path::new(crate::config::HOSTED_CREDENTIAL_SOCKET).parent()
        );
    }
}
