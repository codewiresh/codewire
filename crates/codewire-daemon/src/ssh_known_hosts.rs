//! GitHub's published SSH host keys in a hosted Sandbox's `~/.ssh/known_hosts`.
//!
//! While the SSH key is selected, Git and every other SSH client in the
//! Sandbox may reach `git@github.com` with it, including through Codewire's
//! own `git://github.com/` rewrite (#2720). Before it listens, the hosted
//! daemon therefore makes sure the workspace user's `~/.ssh/known_hosts` lists
//! [`codewire_access::GITHUB_SSH_KNOWN_HOSTS`], the keys GitHub publishes, so
//! no connection to github.com trusts a host key on first use and
//! non-interactive tools never stop at "Host key verification failed".
//!
//! - A missing `~/.ssh` is created `0700`, and a missing file `0600`, holding
//!   exactly those lines.
//! - A regular file of the daemon's uid gets the lines it lacks appended,
//!   compared as whole lines, the way an SSH checkout records them. Existing
//!   lines are never rewritten, reordered or removed. The file is replaced
//!   atomically (an exclusive temporary beside it, fsync, rename), with its
//!   own mode where that is narrower than `0644`, and only while it is still
//!   the file that was read.
//! - Anything else (a symlink, a special or another uid's file or directory,
//!   an oversized file) is the user's and is never touched. Every operation
//!   is relative to the home opened with `O_NOFOLLOW`.
//!
//! The lines are public trust, never a credential, and are not removed when
//! the key is later deselected. A selection change restarts the Sandbox, so
//! one pass at daemon start covers it. A local VM's guest writes the same
//! lines into its persistent home before the workspace starts.
//!
//! Only [`SshKnownHostsSync`] states are logged, never file contents.

use std::io;
use std::path::{Path, PathBuf};

use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};

use crate::private_files::{Entry, PrivateDirectory};

/// OpenSSH's per-user directory and trust file in the home.
pub const SSH_DIRECTORY_NAME: &str = ".ssh";
pub const KNOWN_HOSTS_FILE_NAME: &str = "known_hosts";
const SSH_DIRECTORY_MODE: u32 = 0o700;
const KNOWN_HOSTS_MODE: u32 = 0o600;
/// The widest mode an existing file keeps.
const KNOWN_HOSTS_MAX_MODE: u32 = 0o644;
/// A larger file is left alone.
const MAX_KNOWN_HOSTS_BYTES: u64 = 4 * 1024 * 1024;

/// What one sync did. It names no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshKnownHostsSync {
    /// The SSH key is not selected: nothing was read or written.
    NotSelected,
    /// `~/.ssh/known_hosts` was missing and now holds exactly GitHub's lines.
    Created,
    /// GitHub's missing lines were appended to the existing file.
    Appended,
    /// Every line was already present: nothing was written.
    Current,
    /// The home, `~/.ssh` or the file is the user's (see the module
    /// documentation), or the file changed while it was checked. Nothing
    /// was touched.
    UserOwned,
}

/// The workspace user's home, which holds `~/.ssh/known_hosts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshKnownHosts {
    root: PathBuf,
}

impl SshKnownHosts {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.root
            .join(SSH_DIRECTORY_NAME)
            .join(KNOWN_HOSTS_FILE_NAME)
    }

    /// List GitHub's published keys in `~/.ssh/known_hosts` while the served
    /// `clients` select the SSH key.
    pub fn sync(&self, clients: ManagedCredentialClients) -> io::Result<SshKnownHostsSync> {
        if !clients.contains(ManagedCredentialClient::Ssh) {
            return Ok(SshKnownHostsSync::NotSelected);
        }
        let Some(home) = PrivateDirectory::open_home(&self.root)? else {
            return Ok(SshKnownHostsSync::UserOwned);
        };
        let Some(ssh) = home.open_or_create_child(SSH_DIRECTORY_NAME, SSH_DIRECTORY_MODE)? else {
            return Ok(SshKnownHostsSync::UserOwned);
        };
        let temporary = format!(
            ".{KNOWN_HOSTS_FILE_NAME}.codewire.{}.tmp",
            uuid::Uuid::new_v4().simple()
        );
        let entry = match ssh.read(KNOWN_HOSTS_FILE_NAME, MAX_KNOWN_HOSTS_BYTES)? {
            Entry::Absent => {
                let created = ssh.install_new(
                    &temporary,
                    KNOWN_HOSTS_FILE_NAME,
                    &codewire_access::github_known_hosts_additions(b""),
                    KNOWN_HOSTS_MODE,
                )?;
                return Ok(if created {
                    SshKnownHostsSync::Created
                } else {
                    SshKnownHostsSync::UserOwned
                });
            }
            Entry::Foreign => return Ok(SshKnownHostsSync::UserOwned),
            Entry::Owned(entry) => entry,
        };
        let additions = codewire_access::github_known_hosts_additions(&entry.contents);
        if additions.is_empty() {
            return Ok(SshKnownHostsSync::Current);
        }
        let mut contents = entry.contents.to_vec();
        contents.extend_from_slice(&additions);
        let replaced = ssh.replace_unchanged(
            &temporary,
            KNOWN_HOSTS_FILE_NAME,
            &entry,
            MAX_KNOWN_HOSTS_BYTES,
            &contents,
            entry.mode & KNOWN_HOSTS_MAX_MODE,
        )?;
        Ok(if replaced {
            SshKnownHostsSync::Appended
        } else {
            SshKnownHostsSync::UserOwned
        })
    }

    /// [`Self::sync`] before the daemon listens. A failure is logged and
    /// never stops the daemon: without the lines OpenSSH asks once, as it did
    /// before.
    pub fn prepare(&self, clients: ManagedCredentialClients) {
        match self.sync(clients) {
            Ok(outcome) => {
                tracing::info!(ssh_known_hosts = ?outcome, "hosted GitHub SSH host keys prepared");
            }
            Err(error) => tracing::warn!(
                error_kind = ?error.kind(),
                "hosted SSH known_hosts unavailable; GitHub's host keys were not recorded"
            ),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    fn github_lines() -> String {
        format!("{}\n", codewire_access::GITHUB_SSH_KNOWN_HOSTS.join("\n"))
    }

    fn fresh_home() -> (tempfile::TempDir, SshKnownHosts) {
        let root = tempfile::tempdir().unwrap();
        let home = SshKnownHosts::new(root.path().join("codewire"));
        fs::create_dir(home.root()).unwrap();
        (root, home)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn without_the_ssh_key_nothing_is_read_or_written() {
        for slots in [&[][..], &["github"], &["codex", "anthropic", "github"]] {
            let (_root, home) = fresh_home();
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                SshKnownHostsSync::NotSelected
            );
            assert!(entries(home.root()).is_empty());
        }
    }

    #[test]
    fn a_missing_file_and_directory_are_created_with_githubs_keys_only() {
        for slots in [&["ssh"][..], &["ssh", "github"]] {
            let (_root, home) = fresh_home();
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                SshKnownHostsSync::Created
            );
            assert_eq!(fs::read_to_string(home.path()).unwrap(), github_lines());
            assert_eq!(mode(&home.root().join(SSH_DIRECTORY_NAME)), 0o700);
            assert_eq!(mode(&home.path()), 0o600);
            let metadata = fs::symlink_metadata(home.path()).unwrap();
            // SAFETY: geteuid has no preconditions and cannot fail.
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(
                entries(&home.root().join(SSH_DIRECTORY_NAME)),
                [KNOWN_HOSTS_FILE_NAME]
            );
            // A second pass changes nothing.
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                SshKnownHostsSync::Current
            );
            assert_eq!(fs::read_to_string(home.path()).unwrap(), github_lines());
        }
    }

    #[test]
    fn an_existing_file_keeps_its_lines_and_gains_only_the_missing_ones() {
        let (_root, home) = fresh_home();
        let ssh = home.root().join(SSH_DIRECTORY_NAME);
        fs::create_dir(&ssh).unwrap();
        let existing = format!(
            "git.example.com ssh-ed25519 QUJDRA==\n{}",
            codewire_access::GITHUB_SSH_KNOWN_HOSTS[1]
        );
        fs::write(home.path(), &existing).unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            home.sync(clients(&["ssh"])).unwrap(),
            SshKnownHostsSync::Appended
        );
        assert_eq!(
            fs::read_to_string(home.path()).unwrap(),
            format!(
                "{existing}\n{}\n{}\n",
                codewire_access::GITHUB_SSH_KNOWN_HOSTS[0],
                codewire_access::GITHUB_SSH_KNOWN_HOSTS[2]
            )
        );
        assert_eq!(mode(&home.path()), 0o644);
        assert_eq!(entries(&ssh), [KNOWN_HOSTS_FILE_NAME]);
        assert_eq!(
            home.sync(clients(&["ssh"])).unwrap(),
            SshKnownHostsSync::Current
        );
    }

    #[test]
    fn a_symlinked_directory_or_file_is_the_users_and_never_followed() {
        // A symlinked `~/.ssh`.
        let (root, home) = fresh_home();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, home.root().join(SSH_DIRECTORY_NAME)).unwrap();
        assert_eq!(
            home.sync(clients(&["ssh"])).unwrap(),
            SshKnownHostsSync::UserOwned
        );
        assert!(entries(&outside).is_empty());

        // A symlinked `known_hosts`.
        let (root, home) = fresh_home();
        let ssh = home.root().join(SSH_DIRECTORY_NAME);
        fs::create_dir(&ssh).unwrap();
        let target = root.path().join("target");
        fs::write(&target, b"outside-sentinel").unwrap();
        symlink(&target, home.path()).unwrap();
        assert_eq!(
            home.sync(clients(&["ssh"])).unwrap(),
            SshKnownHostsSync::UserOwned
        );
        assert_eq!(fs::read(&target).unwrap(), b"outside-sentinel");
        assert!(
            fs::symlink_metadata(home.path())
                .unwrap()
                .file_type()
                .is_symlink()
        );

        // A `~/.ssh` that is a file.
        let (_root, home) = fresh_home();
        fs::write(home.root().join(SSH_DIRECTORY_NAME), b"not a directory").unwrap();
        assert_eq!(
            home.sync(clients(&["ssh"])).unwrap(),
            SshKnownHostsSync::UserOwned
        );
    }
}
