//! Codex's home in a hosted Sandbox is the user's own `~/.codex`
//! ([`CODEX_PLATFORM_HOME`]) on the persistent home volume, as on a laptop:
//! sessions, history and the user's own settings survive Stop/Start.
//!
//! The hosted daemon is the only writer of Codewire's files there, in both
//! identity modes. Before it listens, while Codex is selected, it writes the
//! credential-free provider `config.toml`; when Codex is not selected it
//! removes that and Codewire's `auth.json`. The file is Codewire's only while
//! it is a regular file (never a symlink), owned by the daemon's uid, whose
//! first line is exactly [`CODEX_MANAGED_CONFIG_HEADER`]. Any other
//! `config.toml`, including one whose header line the user deleted, is the
//! user's: it is never written, replaced or removed.
//!
//! Once listening, the daemon also keeps Codex's own ChatGPT login in
//! `auth.json` while the broker delivers one ([`login`]); a delivered login
//! removes Codewire's `config.toml`, so Codex uses its built-in provider.
//! Nothing else in the home is touched.

use std::fs::{self, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use codewire_access::{
    CODEX_CONFIG_FILE_NAME, CODEX_MANAGED_CONFIG_HEADER, CODEX_PLATFORM_HOME,
    CodexProviderProjection, ManagedCredentialClientPlacement, ManagedCredentialClients,
};

use crate::private_files::{
    ensure_private_directory, sync_directory, temporary_sibling, write_new,
};

#[cfg(target_os = "linux")]
pub mod login;
#[cfg(target_os = "linux")]
pub use login::{
    CODEX_AUTH_FILE_NAME, CODEX_LOGIN_CHECK_PERIOD, CODEX_LOGIN_LAPSE, CODEX_LOGIN_STATE_DIRECTORY,
    CODEX_MANAGED_REFRESH_TOKEN, CodexLoginDelivery, CodexLoginSync, CodexLoginWriter,
};

const CODEX_HOME_MODE: u32 = 0o700;
const CODEX_CONFIG_MODE: u32 = 0o600;
/// Codewire's file is a few hundred bytes; a larger one is read only this far.
const MAX_MANAGED_CONFIG_BYTES: u64 = 64 * 1024;

/// What one sync did. It names no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexConfigSync {
    /// Codewire's `config.toml` now holds the selected configuration.
    Written,
    /// Codewire's `config.toml` already held it.
    Current,
    /// Codex is not selected, and Codewire's `config.toml` was removed.
    Removed,
    /// Codex is not selected, and there was no Codewire file to remove.
    Absent,
    /// The user owns `config.toml`, or `~/.codex` itself is not a plain
    /// directory of the daemon's uid. Nothing was touched.
    UserOwned,
}

/// Codex's home in one hosted Pod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexHome {
    root: PathBuf,
}

impl Default for CodexHome {
    fn default() -> Self {
        Self::at(CODEX_PLATFORM_HOME)
    }
}

impl CodexHome {
    /// The same layout at `root`, for tests.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(CODEX_CONFIG_FILE_NAME)
    }

    /// Converge Codewire's `config.toml` on what the served `clients` need:
    /// the hosted provider configuration while Codex is selected, no file
    /// otherwise.
    pub fn sync(&self, clients: ManagedCredentialClients) -> io::Result<CodexConfigSync> {
        let selected = clients
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .codex
            .map(CodexProviderProjection::into_config_toml);
        self.sync_config(selected.as_deref())
    }

    /// [`Self::sync`] before the daemon listens, and, when Codex is not
    /// selected, removal of Codewire's `auth.json`. A failure is logged and
    /// never stops the daemon: `~/.codex` belongs to the user, and without
    /// Codewire's file Codex only lacks its managed route.
    pub fn prepare(&self, clients: ManagedCredentialClients) {
        match self.sync(clients) {
            Ok(outcome) => {
                tracing::info!(codex_config = ?outcome, "hosted Codex home prepared");
            }
            Err(error) => tracing::warn!(
                error_kind = ?error.kind(),
                "hosted Codex home unavailable; Codewire's Codex configuration was not written"
            ),
        }
        #[cfg(target_os = "linux")]
        if !clients.contains(codewire_access::ManagedCredentialClient::Codex) {
            match self.remove_codewire_login() {
                Ok(removal) => {
                    tracing::info!(codex_login = ?removal, "hosted Codex login cleared");
                }
                Err(error) => tracing::warn!(
                    error_kind = ?error.kind(),
                    "hosted Codex login could not be cleared"
                ),
            }
        }
    }

    fn sync_config(&self, selected: Option<&str>) -> io::Result<CodexConfigSync> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if !metadata.is_dir() || metadata.uid() != effective_uid() => {
                return Ok(CodexConfigSync::UserOwned);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && selected.is_none() => {
                return Ok(CodexConfigSync::Absent);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let path = self.config_path();
        let Some(contents) = selected else {
            return match inspect(&path, None)? {
                Existing::Absent => Ok(CodexConfigSync::Absent),
                Existing::User => Ok(CodexConfigSync::UserOwned),
                Existing::Managed { identity, .. } => {
                    if identity_of(&path)? != Some(identity) {
                        return Ok(CodexConfigSync::UserOwned);
                    }
                    fs::remove_file(&path)?;
                    sync_directory(&self.root)?;
                    Ok(CodexConfigSync::Removed)
                }
            };
        };
        debug_assert!(contents.starts_with(&format!("{CODEX_MANAGED_CONFIG_HEADER}\n")));
        ensure_private_directory(&self.root, CODEX_HOME_MODE)?;
        match inspect(&path, Some(contents.as_bytes()))? {
            Existing::User => Ok(CodexConfigSync::UserOwned),
            Existing::Managed { current: true, .. } => Ok(CodexConfigSync::Current),
            Existing::Managed { identity, .. } => {
                install(&self.root, &path, contents, Some(identity))
            }
            Existing::Absent => install(&self.root, &path, contents, None),
        }
    }
}

/// One file's device and inode.
type Identity = (u64, u64);

enum Existing {
    Absent,
    User,
    Managed { identity: Identity, current: bool },
}

/// Classify `path` without following a symlink. `current` is whether
/// Codewire's file already holds `selected` with its mode.
fn inspect(path: &Path, selected: Option<&[u8]>) -> io::Result<Existing> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Existing::Absent),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.uid() != effective_uid() {
        return Ok(Existing::User);
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Existing::Absent),
        // Replaced by a symlink since the check above.
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Ok(Existing::User),
        Err(error) => return Err(error),
    };
    let opened = file.metadata()?;
    let identity = (opened.dev(), opened.ino());
    if identity != (metadata.dev(), metadata.ino()) {
        return Ok(Existing::User);
    }
    let mut contents = Vec::new();
    (&mut file)
        .take(MAX_MANAGED_CONFIG_BYTES + 1)
        .read_to_end(&mut contents)?;
    let first_line = contents.split(|byte| *byte == b'\n').next().unwrap_or(&[]);
    if first_line != CODEX_MANAGED_CONFIG_HEADER.as_bytes() {
        return Ok(Existing::User);
    }
    Ok(Existing::Managed {
        identity,
        current: selected == Some(contents.as_slice())
            && opened.permissions().mode() & 0o7777 == CODEX_CONFIG_MODE,
    })
}

fn identity_of(path: &Path) -> io::Result<Option<Identity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Install `contents` at `path`. Without `replace`, a file that appeared
/// since the inspection is the user's and stays: the hard link never
/// replaces. With it, only the exact file inspected as Codewire's is
/// replaced.
fn install(
    root: &Path,
    path: &Path,
    contents: &str,
    replace: Option<Identity>,
) -> io::Result<CodexConfigSync> {
    let temporary = temporary_sibling(path, "codewire")?;
    write_new(&temporary, contents.as_bytes(), CODEX_CONFIG_MODE)?;
    let installed = match replace {
        None => match fs::hard_link(&temporary, path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        },
        Some(identity) => match identity_of(path) {
            Ok(current) if current == Some(identity) => fs::rename(&temporary, path).map(|()| true),
            Ok(_) => Ok(false),
            Err(error) => Err(error),
        },
    };
    let _ = fs::remove_file(&temporary);
    let installed = installed?;
    sync_directory(root)?;
    Ok(if installed {
        CodexConfigSync::Written
    } else {
        CodexConfigSync::UserOwned
    })
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    fn hosted_config() -> String {
        clients(&["codex"])
            .for_placement(ManagedCredentialClientPlacement::Platform)
            .codex
            .unwrap()
            .into_config_toml()
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// Every name in the home other than `config.toml`, so a test can prove
    /// the rest of Codex's state is untouched and no temporary file remains.
    fn other_entries(home: &CodexHome) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(home.root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != CODEX_CONFIG_FILE_NAME)
            .collect();
        names.sort();
        names
    }

    /// A home with Codex's own state beside the config, as after real use.
    fn used_home(root: &Path) -> CodexHome {
        let home = CodexHome::at(root.join(".codex"));
        fs::create_dir_all(home.root().join("sessions/2026/10/03")).unwrap();
        fs::write(
            home.root().join("sessions/2026/10/03/rollout.jsonl"),
            b"synthetic-session",
        )
        .unwrap();
        fs::write(home.root().join("history.jsonl"), b"synthetic-history").unwrap();
        home
    }

    #[test]
    fn production_home_is_codex_default_on_the_persistent_home() {
        assert_eq!(
            CodexHome::default().root(),
            Path::new("/home/codewire/.codex")
        );
        assert_eq!(
            CodexHome::default().config_path(),
            Path::new("/home/codewire/.codex/config.toml")
        );
    }

    #[test]
    fn selected_codex_gets_the_managed_config_in_a_private_home() {
        let root = tempfile::tempdir().unwrap();
        let home = CodexHome::at(root.path().join(".codex"));
        assert_eq!(
            home.sync(clients(&["codex"])).unwrap(),
            CodexConfigSync::Written
        );
        assert_eq!(mode(home.root()), 0o700);
        assert_eq!(mode(&home.config_path()), 0o600);
        let written = fs::read_to_string(home.config_path()).unwrap();
        assert_eq!(written, hosted_config());
        assert_eq!(written.lines().next(), Some(CODEX_MANAGED_CONFIG_HEADER));
        assert!(
            other_entries(&home).is_empty(),
            "{:?}",
            other_entries(&home)
        );
        // An unchanged selection writes nothing.
        let before = fs::symlink_metadata(home.config_path()).unwrap().ino();
        assert_eq!(
            home.sync(clients(&["codex", "openai"])).unwrap(),
            CodexConfigSync::Current
        );
        assert_eq!(
            fs::symlink_metadata(home.config_path()).unwrap().ino(),
            before
        );
    }

    #[test]
    fn codex_state_survives_every_sync_and_an_existing_home_is_tightened() {
        let root = tempfile::tempdir().unwrap();
        let home = used_home(root.path());
        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o755)).unwrap();
        for slots in [&["codex"][..], &[], &["codex"], &["openai"]] {
            home.sync(clients(slots)).unwrap();
            assert_eq!(
                other_entries(&home),
                ["history.jsonl", "sessions"],
                "{slots:?}"
            );
            assert_eq!(
                fs::read(home.root().join("sessions/2026/10/03/rollout.jsonl")).unwrap(),
                b"synthetic-session"
            );
            assert_eq!(
                fs::read(home.root().join("history.jsonl")).unwrap(),
                b"synthetic-history"
            );
        }
        assert_eq!(mode(home.root()), 0o700);
    }

    #[test]
    fn codewire_files_are_replaced_with_the_current_configuration() {
        let root = tempfile::tempdir().unwrap();
        let home = used_home(root.path());
        for stale in [
            format!("{CODEX_MANAGED_CONFIG_HEADER}\nmodel_provider = \"previous\"\n"),
            format!("{CODEX_MANAGED_CONFIG_HEADER}\n"),
            CODEX_MANAGED_CONFIG_HEADER.to_owned(),
            hosted_config() + "user_addition = true\n",
        ] {
            fs::write(home.config_path(), &stale).unwrap();
            fs::set_permissions(home.config_path(), fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                home.sync(clients(&["codex"])).unwrap(),
                CodexConfigSync::Written
            );
            assert_eq!(
                fs::read_to_string(home.config_path()).unwrap(),
                hosted_config()
            );
            assert_eq!(mode(&home.config_path()), 0o600);
        }
        // The right bytes with a widened mode are rewritten too.
        fs::set_permissions(home.config_path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            home.sync(clients(&["codex"])).unwrap(),
            CodexConfigSync::Written
        );
        assert_eq!(mode(&home.config_path()), 0o600);
        assert_eq!(other_entries(&home), ["history.jsonl", "sessions"]);
    }

    #[test]
    fn a_users_config_is_never_written_or_removed() {
        let root = tempfile::tempdir().unwrap();
        let home = used_home(root.path());
        let without_header = hosted_config().split_once('\n').unwrap().1.to_owned();
        for users in [
            // The user deleted the header line and kept Codewire's settings.
            without_header,
            "model = \"gpt-5\"\n".to_owned(),
            String::new(),
            format!("model = \"gpt-5\"\n{CODEX_MANAGED_CONFIG_HEADER}\n"),
            format!(" {CODEX_MANAGED_CONFIG_HEADER}\n"),
            format!("{CODEX_MANAGED_CONFIG_HEADER} \n"),
            format!("{CODEX_MANAGED_CONFIG_HEADER}\r\n"),
        ] {
            fs::write(home.config_path(), &users).unwrap();
            fs::set_permissions(home.config_path(), fs::Permissions::from_mode(0o644)).unwrap();
            for slots in [&["codex"][..], &[]] {
                assert_eq!(
                    home.sync(clients(slots)).unwrap(),
                    CodexConfigSync::UserOwned,
                    "{users:?} {slots:?}"
                );
                assert_eq!(fs::read_to_string(home.config_path()).unwrap(), users);
                assert_eq!(mode(&home.config_path()), 0o644);
            }
        }
        assert_eq!(other_entries(&home), ["history.jsonl", "sessions"]);
    }

    #[test]
    fn symlinks_and_special_files_are_the_users_and_never_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("dotfiles.toml");
        let header_outside = format!("{CODEX_MANAGED_CONFIG_HEADER}\nsynthetic = \"outside\"\n");
        fs::write(&outside, &header_outside).unwrap();

        let home = used_home(root.path());
        symlink(&outside, home.config_path()).unwrap();
        for slots in [&["codex"][..], &[]] {
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                CodexConfigSync::UserOwned
            );
            assert!(
                fs::symlink_metadata(home.config_path())
                    .unwrap()
                    .is_symlink()
            );
            assert_eq!(fs::read_to_string(&outside).unwrap(), header_outside);
        }
        fs::remove_file(home.config_path()).unwrap();
        fs::create_dir(home.config_path()).unwrap();
        for slots in [&["codex"][..], &[]] {
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                CodexConfigSync::UserOwned
            );
            assert!(home.config_path().is_dir());
        }

        // A symlinked home is the user's choice: nothing is written into it
        // or removed from it, and its mode is not changed.
        let target = root.path().join("dotfiles-codex");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(target.join(CODEX_CONFIG_FILE_NAME), &header_outside).unwrap();
        let linked = CodexHome::at(root.path().join("linked-codex"));
        symlink(&target, linked.root()).unwrap();
        for slots in [&["codex"][..], &[]] {
            assert_eq!(
                linked.sync(clients(slots)).unwrap(),
                CodexConfigSync::UserOwned
            );
        }
        assert_eq!(
            fs::read_to_string(target.join(CODEX_CONFIG_FILE_NAME)).unwrap(),
            header_outside
        );
        assert_eq!(mode(&target), 0o755);

        // A stale temporary that is a symlink is unlinked, not written through.
        let fresh = CodexHome::at(root.path().join("fresh-codex"));
        fs::create_dir(fresh.root()).unwrap();
        let decoy = root.path().join("decoy");
        fs::write(&decoy, b"decoy").unwrap();
        symlink(
            &decoy,
            temporary_sibling(&fresh.config_path(), "codewire").unwrap(),
        )
        .unwrap();
        assert_eq!(
            fresh.sync(clients(&["codex"])).unwrap(),
            CodexConfigSync::Written
        );
        assert_eq!(fs::read(&decoy).unwrap(), b"decoy");
        assert!(other_entries(&fresh).is_empty());
    }

    #[test]
    fn deselecting_codex_removes_only_codewires_file() {
        let root = tempfile::tempdir().unwrap();
        let missing = CodexHome::at(root.path().join("never-created"));
        assert_eq!(
            missing.sync(clients(&["openai"])).unwrap(),
            CodexConfigSync::Absent
        );
        assert!(
            !missing.root().exists(),
            "an unselected sync creates nothing"
        );

        let home = used_home(root.path());
        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(home.sync(clients(&[])).unwrap(), CodexConfigSync::Absent);
        assert_eq!(
            mode(home.root()),
            0o755,
            "an unselected sync changes no mode"
        );
        home.sync(clients(&["codex"])).unwrap();
        assert_eq!(
            home.sync(clients(&["openai", "github"])).unwrap(),
            CodexConfigSync::Removed
        );
        assert!(fs::symlink_metadata(home.config_path()).is_err());
        assert_eq!(home.sync(clients(&[])).unwrap(), CodexConfigSync::Absent);
        assert_eq!(other_entries(&home), ["history.jsonl", "sessions"]);
    }

    #[test]
    fn a_file_that_appears_or_changes_after_inspection_is_left_alone() {
        let root = tempfile::tempdir().unwrap();
        let home = used_home(root.path());
        // Inspected as absent, then created by the user.
        fs::write(home.config_path(), b"model = \"users\"\n").unwrap();
        assert_eq!(
            install(home.root(), &home.config_path(), &hosted_config(), None).unwrap(),
            CodexConfigSync::UserOwned
        );
        assert_eq!(
            fs::read(home.config_path()).unwrap(),
            b"model = \"users\"\n"
        );
        // Inspected as Codewire's, then replaced by the user.
        let stale = fs::symlink_metadata(home.config_path()).unwrap();
        let identity = (stale.dev(), stale.ino() + 1);
        assert_eq!(
            install(
                home.root(),
                &home.config_path(),
                &hosted_config(),
                Some(identity)
            )
            .unwrap(),
            CodexConfigSync::UserOwned
        );
        assert_eq!(
            fs::read(home.config_path()).unwrap(),
            b"model = \"users\"\n"
        );
        assert_eq!(other_entries(&home), ["history.jsonl", "sessions"]);
    }

    /// The `SANDBOX_WORKSPACE_IDENTITY_MODE=environment-token` rollback
    /// renders the selection into the container; a bound daemon gets it from
    /// its binding. Both serve the same clients, so both prepare the same home
    /// from the same writer, and both remove Codewire's file once Codex is
    /// cleared.
    #[test]
    fn both_identity_modes_prepare_the_same_home_from_their_served_clients() {
        use crate::config::{
            BindResponseFields, DAEMON_AUTH_TOKEN_ENV, ENVIRONMENT_GENERATION_ENV,
            ENVIRONMENT_ID_ENV, HOSTED_PROJECTION_SHA256_ENV, HostedDaemonMode,
            MANAGED_CREDENTIAL_CLIENTS_ENV, WORKSPACE_BINDING_URL_ENV, WORKSPACE_POD_UID_ENV,
        };
        const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
        const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
        let digest = "ab".repeat(32);
        let mode = |values: &[(&str, &str)]| {
            HostedDaemonMode::from_lookup(|name| {
                values
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).into())
            })
            .unwrap()
        };
        let served = |clients: &str| {
            let HostedDaemonMode::EnvironmentToken(rollback) = mode(&[
                (DAEMON_AUTH_TOKEN_ENV, "synthetic-environment-token"),
                (HOSTED_PROJECTION_SHA256_ENV, &digest),
                (MANAGED_CREDENTIAL_CLIENTS_ENV, clients),
                (ENVIRONMENT_ID_ENV, ENVIRONMENT),
                (ENVIRONMENT_GENERATION_ENV, "7"),
            ]) else {
                panic!("environment-token mode expected");
            };
            let HostedDaemonMode::Binding(binding) = mode(&[
                (WORKSPACE_BINDING_URL_ENV, "http://binding.test:8087"),
                (WORKSPACE_POD_UID_ENV, POD),
            ]) else {
                panic!("binding mode expected");
            };
            let bound = binding
                .validate(&BindResponseFields {
                    environment_id: ENVIRONMENT,
                    pod_uid: POD,
                    operation_generation: 7,
                    daemon_credential: "synthetic-workspace-daemon-credential",
                    projection_selection_sha256: &digest,
                    managed_credential_clients: clients,
                })
                .unwrap();
            [
                rollback.managed_credential_clients,
                binding.into_config(&bound).managed_credential_clients,
            ]
        };
        let root = tempfile::tempdir().unwrap();
        let homes = [
            used_home(&root.path().join("rollback")),
            used_home(&root.path().join("bound")),
        ];
        for (home, clients) in homes.iter().zip(served("v1:codex,openai")) {
            assert_eq!(home.sync(clients).unwrap(), CodexConfigSync::Written);
            assert_eq!(
                fs::read_to_string(home.config_path()).unwrap(),
                hosted_config()
            );
        }
        for (home, clients) in homes.iter().zip(served("v1:openai")) {
            assert_eq!(home.sync(clients).unwrap(), CodexConfigSync::Removed);
            assert_eq!(other_entries(home), ["history.jsonl", "sessions"]);
        }
    }

    #[test]
    fn a_home_that_cannot_be_prepared_is_an_error_not_a_panic() {
        let root = tempfile::tempdir().unwrap();
        let blocked = root.path().join("not-a-directory");
        fs::write(&blocked, b"file").unwrap();
        let home = CodexHome::at(blocked.join(".codex"));
        assert!(home.sync(clients(&["codex"])).is_err());
        // The daemon logs it and keeps starting.
        home.prepare(clients(&["codex"]));
    }
}
