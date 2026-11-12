//! Claude Code's first-run onboarding and workspace trust in a hosted Sandbox,
//! and, in its sign-in form, Claude Code's own login ([`login`]).
//!
//! Claude Code asks whether you trust each folder it starts in. Trust lets it
//! load a folder's own project settings, such as hooks and MCP servers, which
//! run when it starts; the workspace holds the user's own checkouts, so the
//! question protects nothing there. The daemon therefore marks trusted, in
//! `~/.claude.json` (`projects[FOLDER].hasTrustDialogAccepted`), the workspace
//! root and every Git repository under it ([`trusted_folders`]), in both
//! identity modes and whatever clients are selected (#4332). A folder's trust
//! covers the folders beneath it, but Claude Code stops looking upward at a
//! repository's root, so `/workspace`'s trust alone never covers
//! `/workspace/REPO`: each repository is trusted by its own root. It does so
//! before it listens, which covers a local VM's repositories (already on its
//! disk), and again before each session it launches, through
//! [`WorkspaceTrust`], which covers repositories cloned since: a hosted
//! Sandbox's, which setup clones once the daemon serves, and the user's own.
//! Nothing outside the workspace is trusted; other folders, such as the home
//! directory, still ask.
//!
//! While the Anthropic client is selected, in any form (API key, Claude
//! subscription token or Claude sign-in), Claude Code already has Codewire's
//! managed credential, yet on a fresh home it opens its first-run "Select login
//! method" picker, because its `~/.claude.json` does not record onboarding.
//! The daemon therefore also sets [`CLAUDE_ONBOARDING_KEYS`] to `true`. No
//! updater setting is written, and no token, credential or placeholder ever
//! enters the file.
//!
//! - A missing file is created with exactly those keys, mode 0600.
//! - A regular file of the daemon's uid that holds a JSON object gets the keys
//!   that are not already `true`; every other member keeps its value. The file
//!   is replaced atomically (an exclusive temporary beside it, fsync, rename)
//!   with mode 0600, or its own mode where that is narrower, and only while it
//!   is still the file that was read.
//! - Anything else (a symlink, a special or another uid's file, an oversized
//!   file, invalid JSON, a non-object, or a `projects` member or workspace
//!   entry that is not an object) is the user's and is never touched.
//!   Every operation is relative to the home opened with `O_NOFOLLOW`, and the
//!   file is opened with `O_NOFOLLOW`: nothing is followed through a symlink.
//!
//! The keys only skip onboarding and the workspace's trust questions, so they
//! are never removed, also when the Anthropic client is later deselected or a
//! repository is removed. A selection change restarts the
//! Sandbox, so one pass at daemon start covers it. A local VM's guest daemon,
//! which runs as root, does the same for the workload user
//! ([`ClaudeHome::for_owner`]): it reads and replaces only that user's files
//! and gives every file it creates to that user.
//!
//! Before it listens, the daemon also removes Codewire's `claudeAiOauth` from
//! `~/.claude/.credentials.json` unless the sign-in form is selected; the
//! user's own login there is never touched.
//!
//! Only [`ClaudeOnboardingSync`] states are logged, never file contents.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};
use serde_json::{Map, Value};

use crate::private_files::{Entry, FileOwner, PrivateDirectory};

pub mod login;
pub use login::{
    CLAUDE_CONFIG_DIR_NAME, CLAUDE_CREDENTIALS_FILE_NAME, CLAUDE_LOGIN_KEY, CLAUDE_LOGIN_LAPSE,
    CLAUDE_LOGIN_STATE_DIRECTORY, CLAUDE_MANAGED_MARKER, CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX,
    ClaudeLoginDelivery, ClaudeLoginSync, ClaudeLoginWriter, holds_codewire_login,
    is_codewire_leftover, is_codewire_temporary, is_codewire_write_in_progress,
};

/// Claude Code's global configuration file in the user's home.
pub const CLAUDE_CONFIG_FILE_NAME: &str = ".claude.json";
/// The members set to `true`.
pub const CLAUDE_ONBOARDING_KEYS: [&str; 2] =
    ["hasCompletedOnboarding", "hasAcknowledgedCostThreshold"];
/// The per-folder member, under `projects`, that records folder trust.
pub const CLAUDE_TRUST_KEY: &str = "hasTrustDialogAccepted";
const CLAUDE_CONFIG_MODE: u32 = 0o600;
/// Claude Code keeps per-project state in the file, so it grows with use; a
/// larger one is left alone.
const MAX_CLAUDE_CONFIG_BYTES: u64 = 32 * 1024 * 1024;
/// How far below the workspace root repositories are looked for: a declared
/// checkout path such as `/workspace/team/service/api` is three levels down.
const TRUST_DEPTH: usize = 3;
/// The most directory entries one look reads, so a workspace with a huge tree
/// outside its repositories costs a bounded walk.
const MAX_TRUST_ENTRIES: usize = 4096;

/// What one sync did. It names no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeOnboardingSync {
    /// `~/.claude.json` was missing and now holds exactly the keys.
    Created,
    /// The keys that were not `true` were set in the existing file.
    Marked,
    /// Every key was already `true`: nothing was written.
    Current,
    /// The file or the home is the user's (see the module documentation), or
    /// the file changed while it was checked. Nothing was touched.
    UserOwned,
}

/// The workspace user's home, which holds Claude Code's `.claude.json`, and
/// the workspace root it trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeHome {
    root: PathBuf,
    workspace: String,
    /// The workload user a local VM's guest daemon (root) keeps the home for;
    /// `None` on a hosted daemon, whose home is its own.
    owner: Option<FileOwner>,
}

impl ClaudeHome {
    pub fn new(root: impl Into<PathBuf>, workspace: &Path) -> Self {
        Self {
            root: root.into(),
            workspace: workspace.to_string_lossy().into_owned(),
            owner: None,
        }
    }

    /// This home, kept on `owner`'s behalf: a local VM's guest daemon runs as
    /// root and prepares Claude Code for the workload user as a hosted
    /// daemon does for itself.
    pub fn for_owner(mut self, owner: FileOwner) -> Self {
        self.owner = Some(owner);
        self
    }

    pub(crate) fn owner(&self) -> Option<FileOwner> {
        self.owner
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(CLAUDE_CONFIG_FILE_NAME)
    }

    /// Mark the workspace and its repositories trusted and, while the served
    /// `clients` select the Anthropic client in any form, Claude Code's
    /// onboarding complete.
    pub fn sync(&self, clients: ManagedCredentialClients) -> io::Result<ClaudeOnboardingSync> {
        self.mark(
            onboarding_keys(clients),
            &trusted_folders(Path::new(&self.workspace)),
        )
    }

    fn mark(&self, onboarding: &[&str], trusted: &[String]) -> io::Result<ClaudeOnboardingSync> {
        let home = match self.owner {
            Some(owner) => PrivateDirectory::open_for(&self.root, owner)?,
            None => PrivateDirectory::open_home(&self.root)?,
        };
        let Some(home) = home else {
            return Ok(ClaudeOnboardingSync::UserOwned);
        };
        let temporary = format!(
            "{CLAUDE_CONFIG_FILE_NAME}.codewire.{}.tmp",
            uuid::Uuid::new_v4().simple()
        );
        let entry = match home.read(CLAUDE_CONFIG_FILE_NAME, MAX_CLAUDE_CONFIG_BYTES)? {
            Entry::Absent => {
                let created = home.install_new(
                    &temporary,
                    CLAUDE_CONFIG_FILE_NAME,
                    &render(Map::new(), trusted, onboarding)?,
                    CLAUDE_CONFIG_MODE,
                )?;
                return Ok(if created {
                    ClaudeOnboardingSync::Created
                } else {
                    ClaudeOnboardingSync::UserOwned
                });
            }
            Entry::Foreign => return Ok(ClaudeOnboardingSync::UserOwned),
            Entry::Owned(entry) => entry,
        };
        let contents = match mark_onboarding(&entry.contents, trusted, onboarding)? {
            Marking::NotAnObject => return Ok(ClaudeOnboardingSync::UserOwned),
            Marking::Current => return Ok(ClaudeOnboardingSync::Current),
            Marking::Marked(contents) => contents,
        };
        let replaced = home.replace_unchanged(
            &temporary,
            CLAUDE_CONFIG_FILE_NAME,
            &entry,
            MAX_CLAUDE_CONFIG_BYTES,
            &contents,
            entry.mode & CLAUDE_CONFIG_MODE,
        )?;
        Ok(if replaced {
            ClaudeOnboardingSync::Marked
        } else {
            ClaudeOnboardingSync::UserOwned
        })
    }

    /// [`Self::sync`] before the daemon listens, and, unless the sign-in
    /// form is selected, removal of Codewire's Claude login. A failure is
    /// logged and never stops the daemon: without the keys Claude Code only
    /// shows its login picker once.
    pub fn prepare(&self, clients: ManagedCredentialClients) {
        match self.sync(clients) {
            Ok(outcome) => {
                tracing::info!(claude_onboarding = ?outcome, "Claude Code onboarding prepared");
            }
            Err(error) => tracing::warn!(
                error_kind = ?error.kind(),
                "Claude Code home unavailable; onboarding was not marked"
            ),
        }
        if !clients.anthropic_sign_in() {
            match self.remove_codewire_login() {
                Ok(removal) => {
                    tracing::info!(claude_login = ?removal, "Claude login cleared");
                }
                Err(error) => tracing::warn!(
                    error_kind = ?error.kind(),
                    "Claude login could not be cleared"
                ),
            }
        }
    }
}

/// Keeps the workspace's repositories trusted as they appear: a hosted
/// Sandbox's are cloned after the daemon serves, and the user clones more.
/// [`Self::refresh`] runs before each session launch and writes only when the
/// set of trusted folders changed since the last write.
#[derive(Clone, Debug)]
pub struct WorkspaceTrust {
    home: ClaudeHome,
    written: Arc<Mutex<Vec<String>>>,
}

impl WorkspaceTrust {
    pub fn new(home: ClaudeHome) -> Self {
        Self {
            home,
            written: Arc::default(),
        }
    }

    /// Trust any repository that appeared under the workspace. A failure is
    /// logged and never stops the launch: Claude Code then asks once.
    pub fn refresh(&self) {
        let trusted = trusted_folders(Path::new(&self.home.workspace));
        let mut written = self
            .written
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if *written == trusted {
            return;
        }
        match self.home.mark(&[], &trusted) {
            Ok(outcome) => {
                if outcome != ClaudeOnboardingSync::UserOwned {
                    *written = trusted;
                }
                tracing::info!(claude_trust = ?outcome, "Claude Code workspace trust refreshed");
            }
            Err(error) => tracing::warn!(
                error_kind = ?error.kind(),
                "Claude Code home unavailable; workspace trust was not refreshed"
            ),
        }
    }
}

/// The folders Claude Code is told to trust: the workspace root and every Git
/// repository root under it (a folder holding `.git`), at most
/// [`TRUST_DEPTH`] levels down. The walk follows no symlink, skips hidden
/// folders, does not look inside a repository, and reads at most
/// [`MAX_TRUST_ENTRIES`] entries. Sorted, the root first.
pub fn trusted_folders(workspace: &Path) -> Vec<String> {
    let mut repositories = Vec::new();
    let mut level = vec![workspace.to_path_buf()];
    let mut read = 0;
    'walk: for _ in 0..TRUST_DEPTH {
        let mut next = Vec::new();
        for folder in level {
            let Ok(entries) = std::fs::read_dir(&folder) else {
                continue;
            };
            for entry in entries.flatten() {
                read += 1;
                if read > MAX_TRUST_ENTRIES {
                    break 'walk;
                }
                if entry.file_name().as_encoded_bytes().first() == Some(&b'.') {
                    continue;
                }
                // The entry's own type: a symlink is never a directory here.
                if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                let path = entry.path();
                if std::fs::symlink_metadata(path.join(".git")).is_ok() {
                    repositories.push(path.to_string_lossy().into_owned());
                } else {
                    next.push(path);
                }
            }
        }
        level = next;
    }
    repositories.sort();
    std::iter::once(workspace.to_string_lossy().into_owned())
        .chain(repositories)
        .collect()
}

enum Marking {
    NotAnObject,
    Current,
    Marked(Vec<u8>),
}

/// The onboarding keys to set: all of them while the Anthropic client is
/// selected, which gives Claude Code its credential, and none otherwise.
fn onboarding_keys(clients: ManagedCredentialClients) -> &'static [&'static str] {
    if clients.contains(ManagedCredentialClient::Anthropic) {
        &CLAUDE_ONBOARDING_KEYS
    } else {
        &[]
    }
}

/// The file with every `onboarding` key `true` and every `trusted` folder
/// trusted. Claude Code rewrites the whole file itself, so its members keep
/// their values but not their spelling or order. A repeated key counts by its
/// last occurrence, as Claude Code reads it.
fn mark_onboarding(
    contents: &[u8],
    trusted: &[String],
    onboarding: &[&str],
) -> io::Result<Marking> {
    let Ok(Value::Object(config)) = serde_json::from_slice(contents) else {
        return Ok(Marking::NotAnObject);
    };
    let mut all_trusted = true;
    for folder in trusted {
        let trust = match config.get("projects") {
            None => None,
            Some(Value::Object(projects)) => match projects.get(folder) {
                None => None,
                Some(Value::Object(project)) => project.get(CLAUDE_TRUST_KEY),
                Some(_) => return Ok(Marking::NotAnObject),
            },
            Some(_) => return Ok(Marking::NotAnObject),
        };
        all_trusted &= trust == Some(&Value::Bool(true));
    }
    if all_trusted
        && onboarding
            .iter()
            .all(|key| config.get(*key) == Some(&Value::Bool(true)))
    {
        return Ok(Marking::Current);
    }
    render(config, trusted, onboarding).map(Marking::Marked)
}

/// `config` with every `onboarding` key `true` and every `trusted` folder
/// trusted, in Claude Code's two-space layout. A `projects` member and a
/// folder's entry that are present are objects ([`mark_onboarding`] checked
/// them).
fn render(
    mut config: Map<String, Value>,
    trusted: &[String],
    onboarding: &[&str],
) -> io::Result<Vec<u8>> {
    for key in onboarding {
        config.insert((*key).to_owned(), Value::Bool(true));
    }
    let projects = config
        .entry("projects")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(projects) = projects {
        for folder in trusted {
            if let Value::Object(project) = projects
                .entry(folder.as_str())
                .or_insert_with(|| Value::Object(Map::new()))
            {
                project.insert(CLAUDE_TRUST_KEY.to_owned(), Value::Bool(true));
            }
        }
    }
    let mut output = serde_json::to_vec_pretty(&config).map_err(io::Error::other)?;
    output.push(b'\n');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    use serde_json::{Value, json};

    fn clients(slots: &[&str]) -> ManagedCredentialClients {
        ManagedCredentialClients::from_profile_slots(slots.iter().copied()).unwrap()
    }

    /// The Anthropic client in each form, as a binding serves it.
    fn anthropic_forms() -> [ManagedCredentialClients; 6] {
        [
            clients(&["anthropic"]),
            clients(&["anthropic"])
                .with_anthropic_subscription_token()
                .unwrap(),
            clients(&["anthropic"]).with_anthropic_sign_in().unwrap(),
            ManagedCredentialClients::decode("v1:codex,openai,anthropic,ssh").unwrap(),
            ManagedCredentialClients::decode("v2:3f").unwrap(),
            ManagedCredentialClients::decode("v2:5f").unwrap(),
        ]
    }

    const WORKSPACE: &str = "/cw-test-workspace-absent";

    /// What a new file holds.
    fn fresh() -> Value {
        json!({
            "hasCompletedOnboarding": true,
            "hasAcknowledgedCostThreshold": true,
            "projects": { "/cw-test-workspace-absent": { "hasTrustDialogAccepted": true } }
        })
    }

    fn home() -> (tempfile::TempDir, ClaudeHome) {
        let root = tempfile::tempdir().unwrap();
        let home = ClaudeHome::new(root.path().join("codewire"), Path::new(WORKSPACE));
        fs::create_dir(home.root()).unwrap();
        (root, home)
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    /// A new file at `path`, replacing any earlier one, even a read-only one.
    fn write(path: &Path, contents: &str, mode: u32) {
        let _ = fs::remove_file(path);
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Every name in the home but `.claude.json`, so a test can prove no
    /// temporary file remains.
    fn other_entries(home: &ClaudeHome) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(home.root())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != CLAUDE_CONFIG_FILE_NAME)
            .collect();
        names.sort();
        names
    }

    /// A file as Claude Code writes it after use.
    const USED: &str = concat!(
        "{\n",
        "  \"numStartups\": 3,\n",
        "  \"installMethod\": \"npm\",\n",
        "  \"projects\": {\n",
        "    \"/cw-test-workspace-absent\": {\n",
        "      \"allowedTools\": [],\n",
        "      \"hasTrustDialogAccepted\": false\n",
        "    }\n",
        "  },\n",
        "  \"firstStartTime\": \"2026-10-05T12:00:00.000Z\",\n",
        "  \"large\": 123456789012345678901234567890,\n",
        "  \"ratio\": 1.50,\n",
        "  \"escaped\": \"caf\\u00e9\",\n",
        "  \"userID\": \"0123abcd\"\n",
        "}",
    );

    #[test]
    fn a_missing_file_is_created_with_exactly_the_onboarding_keys() {
        for clients in anthropic_forms() {
            let (_root, home) = home();
            assert_eq!(home.sync(clients).unwrap(), ClaudeOnboardingSync::Created);
            let written = fs::read(home.config_path()).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&written).unwrap(), fresh());
            assert!(written.ends_with(b"\n}\n"));
            assert_eq!(mode(&home.config_path()), 0o600);
            let metadata = fs::symlink_metadata(home.config_path()).unwrap();
            // SAFETY: geteuid has no preconditions and cannot fail.
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert!(
                other_entries(&home).is_empty(),
                "{:?}",
                other_entries(&home)
            );
        }
    }

    #[test]
    fn a_local_vm_daemon_prepares_the_workload_users_home_the_same_way() {
        // SAFETY: geteuid and getegid have no preconditions and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let owner = FileOwner { uid, gid };
        for clients in anthropic_forms() {
            let (_root, hosted) = home();
            let home = ClaudeHome::new(hosted.root(), Path::new(WORKSPACE)).for_owner(owner);
            assert_eq!(home.sync(clients).unwrap(), ClaudeOnboardingSync::Created);
            let written = fs::read(home.config_path()).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&written).unwrap(), fresh());
            assert_eq!(mode(&home.config_path()), 0o600);
            assert_eq!(fs::symlink_metadata(home.config_path()).unwrap().uid(), uid);
            assert_eq!(home.sync(clients).unwrap(), ClaudeOnboardingSync::Current);
        }
        // Another user's home is never touched on the workload user's behalf.
        let (_root, hosted) = home();
        let other = FileOwner {
            uid: uid.wrapping_add(1),
            gid,
        };
        let home = ClaudeHome::new(hosted.root(), Path::new(WORKSPACE)).for_owner(other);
        assert_eq!(
            home.sync(anthropic_forms()[0]).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert!(!home.config_path().exists());
    }

    /// `contents` with both onboarding keys `true` and the workspace trusted,
    /// as a value.
    fn marked(contents: &str) -> Value {
        let mut value: Value = serde_json::from_str(contents).unwrap();
        for key in CLAUDE_ONBOARDING_KEYS {
            value[key] = Value::Bool(true);
        }
        value["projects"][WORKSPACE][CLAUDE_TRUST_KEY] = Value::Bool(true);
        value
    }

    fn written(home: &ClaudeHome) -> Value {
        serde_json::from_slice(&fs::read(home.config_path()).unwrap()).unwrap()
    }

    #[test]
    fn existing_members_keep_their_values() {
        let (_root, home) = home();
        write(&home.config_path(), USED, 0o644);
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::Marked
        );
        assert_eq!(written(&home), marked(USED));
        // The workspace entry Claude Code recorded keeps its other members.
        assert_eq!(
            written(&home)["projects"]["/cw-test-workspace-absent"],
            json!({ "allowedTools": [], "hasTrustDialogAccepted": true })
        );
        assert_eq!(mode(&home.config_path()), 0o600, "a wider mode is narrowed");
        assert!(other_entries(&home).is_empty());

        // A key Claude Code recorded as false is set; a narrower mode is kept.
        let compact = "{\"theme\":\"dark\",\"hasCompletedOnboarding\":false,\"tips\":{\"a\":1}}\n";
        write(&home.config_path(), compact, 0o400);
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::Marked
        );
        assert_eq!(written(&home), marked(compact));
        assert_eq!(mode(&home.config_path()), 0o400);

        // An empty object, and a key spelled with an escape, which Claude
        // Code reads as the same key.
        for before in [
            "{}",
            "{\"has\\u0043ompletedOnboarding\": 1, \"hasAcknowledgedCostThreshold\": true}",
        ] {
            write(&home.config_path(), before, 0o600);
            assert_eq!(
                home.sync(clients(&["anthropic"])).unwrap(),
                ClaudeOnboardingSync::Marked,
                "{before}"
            );
            assert_eq!(written(&home), fresh());
        }
        assert!(other_entries(&home).is_empty());
    }

    #[test]
    fn keys_already_true_are_never_rewritten() {
        let (_root, home) = home();
        for current in [
            "{\"hasAcknowledgedCostThreshold\":true,\"hasCompletedOnboarding\":true,\
             \"projects\":{\"/cw-test-workspace-absent\":{\"hasTrustDialogAccepted\":true}}}",
            // Claude Code reads the last of a repeated key.
            "{\"hasCompletedOnboarding\": false, \"hasCompletedOnboarding\": true, \
             \"hasAcknowledgedCostThreshold\": true, \"other\": null, \
             \"projects\": {\"/elsewhere\": {}, \"/cw-test-workspace-absent\": {\"hasTrustDialogAccepted\": true}}}",
        ] {
            write(&home.config_path(), current, 0o644);
            let before = fs::symlink_metadata(home.config_path()).unwrap();
            for clients in anthropic_forms() {
                assert_eq!(home.sync(clients).unwrap(), ClaudeOnboardingSync::Current);
            }
            let after = fs::symlink_metadata(home.config_path()).unwrap();
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.mtime_nsec(), before.mtime_nsec());
            assert_eq!(fs::read_to_string(home.config_path()).unwrap(), current);
            assert_eq!(mode(&home.config_path()), 0o644, "the mode is not changed");
        }
        // A repeated key whose last occurrence is not true is set.
        write(
            &home.config_path(),
            "{\"hasCompletedOnboarding\": true, \"hasAcknowledgedCostThreshold\": true, \
             \"hasCompletedOnboarding\": false}",
            0o600,
        );
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::Marked
        );
        assert_eq!(written(&home), fresh());

        // Onboarding recorded but the workspace not trusted, or another
        // folder trusted only: the workspace is trusted.
        for untrusted in [
            "{\"hasCompletedOnboarding\": true, \"hasAcknowledgedCostThreshold\": true}",
            "{\"hasCompletedOnboarding\": true, \"hasAcknowledgedCostThreshold\": true, \
             \"projects\": {\"/home/codewire\": {\"hasTrustDialogAccepted\": true}, \
             \"/cw-test-workspace-absent\": {\"hasTrustDialogAccepted\": false}}}",
        ] {
            write(&home.config_path(), untrusted, 0o600);
            assert_eq!(
                home.sync(clients(&["anthropic"])).unwrap(),
                ClaudeOnboardingSync::Marked,
                "{untrusted}"
            );
            assert_eq!(written(&home), marked(untrusted));
        }
        assert!(other_entries(&home).is_empty());
    }

    #[test]
    fn invalid_json_and_non_objects_are_the_users_and_untouched() {
        let (_root, home) = home();
        for users in [
            "",
            "{",
            "{\"hasCompletedOnboarding\": true,}",
            "{} trailing",
            "{}{}",
            "[]",
            "[{\"hasCompletedOnboarding\": false}]",
            "\"hasCompletedOnboarding\"",
            "null",
            "true",
            "7",
            "\u{feff}{}",
            "// a comment\n{}",
            // `projects`, or the workspace's entry, that Claude Code could not
            // read as an object.
            "{\"projects\": []}",
            "{\"projects\": {\"/cw-test-workspace-absent\": true}}",
        ] {
            write(&home.config_path(), users, 0o644);
            let before = fs::symlink_metadata(home.config_path()).unwrap().ino();
            assert_eq!(
                home.sync(clients(&["anthropic"])).unwrap(),
                ClaudeOnboardingSync::UserOwned,
                "{users:?}"
            );
            assert_eq!(fs::read_to_string(home.config_path()).unwrap(), users);
            assert_eq!(
                fs::symlink_metadata(home.config_path()).unwrap().ino(),
                before
            );
            assert_eq!(mode(&home.config_path()), 0o644);
        }
        fs::write(home.config_path(), [b'{', 0xff, b'}']).unwrap();
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert_eq!(fs::read(home.config_path()).unwrap(), [b'{', 0xff, b'}']);

        // Larger than Claude Code's file grows: never read, never replaced.
        let oversized = fs::File::create(home.config_path()).unwrap();
        oversized.set_len(MAX_CLAUDE_CONFIG_BYTES + 1).unwrap();
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert_eq!(
            fs::metadata(home.config_path()).unwrap().len(),
            MAX_CLAUDE_CONFIG_BYTES + 1
        );
        assert!(other_entries(&home).is_empty());
    }

    #[test]
    fn symlinks_and_special_files_are_never_followed_or_replaced() {
        let (root, home) = home();
        let dotfile = root.path().join("dotfiles-claude.json");
        let unmarked = "{\"hasCompletedOnboarding\": false}";
        write(&dotfile, unmarked, 0o644);
        symlink(&dotfile, home.config_path()).unwrap();
        // A dangling link is not created through either.
        let dangling = ClaudeHome::new(root.path().join("dangling"), Path::new(WORKSPACE));
        fs::create_dir(dangling.root()).unwrap();
        let missing = root.path().join("never-created.json");
        symlink(&missing, dangling.config_path()).unwrap();
        for clients in anthropic_forms() {
            for home in [&home, &dangling] {
                assert_eq!(home.sync(clients).unwrap(), ClaudeOnboardingSync::UserOwned);
                assert!(
                    fs::symlink_metadata(home.config_path())
                        .unwrap()
                        .is_symlink()
                );
                assert!(other_entries(home).is_empty());
            }
        }
        assert_eq!(fs::read_to_string(&dotfile).unwrap(), unmarked);
        assert_eq!(mode(&dotfile), 0o644);
        assert!(fs::symlink_metadata(&missing).is_err());

        // A directory of that name is not a file to write.
        let directory = ClaudeHome::new(root.path().join("directory"), Path::new(WORKSPACE));
        fs::create_dir_all(directory.config_path()).unwrap();
        assert_eq!(
            directory.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert!(directory.config_path().is_dir());

        // A symlinked home receives nothing.
        let target = root.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        let linked = ClaudeHome::new(root.path().join("linked"), Path::new(WORKSPACE));
        symlink(&target, linked.root()).unwrap();
        assert_eq!(
            linked.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    #[test]
    fn without_the_anthropic_client_only_the_workspace_is_trusted() {
        let trusted = json!({ "projects": { "/cw-test-workspace-absent": { "hasTrustDialogAccepted": true } } });
        for slots in [&[][..], &["codex"], &["openai", "ssh", "github"]] {
            let (_root, home) = home();
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                ClaudeOnboardingSync::Created
            );
            assert_eq!(written(&home), trusted, "{slots:?}");
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                ClaudeOnboardingSync::Current
            );
            assert!(other_entries(&home).is_empty());
        }
        // An existing home keeps every member, onboarding included, and gains
        // only the workspace's trust; another folder's entry is untouched.
        let (_root, home) = home();
        write(
            &home.config_path(),
            "{\"hasCompletedOnboarding\": false, \"projects\": {\"/home/codewire\": {\"hasTrustDialogAccepted\": false}}}",
            0o600,
        );
        assert_eq!(
            home.sync(clients(&["codex"])).unwrap(),
            ClaudeOnboardingSync::Marked
        );
        assert_eq!(
            written(&home),
            json!({
                "hasCompletedOnboarding": false,
                "projects": {
                    "/home/codewire": { "hasTrustDialogAccepted": false },
                    "/cw-test-workspace-absent": { "hasTrustDialogAccepted": true }
                }
            })
        );
        // Keys written while Anthropic was selected stay after it is
        // deselected.
        fs::remove_file(home.config_path()).unwrap();
        home.sync(clients(&["anthropic"])).unwrap();
        let marked = fs::read(home.config_path()).unwrap();
        assert_eq!(
            home.sync(clients(&["codex"])).unwrap(),
            ClaudeOnboardingSync::Current
        );
        assert_eq!(fs::read(home.config_path()).unwrap(), marked);
    }

    /// A workspace with repositories at each depth, a plain folder, a hidden
    /// folder, a symlinked repository and a repository nested in another.
    fn workspace_tree(root: &Path) -> PathBuf {
        let workspace = root.join("workspace");
        for repository in [
            "app",
            "team/api",
            "a/b/deep",
            "app/vendor/nested",
            ".hidden/repo",
        ] {
            fs::create_dir_all(workspace.join(repository).join(".git")).unwrap();
        }
        fs::create_dir_all(workspace.join("notes")).unwrap();
        // A worktree's `.git` is a file.
        fs::create_dir_all(workspace.join("linked")).unwrap();
        fs::write(workspace.join("linked/.git"), "gitdir: /elsewhere\n").unwrap();
        fs::create_dir_all(root.join("outside/.git")).unwrap();
        symlink(root.join("outside"), workspace.join("escape")).unwrap();
        // Four levels down is past the walk.
        fs::create_dir_all(workspace.join("w/x/y/z/.git")).unwrap();
        workspace
    }

    #[test]
    fn the_workspace_and_each_repository_root_under_it_are_trusted() {
        let root = tempfile::tempdir().unwrap();
        let workspace = workspace_tree(root.path());
        let at = |folder: &str| workspace.join(folder).to_string_lossy().into_owned();
        assert_eq!(
            trusted_folders(&workspace),
            [
                workspace.to_string_lossy().into_owned(),
                at("a/b/deep"),
                at("app"),
                at("linked"),
                at("team/api"),
            ]
        );
        assert_eq!(
            trusted_folders(&root.path().join("absent")),
            [root.path().join("absent").to_string_lossy().into_owned()]
        );
    }

    #[test]
    fn a_refresh_trusts_repositories_cloned_since_and_keeps_the_rest() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        fs::create_dir_all(workspace.join("first/.git")).unwrap();
        let home = ClaudeHome::new(root.path().join("home"), &workspace);
        fs::create_dir(home.root()).unwrap();
        let folder = |name: &str| match name {
            "" => workspace.to_string_lossy().into_owned(),
            name => workspace.join(name).to_string_lossy().into_owned(),
        };
        let trusted =
            |name: &str| written(&home)["projects"][folder(name)][CLAUDE_TRUST_KEY].clone();
        write(
            &home.config_path(),
            r#"{"numStartups": 4, "projects": {"/home/codewire": {"hasTrustDialogAccepted": false}}}"#,
            0o600,
        );
        let trust = WorkspaceTrust::new(home.clone());
        trust.refresh();
        assert_eq!(trusted(""), json!(true));
        assert_eq!(trusted("first"), json!(true));
        assert_eq!(written(&home)["numStartups"], json!(4));
        assert_eq!(
            written(&home)["projects"]["/home/codewire"],
            json!({ "hasTrustDialogAccepted": false })
        );
        assert!(written(&home).get("hasCompletedOnboarding").is_none());
        // Nothing new: the file is not rewritten, even after Claude Code
        // changed it.
        write(&home.config_path(), "{\"theme\": \"dark\"}", 0o600);
        trust.refresh();
        assert_eq!(written(&home), json!({ "theme": "dark" }));
        // A repository cloned since is trusted, and the rest stay as they are.
        fs::create_dir_all(workspace.join("second/.git")).unwrap();
        trust.refresh();
        assert_eq!(written(&home)["theme"], json!("dark"));
        assert_eq!(trusted("second"), json!(true));
        assert_eq!(trusted("first"), json!(true));
        assert!(other_entries(&home).is_empty());
    }

    #[test]
    fn no_projected_value_or_credential_enters_the_file() {
        let (_root, home) = home();
        write(&home.config_path(), "{\"theme\": \"dark\"}", 0o600);
        for clients in anthropic_forms() {
            home.sync(clients).unwrap();
            let written = fs::read_to_string(home.config_path()).unwrap();
            let Value::Object(members) = serde_json::from_str(&written).unwrap() else {
                panic!("an object");
            };
            assert_eq!(
                members.keys().map(String::as_str).collect::<Vec<_>>(),
                [
                    "hasAcknowledgedCostThreshold",
                    "hasCompletedOnboarding",
                    "projects",
                    "theme"
                ]
            );
            assert_eq!(
                members["projects"],
                json!({ "/cw-test-workspace-absent": { "hasTrustDialogAccepted": true } })
            );
            for value in clients
                .for_placement(codewire_access::ManagedCredentialClientPlacement::Platform)
                .environment
                .values()
                .filter(|value| !value.is_empty())
            {
                assert!(!written.contains(value.as_str()), "{value}");
            }
        }
    }

    #[test]
    fn a_missing_home_is_an_error_not_a_panic() {
        let root = tempfile::tempdir().unwrap();
        let home = ClaudeHome::new(root.path().join("absent"), Path::new(WORKSPACE));
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!home.root().exists(), "the home is never created");
        // The daemon logs it and keeps starting.
        home.prepare(clients(&["anthropic"]));
    }
}
