//! Claude Code's first-run onboarding in a hosted Sandbox.
//!
//! While the Anthropic client is selected, in either form (API key or Claude
//! subscription token), Claude Code already has Codewire's managed
//! credential, yet on a fresh home it opens its first-run "Select login
//! method" picker, because its `~/.claude.json` does not record onboarding.
//! Before it listens, the hosted daemon therefore sets
//! [`CLAUDE_ONBOARDING_KEYS`] to `true` in that file, in both identity modes.
//! Claude Code still asks once per folder whether you trust it: no project
//! trust and no updater setting is written, and no token, credential or
//! placeholder ever enters the file.
//!
//! - A missing file is created with exactly those two keys, mode 0600.
//! - A regular file of the daemon's uid that holds a JSON object gets the keys
//!   that are not already `true`; every other member keeps its value. The file
//!   is replaced atomically (an exclusive temporary beside it, fsync, rename)
//!   with mode 0600, or its own mode where that is narrower, and only while it
//!   is still the file that was read.
//! - Anything else (a symlink, a special or another uid's file, an oversized
//!   file, invalid JSON or a non-object) is the user's and is never touched.
//!   Every operation is relative to the home opened with `O_NOFOLLOW`, and the
//!   file is opened with `O_NOFOLLOW`: nothing is followed through a symlink.
//!
//! The keys only skip onboarding, so they are never removed, also when the
//! Anthropic client is later deselected. A selection change restarts the
//! Sandbox, so one pass at daemon start covers it. Hosted Sandboxes only: a
//! local VM's guest daemon runs as root and keeps the user's home in an
//! overlay, and does not write it.
//!
//! Only [`ClaudeOnboardingSync`] states are logged, never file contents.

use std::io;
use std::path::{Path, PathBuf};

use codewire_access::{ManagedCredentialClient, ManagedCredentialClients};
use serde_json::{Map, Value};

use crate::private_files::{Entry, PrivateDirectory};

/// Claude Code's global configuration file in the user's home.
pub const CLAUDE_CONFIG_FILE_NAME: &str = ".claude.json";
/// The members set to `true`.
pub const CLAUDE_ONBOARDING_KEYS: [&str; 2] =
    ["hasCompletedOnboarding", "hasAcknowledgedCostThreshold"];
const CLAUDE_CONFIG_MODE: u32 = 0o600;
/// Claude Code keeps per-project state in the file, so it grows with use; a
/// larger one is left alone.
const MAX_CLAUDE_CONFIG_BYTES: u64 = 32 * 1024 * 1024;

/// What one sync did. It names no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeOnboardingSync {
    /// The Anthropic client is not selected: nothing was read or written.
    NotSelected,
    /// `~/.claude.json` was missing and now holds exactly the two keys.
    Created,
    /// The keys that were not `true` were set in the existing file.
    Marked,
    /// Both keys were already `true`: nothing was written.
    Current,
    /// The file or the home is the user's (see the module documentation), or
    /// the file changed while it was checked. Nothing was touched.
    UserOwned,
}

/// The workspace user's home, which holds Claude Code's `.claude.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaudeHome {
    root: PathBuf,
}

impl ClaudeHome {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join(CLAUDE_CONFIG_FILE_NAME)
    }

    /// Mark Claude Code's onboarding complete while the served `clients`
    /// select the Anthropic client, in either form.
    pub fn sync(&self, clients: ManagedCredentialClients) -> io::Result<ClaudeOnboardingSync> {
        if !clients.contains(ManagedCredentialClient::Anthropic) {
            return Ok(ClaudeOnboardingSync::NotSelected);
        }
        let Some(home) = PrivateDirectory::open_home(&self.root)? else {
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
                    &render(Map::new())?,
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
        let contents = match mark_onboarding(&entry.contents)? {
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

    /// [`Self::sync`] before the daemon listens. A failure is logged and
    /// never stops the daemon: without the keys Claude Code only shows its
    /// login picker once.
    pub fn prepare(&self, clients: ManagedCredentialClients) {
        match self.sync(clients) {
            Ok(outcome) => {
                tracing::info!(claude_onboarding = ?outcome, "hosted Claude Code onboarding prepared");
            }
            Err(error) => tracing::warn!(
                error_kind = ?error.kind(),
                "hosted Claude Code home unavailable; onboarding was not marked"
            ),
        }
    }
}

enum Marking {
    NotAnObject,
    Current,
    Marked(Vec<u8>),
}

/// The file with every onboarding key `true`. Claude Code rewrites the whole
/// file itself, so its members keep their values but not their spelling or
/// order. A repeated key counts by its last occurrence, as Claude Code reads
/// it.
fn mark_onboarding(contents: &[u8]) -> io::Result<Marking> {
    let Ok(Value::Object(config)) = serde_json::from_slice(contents) else {
        return Ok(Marking::NotAnObject);
    };
    if CLAUDE_ONBOARDING_KEYS
        .iter()
        .all(|key| config.get(*key) == Some(&Value::Bool(true)))
    {
        return Ok(Marking::Current);
    }
    render(config).map(Marking::Marked)
}

/// `config` with every onboarding key `true`, in Claude Code's two-space
/// layout.
fn render(mut config: Map<String, Value>) -> io::Result<Vec<u8>> {
    for key in CLAUDE_ONBOARDING_KEYS {
        config.insert(key.to_owned(), Value::Bool(true));
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
    fn anthropic_forms() -> [ManagedCredentialClients; 4] {
        [
            clients(&["anthropic"]),
            clients(&["anthropic"])
                .with_anthropic_subscription_token()
                .unwrap(),
            ManagedCredentialClients::decode("v1:codex,openai,anthropic,ssh").unwrap(),
            ManagedCredentialClients::decode("v2:3f").unwrap(),
        ]
    }

    fn home() -> (tempfile::TempDir, ClaudeHome) {
        let root = tempfile::tempdir().unwrap();
        let home = ClaudeHome::at(root.path().join("codewire"));
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
        "    \"/workspace\": {\n",
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
            assert_eq!(
                serde_json::from_slice::<Value>(&written).unwrap(),
                json!({ "hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true })
            );
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

    /// `contents` with both onboarding keys `true`, as a value.
    fn marked(contents: &str) -> Value {
        let mut value: Value = serde_json::from_str(contents).unwrap();
        for key in CLAUDE_ONBOARDING_KEYS {
            value[key] = Value::Bool(true);
        }
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
        assert_eq!(
            written(&home)["projects"]["/workspace"]["hasTrustDialogAccepted"],
            false
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
            assert_eq!(
                written(&home),
                json!({ "hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true })
            );
        }
        assert!(other_entries(&home).is_empty());
    }

    #[test]
    fn keys_already_true_are_never_rewritten() {
        let (_root, home) = home();
        for current in [
            "{\"hasAcknowledgedCostThreshold\":true,\"hasCompletedOnboarding\":true}",
            // Claude Code reads the last of a repeated key.
            "{\"hasCompletedOnboarding\": false, \"hasCompletedOnboarding\": true, \
             \"hasAcknowledgedCostThreshold\": true, \"other\": null}",
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
        assert_eq!(
            written(&home),
            json!({ "hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true })
        );
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
        let dangling = ClaudeHome::at(root.path().join("dangling"));
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
        let directory = ClaudeHome::at(root.path().join("directory"));
        fs::create_dir_all(directory.config_path()).unwrap();
        assert_eq!(
            directory.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert!(directory.config_path().is_dir());

        // A symlinked home receives nothing.
        let target = root.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        let linked = ClaudeHome::at(root.path().join("linked"));
        symlink(&target, linked.root()).unwrap();
        assert_eq!(
            linked.sync(clients(&["anthropic"])).unwrap(),
            ClaudeOnboardingSync::UserOwned
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }

    #[test]
    fn nothing_is_written_or_removed_without_the_anthropic_client() {
        let (_root, home) = home();
        for slots in [&[][..], &["codex"], &["openai", "ssh", "github"]] {
            assert_eq!(
                home.sync(clients(slots)).unwrap(),
                ClaudeOnboardingSync::NotSelected
            );
            assert!(
                fs::symlink_metadata(home.config_path()).is_err(),
                "{slots:?}"
            );
        }
        assert!(other_entries(&home).is_empty());
        // The user's file is not read, and keys written while Anthropic was
        // selected stay after it is deselected.
        write(
            &home.config_path(),
            "{\"hasCompletedOnboarding\": false}",
            0o644,
        );
        assert_eq!(
            home.sync(clients(&["codex"])).unwrap(),
            ClaudeOnboardingSync::NotSelected
        );
        assert_eq!(
            fs::read_to_string(home.config_path()).unwrap(),
            "{\"hasCompletedOnboarding\": false}"
        );
        fs::remove_file(home.config_path()).unwrap();
        home.sync(clients(&["anthropic"])).unwrap();
        let marked = fs::read(home.config_path()).unwrap();
        assert_eq!(
            home.sync(clients(&["codex"])).unwrap(),
            ClaudeOnboardingSync::NotSelected
        );
        assert_eq!(fs::read(home.config_path()).unwrap(), marked);
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
                    "theme"
                ]
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
        let home = ClaudeHome::at(root.path().join("absent"));
        assert_eq!(
            home.sync(clients(&["anthropic"])).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!home.root().exists(), "the home is never created");
        // The daemon logs it and keeps starting.
        home.prepare(clients(&["anthropic"]));
    }
}
