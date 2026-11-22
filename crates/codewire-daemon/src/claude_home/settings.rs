//! Claude Code's own settings in a Sandbox, so that `claude` starts straight
//! into work, in bypass permissions mode, with no screen (#5813; the Claude
//! home paragraph of `docs/dev/SECRETS-AND-CREDENTIALS.md`).
//!
//! The daemon's [`ClaudeHome::prepare`] pass sets, in `~/.claude/settings.json`,
//! each of [`CLAUDE_SANDBOX_SETTINGS`] that is missing:
//! - `permissions.defaultMode` `"bypassPermissions"`, so plain `claude` runs
//!   every tool without asking;
//! - `skipDangerousModePermissionPrompt`, so neither that default nor
//!   `--dangerously-skip-permissions` stops at the bypass screen, whose
//!   default answer ends the session;
//! - `enableAllProjectMcpServers`, so a repository's own `.mcp.json` servers
//!   start without a question, as the workspace's folders are already trusted.
//!
//! A member the user or an image set keeps its value, whatever it is, and so
//! does every other member; an administrator's managed
//! `permissions.disableBypassPermissionsMode` is Claude Code's to apply and
//! still turns bypass off. Only the daemon of a Sandbox placement runs this
//! pass; a trusted host's never does.
//!
//! The file follows `~/.claude.json`'s rules: a missing one is created mode
//! 0600 (and a missing `~/.claude` 0700) holding exactly the settings; an
//! existing regular file of the home's owner that holds a JSON object is
//! replaced atomically, only while it is still the file that was read; and
//! anything else (a symlink, another uid's or an oversized file, invalid
//! JSON, a non-object, or a `permissions` member that is not an object) is
//! the user's and is never touched. Nothing here is a credential, and no
//! token or placeholder is ever written.

use std::io;

use serde_json::{Map, Value};

use super::ClaudeHome;
use crate::private_files::Entry;

/// Claude Code's user settings file in `~/.claude`.
pub const CLAUDE_SETTINGS_FILE_NAME: &str = "settings.json";
/// The member that holds `defaultMode`.
pub const CLAUDE_PERMISSIONS_KEY: &str = "permissions";
/// `permissions.defaultMode`, and the value set while it is missing.
pub const CLAUDE_DEFAULT_MODE_KEY: &str = "defaultMode";
pub const CLAUDE_SANDBOX_DEFAULT_MODE: &str = "bypassPermissions";
/// The top-level members set to `true` while they are missing.
pub const CLAUDE_SANDBOX_SETTINGS: [&str; 2] = [
    "skipDangerousModePermissionPrompt",
    "enableAllProjectMcpServers",
];
const SETTINGS_MODE: u32 = 0o600;
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// What one settings pass did. It names no file contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeSettingsSync {
    /// `~/.claude/settings.json` was missing and now holds exactly the
    /// settings.
    Created,
    /// The missing settings were added to the existing file.
    Marked,
    /// Every setting was already present: nothing was written.
    Current,
    /// The home, `~/.claude` or the file is the user's (see the module
    /// documentation), or the file changed while it was checked. Nothing was
    /// touched.
    UserOwned,
}

enum Merge {
    NotOurs,
    Current,
    Merged(Vec<u8>),
}

impl ClaudeHome {
    /// Add the missing [`CLAUDE_SANDBOX_SETTINGS`] and default mode to
    /// `~/.claude/settings.json`.
    pub fn sync_settings(&self) -> io::Result<ClaudeSettingsSync> {
        let Some(directory) = super::login::open_config(self.root(), true, self.owner())? else {
            return Ok(ClaudeSettingsSync::UserOwned);
        };
        let temporary = format!(
            ".{CLAUDE_SETTINGS_FILE_NAME}.codewire.{}.tmp",
            uuid::Uuid::new_v4().simple()
        );
        let entry = match directory.read(CLAUDE_SETTINGS_FILE_NAME, MAX_SETTINGS_BYTES)? {
            Entry::Absent => {
                let created = directory.install_new(
                    &temporary,
                    CLAUDE_SETTINGS_FILE_NAME,
                    &render(sandbox_settings())?,
                    SETTINGS_MODE,
                )?;
                return Ok(if created {
                    ClaudeSettingsSync::Created
                } else {
                    ClaudeSettingsSync::UserOwned
                });
            }
            Entry::Foreign => return Ok(ClaudeSettingsSync::UserOwned),
            Entry::Owned(entry) => entry,
        };
        let contents = match merge(&entry.contents)? {
            Merge::NotOurs => return Ok(ClaudeSettingsSync::UserOwned),
            Merge::Current => return Ok(ClaudeSettingsSync::Current),
            Merge::Merged(contents) => contents,
        };
        let replaced = directory.replace_unchanged(
            &temporary,
            CLAUDE_SETTINGS_FILE_NAME,
            &entry,
            MAX_SETTINGS_BYTES,
            &contents,
            entry.mode & SETTINGS_MODE,
        )?;
        Ok(if replaced {
            ClaudeSettingsSync::Marked
        } else {
            ClaudeSettingsSync::UserOwned
        })
    }
}

/// Exactly the settings, as a new file holds them.
fn sandbox_settings() -> Map<String, Value> {
    let mut settings = Map::new();
    add_missing(&mut settings);
    settings
}

/// `contents` with every missing setting added, or why nothing is written.
/// A repeated key counts by its last occurrence, as Claude Code reads it.
fn merge(contents: &[u8]) -> io::Result<Merge> {
    let Ok(Value::Object(mut settings)) = serde_json::from_slice(contents) else {
        return Ok(Merge::NotOurs);
    };
    if settings
        .get(CLAUDE_PERMISSIONS_KEY)
        .is_some_and(|permissions| !permissions.is_object())
    {
        return Ok(Merge::NotOurs);
    }
    if !add_missing(&mut settings) {
        return Ok(Merge::Current);
    }
    render(settings).map(Merge::Merged)
}

/// Add each setting `settings` lacks, keeping every value already there.
/// `permissions`, when present, is an object ([`merge`] checked it). Whether
/// anything was added.
fn add_missing(settings: &mut Map<String, Value>) -> bool {
    let mut added = false;
    for key in CLAUDE_SANDBOX_SETTINGS {
        if !settings.contains_key(key) {
            settings.insert(key.to_owned(), Value::Bool(true));
            added = true;
        }
    }
    if let Value::Object(permissions) = settings
        .entry(CLAUDE_PERMISSIONS_KEY)
        .or_insert_with(|| Value::Object(Map::new()))
        && !permissions.contains_key(CLAUDE_DEFAULT_MODE_KEY)
    {
        permissions.insert(
            CLAUDE_DEFAULT_MODE_KEY.to_owned(),
            Value::String(CLAUDE_SANDBOX_DEFAULT_MODE.to_owned()),
        );
        added = true;
    }
    added
}

/// `settings` in Claude Code's two-space layout.
fn render(settings: Map<String, Value>) -> io::Result<Vec<u8>> {
    let mut output = serde_json::to_vec_pretty(&settings).map_err(io::Error::other)?;
    output.push(b'\n');
    Ok(output)
}

#[cfg(test)]
mod tests;
