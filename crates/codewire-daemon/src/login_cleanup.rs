//! Clearing Codewire's delivered agent logins when nothing keeps them.
//!
//! A Codex or Claude Code login Codewire delivered (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Direct delivery exceptions") is live material only while its writer keeps
//! it for the current boot and owner. A disk that outlived that boot, such as a
//! stopped VM's or one carried into another environment, may still hold one.
//! The daemon clears it whenever no writer keeps it, and a local VM's guest
//! clears both when it first boots as a different environment. Each removal
//! recognises only a file Codewire wrote, so the user's own logins are kept.

use std::io;

use crate::claude_home::ClaudeHome;
use crate::codex_home::CodexHome;

/// Remove Codewire's Codex `auth.json` from `home`. A failure is logged and
/// returned.
pub fn clear_codex_login(home: &CodexHome) -> io::Result<()> {
    match home.remove_codewire_login() {
        Ok(removal) => {
            tracing::info!(codex_login = ?removal, "Codewire's Codex login cleared");
            Ok(())
        }
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                "Codewire's Codex login could not be cleared"
            );
            Err(error)
        }
    }
}

/// Remove Codewire's Claude Code login from `home`. A failure is logged and
/// returned.
pub fn clear_claude_login(home: &ClaudeHome) -> io::Result<()> {
    match home.remove_codewire_login() {
        Ok(removal) => {
            tracing::info!(claude_login = ?removal, "Codewire's Claude login cleared");
            Ok(())
        }
        Err(error) => {
            tracing::warn!(
                error_kind = ?error.kind(),
                "Codewire's Claude login could not be cleared"
            );
            Err(error)
        }
    }
}

/// Remove each agent's Codewire login that no writer keeps for this boot and
/// owner, whatever the reason the writer is absent: the agent is not selected,
/// there is no bridge, or the home is of another placement. A failure is
/// logged and never stops the daemon.
pub(crate) fn clear_unkept_logins(
    codex: &CodexHome,
    claude: &ClaudeHome,
    codex_kept: bool,
    claude_kept: bool,
) {
    if !codex_kept {
        let _ = clear_codex_login(codex);
    }
    if !claude_kept {
        let _ = clear_claude_login(claude);
    }
}

/// The name, in the home's `.codewire`, of the environment whose logins the
/// home may hold.
#[cfg(target_os = "linux")]
const LOGIN_ENVIRONMENT_FILE: &str = "login-environment";

/// Clear both agents' Codewire logins when this home last belonged to another
/// environment, before any writer starts, as a local guest does. A disk made
/// from a snapshot had its logins cleared at capture; this covers any disk that
/// arrives another way, and a writer that hasn't delivered yet. An unreadable
/// record is treated as another environment's. A failure is logged and never
/// stops the daemon; the record is written only once both logins are cleared.
#[cfg(target_os = "linux")]
pub(crate) fn clear_logins_on_environment_change(
    home: &std::path::Path,
    environment_id: &str,
    owner: Option<crate::private_files::FileOwner>,
    clear: impl FnOnce() -> io::Result<()>,
) {
    use crate::private_files::{Entry, PrivateDirectory};

    let opened = match owner {
        Some(owner) => PrivateDirectory::open_for(home, owner),
        None => PrivateDirectory::open_home(home),
    }
    .and_then(|home| match home {
        Some(home) => home.open_or_create_child(".codewire", 0o700),
        None => Ok(None),
    });
    let directory = match opened {
        Ok(directory) => directory,
        Err(error) => {
            tracing::warn!(error_kind = ?error.kind(), "the home's login record is unavailable");
            None
        }
    };
    let recorded = directory
        .as_ref()
        .and_then(|directory| directory.read(LOGIN_ENVIRONMENT_FILE, 128).ok());
    if let Some(Entry::Owned(entry)) = &recorded
        && entry.contents.as_slice() == environment_id.as_bytes()
    {
        return;
    }
    if clear().is_err() {
        return;
    }
    let Some(directory) = directory else {
        return;
    };
    let temporary = format!(".{LOGIN_ENVIRONMENT_FILE}.{}", std::process::id());
    let written = directory
        .write_new(&temporary, environment_id.as_bytes(), 0o600)
        .and_then(|()| directory.rename(&temporary, LOGIN_ENVIRONMENT_FILE))
        .and_then(|()| directory.sync());
    if let Err(error) = written {
        let _ = directory.unlink(&temporary);
        tracing::warn!(error_kind = ?error.kind(), "the home's login record could not be written");
    }
}

/// What a hosted daemon runs once bound, before any login writer starts.
#[cfg(target_os = "linux")]
pub fn clear_logins_for_bound_environment(config: &crate::Config, environment_id: uuid::Uuid) {
    let codex = CodexHome::default();
    let claude = ClaudeHome::new(&config.home_root, &config.workspace_root);
    clear_logins_on_environment_change(
        &config.home_root,
        &environment_id.hyphenated().to_string(),
        None,
        || clear_logins(&codex, &claude),
    );
}

/// Remove both agents' Codewire logins. Both are attempted; the first failure
/// is returned.
pub fn clear_logins(codex: &CodexHome, claude: &ClaudeHome) -> io::Result<()> {
    let codex = clear_codex_login(codex);
    let claude = clear_claude_login(claude);
    codex.and(claude)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::cell::Cell;

    use super::*;

    const THIS: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER: &str = "6ba7b810-9dad-41d1-80b4-00c04fd430c8";

    fn cleared(home: &std::path::Path, environment_id: &str, result: io::Result<()>) -> bool {
        let called = Cell::new(false);
        clear_logins_on_environment_change(home, environment_id, None, || {
            called.set(true);
            result
        });
        called.get()
    }

    #[test]
    fn a_home_clears_once_for_each_new_environment() {
        let home = tempfile::tempdir().unwrap();
        assert!(cleared(home.path(), THIS, Ok(())), "a home with no record");
        assert!(!cleared(home.path(), THIS, Ok(())), "the same environment");
        assert!(cleared(home.path(), OTHER, Ok(())), "a disk carried over");
        assert!(!cleared(home.path(), OTHER, Ok(())));
    }

    #[test]
    fn a_failed_clear_is_tried_again_at_the_next_start() {
        let home = tempfile::tempdir().unwrap();
        assert!(cleared(home.path(), THIS, Err(io::Error::other("busy"))));
        assert!(cleared(home.path(), THIS, Ok(())));
        assert!(!cleared(home.path(), THIS, Ok(())));
    }

    #[test]
    fn a_record_that_is_a_symlink_never_counts() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = home.path().join("elsewhere");
        std::fs::write(&elsewhere, THIS).unwrap();
        std::fs::create_dir(home.path().join(".codewire")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.path().join(".codewire/login-environment"))
            .unwrap();
        assert!(cleared(home.path(), THIS, Ok(())));
        assert!(
            !std::fs::symlink_metadata(home.path().join(".codewire/login-environment"))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn a_symlinked_record_directory_still_clears_and_writes_nothing_through_it() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = home.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.path().join(".codewire")).unwrap();
        assert!(cleared(home.path(), THIS, Ok(())));
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }
}
