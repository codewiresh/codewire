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

/// Remove both agents' Codewire logins. Both are attempted; the first failure
/// is returned.
pub fn clear_logins(codex: &CodexHome, claude: &ClaudeHome) -> io::Result<()> {
    let codex = clear_codex_login(codex);
    let claude = clear_claude_login(claude);
    codex.and(claude)
}
