//! SSH session discovery and git status
//!
//! This module provides:
//! - Terminal session discovery (tmux/zellij) — pure parsing + generic over SshSession
//! - Git repository discovery and status — pure parsing + generic over SshSession
//!
//! The actual SSH connection implementation lives in `codewire-platform-native`.

mod git;
mod session;

pub use git::{
    DiffDiscovery, GitDiscovery, PrDiscovery, parse_git_status, parse_name_status, parse_numstat,
    parse_pr_json, parse_unified_diff,
};
pub use session::{
    SessionDiscovery, SessionUpdate, SessionUpdateCallback, parse_tmux_sessions,
    parse_zellij_sessions,
};
