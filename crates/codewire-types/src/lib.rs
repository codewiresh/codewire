//! Codewire Types — shared types and pure functions
//!
//! This crate has zero tokio dependency and compiles for all targets
//! including wasm32-unknown-unknown. It provides:
//!
//! - Core data types (Workspace, ChatMessage, etc.)
//! - Error types (CoreError)
//! - Pure parsing functions (SSE, git status, tmux/zellij sessions, URLs)
//!
//! Platform-specific clients consume this crate directly.

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod error;
pub mod parsers;
pub mod types;

// Re-export key items at crate root
pub use error::CoreError;
pub use parsers::{
    extract_code_from_url, parse_anthropic_sse_event, parse_git_status, parse_name_status,
    parse_numstat, parse_openai_sse_event, parse_pr_json, parse_tmux_sessions, parse_unified_diff,
    parse_zellij_sessions, process_sse_buffer,
};
pub use types::*;
