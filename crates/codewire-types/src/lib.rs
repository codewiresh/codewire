//! Shared local status, diff, and chat display primitives for the Codewire desktop.
//!
//! The crate is intentionally I/O-free; `codewire-desktop` owns local process
//! execution and passes command output into these parsers.

pub mod parsers;
pub mod types;

// Re-export key items at crate root
pub use parsers::{parse_git_status, parse_name_status, parse_numstat, parse_unified_diff};
pub use types::*;
