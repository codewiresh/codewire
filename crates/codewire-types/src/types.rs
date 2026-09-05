//! Serializable local status, diff, and chat display types for the desktop.

use serde::{Deserialize, Serialize};

/// Git repository status discovered from a local project
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitStatus {
    /// Commits ahead of remote
    pub ahead: u32,
    /// Commits behind remote
    pub behind: u32,
    /// Has uncommitted changes
    pub dirty: bool,
    /// Lines added vs merge-base
    pub additions: u32,
    /// Lines deleted vs merge-base
    pub deletions: u32,
}

// ============================================================================
// Diff Types
// ============================================================================

/// Type of file change in a diff
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileChangeType {
    Added,
    Deleted,
    Modified,
    Renamed,
}

/// Type of a line within a diff hunk
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiffLineType {
    Add,
    Remove,
    Context,
    Header,
}

/// A single line in a diff hunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    pub line_type: DiffLineType,
    pub content: String,
    pub old_line_number: Option<u32>,
    pub new_line_number: Option<u32>,
}

/// A contiguous block of changes in a file diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    pub header: String,
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
    pub lines: Vec<DiffLine>,
}

/// Diff information for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiff {
    pub file_path: String,
    pub old_path: Option<String>,
    pub change_type: FileChangeType,
    pub is_binary: bool,
    pub additions: u32,
    pub deletions: u32,
    pub hunks: Vec<DiffHunk>,
}

/// A chat message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub role: MessageRole,
    pub content: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
}

/// Role of a message sender
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Assistant,
    System,
}
