//! Core types exposed via UniFFI (when feature is enabled) and Tsify for WASM (when feature is enabled)

use serde::{Deserialize, Serialize};

/// A terminal session discovered via SSH (tmux/zellij)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct TerminalSession {
    pub name: String,
    pub session_type: SessionType,
    pub attached: bool,
    /// Number of windows (tmux only)
    pub windows: Option<u32>,
}

/// Type of terminal multiplexer
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum SessionType {
    Zellij,
    Tmux,
}

/// Git repository status discovered via SSH
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
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
// Diff / Pull Request Types
// ============================================================================

/// Type of file change in a diff
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum FileChangeType {
    Added,
    Deleted,
    Modified,
    Renamed,
}

/// Type of a line within a diff hunk
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum DiffLineType {
    Add,
    Remove,
    Context,
    Header,
}

/// A single line in a diff hunk
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct DiffLine {
    pub line_type: DiffLineType,
    pub content: String,
    pub old_line_number: Option<u32>,
    pub new_line_number: Option<u32>,
}

/// A contiguous block of changes in a file diff
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct FileDiff {
    pub file_path: String,
    pub old_path: Option<String>,
    pub change_type: FileChangeType,
    pub is_binary: bool,
    pub additions: u32,
    pub deletions: u32,
    pub hunks: Vec<DiffHunk>,
}

/// State of a pull request
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum PrState {
    Open,
    Closed,
    Merged,
}

/// Whether a PR can be merged
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum MergeableState {
    Mergeable,
    Conflicting,
    Unknown,
}

/// GitHub pull request information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct PullRequest {
    pub number: u32,
    pub title: String,
    pub url: String,
    pub state: PrState,
    pub is_draft: bool,
    pub head_ref: String,
    pub base_ref: String,
    pub mergeable: MergeableState,
    pub has_failed_checks: bool,
    pub has_pending_checks: bool,
}

/// Represents a workspace (local, SSH, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub project_path: String,
    pub runtime_type: RuntimeType,
    pub status: WorkspaceStatus,
}

/// The type of runtime environment for a workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RuntimeType {
    /// Local filesystem
    Local,
    /// Git worktree
    Worktree { src_base_dir: String },
    /// SSH connection
    Ssh { host: String, user: String },
    /// Docker container
    Docker { image: String },
}

/// Current status of a workspace
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum WorkspaceStatus {
    Ready,
    Connecting,
    Error { message: String },
}

/// A chat message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct ChatMessage {
    pub id: String,
    pub role: MessageRole,
    pub content: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
}

/// Role of a message sender
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum MessageRole {
    User,
    Assistant,
    System,
}

/// Events emitted during AI streaming
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum StreamEvent {
    /// A text token was received
    Token { text: String },
    /// A tool call started
    ToolCallStart { id: String, name: String },
    /// A tool call completed
    ToolCallEnd { id: String, output: String },
    /// Reasoning/thinking content
    Reasoning { text: String },
    /// Stream completed successfully
    Done { message: ChatMessage },
    /// An error occurred
    Error { message: String },
}

/// AI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct AiConfig {
    pub provider: AiProvider,
    pub api_key: String,
    pub model: String,
    /// Optional base URL override
    pub base_url: Option<String>,
}

/// Supported AI providers
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
#[derive(Default)]
pub enum AiProvider {
    #[default]
    Anthropic,
    OpenAi,
    OpenRouter,
}

// ============================================================================
// Codewire Platform Types
// ============================================================================

/// Codewire platform tenant info
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct TenantInfo {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub status: String,
}

// ============================================================================
// Organization Types
// ============================================================================

/// Role within an organization
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub enum OrgRole {
    Owner,
    Admin,
    Member,
}

impl std::fmt::Display for OrgRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrgRole::Owner => write!(f, "owner"),
            OrgRole::Admin => write!(f, "admin"),
            OrgRole::Member => write!(f, "member"),
        }
    }
}

impl std::str::FromStr for OrgRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(OrgRole::Owner),
            "admin" => Ok(OrgRole::Admin),
            "member" => Ok(OrgRole::Member),
            _ => Err(format!("Invalid org role: {}", s)),
        }
    }
}

/// A member of an organization (enriched with user info)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrgMember {
    pub id: String,
    pub user_id: String,
    pub role: OrgRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// An invitation to join an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(tsify_next::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct OrgInvitation {
    pub id: String,
    pub email: String,
    pub role: OrgRole,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// Request to invite a member to an organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub role: OrgRole,
}

/// Request to update a member's role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: OrgRole,
}
