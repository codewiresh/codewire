//! Codewire Core - Shared business logic for the Codewire app
//!
//! This crate provides the core functionality shared across all platforms:
//! - Native desktop/mobile (via UniFFI bindings when `uniffi` feature is enabled)
//! - WASM (browser) — types only, via `codewire-types`
//! - Server
//!
//! All I/O is abstracted behind traits in the `platform` module.
//! Platform-specific implementations live in separate crates
//! (e.g., `codewire-platform-native`, `codewire-platform-wasm`).
//!
//! Pure types and parsing functions live in `codewire-types` and are
//! re-exported here for convenience.

#[cfg(not(target_arch = "wasm32"))]
pub mod ai;
pub mod codewire;
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod github;
pub mod history;
pub mod platform;
#[cfg(not(target_arch = "wasm32"))]
pub mod ssh;
pub mod storage;
pub mod types;
#[cfg(not(target_arch = "wasm32"))]
pub mod workspace;

// Re-export everything from codewire-types at crate root
pub use codewire_api_types::{
    CreateOrgRequest, Environment, EnvironmentPort, OrgWithRole, Organization,
};
pub use codewire_types::CoreError;
pub use codewire_types::{
    AiConfig, AiProvider, ChatMessage, DiffHunk, DiffLine, DiffLineType, FileChangeType, FileDiff,
    GitStatus, MergeableState, MessageRole, PrState, PullRequest, RuntimeType, SessionType,
    StreamEvent, TenantInfo, TerminalSession, Workspace, WorkspaceStatus,
};
pub use codewire_types::{
    extract_code_from_url, parse_anthropic_sse_event, parse_git_status, parse_name_status,
    parse_numstat, parse_openai_sse_event, parse_pr_json, parse_tmux_sessions, parse_unified_diff,
    parse_zellij_sessions, process_sse_buffer,
};

// Re-export core business logic
pub use codewire::CodewireClient;
#[cfg(not(target_arch = "wasm32"))]
pub use codewire::{CodewireAuthManager, TokenInfo};
#[cfg(not(target_arch = "wasm32"))]
pub use github::{DeviceCodeResponse, GitHubAuthManager, GitHubClient, GitHubRepo, GitHubToken};
pub use history::ChatHistory;
pub use platform::{
    AsyncStorage, HttpClient, HttpResponse, OAuthCallbackHandler, PersistentStorage, SecureStorage,
};
#[cfg(not(target_arch = "wasm32"))]
pub use platform::{ByteChunk, SshClient, SshSession};
#[cfg(not(target_arch = "wasm32"))]
pub use ssh::{
    DiffDiscovery, GitDiscovery, PrDiscovery, SessionDiscovery, SessionUpdate,
    SessionUpdateCallback,
};
pub use storage::ConfigStorage;
#[cfg(not(target_arch = "wasm32"))]
pub use workspace::WorkspaceManager;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
