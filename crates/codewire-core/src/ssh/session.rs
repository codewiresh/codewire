//! Terminal session discovery (tmux/zellij)

use crate::CoreError;
use crate::platform::SshSession;
use crate::types::TerminalSession;

// Re-export pure parsers from codewire-types
pub use codewire_types::{parse_tmux_sessions, parse_zellij_sessions};

/// Callback for session updates
pub trait SessionUpdateCallback: Send + Sync {
    fn on_update(&self, update: SessionUpdate);
}

/// Update containing discovered sessions for a workspace
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SessionUpdate {
    pub workspace_id: String,
    pub sessions: Vec<TerminalSession>,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
}

/// Session discovery service
pub struct SessionDiscovery;

impl SessionDiscovery {
    pub fn new() -> Self {
        Self
    }

    /// Discover sessions from a connected SSH session
    pub async fn discover<S: SshSession>(
        &self,
        connection: &S,
    ) -> Result<Vec<TerminalSession>, CoreError> {
        let mut sessions = Vec::new();

        // Try zellij first (more common for modern setups)
        if let Ok(zellij_sessions) = self.discover_zellij(connection).await {
            sessions.extend(zellij_sessions);
        }

        // Then try tmux
        if let Ok(tmux_sessions) = self.discover_tmux(connection).await {
            sessions.extend(tmux_sessions);
        }

        Ok(sessions)
    }

    async fn discover_zellij<S: SshSession>(
        &self,
        connection: &S,
    ) -> Result<Vec<TerminalSession>, CoreError> {
        let output = connection
            .exec("zellij ls --no-formatting 2>/dev/null || true")
            .await?;
        Ok(parse_zellij_sessions(&output))
    }

    async fn discover_tmux<S: SshSession>(
        &self,
        connection: &S,
    ) -> Result<Vec<TerminalSession>, CoreError> {
        let output = connection
            .exec(
                "tmux ls -F '#{session_name}|#{session_attached}|#{session_windows}' 2>/dev/null || true",
            )
            .await?;
        Ok(parse_tmux_sessions(&output))
    }
}

impl Default for SessionDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

// Tests for the parsers are in codewire-types::parsers
